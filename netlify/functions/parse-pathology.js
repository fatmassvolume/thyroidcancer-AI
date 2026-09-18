/**
 * Netlify serverless function: parse-pathology
 * 
 * Security features:
 *   - Rate limiting via Neon DB (10 requests/hour per IP, 50/day per IP)
 *   - IP extraction with proxy header support
 *   - Body size check (< 5.5 MB)
 *   - CORS restricted to thyroidca.com
 *   - API key validated before use
 *   - Detailed error messages only in non-production environments
 * 
 * POST /.netlify/functions/parse-pathology
 * Body: { data: string (base64), mimeType: string, isPdf: boolean }
 * Returns: { extracted: object } | { error: string }
 */

const { Client } = require('pg');

// ── Constants ────────────────────────────────────────────────────────────────
const RATE_LIMIT_HOUR  = 10;   // max extractions per IP per hour
const RATE_LIMIT_DAY   = 50;   // max extractions per IP per day
const MAX_BODY_BYTES    = 5.5 * 1024 * 1024;
const ALLOWED_ORIGINS  = ['https://thyroidca.com', 'https://www.thyroidca.com', 'https://ata-dtc.netlify.app'];

const EXTRACT_PROMPT = `You are a clinical data extraction assistant reading a thyroid surgical pathology report.

Extract the following fields and return ONLY a valid JSON object with exactly these keys. Use null for any field not found or not determinable from the report.

{
  "patientName": string or null,
  "age": number or null,
  "tumorSize": number (cm, largest focus) or null,
  "histology": one of "PTC","FTC","OTC","IEFVPTC" or null,
  "unfavHist": one of "tallcell","columnar","hobnail","diffscler","solidtrab","pdtc","otc_unfav","none",
  "multifocal": "yes" or "no",
  "fociCount": number or null,
  "fociDistrib": "ipsilateral" or "bilateral" or null,
  "intrathyroidal": "yes" or "no",
  "grossETE": "yes" or "no",
  "resectionStatus": "R0" or "R1" or "R2",
  "marginDist": number (mm) or null,
  "distantMet": "yes" or "no",
  "vasInvasion": "none" or "minimal" or "extensive",
  "vasFoci": number (0-20) or null,
  "nodesNum": number or null,
  "nodeLargest": number (cm) or null,
  "micromet": "yes" or "no",
  "ene": "yes" or "no",
  "pathNotes": string summarising any key pathology details not captured above, or null
}

Rules:
- tumorSize: report the largest tumour focus in cm
- histology: papillary->PTC, follicular->FTC, oncocytic/hurthle->OTC, follicular variant PTC->IEFVPTC
- unfavHist: tall cell->tallcell, columnar->columnar, hobnail/micropapillary->hobnail, diffuse sclerosing->diffscler, solid/trabecular->solidtrab, poorly differentiated->pdtc, oncocytic high-grade->otc_unfav, none->none
- vasInvasion: >=4 foci or extensive->extensive; 1-3 foci or minimal->minimal; none->none
- resectionStatus: clear margins->R0; microscopic positive->R1; gross residual->R2
- grossETE: yes only for GROSS (macroscopic) ETE; minimal/microscopic does NOT qualify
- micromet: yes only if ALL nodal deposits are <2mm
- multifocal: yes if more than one distinct tumour focus
- pathNotes: BRAF status, LVI details, capsular invasion, Ki-67, any other significant findings
- Return ONLY the raw JSON object. No markdown, no preamble.`;

// ── Helpers ───────────────────────────────────────────────────────────────────

function getClientIP(event) {
  // Netlify passes the real IP in x-nf-client-connection-ip
  return (
    event.headers['x-nf-client-connection-ip'] ||
    event.headers['x-forwarded-for']?.split(',')[0]?.trim() ||
    event.headers['client-ip'] ||
    'unknown'
  );
}

function getAllowedOriginHeader(event) {
  const origin = event.headers['origin'] || '';
  if (ALLOWED_ORIGINS.includes(origin)) return origin;
  // Allow all origins in local dev (no origin header)
  if (!origin) return '*';
  return null;
}

function buildHeaders(event) {
  const origin = getAllowedOriginHeader(event);
  const headers = { 'Content-Type': 'application/json' };
  if (origin) {
    headers['Access-Control-Allow-Origin'] = origin;
    headers['Access-Control-Allow-Headers'] = 'Content-Type';
    headers['Access-Control-Allow-Methods'] = 'POST, OPTIONS';
  }
  return headers;
}

function safeError(msg, detail, isProd) {
  // In production, don't leak internal details
  return isProd ? msg : `${msg}: ${detail}`;
}

// ── Rate limiting via Neon ────────────────────────────────────────────────────

async function checkAndRecordRateLimit(ip, dbUrl) {
  // Returns { allowed: bool, hourCount: int, dayCount: int }
  // Uses a simple rate_limit table; creates it if missing.
  const client = new Client({ connectionString: dbUrl, ssl: { rejectUnauthorized: false } });
  try {
    await client.connect();

    // Ensure table exists
    await client.query(`
      CREATE TABLE IF NOT EXISTS parse_rate_limit (
        id         SERIAL PRIMARY KEY,
        ip         TEXT NOT NULL,
        called_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
      );
      CREATE INDEX IF NOT EXISTS idx_prl_ip_time ON parse_rate_limit (ip, called_at);
    `);

    // Count recent calls
    const hourRes = await client.query(
      `SELECT COUNT(*) AS cnt FROM parse_rate_limit
       WHERE ip = $1 AND called_at > NOW() - INTERVAL '1 hour'`,
      [ip]
    );
    const dayRes = await client.query(
      `SELECT COUNT(*) AS cnt FROM parse_rate_limit
       WHERE ip = $1 AND called_at > NOW() - INTERVAL '24 hours'`,
      [ip]
    );

    const hourCount = parseInt(hourRes.rows[0].cnt, 10);
    const dayCount  = parseInt(dayRes.rows[0].cnt, 10);

    if (hourCount >= RATE_LIMIT_HOUR || dayCount >= RATE_LIMIT_DAY) {
      return { allowed: false, hourCount, dayCount };
    }

    // Record this call
    await client.query(
      `INSERT INTO parse_rate_limit (ip) VALUES ($1)`,
      [ip]
    );

    // Purge records older than 7 days to keep the table lean
    await client.query(
      `DELETE FROM parse_rate_limit WHERE called_at < NOW() - INTERVAL '7 days'`
    );

    return { allowed: true, hourCount: hourCount + 1, dayCount: dayCount + 1 };
  } finally {
    await client.end();
  }
}

// ── Main handler ──────────────────────────────────────────────────────────────

exports.handler = async function(event) {
  const isProd = process.env.CONTEXT === 'production';
  const headers = buildHeaders(event);

  // Block disallowed origins in production
  if (isProd && getAllowedOriginHeader(event) === null) {
    return { statusCode: 403, headers, body: JSON.stringify({ error: 'Origin not allowed' }) };
  }

  // Preflight
  if (event.httpMethod === 'OPTIONS') {
    return { statusCode: 204, headers, body: '' };
  }

  if (event.httpMethod !== 'POST') {
    return { statusCode: 405, headers, body: JSON.stringify({ error: 'Method not allowed' }) };
  }

  // ── API key check ──
  const apiKey = process.env.ANTHROPIC_API_KEY;
  if (!apiKey || !apiKey.startsWith('sk-')) {
    return {
      statusCode: 500,
      headers,
      body: JSON.stringify({ error: 'ANTHROPIC_API_KEY is not configured. Add it in Netlify → Environment Variables.' })
    };
  }

  // ── Body size check ──
  const rawBody = event.body || '';
  if (Buffer.byteLength(rawBody, 'utf8') > MAX_BODY_BYTES) {
    return {
      statusCode: 413,
      headers,
      body: JSON.stringify({ error: 'File too large (max ~4 MB after encoding). Compress the PDF or reduce image resolution and try again.' })
    };
  }

  // ── Parse body ──
  let body;
  try {
    body = JSON.parse(rawBody);
  } catch {
    return { statusCode: 400, headers, body: JSON.stringify({ error: 'Invalid request body' }) };
  }

  const { data, mimeType, isPdf } = body;
  if (!data || !mimeType) {
    return { statusCode: 400, headers, body: JSON.stringify({ error: 'Missing data or mimeType' }) };
  }
  if (data.length < 100) {
    return { statusCode: 400, headers, body: JSON.stringify({ error: 'File data appears empty or corrupt' }) };
  }

  // ── Rate limiting ──
  const ip = getClientIP(event);
  const dbUrl = process.env.NETLIFY_DATABASE_URL;

  if (dbUrl) {
    let rateResult;
    try {
      rateResult = await checkAndRecordRateLimit(ip, dbUrl);
    } catch (e) {
      // If DB is unavailable, fail open (log but allow) rather than blocking all users
      console.error('Rate limit DB error:', e.message);
      rateResult = { allowed: true };
    }

    if (!rateResult.allowed) {
      return {
        statusCode: 429,
        headers: { ...headers, 'Retry-After': '3600' },
        body: JSON.stringify({
          error: `Rate limit reached. Maximum ${RATE_LIMIT_HOUR} extractions per hour and ${RATE_LIMIT_DAY} per day per user. Please try again later.`
        })
      };
    }
  } else {
    console.warn('NETLIFY_DATABASE_URL not set — rate limiting disabled');
  }

  // ── Call Anthropic ──
  const contentBlock = isPdf
    ? { type: 'document', source: { type: 'base64', media_type: 'application/pdf', data } }
    : { type: 'image',    source: { type: 'base64', media_type: mimeType, data } };

  let anthropicResp;
  try {
    anthropicResp = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': apiKey,
        'anthropic-version': '2023-06-01',
      },
      body: JSON.stringify({
        model: 'claude-sonnet-4-6',
        max_tokens: 1024,
        system: EXTRACT_PROMPT,
        messages: [{
          role: 'user',
          content: [
            contentBlock,
            { type: 'text', text: 'Extract the clinical fields from this pathology report and return the JSON object as instructed.' }
          ]
        }]
      })
    });
  } catch (e) {
    return {
      statusCode: 502,
      headers,
      body: JSON.stringify({ error: safeError('Could not reach Anthropic API', e.message, isProd) })
    };
  }

  if (!anthropicResp.ok) {
    let errMsg = 'Anthropic API error ' + anthropicResp.status;
    try {
      const errBody = await anthropicResp.json();
      if (errBody.error?.message) errMsg = errBody.error.message;
    } catch {}
    if (anthropicResp.status === 401) errMsg = 'Invalid API key. Check ANTHROPIC_API_KEY in Netlify Environment Variables.';
    if (anthropicResp.status === 529) errMsg = 'Anthropic API is overloaded. Please try again in a moment.';
    return { statusCode: 502, headers, body: JSON.stringify({ error: errMsg }) };
  }

  const anthropicData = await anthropicResp.json();
  const rawText = (anthropicData.content || [])
    .filter(b => b.type === 'text')
    .map(b => b.text)
    .join('');

  if (!rawText) {
    return {
      statusCode: 502,
      headers,
      body: JSON.stringify({ error: 'Claude returned an empty response. The document may not contain readable text.' })
    };
  }

  const clean = rawText.replace(/```json\s*/gi, '').replace(/```\s*/g, '').trim();
  let extracted;
  try {
    extracted = JSON.parse(clean);
  } catch {
    return {
      statusCode: 502,
      headers,
      body: JSON.stringify({ error: safeError('Could not parse extraction result', rawText.slice(0, 200), isProd) })
    };
  }

  return {
    statusCode: 200,
    headers,
    body: JSON.stringify({ extracted })
  };
};

