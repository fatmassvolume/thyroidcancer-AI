/**
 * Netlify function: parse-pathology
 * 
 * Access tiers:
 *   - Paid subscribers: unlimited (validated via subscription token)
 *   - Free users: 3 extractions (tracked by IP in Neon DB)
 * 
 * Security:
 *   - CORS restricted to thyroidca.com
 *   - Rate limiting: 10/hour, 50/day per IP (all users)
 *   - Body size limit: 5.5 MB
 *   - API key server-side only
 */

const { Client } = require('pg');

const RATE_LIMIT_HOUR  = 10;
const RATE_LIMIT_DAY   = 50;
const FREE_EXTRACTIONS = 3;
const MAX_BODY_BYTES   = 5.5 * 1024 * 1024;
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
  "nodesNum": number or null (nodes POSITIVE for carcinoma, never the number examined),
  "nodesExamined": number or null (total nodes dissected or examined),
  "nodeLargest": number (cm; size of the largest nodal deposit, convert mm to cm) or null,
  "micromet": "yes" or "no",
  "ene": "yes" or "no",
  "pathNotes": string summarising any key pathology details not captured above, or null
}

Rules:
- tumorSize: largest tumour focus in cm
- histology: papillary->PTC, follicular->FTC, oncocytic/hurthle->OTC, follicular variant PTC->IEFVPTC
- unfavHist: tall cell->tallcell, columnar->columnar, hobnail/micropapillary->hobnail, diffuse sclerosing->diffscler, solid/trabecular->solidtrab, poorly differentiated->pdtc, oncocytic high-grade->otc_unfav, none->none
- unfavHist percentage rule: tall cell, hobnail and solid/trabecular count as unfavourable ONLY when they make up 30% or more of the tumour (the app's threshold). If the report gives a percentage below 30% (for example "solid/trabecular growth pattern, 20%"), set unfavHist to "none" and record the finding and percentage in pathNotes. If the report names the entity as the tumour's variant or subtype without giving a percentage, assign it. If it gives a percentage of exactly 30%, assign it and say in pathNotes that the percentage is at the threshold. Focal or minor components (for example "focal tall cell features", "focal hobnail") are NOT the variant: use "none" and note them in pathNotes. Never infer a percentage that is not stated.
- vasInvasion: >=4 foci or extensive->extensive; 1-3 foci or minimal->minimal; none->none
- resectionStatus: clear margins->R0; microscopic positive->R1; gross residual->R2
- grossETE: yes only for GROSS (macroscopic) ETE; minimal/microscopic does NOT qualify
- nodesNum: the number of lymph nodes INVOLVED BY CARCINOMA (positive nodes) only. Never use the total or examined count. Read "involved (1/19)", "1 of 19 nodes positive", "1/19" or "number of involved nodes: 1; total number of nodes: 19" as nodesNum = 1 and nodesExamined = 19. If no node is involved, nodesNum = 0. Prefer the synoptic total over adding up levels yourself.
- nodesExamined: the total number of nodes examined across all levels and specimens, from the synoptic total if given
- nodeLargest: size of the largest metastatic deposit in cm (9 mm = 0.9); null if no node is involved
- micromet: yes only if ALL nodal deposits <2mm
- multifocal: yes if more than one distinct tumour focus
- pathNotes: BRAF status, LVI, capsular invasion, Ki-67, other significant findings
- Return ONLY the raw JSON object. No markdown, no preamble.`;

function getClientIP(event) {
  return (
    event.headers['x-nf-client-connection-ip'] ||
    event.headers['x-forwarded-for']?.split(',')[0]?.trim() ||
    event.headers['client-ip'] ||
    'unknown'
  );
}

function getAllowedOrigin(event) {
  const origin = event.headers['origin'] || '';
  if (ALLOWED_ORIGINS.includes(origin)) return origin;
  if (!origin) return '*';
  return null;
}

function buildHeaders(event) {
  const origin = getAllowedOrigin(event);
  const h = { 'Content-Type': 'application/json' };
  if (origin) {
    h['Access-Control-Allow-Origin'] = origin;
    h['Access-Control-Allow-Headers'] = 'Content-Type';
    h['Access-Control-Allow-Methods'] = 'POST, OPTIONS';
  }
  return h;
}

async function getDb(dbUrl) {
  const client = new Client({ connectionString: dbUrl, ssl: { rejectUnauthorized: false } });
  await client.connect();
  // Ensure tables exist
  await client.query(`
    CREATE TABLE IF NOT EXISTS parse_rate_limit (
      id        SERIAL PRIMARY KEY,
      ip        TEXT NOT NULL,
      called_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE INDEX IF NOT EXISTS idx_prl_ip_time ON parse_rate_limit (ip, called_at);

    CREATE TABLE IF NOT EXISTS free_extractions (
      id        SERIAL PRIMARY KEY,
      ip        TEXT NOT NULL UNIQUE,
      count     INT NOT NULL DEFAULT 0,
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE INDEX IF NOT EXISTS idx_fe_ip ON free_extractions (ip);
  `);
  return client;
}

async function checkSubscription(token, client) {
  if (!token) return false;
  const res = await client.query(
    `SELECT status FROM subscriptions WHERE token=$1 LIMIT 1`,
    [token]
  );
  return res.rows.length > 0 && res.rows[0].status === 'active';
}

async function checkFreeExtractionsLeft(ip, client) {
  const res = await client.query(
    `SELECT count FROM free_extractions WHERE ip=$1`,
    [ip]
  );
  if (res.rows.length === 0) return FREE_EXTRACTIONS; // never used
  return Math.max(0, FREE_EXTRACTIONS - res.rows[0].count);
}

async function recordFreeExtraction(ip, client) {
  await client.query(`
    INSERT INTO free_extractions (ip, count, updated_at)
    VALUES ($1, 1, NOW())
    ON CONFLICT (ip) DO UPDATE
    SET count = free_extractions.count + 1, updated_at = NOW()
  `, [ip]);
}

async function checkRateLimit(ip, client) {
  const hourRes = await client.query(
    `SELECT COUNT(*) AS cnt FROM parse_rate_limit WHERE ip=$1 AND called_at > NOW() - INTERVAL '1 hour'`,
    [ip]
  );
  const dayRes = await client.query(
    `SELECT COUNT(*) AS cnt FROM parse_rate_limit WHERE ip=$1 AND called_at > NOW() - INTERVAL '24 hours'`,
    [ip]
  );
  const hourCount = parseInt(hourRes.rows[0].cnt, 10);
  const dayCount  = parseInt(dayRes.rows[0].cnt, 10);
  if (hourCount >= RATE_LIMIT_HOUR || dayCount >= RATE_LIMIT_DAY) return false;
  await client.query(`INSERT INTO parse_rate_limit (ip) VALUES ($1)`, [ip]);
  await client.query(`DELETE FROM parse_rate_limit WHERE called_at < NOW() - INTERVAL '7 days'`);
  return true;
}

exports.handler = async function(event) {
  const isProd = process.env.CONTEXT === 'production';
  const headers = buildHeaders(event);

  if (isProd && getAllowedOrigin(event) === null) {
    return { statusCode: 403, headers, body: JSON.stringify({ error: 'Origin not allowed' }) };
  }
  if (event.httpMethod === 'OPTIONS') return { statusCode: 204, headers, body: '' };
  if (event.httpMethod !== 'POST') return { statusCode: 405, headers, body: JSON.stringify({ error: 'Method not allowed' }) };

  const apiKey = process.env.ANTHROPIC_API_KEY;
  if (!apiKey || !apiKey.startsWith('sk-')) {
    return { statusCode: 500, headers, body: JSON.stringify({ error: 'ANTHROPIC_API_KEY is not configured.' }) };
  }

  const rawBody = event.body || '';
  if (Buffer.byteLength(rawBody, 'utf8') > MAX_BODY_BYTES) {
    return { statusCode: 413, headers, body: JSON.stringify({ error: 'File too large (max ~4 MB). Compress the PDF and try again.' }) };
  }

  let body;
  try { body = JSON.parse(rawBody); }
  catch { return { statusCode: 400, headers, body: JSON.stringify({ error: 'Invalid request body' }) }; }

  const { data, mimeType, isPdf, subscriptionToken } = body;
  if (!data || !mimeType) return { statusCode: 400, headers, body: JSON.stringify({ error: 'Missing data or mimeType' }) };
  if (data.length < 100) return { statusCode: 400, headers, body: JSON.stringify({ error: 'File data appears empty or corrupt' }) };

  const ip = getClientIP(event);
  const dbUrl = process.env.NETLIFY_DATABASE_URL;

  if (dbUrl) {
    let dbClient;
    try {
      dbClient = await getDb(dbUrl);

      // Rate limit check (all users)
      const withinRate = await checkRateLimit(ip, dbClient);
      if (!withinRate) {
        return {
          statusCode: 429,
          headers: { ...headers, 'Retry-After': '3600' },
          body: JSON.stringify({ error: `Rate limit reached. Max ${RATE_LIMIT_HOUR} extractions/hour per user.` })
        };
      }

      // Subscription check
      const isSubscribed = await checkSubscription(subscriptionToken, dbClient);

      if (!isSubscribed) {
        // Check free extractions remaining
        const freeLeft = await checkFreeExtractionsLeft(ip, dbClient);
        if (freeLeft <= 0) {
          return {
            statusCode: 402,
            headers,
            body: JSON.stringify({
              error: 'free_limit_reached',
              message: `You have used all ${FREE_EXTRACTIONS} free extractions. Subscribe to ThyroidCA Pro for unlimited access.`
            })
          };
        }
        // Record free extraction use
        await recordFreeExtraction(ip, dbClient);
        // Include remaining count in response so UI can update
        const newFreeLeft = freeLeft - 1;
        // We'll add freeLeft to the success response below
        body._freeLeft = newFreeLeft;
      }

    } catch (e) {
      console.error('DB error:', e.message);
      // Fail open — don't block users if DB is down
    } finally {
      if (dbClient) await dbClient.end().catch(() => {});
    }
  }

  // Call Anthropic
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
    return { statusCode: 502, headers, body: JSON.stringify({ error: 'Could not reach Anthropic API: ' + e.message }) };
  }

  if (!anthropicResp.ok) {
    let errMsg = 'Anthropic API error ' + anthropicResp.status;
    try {
      const errBody = await anthropicResp.json();
      if (errBody.error?.message) errMsg = errBody.error.message;
    } catch {}
    if (anthropicResp.status === 401) errMsg = 'Invalid API key.';
    if (anthropicResp.status === 529) errMsg = 'Anthropic API overloaded. Please try again.';
    return { statusCode: 502, headers, body: JSON.stringify({ error: errMsg }) };
  }

  const anthropicData = await anthropicResp.json();
  const rawText = (anthropicData.content || []).filter(b => b.type === 'text').map(b => b.text).join('');
  if (!rawText) return { statusCode: 502, headers, body: JSON.stringify({ error: 'Claude returned an empty response.' }) };

  const clean = rawText.replace(/```json\s*/gi, '').replace(/```\s*/g, '').trim();
  let extracted;
  try { extracted = JSON.parse(clean); }
  catch { return { statusCode: 502, headers, body: JSON.stringify({ error: 'Could not parse extraction result.' }) }; }

  // Sanity guard: involved nodes can never exceed nodes examined
  if (extracted && typeof extracted.nodesNum === 'number' && typeof extracted.nodesExamined === 'number' && extracted.nodesNum > extracted.nodesExamined) {
    extracted.nodesNum = null;
    extracted.pathNotes = ((extracted.pathNotes || '') + ' Nodal count was inconsistent (involved exceeded examined); please enter the number of involved nodes manually.').trim();
  }

  return {
    statusCode: 200,
    headers,
    body: JSON.stringify({ extracted, freeLeft: body._freeLeft })
  };
};
