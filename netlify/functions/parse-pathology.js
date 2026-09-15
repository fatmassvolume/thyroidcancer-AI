/**
 * Netlify serverless function: parse-pathology
 * Proxies pathology document to Anthropic API.
 * API key stored in ANTHROPIC_API_KEY environment variable.
 *
 * POST /.netlify/functions/parse-pathology
 * Body: { data: string (base64), mimeType: string, isPdf: boolean }
 * Returns: { extracted: object } | { error: string }
 */

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
- histology mapping: papillary->PTC, follicular->FTC, oncocytic/hurthle->OTC, follicular variant PTC->IEFVPTC
- unfavHist: tall cell variant->tallcell, columnar cell->columnar, hobnail/micropapillary->hobnail, diffuse sclerosing->diffscler, solid/trabecular variant->solidtrab, poorly differentiated->pdtc, oncocytic high-grade->otc_unfav, none of the above->none
- vasInvasion: if foci count >=4 or described as extensive->extensive; 1-3 foci or limited/minimal->minimal; none->none
- vasFoci: extract the number of vascular invasion foci if stated
- resectionStatus: negative/clear margins->R0; microscopic positive->R1; gross residual->R2
- grossETE: only mark yes for GROSS (macroscopic) extrathyroidal extension; minimal/microscopic ETE does NOT qualify
- micromet: yes only if ALL nodal deposits are <2mm
- ene: extranodal extension of nodal metastases
- multifocal: yes if more than one distinct tumour focus is described
- pathNotes: include BRAF status, lymphovascular invasion details, capsular invasion details, Ki-67, and any other clinically significant findings not captured in the fields above
- Return ONLY the raw JSON object. No markdown, no explanation, no preamble.`;

exports.handler = async function(event) {
  const headers = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Content-Type': 'application/json',
  };

  if (event.httpMethod === 'OPTIONS') {
    return { statusCode: 204, headers, body: '' };
  }

  if (event.httpMethod !== 'POST') {
    return { statusCode: 405, headers, body: JSON.stringify({ error: 'Method not allowed' }) };
  }

  const apiKey = process.env.ANTHROPIC_API_KEY;
  if (!apiKey || !apiKey.startsWith('sk-')) {
    return {
      statusCode: 500,
      headers,
      body: JSON.stringify({ error: 'ANTHROPIC_API_KEY is not set or invalid. Go to Netlify → ata-dtc → Environment Variables and add it.' })
    };
  }

  // Netlify Functions default body limit is 6MB. Check size early.
  const rawBody = event.body || '';
  const bodySizeBytes = Buffer.byteLength(rawBody, 'utf8');
  if (bodySizeBytes > 5.5 * 1024 * 1024) {
    return {
      statusCode: 413,
      headers,
      body: JSON.stringify({ error: 'File too large for extraction (max ~4MB after base64 encoding). Please reduce the file size or resolution and try again.' })
    };
  }

  let body;
  try {
    body = JSON.parse(rawBody);
  } catch {
    return { statusCode: 400, headers, body: JSON.stringify({ error: 'Invalid request body' }) };
  }

  const { data, mimeType, isPdf } = body;
  if (!data || !mimeType) {
    return { statusCode: 400, headers, body: JSON.stringify({ error: 'Missing data or mimeType in request' }) };
  }

  // Validate base64 data isn't empty
  if (data.length < 100) {
    return { statusCode: 400, headers, body: JSON.stringify({ error: 'File data appears empty or corrupt' }) };
  }

  // Build the content block for Claude
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
      body: JSON.stringify({ error: 'Could not reach Anthropic API: ' + e.message })
    };
  }

  if (!anthropicResp.ok) {
    let errMsg = 'Anthropic API error ' + anthropicResp.status;
    try {
      const errBody = await anthropicResp.json();
      if (errBody.error && errBody.error.message) errMsg = errBody.error.message;
      // Common errors with helpful messages
      if (anthropicResp.status === 401) errMsg = 'Invalid API key. Check ANTHROPIC_API_KEY in Netlify Environment Variables.';
      if (anthropicResp.status === 529) errMsg = 'Anthropic API is overloaded. Please try again in a moment.';
    } catch {}
    return { statusCode: 502, headers, body: JSON.stringify({ error: errMsg }) };
  }

  const anthropicData = await anthropicResp.json();
  const rawText = (anthropicData.content || [])
    .filter(b => b.type === 'text')
    .map(b => b.text)
    .join('');

  if (!rawText) {
    return { statusCode: 502, headers, body: JSON.stringify({ error: 'Claude returned an empty response. The document may not contain readable text.' }) };
  }

  // Strip accidental markdown fences
  const clean = rawText.replace(/```json\s*/gi, '').replace(/```\s*/g, '').trim();

  let extracted;
  try {
    extracted = JSON.parse(clean);
  } catch {
    return {
      statusCode: 502,
      headers,
      body: JSON.stringify({ error: 'Could not parse extraction result. Raw response: ' + rawText.slice(0, 200) })
    };
  }

  return {
    statusCode: 200,
    headers,
    body: JSON.stringify({ extracted })
  };
};
