/**
 * Netlify function: verify-subscription
 * Checks if a token is valid and subscription is active.
 * Also handles post-checkout token retrieval by session_id.
 * 
 * POST /.netlify/functions/verify-subscription
 * Body: { token?: string, sessionId?: string }
 * Returns: { valid: bool, token?: string, email?: string, status?: string }
 */

const { Client } = require('pg');

const ALLOWED_ORIGINS = ['https://thyroidca.com', 'https://www.thyroidca.com', 'https://ata-dtc.netlify.app'];

function buildHeaders(event) {
  const origin = event.headers['origin'] || '';
  const allowedOrigin = ALLOWED_ORIGINS.includes(origin) ? origin : (origin ? null : '*');
  const headers = { 'Content-Type': 'application/json' };
  if (allowedOrigin) {
    headers['Access-Control-Allow-Origin'] = allowedOrigin;
    headers['Access-Control-Allow-Headers'] = 'Content-Type';
    headers['Access-Control-Allow-Methods'] = 'POST, OPTIONS';
  }
  return headers;
}

exports.handler = async function(event) {
  const headers = buildHeaders(event);
  if (event.httpMethod === 'OPTIONS') return { statusCode: 204, headers, body: '' };
  if (event.httpMethod !== 'POST') return { statusCode: 405, headers, body: JSON.stringify({ error: 'Method not allowed' }) };

  const dbUrl = process.env.NETLIFY_DATABASE_URL;
  const stripeKey = process.env.STRIPE_SECRET_KEY;
  if (!dbUrl) return { statusCode: 500, headers, body: JSON.stringify({ error: 'DB not configured' }) };

  let body;
  try { body = JSON.parse(event.body || '{}'); }
  catch { return { statusCode: 400, headers, body: JSON.stringify({ error: 'Invalid body' }) }; }

  const client = new Client({ connectionString: dbUrl, ssl: { rejectUnauthorized: false } });
  try {
    await client.connect();

    // Path 1: post-checkout — exchange Stripe session_id for our token
    if (body.sessionId && stripeKey) {
      const stripeResp = await fetch(`https://api.stripe.com/v1/checkout/sessions/${body.sessionId}`, {
        headers: { 'Authorization': `Bearer ${stripeKey}` }
      });
      const session = await stripeResp.json();
      if (!stripeResp.ok) {
        return { statusCode: 400, headers, body: JSON.stringify({ valid: false, error: 'Invalid session' }) };
      }
      const customerId = session.customer;
      const res = await client.query(
        `SELECT token, email, status FROM subscriptions WHERE stripe_customer_id=$1 AND status='active' LIMIT 1`,
        [customerId]
      );
      if (res.rows.length === 0) {
        // Webhook may not have fired yet — wait and retry handled client-side
        return { statusCode: 200, headers, body: JSON.stringify({ valid: false, pending: true }) };
      }
      const row = res.rows[0];
      return { statusCode: 200, headers, body: JSON.stringify({ valid: true, token: row.token, email: row.email, status: row.status }) };
    }

    // Path 2: validate existing token
    if (body.token) {
      const res = await client.query(
        `SELECT email, status, current_period_end FROM subscriptions WHERE token=$1 LIMIT 1`,
        [body.token]
      );
      if (res.rows.length === 0) {
        return { statusCode: 200, headers, body: JSON.stringify({ valid: false }) };
      }
      const row = res.rows[0];
      const isActive = row.status === 'active';
      return { statusCode: 200, headers, body: JSON.stringify({ valid: isActive, email: row.email, status: row.status }) };
    }

    // Path 3: restore by email
    if (body.email) {
      const email = body.email.trim().toLowerCase();
      const res = await client.query(
        `SELECT token, email, status FROM subscriptions WHERE LOWER(email)=$1 AND status='active' ORDER BY created_at DESC LIMIT 1`,
        [email]
      );
      if (res.rows.length === 0) {
        return { statusCode: 200, headers, body: JSON.stringify({ valid: false }) };
      }
      const row = res.rows[0];
      return { statusCode: 200, headers, body: JSON.stringify({ valid: true, token: row.token, email: row.email, status: row.status }) };
    }

    return { statusCode: 400, headers, body: JSON.stringify({ error: 'Provide token, sessionId, or email' }) };

  } catch (e) {
    console.error('verify-subscription error:', e.message);
    return { statusCode: 500, headers, body: JSON.stringify({ error: 'Internal error' }) };
  } finally {
    await client.end();
  }
};

