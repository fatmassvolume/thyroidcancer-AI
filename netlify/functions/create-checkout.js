/**
 * Netlify function: create-checkout
 * Creates a Stripe Checkout session for ThyroidCA Pro subscription.
 * POST /.netlify/functions/create-checkout
 * Body: { email?: string, returnUrl: string }
 * Returns: { url: string } — redirect user to this URL
 */

const ALLOWED_ORIGINS = ['https://thyroidca.com', 'https://www.thyroidca.com', 'https://ata-dtc.netlify.app'];
const PRICE_ID = 'price_1UGz6iGSaNumIARAwCtsUSUk';
const FREE_EXTRACTIONS = 3;

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

  const stripeKey = process.env.STRIPE_SECRET_KEY;
  if (!stripeKey || !stripeKey.startsWith('sk_')) {
    return { statusCode: 500, headers, body: JSON.stringify({ error: 'Stripe is not configured.' }) };
  }

  let body;
  try { body = JSON.parse(event.body || '{}'); }
  catch { return { statusCode: 400, headers, body: JSON.stringify({ error: 'Invalid request body' }) }; }

  const returnUrl = body.returnUrl || 'https://thyroidca.com';
  const email = body.email || undefined;

  // Build checkout session via Stripe REST API (no SDK needed)
  const params = new URLSearchParams({
    'mode': 'subscription',
    'line_items[0][price]': PRICE_ID,
    'line_items[0][quantity]': '1',
    'success_url': `${returnUrl}?subscribed=true&session_id={CHECKOUT_SESSION_ID}`,
    'cancel_url': `${returnUrl}?subscribed=false`,
    'payment_method_collection': 'always',
    'subscription_data[trial_period_days]': '14',
    'allow_promotion_codes': 'true',
    'billing_address_collection': 'auto',
  });

  if (email) params.append('customer_email', email);

  let stripeResp;
  try {
    stripeResp = await fetch('https://api.stripe.com/v1/checkout/sessions', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${stripeKey}`,
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: params.toString()
    });
  } catch (e) {
    return { statusCode: 502, headers, body: JSON.stringify({ error: 'Could not reach Stripe: ' + e.message }) };
  }

  const session = await stripeResp.json();
  if (!stripeResp.ok) {
    return { statusCode: 502, headers, body: JSON.stringify({ error: session.error?.message || 'Stripe error' }) };
  }

  return { statusCode: 200, headers, body: JSON.stringify({ url: session.url }) };
};

