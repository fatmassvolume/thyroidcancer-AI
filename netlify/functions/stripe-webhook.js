/**
 * Netlify function: stripe-webhook
 * Receives Stripe webhook events and updates subscription status in Neon DB.
 * POST /.netlify/functions/stripe-webhook
 * 
 * Events handled:
 *   - checkout.session.completed      → create subscription record
 *   - customer.subscription.deleted   → mark cancelled
 *   - customer.subscription.updated   → update status
 *   - invoice.payment_failed          → mark past_due
 */

const { Client } = require('pg');
const crypto = require('crypto');

function verifyStripeSignature(payload, sigHeader, secret) {
  // Stripe signs webhooks with HMAC-SHA256
  const parts = sigHeader.split(',');
  const timestamp = parts.find(p => p.startsWith('t=')).split('=')[1];
  const signature = parts.find(p => p.startsWith('v1=')).split('=')[1];
  const signedPayload = `${timestamp}.${payload}`;
  const expected = crypto.createHmac('sha256', secret).update(signedPayload).digest('hex');
  // Reject if timestamp is >5 minutes old (replay attack protection)
  if (Math.abs(Date.now() / 1000 - parseInt(timestamp)) > 300) return false;
  return crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(signature));
}

async function getOrCreateDb(dbUrl) {
  const client = new Client({ connectionString: dbUrl, ssl: { rejectUnauthorized: false } });
  await client.connect();
  await client.query(`
    CREATE TABLE IF NOT EXISTS subscriptions (
      id                  SERIAL PRIMARY KEY,
      stripe_customer_id  TEXT NOT NULL,
      stripe_sub_id       TEXT,
      email               TEXT,
      status              TEXT NOT NULL DEFAULT 'active',
      token               TEXT NOT NULL UNIQUE,
      trial_end           TIMESTAMPTZ,
      current_period_end  TIMESTAMPTZ,
      created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE INDEX IF NOT EXISTS idx_subs_token ON subscriptions (token);
    CREATE INDEX IF NOT EXISTS idx_subs_customer ON subscriptions (stripe_customer_id);
    CREATE INDEX IF NOT EXISTS idx_subs_email ON subscriptions (email);
  `);
  return client;
}

function generateToken() {
  return 'tc_' + crypto.randomBytes(32).toString('hex');
}

exports.handler = async function(event) {
  const headers = { 'Content-Type': 'application/json' };

  if (event.httpMethod !== 'POST') {
    return { statusCode: 405, headers, body: JSON.stringify({ error: 'Method not allowed' }) };
  }

  const webhookSecret = process.env.STRIPE_WEBHOOK_SECRET;
  const dbUrl = process.env.NETLIFY_DATABASE_URL;
  const stripeKey = process.env.STRIPE_SECRET_KEY;

  if (!webhookSecret || !dbUrl || !stripeKey) {
    console.error('Missing env vars: STRIPE_WEBHOOK_SECRET, NETLIFY_DATABASE_URL, or STRIPE_SECRET_KEY');
    return { statusCode: 500, headers, body: JSON.stringify({ error: 'Server misconfiguration' }) };
  }

  // Verify Stripe signature
  const sig = event.headers['stripe-signature'];
  if (!sig) return { statusCode: 400, headers, body: JSON.stringify({ error: 'Missing signature' }) };

  let stripeEvent;
  try {
    const rawBody = event.isBase64Encoded
      ? Buffer.from(event.body, 'base64').toString('utf8')
      : event.body;
    if (!verifyStripeSignature(rawBody, sig, webhookSecret)) {
      return { statusCode: 400, headers, body: JSON.stringify({ error: 'Invalid signature' }) };
    }
    stripeEvent = JSON.parse(rawBody);
  } catch (e) {
    return { statusCode: 400, headers, body: JSON.stringify({ error: 'Webhook error: ' + e.message }) };
  }

  let client;
  try {
    client = await getOrCreateDb(dbUrl);
    const obj = stripeEvent.data.object;

    if (stripeEvent.type === 'checkout.session.completed') {
      // New subscriber — create subscription record with a unique token
      const customerId = obj.customer;
      const email = obj.customer_details?.email || obj.customer_email;
      const subId = obj.subscription;

      // Fetch subscription to get period end
      let periodEnd = null, trialEnd = null;
      if (subId) {
        const subResp = await fetch(`https://api.stripe.com/v1/subscriptions/${subId}`, {
          headers: { 'Authorization': `Bearer ${stripeKey}` }
        });
        const sub = await subResp.json();
        periodEnd = sub.current_period_end ? new Date(sub.current_period_end * 1000) : null;
        trialEnd = sub.trial_end ? new Date(sub.trial_end * 1000) : null;
      }

      const token = generateToken();
      await client.query(`
        INSERT INTO subscriptions (stripe_customer_id, stripe_sub_id, email, status, token, trial_end, current_period_end)
        VALUES ($1, $2, $3, 'active', $4, $5, $6)
        ON CONFLICT (token) DO NOTHING
      `, [customerId, subId, email, token, trialEnd, periodEnd]);

      console.log(`New subscriber: ${email}, customer: ${customerId}`);
    }

    else if (stripeEvent.type === 'customer.subscription.deleted') {
      await client.query(`
        UPDATE subscriptions SET status='cancelled', updated_at=NOW()
        WHERE stripe_customer_id=$1
      `, [obj.customer]);
      console.log(`Subscription cancelled: ${obj.customer}`);
    }

    else if (stripeEvent.type === 'customer.subscription.updated') {
      const status = obj.status === 'active' || obj.status === 'trialing' ? 'active' : obj.status;
      const periodEnd = obj.current_period_end ? new Date(obj.current_period_end * 1000) : null;
      await client.query(`
        UPDATE subscriptions SET status=$1, current_period_end=$2, updated_at=NOW()
        WHERE stripe_customer_id=$3
      `, [status, periodEnd, obj.customer]);
    }

    else if (stripeEvent.type === 'invoice.payment_failed') {
      await client.query(`
        UPDATE subscriptions SET status='past_due', updated_at=NOW()
        WHERE stripe_customer_id=$1
      `, [obj.customer]);
      console.log(`Payment failed: ${obj.customer}`);
    }

    return { statusCode: 200, headers, body: JSON.stringify({ received: true }) };

  } catch (e) {
    console.error('Webhook handler error:', e.message);
    return { statusCode: 500, headers, body: JSON.stringify({ error: 'Internal error' }) };
  } finally {
    if (client) await client.end();
  }
};

