// /api/verify-recaptcha.js
export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', process.env.NEXT_PUBLIC_DOMAIN || '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

  const { token } = req.body;
  const secretKey = process.env.RECAPTCHA_SECRET_KEY;
  const clientIP = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.socket.remoteAddress;

  if (!token || token === 'dummy-token') {
    return res.status(400).json({ 
      success: false, 
      error: 'reCAPTCHA token missing or invalid' 
    });
  }

  if (!secretKey) {
    return res.status(500).json({ 
      success: false, 
      error: 'Server configuration error' 
    });
  }

  try {
    const verifyUrl = 'https://www.google.com/recaptcha/api/siteverify';
    const params = new URLSearchParams({
      secret: secretKey,
      response: token,
      remoteip: clientIP
    });

    const response = await fetch(verifyUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: params.toString()
    });

    const data = await response.json();

    if (!data.success) {
      const errorCodes = data['error-codes'] || [];
      console.error('reCAPTCHA failed:', errorCodes);
      return res.status(400).json({
        success: false,
        error: 'reCAPTCHA verification failed',
        codes: errorCodes
      });
    }

    // التحقق من النتيجة (score لـ v3، لكن نحن نستخدم v2)
    // لـ v2 checkbox: success = true يكفي
    return res.status(200).json({
      success: true,
      challenge_ts: data.challenge_ts,
      hostname: data.hostname
    });

  } catch (err) {
    console.error('reCAPTCHA verify error:', err);
    return res.status(500).json({
      success: false,
      error: 'Failed to verify reCAPTCHA'
    });
  }
}
