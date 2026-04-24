import { createClient } from '@supabase/supabase-js';

const supabase = createClient(
  process.env.NEXT_PUBLIC_SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY
);

export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', process.env.NEXT_PUBLIC_DOMAIN);
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

  const { userId, fingerprint, action } = req.body;
  const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
  
  // جلب الموقع الجغرافي من IP
  let geo = { country: 'Unknown', city: 'Unknown' };
  try {
    const geoRes = await fetch(`https://ipapi.co/${ip}/json/`);
    geo = await geoRes.json();
  } catch (e) {}

  // تسجيل في security_logs
  await supabase.from('security_logs').insert({
    user_id: userId || null,
    action,
    ip_address: ip,
    country: geo.country_name || geo.country,
    city: geo.city,
    device_info: fingerprint,
    status: 'success',
    details: `Action: ${action}`
  });

  // الكشف عن الشذوذ (مثال: تغير الدولة)
  if (userId) {
    const { data: lastSession } = await supabase
      .from('sessions')
      .select('country')
      .eq('user_id', userId)
      .order('created_at', { ascending: false })
      .limit(1);

    if (lastSession?.[0]?.country && lastSession[0].country !== geo.country_name) {
      // تنبيه: تسجيل دخول من دولة جديدة
      await supabase.from('security_logs').insert({
        user_id: userId,
        action: 'new_country_login',
        ip_address: ip,
        country: geo.country_name,
        city: geo.city,
        status: 'suspicious',
        details: `Login from new country: ${geo.country_name}`
      });
    }
  }

  // تسجيل/تحديث الجلسة
  await supabase.from('sessions').insert({
    user_id: userId || null,
    device_fingerprint: fingerprint,
    ip_address: ip,
    country: geo.country_name || geo.country,
    city: geo.city,
    user_agent: fingerprint?.userAgent || req.headers['user-agent']
  });

  res.status(200).json({ success: true, ip, country: geo.country_name, city: geo.city });
}
