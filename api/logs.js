import { createClient } from '@supabase/supabase-js';

const supabase = createClient(
  process.env.NEXT_PUBLIC_SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY
);

export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', process.env.NEXT_PUBLIC_DOMAIN);
  res.setHeader('Access-Control-Allow-Methods', 'POST, GET, OPTIONS');
  if (action === 'check') {
  const { data: isAdmin } = await supabase
    .from('admin_list')
    .select('email')
    .eq('email', adminEmail)
    .single();
  
  return res.status(200).json({ isAdmin: !!isAdmin });
  }
  
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'GET' && req.method !== 'POST') return res.status(405).end();

  const { action, email, adminEmail } = req.query;
  const authHeader = req.headers.authorization;

  // التحقق من المشرف (يمكن تحسينه لاحقاً بـ JWT)
  if (!adminEmail) return res.status(404).json({ error: 'Not Found' });

  const { data: isAdmin } = await supabase
    .from('admin_list')
    .select('*')
    .eq('email', adminEmail)
    .single();

  if (!isAdmin) return res.status(404).json({ error: 'Not Found' });

  try {
    if (action === 'logs') {
      const { data, error } = await supabase
        .from('security_logs')
        .select('*')
        .order('created_at', { ascending: false })
        .limit(100);
      return res.status(200).json({ logs: data });
    }

    if (action === 'stats') {
      const { count: totalUsers } = await supabase.from('profiles').select('*', { count: 'exact', head: true });
      const { count: activeSessions } = await supabase.from('sessions').select('*', { count: 'exact', head: true }).eq('is_active', true);
      const { count: failedToday } = await supabase.from('security_logs').select('*', { count: 'exact', head: true }).eq('status', 'failed').gte('created_at', new Date(Date.now() - 86400000).toISOString());
      
      return res.status(200).json({ totalUsers, activeSessions, failedToday });
    }

    res.status(400).json({ error: 'Invalid action' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
}
