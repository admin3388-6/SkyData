const { createClient } = require('@supabase/supabase-js');

const supabase = createClient(
  process.env.NEXT_PUBLIC_SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY
);

module.exports = async function(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).json({ error: 'الطريقة غير مسموحة' });

  const { action, email, password, username } = req.body;

  try {
    if (action === 'register') {
      // التأكد من توفر اسم المستخدم
      const { data: userExists } = await supabase.from('profiles').select('username').eq('username', username).single();
      if (userExists) throw new Error('اسم المستخدم محجوز مسبقاً');

      // إنشاء الحساب
      const { data, error } = await supabase.auth.signUp({
        email,
        password,
        options: { data: { username, auth_method: 'email' } }
      });

      if (error) throw error;
      return res.status(200).json({ success: true });

    } else if (action === 'login') {
      const { data, error } = await supabase.auth.signInWithPassword({ email, password });
      if (error) throw error;
      return res.status(200).json({ success: true, session: data.session });
    }
  } catch (error) {
    return res.status(400).json({ success: false, error: error.message });
  }
};
