const { createClient } = require('@supabase/supabase-js');

// 1. فحص الأمان: منع تحطم الخادم إذا كانت المفاتيح مفقودة
if (!process.env.NEXT_PUBLIC_SUPABASE_URL || !process.env.SUPABASE_SERVICE_ROLE_KEY) {
    console.error('CRITICAL ERROR: Supabase keys are missing in Vercel Environment Variables!');
}

const supabase = createClient(
  process.env.NEXT_PUBLIC_SUPABASE_URL || 'https://placeholder.supabase.co',
  process.env.SUPABASE_SERVICE_ROLE_KEY || 'placeholder_key'
);

// 2. تصدير الدالة بالطريقة التي يفهمها Vercel
module.exports = async function(req, res) {
  // السماح بالاتصال من الواجهة الأمامية (CORS headers)
  res.setHeader('Access-Control-Allow-Credentials', true);
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,OPTIONS,PATCH,DELETE,POST,PUT');

  // معالجة طلبات الفحص الأولي للمتصفح
  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

  const { action, email, password, captchaToken, username } = req.body;

  try {
    // التحقق من reCAPTCHA
    if (process.env.NODE_ENV !== 'development') {
      if (!captchaToken) throw new Error('reCAPTCHA token is missing');

      const recaptchaRes = await fetch('https://www.google.com/recaptcha/api/siteverify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: `secret=${process.env.RECAPTCHA_SECRET_KEY}&response=${captchaToken}`
      });
      
      const recaptchaData = await recaptchaRes.json();
      if (!recaptchaData.success) throw new Error('reCAPTCHA verification failed. Bot detected.');
    }

    // معالجة التسجيل
    if (action === 'register') {
      const { data: existingUser } = await supabase
        .from('profiles')
        .select('username')
        .eq('username', username)
        .single();

      if (existingUser) throw new Error('Username already taken');

      const { data, error } = await supabase.auth.signUp({
        email,
        password,
        options: { data: { username, auth_method: 'email' } }
      });

      if (error) throw error;
      return res.status(200).json({ success: true, user: data.user });

    } 
    // معالجة تسجيل الدخول
    else if (action === 'login') {
      const { data, error } = await supabase.auth.signInWithPassword({
        email,
        password
      });

      if (error) throw error;
      return res.status(200).json({ success: true, session: data.session });
    }

  } catch (error) {
    return res.status(400).json({ success: false, error: error.message });
  }
};
