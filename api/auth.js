import { createClient } from '@supabase/supabase-js'

const supabase = createClient(
  process.env.NEXT_PUBLIC_SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY
)

export default async function handler(req, res) {
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

  const { action, email, password, captchaToken, username } = req.body;

  try {
    // 1. التحقق من reCAPTCHA
    // ملاحظة: قمنا بإضافة شرط لتجاوز التحقق إذا كنت تختبر محلياً لتسريع عملك
    const isDevelopment = process.env.NODE_ENV === 'development';
    
    if (!isDevelopment) {
      if (!captchaToken) throw new Error('reCAPTCHA token is missing');

      const recaptchaRes = await fetch('https://www.google.com/recaptcha/api/siteverify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: `secret=${process.env.RECAPTCHA_SECRET_KEY}&response=${captchaToken}`
      });
      
      const recaptchaData = await recaptchaRes.json();
      if (!recaptchaData.success) throw new Error('reCAPTCHA verification failed. Bot detected.');
    }

    // 2. معالجة التسجيل
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
    // 3. معالجة تسجيل الدخول
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
}
