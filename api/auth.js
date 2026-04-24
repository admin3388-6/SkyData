// api/auth.js
import { createClient } from '@supabase/supabase-js'

const supabase = createClient(
  process.env.NEXT_PUBLIC_SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY // مفتاح سري لا يراه المتصفح
)

export default async function handler(req, res) {
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

  const { action, email, password, captchaToken, username } = req.body;

  try {
    // 1. التحقق من reCAPTCHA (سنقوم بتفعيله في الخطوة القادمة)
    
    if (action === 'register') {
      // التحقق من اسم المستخدم أولاً (Unique check)
      const { data: existingUser } = await supabase
        .from('profiles')
        .select('username')
        .eq('username', username)
        .single();

      if (existingUser) throw new Error('Username already taken');

      // عملية التسجيل
      const { data, error } = await supabase.auth.signUp({
        email,
        password,
        options: { data: { username } }
      });

      if (error) throw error;
      return res.status(200).json({ success: true, user: data.user });

    } else if (action === 'login') {
      // عملية تسجيل الدخول
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
