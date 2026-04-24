import { createClient } from '@supabase/supabase-js';

const supabase = createClient(
  process.env.NEXT_PUBLIC_SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY
);

function generateOTP() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', process.env.NEXT_PUBLIC_DOMAIN);
  res.setHeader('Access-Control-Allow-Methods', 'POST, GET, OPTIONS');
  
  if (req.method === 'OPTIONS') return res.status(200).end();

  const { action, email, code, newPassword } = req.body;

  try {
    if (action === 'request') {
      // التحقق من وجود البريد (بدون كشف ذلك للمستخدم)
      const { data: user } = await supabase
        .from('profiles')
        .select('id, email')
        .eq('email', email)
        .single();

      if (user) {
        const otp = generateOTP();
        const expiresAt = new Date(Date.now() + 5 * 60 * 1000); // 5 دقائق

        await supabase.from('otp_codes').insert({
          user_id: user.id,
          email,
          code: otp,
          type: 'password_reset',
          expires_at: expiresAt.toISOString()
        });

        // إرسال البريد عبر Supabase (سنضيف القالب لاحقاً)
        await supabase.auth.admin.sendRawEmail({
          to: email,
          subject: 'SkyData — Password Reset Code',
          html: `<div style="background: linear-gradient(135deg, #0f0f0f, #1a4d2e); padding: 40px; text-align: center; color: white; font-family: Arial;">
            <img src="https://i.ibb.co/v6c4ZzL2/Picsart-26-04-23-01-10-59-946.png" width="120" style="margin-bottom: 20px;">
            <h2>Password Reset Request</h2>
            <p>Your verification code:</p>
            <h1 style="font-size: 48px; letter-spacing: 10px; color: #00ff88;">${otp}</h1>
            <p style="color: #aaa;">This code expires in 5 minutes</p>
            <p style="margin-top: 30px; font-size: 12px; color: #666;">If you didn't request this, ignore this email.</p>
          </div>`
        });
      }

      // دائماً نرجع نفس الرسالة (أمان)
      return res.status(200).json({ message: 'If this email exists, a code has been sent.' });
    }

    if (action === 'verify') {
      const { data: otpRecord } = await supabase
        .from('otp_codes')
        .select('*')
        .eq('email', email)
        .eq('code', code)
        .eq('type', 'password_reset')
        .eq('is_used', false)
        .eq('is_invalidated', false)
        .gt('expires_at', new Date().toISOString())
        .single();

      if (!otpRecord) {
        return res.status(400).json({ error: 'Invalid or expired code' });
      }

      return res.status(200).json({ success: true, token: otpRecord.id });
    }

    if (action === 'reset') {
      const { token, newPassword } = req.body;
      
      const { data: otpRecord } = await supabase
        .from('otp_codes')
        .select('user_id')
        .eq('id', token)
        .single();

      if (!otpRecord) return res.status(400).json({ error: 'Invalid token' });

      await supabase.auth.admin.updateUserById(otpRecord.user_id, { password: newPassword });
      await supabase.from('otp_codes').update({ is_used: true }).eq('id', token);

      return res.status(200).json({ success: true });
    }

    if (action === 'invalidate') {
      const { token } = req.query;
      await supabase.from('otp_codes').update({ is_invalidated: true }).eq('id', token);
      return res.status(200).json({ success: true });
    }

    res.status(400).json({ error: 'Invalid action' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
}
