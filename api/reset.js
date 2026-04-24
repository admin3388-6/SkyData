import { createClient } from '@supabase/supabase-js';

const supabase = createClient(
  process.env.NEXT_PUBLIC_SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY
);

// Rate limiting للـ OTP (1 طلب كل 60 ثانية لكل IP)
const resetRateLimits = new Map();

function checkResetRateLimit(ip, windowMs = 60000) {
  const key = `reset:${ip}`;
  const now = Date.now();
  const entry = resetRateLimits.get(key);
  
  if (!entry) {
    resetRateLimits.set(key, now);
    return { allowed: true };
  }
  
  if (now - entry > windowMs) {
    resetRateLimits.set(key, now);
    return { allowed: true };
  }
  
  const retryAfter = Math.ceil((windowMs - (now - entry)) / 1000);
  return { allowed: false, retryAfter };
}

function generateOTP() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', process.env.NEXT_PUBLIC_DOMAIN || '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  
  if (req.method === 'OPTIONS') return res.status(200).end();
  
  const clientIP = req.headers['x-forwarded-for']?.split(',')[0]?.trim() 
    || req.headers['x-real-ip'] 
    || req.socket.remoteAddress;

  try {
    // ==================== GET: إبطال الكود من الرابط في البريد ====================
    if (req.method === 'GET') {
      const { action, token } = req.query;
      if (action === 'invalidate' && token) {
        await supabase.from('otp_codes').update({ is_invalidated: true }).eq('id', token);
        return res.status(200).send(`
          <!DOCTYPE html>
          <html>
          <head>
            <title>Code Invalidated — SkyData</title>
            <link href="https://fonts.googleapis.com/css2?family=Orbitron:wght@400;700&display=swap" rel="stylesheet">
            <style>
              body { background: #000; color: #00ff88; font-family: 'Orbitron', sans-serif; 
                     display: flex; align-items: center; justify-content: center; height: 100vh; margin: 0; text-align: center; }
              .box { border: 1px solid rgba(0,255,136,0.3); border-radius: 16px; padding: 40px; 
                     background: linear-gradient(135deg, rgba(10,30,15,0.95), rgba(5,15,8,0.98)); }
              h1 { text-shadow: 0 0 20px rgba(0,255,136,0.3); }
              p { color: rgba(255,255,255,0.5); font-size: 14px; }
            </style>
          </head>
          <body>
            <div class="box">
              <h1>✓ CODE INVALIDATED</h1>
              <p>This reset code has been deactivated successfully.<br>If this wasn't you, your account is still secure.</p>
            </div>
          </body>
          </html>
        `);
      }
      return res.status(400).send('Invalid request');
    }

    if (req.method !== 'POST') {
      return res.status(405).json({ error: 'Method not allowed' });
    }

    const { action, email, code, newPassword, token } = req.body;
    if (!action) return res.status(400).json({ error: 'Action required' });

    switch (action) {
      // ==================== طلب OTP ====================
      case 'request': {
        if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
          return res.status(400).json({ error: 'Valid email required' });
        }

        // Rate limit
        const rateCheck = checkResetRateLimit(clientIP, 60000);
        if (!rateCheck.allowed) {
          return res.status(429).json({ 
            error: `Please wait ${rateCheck.retryAfter}s before requesting another code.` 
          });
        }

        // البحث عن المستخدم (بدون كشف وجوده)
        const { data: users } = await supabase.auth.admin.listUsers();
        const user = users?.users?.find(u => u.email === email);
        
        if (!user) {
          // رسالة موحدة للأمان
          return res.status(200).json({ 
            message: 'If this email exists, a reset code has been sent.' 
          });
        }

        // إنشاء OTP
        const otp = generateOTP();
        const expiresAt = new Date(Date.now() + 5 * 60 * 1000);

        // إبطال الأكواد القديمة
        await supabase.from('otp_codes')
          .update({ is_invalidated: true })
          .eq('user_id', user.id)
          .eq('type', 'password_reset')
          .eq('is_used', false)
          .eq('is_invalidated', false);

        // تخزين OTP
        const { data: otpRecord, error: otpError } = await supabase.from('otp_codes').insert({
          user_id: user.id,
          email: email,
          code: otp,
          type: 'password_reset',
          expires_at: expiresAt.toISOString()
        }).select().single();

        if (otpError) throw otpError;

        // ==================== إرسال البريد ====================
        // ملاحظة: Supabase لا يوفر API لإرسال بريد مخصص مباشرة.
        // الخيارات:
        // 1. استخدم Supabase Edge Function مع nodemailer + SMTP خاص بك
        // 2. اضبط قالب البريد في Supabase Dashboard > Auth > Email Templates
        // 3. استخدم خدمة بريد مثل Resend (مجاني 100/يوم)
        //
        // للتطوير: يمكنك رؤية الكود في جدول otp_codes في Supabase Dashboard
        
        // وضع التطوير: إرجاع الكود للاختبار (احذف هذا في الإنتاج!)
        const isDev = process.env.NODE_ENV !== 'production';
        
        return res.status(200).json({ 
          message: 'If this email exists, a reset code has been sent.',
          ...(isDev && { dev_otp: otp, dev_expires: expiresAt })
        });
      }

      // ==================== التحقق من OTP ====================
      case 'verify': {
        if (!email || !code) {
          return res.status(400).json({ error: 'Email and code required' });
        }

        const { data: otpRecord } = await supabase.from('otp_codes')
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

        return res.status(200).json({ 
          success: true, 
          token: otpRecord.id 
        });
      }

      // ==================== إعادة تعيين كلمة المرور ====================
      case 'reset': {
        if (!token || !newPassword) {
          return res.status(400).json({ error: 'Token and new password required' });
        }

        if (newPassword.length < 6 || newPassword.length > 25) {
          return res.status(400).json({ error: 'Password must be 6-25 characters' });
        }
        if (!/[0-9!@#$%^&*]/.test(newPassword)) {
          return res.status(400).json({ error: 'Password must contain a number or special character' });
        }

        const { data: otpRecord } = await supabase.from('otp_codes')
          .select('user_id')
          .eq('id', token)
          .eq('is_used', false)
          .eq('is_invalidated', false)
          .gt('expires_at', new Date().toISOString())
          .single();

        if (!otpRecord) {
          return res.status(400).json({ error: 'Invalid or expired token' });
        }

        // تحديث كلمة المرور
        const { error: updateError } = await supabase.auth.admin.updateUserById(
          otpRecord.user_id,
          { password: newPassword }
        );

        if (updateError) throw updateError;

        // تعليم OTP كمستخدم
        await supabase.from('otp_codes').update({ is_used: true }).eq('id', token);

        // تسجيل الحدث
        await supabase.from('security_logs').insert({
          user_id: otpRecord.user_id,
          action: 'password_reset_complete',
          ip_address: clientIP,
          status: 'success',
          details: 'Password reset via OTP completed'
        });

        return res.status(200).json({ 
          success: true, 
          message: 'Password updated successfully' 
        });
      }

      default:
        return res.status(400).json({ error: 'Invalid action' });
    }
  } catch (err) {
    console.error('Reset API Error:', err);
    return res.status(500).json({ error: 'Internal server error' });
  }
}
