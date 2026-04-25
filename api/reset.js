import { createClient } from '@supabase/supabase-js';

const supabase = createClient(
  process.env.NEXT_PUBLIC_SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY
);

function generateOTP() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

// إرسال بريد عبر Elastic Email API
async function sendOTPEmail({ to, otp, token }) {
  const apiKey = process.env.ELASTIC_EMAIL_API_KEY;
  if (!apiKey) {
    console.error('❌ ELASTIC_EMAIL_API_KEY not configured');
    return { sent: false, error: 'Email service not configured' };
  }

  const fromEmail = process.env.EMAIL_FROM || 'security@skydata.bond';
  const fromName = process.env.EMAIL_FROM_NAME || 'SkyData Security';

  const htmlBody = `
    <!DOCTYPE html>
    <html>
    <head>
      <meta charset="UTF-8">
      <style>
        @import url('https://fonts.googleapis.com/css2?family=Orbitron:wght@400;700&family=Rajdhani:wght@400;600&display=swap');
        body { margin: 0; padding: 0; background: #000; font-family: 'Rajdhani', sans-serif; }
        .container { max-width: 600px; margin: 0 auto; background: linear-gradient(135deg, #0d2818, #051208); border: 1px solid rgba(0,255,136,0.1); }
        .header { text-align: center; padding: 40px 20px; background: linear-gradient(135deg, rgba(0,255,136,0.1), transparent); }
        .logo { width: 80px; margin-bottom: 15px; }
        .title { font-family: 'Orbitron', sans-serif; color: #00ff88; font-size: 22px; margin: 0; text-shadow: 0 0 20px rgba(0,255,136,0.3); }
        .content { padding: 30px; color: #fff; }
        .code-box { background: rgba(0,0,0,0.5); border: 1px solid rgba(0,255,136,0.3); border-radius: 12px; padding: 25px; text-align: center; margin: 25px 0; }
        .code { font-family: 'Orbitron', monospace; font-size: 42px; color: #00ff88; letter-spacing: 8px; margin: 0; text-shadow: 0 0 30px rgba(0,255,136,0.5); }
        .warning { background: rgba(220,38,38,0.1); border: 1px solid rgba(220,38,38,0.3); border-radius: 8px; padding: 15px; margin-top: 25px; color: #fca5a5; font-size: 13px; }
        .footer { text-align: center; padding: 25px; color: rgba(255,255,255,0.3); font-size: 12px; border-top: 1px solid rgba(255,255,255,0.05); }
        .btn { display: inline-block; background: #ef4444; color: #fff; padding: 10px 20px; border-radius: 6px; text-decoration: none; font-weight: 600; margin-top: 10px; }
      </style>
    </head>
    <body>
      <div class="container">
        <div class="header">
          <img src="https://i.ibb.co/v6c4ZzL2/Picsart-26-04-23-01-10-59-946.png" alt="SkyData" class="logo">
          <h1 class="title">PASSWORD RESET</h1>
        </div>
        <div class="content">
          <p style="font-size: 15px; line-height: 1.6; color: rgba(255,255,255,0.8);">You requested to reset your password for your SkyData Gaming account.</p>
          
          <div class="code-box">
            <p style="margin: 0 0 10px; color: rgba(255,255,255,0.5); font-size: 13px;">Your verification code</p>
            <h2 class="code">${otp}</h2>
            <p style="margin: 10px 0 0; color: rgba(255,255,255,0.4); font-size: 12px;">This code expires in 5 minutes</p>
          </div>
          
          <div class="warning">
            <p style="margin: 0; font-weight: 600;">⚠️ Didn't request this?</p>
            <p style="margin: 5px 0 0;">If you didn't request a password reset, click the button below to invalidate this code immediately.</p>
            <a href="https://skydata.bond/api/reset.js?action=invalidate&token=${token}" class="btn">INVALIDATE CODE</a>
          </div>
        </div>
        <div class="footer">
          <p>SkyData Gaming Platform — skydata.bond</p>
          <p style="margin-top: 5px;">This is an automated security email.</p>
        </div>
      </div>
    </body>
    </html>
  `;

  try {
    const params = new URLSearchParams({
      apikey: apiKey,
      from: fromEmail,
      fromName: fromName,
      subject: 'SkyData — Password Reset Code',
      bodyHtml: htmlBody,
      to: to,
      isTransactional: 'true'
    });

    const response = await fetch('https://api.elasticemail.com/v2/email/send', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: params.toString()
    });

    const data = await response.json();
    
    if (data.success) {
      console.log('✅ Email sent via Elastic Email:', data.data);
      return { sent: true };
    } else {
      console.error('❌ Elastic Email error:', data.error);
      return { sent: false, error: data.error };
    }
  } catch (err) {
    console.error('❌ Email send error:', err);
    return { sent: false, error: err.message };
  }
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
    // GET: إبطال الكود من الرابط في البريد
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
      case 'request': {
        if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
          return res.status(400).json({ error: 'Valid email required' });
        }

        // البحث عن المستخدم
        const { data: users } = await supabase.auth.admin.listUsers();
        const user = users?.users?.find(u => u.email === email);
        
        if (!user) {
          return res.status(200).json({ 
            message: 'If this email exists, a reset code has been sent.' 
          });
        }

        // إنشاء OTP
        const otp = generateOTP();
        const expiresAt = new Date(Date.now() + 5 * 60 * 1000);

        // إبطال الأكواد القديمة
        await supabase.from('otp_codes').update({ is_invalidated: true })
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

        // إرسال البريد عبر Elastic Email
        const emailResult = await sendOTPEmail({
          to: email,
          otp: otp,
          token: otpRecord.id
        });

        if (!emailResult.sent) {
          console.error('Email failed:', emailResult.error);
          // في حالة فشل البريد، نعيد OTP للعميل (للتطوير فقط)
          return res.status(200).json({ 
            success: true,
            message: 'Code generated (email failed — check console)',
            otp: otp,
            expires_in: '5 minutes'
          });
        }

        return res.status(200).json({ 
          success: true,
          message: 'Reset code sent to your email'
        });
      }

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
