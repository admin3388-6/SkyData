import { createClient } from '@supabase/supabase-js';

const supabase = createClient(
  process.env.NEXT_PUBLIC_SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY
);

export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', process.env.NEXT_PUBLIC_DOMAIN || '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

  const clientIP = req.headers['x-forwarded-for']?.split(',')[0]?.trim() 
    || req.headers['x-real-ip'] 
    || req.socket.remoteAddress;

  const { action, email, password, token, type } = req.body;

  try {
    switch (action) {
      // ─── REQUEST PASSWORD RESET ───
      // Client calls this → Supabase sends the reset email automatically
      case 'request': {
        if (!email) return res.status(400).json({ error: 'Email required' });

        // Verify user exists first (don't reveal to client)
        const { data: users } = await supabase.auth.admin.listUsers();
        const userExists = users?.users?.some(u => u.email === email);

        if (!userExists) {
          // Security: return same message whether exists or not
          return res.status(200).json({ 
            success: true, 
            message: 'If this email exists, a reset link has been sent.' 
          });
        }

        // Supabase sends the email automatically using your custom HTML template
        const { error } = await supabase.auth.resetPasswordForEmail(email, {
          redirectTo: `${process.env.NEXT_PUBLIC_DOMAIN}/index.html?reset=1`
        });

        if (error) throw error;

        // Log security event
        await supabase.from('security_logs').insert({
          action: 'password_reset_request',
          ip_address: clientIP,
          status: 'success',
          details: `Reset requested for ${email}`
        });

        return res.status(200).json({ 
          success: true, 
          message: 'If this email exists, a reset link has been sent.' 
        });
      }

      // ─── VERIFY TOKEN & UPDATE PASSWORD ───
      // Called from index.html after user clicks Supabase email link
      case 'reset': {
        if (!token || !password) {
          return res.status(400).json({ error: 'Token and password required' });
        }

        // Verify the OTP token first
        const { data: verifyData, error: verifyError } = await supabase.auth.verifyOtp({
          token_hash: token,
          type: type || 'recovery'
        });

        if (verifyError) {
          return res.status(400).json({ error: 'Invalid or expired link. Please request a new one.' });
        }

        // Update password
        const { error: updateError } = await supabase.auth.admin.updateUserById(
          verifyData.user.id, 
          { password }
        );

        if (updateError) throw updateError;

        // Log success
        await supabase.from('security_logs').insert({
          user_id: verifyData.user.id,
          action: 'password_reset_complete',
          ip_address: clientIP,
          status: 'success',
          details: 'Password reset via Supabase email link'
        });

        return res.status(200).json({ 
          success: true, 
          message: 'Password updated successfully. Redirecting...' 
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
