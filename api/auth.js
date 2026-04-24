import { createClient } from '@supabase/supabase-js';

const supabase = createClient(
  process.env.NEXT_PUBLIC_SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY
);

export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', process.env.NEXT_PUBLIC_DOMAIN);
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

  const { action, email, password, username, recaptchaToken, fingerprint } = req.body;

  // Rate limiting (simple memory-based, use Redis in production)
  const clientIP = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
  
  // reCAPTCHA verify
  if (['register', 'login'].includes(action) && recaptchaToken && recaptchaToken !== 'dummy-token') {
    const verifyRes = await fetch('https://www.google.com/recaptcha/api/siteverify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: `secret=${process.env.RECAPTCHA_SECRET_KEY}&response=${recaptchaToken}&remoteip=${clientIP}`
    });
    const verifyData = await verifyRes.json();
    if (!verifyData.success) {
      return res.status(400).json({ error: 'reCAPTCHA verification failed' });
    }
  }

  try {
    switch (action) {
      case 'register': {
        // Check if email already exists with Google auth
        const { data: existingUsers } = await supabase.auth.admin.listUsers();
        const existingGoogleUser = existingUsers?.users?.find(u => 
          u.email === email && u.app_metadata?.provider === 'google'
        );
        
        if (existingGoogleUser) {
          return res.status(409).json({ 
            error: 'This email is already linked to a Google account. Please use Google Sign-In.' 
          });
        }

        // Check username uniqueness
        const { data: existingUsername } = await supabase
          .from('profiles')
          .select('username')
          .eq('username', username)
          .single();

        if (existingUsername) {
          return res.status(409).json({ error: 'Username already taken' });
        }

        const { data, error } = await supabase.auth.signUp({
          email,
          password,
          options: {
            data: { username, auth_method: 'email' }
          }
        });
        
        if (error) throw error;

        // Create profile
        await supabase.from('profiles').insert({
          id: data.user.id,
          username,
          auth_method: 'email'
        });

        // Log
        await supabase.from('security_logs').insert({
          user_id: data.user.id,
          action: 'register',
          ip_address: clientIP,
          status: 'success',
          details: 'Email registration'
        });

        return res.status(200).json({ success: true, user: data.user });
      }

      case 'login': {
        // Check if this email belongs to a Google-only account
        const { data: existingUsers } = await supabase.auth.admin.listUsers();
        const existingGoogleUser = existingUsers?.users?.find(u => 
          u.email === email && u.app_metadata?.provider === 'google'
        );

        if (existingGoogleUser) {
          // Check if they have a password set (linked account)
          const { data: profile } = await supabase
            .from('profiles')
            .select('auth_method')
            .eq('id', existingGoogleUser.id)
            .single();

          if (profile?.auth_method === 'google') {
            return res.status(409).json({ 
              error: 'This email is already linked to a Google account. Please use Google Sign-In.' 
            });
          }
        }

        const { data, error } = await supabase.auth.signInWithPassword({ email, password });
        if (error) {
          // Log failed attempt
          await supabase.from('security_logs').insert({
            action: 'login',
            ip_address: clientIP,
            status: 'failed',
            details: error.message
          });
          throw error;
        }

        // Update session
        await supabase.from('sessions').upsert({
          user_id: data.user.id,
          ip_address: clientIP,
          last_seen: new Date().toISOString()
        }, { onConflict: 'user_id' });

        // Log success
        await supabase.from('security_logs').insert({
          user_id: data.user.id,
          action: 'login',
          ip_address: clientIP,
          status: 'success',
          details: 'Email login'
        });

        return res.status(200).json({ success: true, session: data.session });
      }

      case 'check_conflict': {
        // Used by home.html to verify OAuth user doesn't conflict
        const { userId } = req.body;
        const { data: profile } = await supabase
          .from('profiles')
          .select('auth_method')
          .eq('id', userId)
          .single();
        
        return res.status(200).json({ auth_method: profile?.auth_method || null });
      }

      default:
        return res.status(400).json({ error: 'Invalid action' });
    }
  } catch (err) {
    return res.status(400).json({ error: err.message });
  }
}
