import { createClient } from '@supabase/supabase-js';

const supabase = createClient(
  process.env.NEXT_PUBLIC_SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY
);

const rateLimits = new Map();

function checkRateLimit(ip, action, maxAttempts = 5, windowMs = 600000) {
  const key = `${ip}:${action}`;
  const now = Date.now();
  const entry = rateLimits.get(key);
  
  if (!entry) {
    rateLimits.set(key, { count: 1, firstAttempt: now });
    return { allowed: true };
  }
  
  if (now - entry.firstAttempt > windowMs) {
    rateLimits.set(key, { count: 1, firstAttempt: now });
    return { allowed: true };
  }
  
  if (entry.count >= maxAttempts) {
    return { allowed: false, retryAfter: Math.ceil((windowMs - (now - entry.firstAttempt)) / 1000) };
  }
  
  entry.count++;
  return { allowed: true };
}

async function logSecurityEvent({ userId, action, ip, country, city, deviceInfo, status, details }) {
  try {
    await supabase.from('security_logs').insert({
      user_id: userId || null,
      action,
      ip_address: ip,
      country: country || 'Unknown',
      city: city || 'Unknown',
      device_info: deviceInfo || {},
      status,
      details: details || ''
    });
  } catch (e) {
    console.error('Security log error:', e);
  }
}

async function getGeoData(ip) {
  try {
    const response = await fetch(`https://ipapi.co/${ip}/json/`);
    const data = await response.json();
    return {
      country: data.country_name || data.country || 'Unknown',
      city: data.city || 'Unknown'
    };
  } catch (e) {
    return { country: 'Unknown', city: 'Unknown' };
  }
}

export default async function handler(req, res) {
  const origin = process.env.NEXT_PUBLIC_DOMAIN || '*';
  res.setHeader('Access-Control-Allow-Origin', origin);
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  res.setHeader('Content-Type', 'application/json');
  
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  const clientIP = req.headers['x-forwarded-for']?.split(',')[0]?.trim() 
    || req.headers['x-real-ip'] 
    || req.socket.remoteAddress;
    
  const { action, email, password, username, fingerprint } = req.body;

  if (!action || !email) {
    return res.status(400).json({ error: 'Missing required fields' });
  }

  const rateCheck = checkRateLimit(clientIP, action, 10, 600000);
  if (!rateCheck.allowed) {
    await logSecurityEvent({ action: `${action}_rate_limited`, ip: clientIP, status: 'blocked', details: `Rate limit exceeded. Retry after ${rateCheck.retryAfter}s` });
    return res.status(429).json({ error: `Too many attempts. Try again in ${rateCheck.retryAfter} seconds.` });
  }

  const geo = await getGeoData(clientIP);

  try {
    switch (action) {
      case 'register': {
        if (!username || !password) {
          return res.status(400).json({ error: 'Username and password are required' });
        }

        if (!/^[a-zA-Z0-9]{3,20}$/.test(username)) {
          return res.status(400).json({ error: 'Invalid username format' });
        }
        if (password.length < 6 || password.length > 25) {
          return res.status(400).json({ error: 'Password must be 6-25 characters' });
        }
        if (!/[0-9!@#$%^&*]/.test(password)) {
          return res.status(400).json({ error: 'Password must contain a number or special character' });
        }

        const { data: existingUsers, error: listError } = await supabase.auth.admin.listUsers();
        if (listError) throw listError;
        
        const existingGoogleUser = existingUsers?.users?.find(u => 
          u.email === email && u.app_metadata?.provider === 'google'
        );
        
        if (existingGoogleUser) {
          return res.status(409).json({ 
            error: 'This email is already linked to a Google account. Please use Google Sign-In.' 
          });
        }

        const { data: existingProfile } = await supabase
          .from('profiles')
          .select('username')
          .eq('username', username)
          .single();

        if (existingProfile) {
          return res.status(409).json({ error: 'Username already taken' });
        }

        const { data: authData, error: authError } = await supabase.auth.signUp({
          email,
          password,
          options: {
            data: { 
              username, 
              auth_method: 'email',
              display_name: username
            }
          }
        });

        if (authError) {
          if (authError.message.includes('already registered')) {
            return res.status(409).json({ error: 'Email already registered' });
          }
          throw authError;
        }

        const { error: profileError } = await supabase.from('profiles').insert({
          id: authData.user.id,
          username,
          display_name: username,
          auth_method: 'email',
          email
        });

        if (profileError) {
          await supabase.auth.admin.deleteUser(authData.user.id);
          throw new Error('Failed to create profile: ' + profileError.message);
        }

        await logSecurityEvent({
          userId: authData.user.id,
          action: 'register',
          ip: clientIP,
          country: geo.country,
          city: geo.city,
          deviceInfo: fingerprint,
          status: 'success',
          details: 'Email registration successful'
        });

        return res.status(200).json({ 
          success: true, 
          user: { id: authData.user.id, email: authData.user.email, username },
          message: 'Account created successfully. Please check your email to verify.'
        });
      }

      case 'login': {
        if (!password) {
          return res.status(400).json({ error: 'Password is required' });
        }

        const { data: existingUsers } = await supabase.auth.admin.listUsers();
        const existingGoogleUser = existingUsers?.users?.find(u => 
          u.email === email && u.app_metadata?.provider === 'google'
        );

        if (existingGoogleUser) {
          const { data: profile } = await supabase
            .from('profiles')
            .select('auth_method')
            .eq('id', existingGoogleUser.id)
            .single();

          if (profile?.auth_method === 'google') {
            await logSecurityEvent({
              action: 'login_conflict',
              ip: clientIP,
              country: geo.country,
              city: geo.city,
              status: 'failed',
              details: 'Attempted email login on Google-only account'
            });
            return res.status(409).json({ 
              error: 'This email is already linked to a Google account. Please use Google Sign-In.' 
            });
          }
        }

        const { data: authData, error: authError } = await supabase.auth.signInWithPassword({
          email,
          password
        });

        if (authError) {
          await logSecurityEvent({
            action: 'login',
            ip: clientIP,
            country: geo.country,
            city: geo.city,
            deviceInfo: fingerprint,
            status: 'failed',
            details: authError.message
          });
          return res.status(401).json({ error: 'Invalid email or password' });
        }

        const { error: sessionError } = await supabase.from('sessions').upsert({
          user_id: authData.user.id,
          ip_address: clientIP,
          country: geo.country,
          city: geo.city,
          user_agent: fingerprint?.userAgent || req.headers['user-agent'],
          device_fingerprint: fingerprint,
          last_seen: new Date().toISOString()
        }, { onConflict: 'user_id' });

        if (sessionError) console.error('Session update error:', sessionError);

        await logSecurityEvent({
          userId: authData.user.id,
          action: 'login',
          ip: clientIP,
          country: geo.country,
          city: geo.city,
          deviceInfo: fingerprint,
          status: 'success',
          details: 'Email login successful'
        });

        return res.status(200).json({
          success: true,
          session: {
            access_token: authData.session.access_token,
            refresh_token: authData.session.refresh_token,
            expires_at: authData.session.expires_at,
            user: {
              id: authData.user.id,
              email: authData.user.email,
              username: authData.user.user_metadata?.username || username
            }
          }
        });
      }

      case 'check_conflict': {
        const { userId } = req.body;
        if (!userId) return res.status(400).json({ error: 'User ID required' });
        
        const { data: profile } = await supabase
          .from('profiles')
          .select('auth_method, username')
          .eq('id', userId)
          .single();
        
        return res.status(200).json({ 
          auth_method: profile?.auth_method || null,
          username: profile?.username || null
        });
      }

      default:
        return res.status(400).json({ error: 'Invalid action' });
    }
  } catch (err) {
    console.error('Auth API Error:', err);
    await logSecurityEvent({
      action: action || 'unknown',
      ip: clientIP,
      country: geo.country,
      city: geo.city,
      status: 'failed',
      details: err.message
    });
    return res.status(500).json({ error: 'Internal server error. Please try again later.' });
  }
}
