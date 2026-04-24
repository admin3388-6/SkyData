// routes/authRoutes.js
const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const { OAuth2Client } = require('google-auth-library');
const axios = require('axios');

const supabase = require('../config/supabase');
const env = require('../config/env');
const { decryptPayload } = require('../utils/encryption');
const { validateEmail, validateUsername, validatePassword } = require('../utils/validators');
const { loginRateLimiter, registerRateLimiter } = require('../middleware/rateLimiter');
const { requireAuth } = require('../middleware/auth');
const { checkDeviceFingerprint } = require('../services/fingerprintService');
const { getGeoFromIP } = require('../services/geoService');
const { logActivity, recordFailedLogin, checkCountryChange } = require('../services/anomalyService');
const { sendLoginAlertEmail, sendNewDeviceAlertEmail, sendVerificationCodeEmail } = require('../services/emailService');

const googleClient = new OAuth2Client(env.GOOGLE_CLIENT_ID);

// =============================================
// إنشاء الجلسة + الكوكيز
// =============================================
async function createSessionAndRespond(user, req, res, fingerprintData) {
  const ip = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.ip;
  const userAgent = req.headers['user-agent'] || '';

  // فحص بصمة الجهاز
  const deviceCheck = await checkDeviceFingerprint(user.id, fingerprintData || {}, ip);

  // فحص الموقع الجغرافي
  const geoCheck = await checkCountryChange(user.id, user.email, ip);
  const geo = geoCheck.geo;

  // إنشاء Session Token
  const sessionToken = uuidv4();
  const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000); // 7 أيام

  // حفظ الجلسة
  await supabase.from('sessions').insert({
    user_id: user.id,
    session_token: sessionToken,
    device_fingerprint_id: deviceCheck.fingerprint?.id || null,
    ip_address: ip,
    user_agent: userAgent,
    country: geo.country,
    city: geo.city,
    expires_at: expiresAt.toISOString()
  });

  // تحديث بيانات آخر تسجيل دخول
  await supabase.from('users').update({
    last_login_at: new Date().toISOString(),
    last_login_ip: ip,
    last_login_country: geo.country,
    last_login_city: geo.city
  }).eq('id', user.id);

  // إنشاء JWT
  const token = jwt.sign(
    { userId: user.id, sessionId: sessionToken },
    env.JWT_SECRET,
    { expiresIn: env.JWT_EXPIRES_IN }
  );

  // تسجيل النشاط
  await logActivity(user.id, 'login_success', {
    provider: user.auth_provider,
    country: geo.country,
    city: geo.city
  }, req);

  // إرسال تنبيه تسجيل دخول
  sendLoginAlertEmail(user.email, {
    country: geo.country,
    city: geo.city,
    userAgent: userAgent,
    ip: ip
  }).catch(err => console.error('[EMAIL] Login alert failed:', err.message));

  // إرسال تنبيه جهاز جديد
  if (deviceCheck.isNew) {
    sendNewDeviceAlertEmail(user.email, {
      country: geo.country,
      city: geo.city,
      userAgent: userAgent,
      ip: ip
    }).catch(err => console.error('[EMAIL] New device alert failed:', err.message));
  }

  // تعيين الكوكيز الآمنة
  res.cookie('session_token', token, {
    httpOnly: true,
    secure: true, // HTTPS فقط
    sameSite: 'lax',
    maxAge: 7 * 24 * 60 * 60 * 1000, // 7 أيام
    path: '/'
  });

  return res.status(200).json({
    success: true,
    message: 'تم تسجيل الدخول بنجاح',
    user: {
      id: user.id,
      username: user.username,
      email: user.email
    },
    redirect: '/home.html'
  });
}

// =============================================
// POST /auth/google - تسجيل الدخول عبر Google
// =============================================
router.post('/google', loginRateLimiter, async (req, res) => {
  try {
    const { credential, fingerprint } = req.body;

    if (!credential) {
      return res.status(400).json({ success: false, message: 'بيانات Google مطلوبة.' });
    }

    // التحقق من Google ID Token على جانب الخادم
    const ticket = await googleClient.verifyIdToken({
      idToken: credential,
      audience: env.GOOGLE_CLIENT_ID
    });

    const payload = ticket.getPayload();
    const googleId = payload.sub;
    const email = payload.email;
    const name = payload.name;
    const avatarUrl = payload.picture;

    if (!email) {
      return res.status(400).json({ success: false, message: 'لم يتم العثور على بريد إلكتروني في حساب Google.' });
    }

    // البحث عن المستخدم
    let { data: existingUser } = await supabase
      .from('users')
      .select('*')
      .eq('email', email.toLowerCase())
      .single();

    if (existingUser) {
      // المستخدم موجود
      if (existingUser.auth_provider === 'email') {
        // الحساب مسجل بالبريد: ربط Google ID
        await supabase.from('users').update({
          google_id: googleId,
          avatar_url: avatarUrl
        }).eq('id', existingUser.id);
        existingUser.google_id = googleId;
      }

      if (existingUser.is_banned) {
        return res.status(403).json({ success: false, message: 'تم حظر هذا الحساب.' });
      }

      return await createSessionAndRespond(existingUser, req, res, fingerprint);
    }

    // مستخدم جديد: إنشاء حساب
    // إنشاء اسم مستخدم فريد من اسم Google
    let baseUsername = (name || 'user').replace(/[^a-zA-Z0-9]/g, '').substring(0, 15);
    if (baseUsername.length < 3) baseUsername = 'user';
    let username = baseUsername;
    let counter = 1;

    while (true) {
      const { data: existing } = await supabase
        .from('users')
        .select('id')
        .eq('username', username)
        .single();
      if (!existing) break;
      username = `${baseUsername}${counter}`;
      counter++;
    }

    const { data: newUser, error } = await supabase
      .from('users')
      .insert({
        username,
        email: email.toLowerCase(),
        auth_provider: 'google',
        google_id: googleId,
        avatar_url: avatarUrl,
        terms_accepted: true,
        privacy_accepted: true,
        cookies_accepted: true
      })
      .select()
      .single();

    if (error) {
      console.error('[AUTH] Google register error:', error);
      return res.status(500).json({ success: false, message: 'خطأ في إنشاء الحساب.' });
    }

    // إنشاء ملف شخصي
    await supabase.from('profiles').insert({
      user_id: newUser.id,
      display_name: name
    });

    await logActivity(newUser.id, 'account_created', { provider: 'google' }, req);

    return await createSessionAndRespond(newUser, req, res, fingerprint);
  } catch (error) {
    console.error('[AUTH] Google login error:', error);
    return res.status(500).json({ success: false, message: 'خطأ في تسجيل الدخول عبر Google.' });
  }
});

// =============================================
// POST /auth/login - تسجيل الدخول عبر البريد
// =============================================
router.post('/login', loginRateLimiter, async (req, res) => {
  try {
    const { encryptedData, recaptchaToken, fingerprint } = req.body;

    // --- التحقق من reCAPTCHA ---
    if (!recaptchaToken) {
      return res.status(400).json({ success: false, message: 'التحقق من reCAPTCHA مطلوب.' });
    }

    try {
      const recaptchaResponse = await axios.post(
        'https://www.google.com/recaptcha/api/siteverify',
        null,
        {
          params: {
            secret: env.RECAPTCHA_SECRET_KEY,
            response: recaptchaToken
          }
        }
      );

      if (!recaptchaResponse.data.success) {
        return res.status(400).json({ success: false, message: 'فشل التحقق من reCAPTCHA.' });
      }
    } catch (err) {
      console.error('[AUTH] reCAPTCHA verification error:', err.message);
      return res.status(500).json({ success: false, message: 'خطأ في التحقق من reCAPTCHA.' });
    }

    // --- فك التشفير ---
    let data;
    try {
      data = decryptPayload(encryptedData);
    } catch (err) {
      return res.status(400).json({ success: false, message: 'بيانات غير صالحة.' });
    }

    const { email, password } = data;

    // --- Honeypot check ---
    if (data._hp_field) {
      return res.status(403).json({ success: false, message: 'تم رفض الطلب.' });
    }

    // --- التحقق من المدخلات ---
    const emailValidation = validateEmail(email);
    if (!emailValidation.valid) {
      return res.status(400).json({ success: false, message: emailValidation.message });
    }

    // --- البحث عن المستخدم ---
    const { data: user } = await supabase
      .from('users')
      .select('*')
      .eq('email', emailValidation.email)
      .single();

    if (!user) {
      await recordFailedLogin(emailValidation.email, req);
      return res.status(401).json({ success: false, message: 'البريد الإلكتروني أو كلمة السر غير صحيحة.' });
    }

    if (user.is_banned) {
      return res.status(403).json({ success: false, message: 'تم حظر هذا الحساب.' });
    }

    // إذا كان الحساب عبر Google فقط
    if (user.auth_provider === 'google' && !user.password_hash) {
      return res.status(400).json({
        success: false,
        message: 'هذا الحساب مسجل عبر Google. استخدم تسجيل الدخول عبر Google.'
      });
    }

    // --- مقارنة كلمة السر ---
    const isPasswordValid = await bcrypt.compare(password, user.password_hash);
    if (!isPasswordValid) {
      await recordFailedLogin(emailValidation.email, req);
      return res.status(401).json({ success: false, message: 'البريد الإلكتروني أو كلمة السر غير صحيحة.' });
    }

    return await createSessionAndRespond(user, req, res, fingerprint);
  } catch (error) {
    console.error('[AUTH] Login error:', error);
    return res.status(500).json({ success: false, message: 'خطأ في تسجيل الدخول.' });
  }
});

// =============================================
// POST /auth/register - إنشاء حساب جديد
// =============================================
router.post('/register', registerRateLimiter, async (req, res) => {
  try {
    const { encryptedData, recaptchaToken, fingerprint } = req.body;

    // --- التحقق من reCAPTCHA ---
    if (!recaptchaToken) {
      return res.status(400).json({ success: false, message: 'التحقق من reCAPTCHA مطلوب.' });
    }

    try {
      const recaptchaResponse = await axios.post(
        'https://www.google.com/recaptcha/api/siteverify',
        null,
        { params: { secret: env.RECAPTCHA_SECRET_KEY, response: recaptchaToken } }
      );
      if (!recaptchaResponse.data.success) {
        return res.status(400).json({ success: false, message: 'فشل التحقق من reCAPTCHA.' });
      }
    } catch (err) {
      return res.status(500).json({ success: false, message: 'خطأ في التحقق من reCAPTCHA.' });
    }

    // --- فك التشفير ---
    let data;
    try {
      data = decryptPayload(encryptedData);
    } catch (err) {
      return res.status(400).json({ success: false, message: 'بيانات غير صالحة.' });
    }

    const { username, email, password } = data;

    // --- Honeypot ---
    if (data._hp_field) {
      return res.status(403).json({ success: false, message: 'تم رفض الطلب.' });
    }

    // --- التحقق من المدخلات ---
    const emailVal = validateEmail(email);
    if (!emailVal.valid) return res.status(400).json({ success: false, message: emailVal.message });

    const usernameVal = validateUsername(username);
    if (!usernameVal.valid) return res.status(400).json({ success: false, message: usernameVal.message });

    const passwordVal = validatePassword(password);
    if (!passwordVal.valid) return res.status(400).json({ success: false, message: passwordVal.message });

    // --- التحقق من البريد المكرر ---
    const { data: existingEmail } = await supabase
      .from('users')
      .select('id, auth_provider')
      .eq('email', emailVal.email)
      .single();

    if (existingEmail) {
      if (existingEmail.auth_provider === 'google') {
        return res.status(400).json({
          success: false,
          message: 'هذا البريد مرتبط بحساب Google. استخدم تسجيل الدخول عبر Google.'
        });
      }
      return res.status(400).json({ success: false, message: 'البريد الإلكتروني مستخدم بالفعل.' });
    }

    // --- التحقق من اسم المستخدم المكرر ---
    const { data: existingUsername } = await supabase
      .from('users')
      .select('id')
      .eq('username', usernameVal.username)
      .single();

    if (existingUsername) {
      return res.status(400).json({ success: false, message: 'اسم المستخدم مستخدم بالفعل. اختر اسماً آخر.' });
    }

    // --- تشفير كلمة السر ---
    const salt = await bcrypt.genSalt(12);
    const passwordHash = await bcrypt.hash(password, salt);

    // --- إنشاء المستخدم ---
    const { data: newUser, error } = await supabase
      .from('users')
      .insert({
        username: usernameVal.username,
        email: emailVal.email,
        password_hash: passwordHash,
        auth_provider: 'email',
        terms_accepted: true,
        privacy_accepted: true,
        cookies_accepted: true
      })
      .select()
      .single();

    if (error) {
      console.error('[AUTH] Register error:', error);
      return res.status(500).json({ success: false, message: 'خطأ في إنشاء الحساب.' });
    }

    // إنشاء ملف شخصي
    await supabase.from('profiles').insert({
      user_id: newUser.id,
      display_name: usernameVal.username
    });

    await logActivity(newUser.id, 'account_created', { provider: 'email' }, req);

    return await createSessionAndRespond(newUser, req, res, fingerprint);
  } catch (error) {
    console.error('[AUTH] Register error:', error);
    return res.status(500).json({ success: false, message: 'خطأ في إنشاء الحساب.' });
  }
});

// =============================================
// POST /auth/logout - تسجيل الخروج
// =============================================
router.post('/logout', requireAuth, async (req, res) => {
  try {
    // إلغاء تفعيل الجلسة
    await supabase
      .from('sessions')
      .update({ is_active: false })
      .eq('id', req.sessionId);

    await logActivity(req.user.id, 'logout', {}, req);

    // حذف الكوكيز
    res.clearCookie('session_token', {
      httpOnly: true,
      secure: true,
      sameSite: 'lax',
      path: '/'
    });

    return res.status(200).json({ success: true, message: 'تم تسجيل الخروج بنجاح.' });
  } catch (error) {
    console.error('[AUTH] Logout error:', error);
    return res.status(500).json({ success: false, message: 'خطأ في تسجيل الخروج.' });
  }
});

// =============================================
// GET /auth/me - معلومات المستخدم الحالي
// =============================================
router.get('/me', requireAuth, async (req, res) => {
  try {
    const { data: user } = await supabase
      .from('users')
      .select('id, username, email, avatar_url, money, xp, age, auth_provider, created_at')
      .eq('id', req.user.id)
      .single();

    const { data: profile } = await supabase
      .from('profiles')
      .select('*')
      .eq('user_id', req.user.id)
      .single();

    return res.status(200).json({
      success: true,
      user: { ...user, profile }
    });
  } catch (error) {
    console.error('[AUTH] Me error:', error);
    return res.status(500).json({ success: false, message: 'خطأ في جلب البيانات.' });
  }
});

module.exports = router;
