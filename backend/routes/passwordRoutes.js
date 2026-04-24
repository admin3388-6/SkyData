// routes/passwordRoutes.js
const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const crypto = require('crypto');

const supabase = require('../config/supabase');
const env = require('../config/env');
const { decryptPayload } = require('../utils/encryption');
const { validateEmail, validatePassword } = require('../utils/validators');
const { passwordResetRateLimiter } = require('../middleware/rateLimiter');
const { sendPasswordResetEmail, sendPasswordChangedEmail } = require('../services/emailService');
const { logActivity } = require('../services/anomalyService');

// =============================================
// POST /password/request-reset - طلب إعادة تعيين
// =============================================
router.post('/request-reset', passwordResetRateLimiter, async (req, res) => {
  try {
    const { encryptedData, recaptchaToken } = req.body;

    // --- reCAPTCHA ---
    if (!recaptchaToken) {
      return res.status(400).json({ success: false, message: 'التحقق من reCAPTCHA مطلوب.' });
    }

    const axios = require('axios');
    const recaptchaResponse = await axios.post(
      'https://www.google.com/recaptcha/api/siteverify',
      null,
      { params: { secret: env.RECAPTCHA_SECRET_KEY, response: recaptchaToken } }
    );

    if (!recaptchaResponse.data.success) {
      return res.status(400).json({ success: false, message: 'فشل التحقق من reCAPTCHA.' });
    }

    // --- فك التشفير ---
    let data;
    try {
      data = decryptPayload(encryptedData);
    } catch {
      return res.status(400).json({ success: false, message: 'بيانات غير صالحة.' });
    }

    const emailVal = validateEmail(data.email);
    if (!emailVal.valid) {
      return res.status(400).json({ success: false, message: emailVal.message });
    }

    // --- البحث عن المستخدم ---
    const { data: user } = await supabase
      .from('users')
      .select('id, email, auth_provider, password_hash')
      .eq('email', emailVal.email)
      .single();

    if (!user) {
      // لا نُفصح عن عدم وجود الحساب (أمان)
      return res.status(200).json({
        success: true,
        message: 'إذا كان البريد مسجلاً، ستصلك رسالة تحتوي على الرمز.'
      });
    }

    if (user.auth_provider === 'google' && !user.password_hash) {
      return res.status(200).json({
        success: true,
        message: 'إذا كان البريد مسجلاً، ستصلك رسالة تحتوي على الرمز.'
      });
    }

    // --- إلغاء أي رموز سابقة ---
    await supabase
      .from('password_reset_codes')
      .update({ is_used: true })
      .eq('user_id', user.id)
      .eq('is_used', false);

    // --- إنشاء رمز جديد ---
    const code = crypto.randomInt(100000, 999999).toString();
    const expiresAt = new Date(Date.now() + 5 * 60 * 1000); // 5 دقائق

    const { data: resetRecord } = await supabase
      .from('password_reset_codes')
      .insert({
        user_id: user.id,
        email: emailVal.email,
        code,
        expires_at: expiresAt.toISOString()
      })
      .select('cancel_token')
      .single();

    // --- إرسال البريد ---
    await sendPasswordResetEmail(emailVal.email, code, resetRecord.cancel_token);

    await logActivity(user.id, 'password_reset_requested', {}, req);

    return res.status(200).json({
      success: true,
      message: 'تم إرسال رمز إعادة التعيين إلى بريدك الإلكتروني.'
    });
  } catch (error) {
    console.error('[PASSWORD] Request reset error:', error);
    return res.status(500).json({ success: false, message: 'خطأ في معالجة الطلب.' });
  }
});

// =============================================
// POST /password/verify-code - التحقق من الرمز
// =============================================
router.post('/verify-code', async (req, res) => {
  try {
    const { encryptedData } = req.body;

    let data;
    try {
      data = decryptPayload(encryptedData);
    } catch {
      return res.status(400).json({ success: false, message: 'بيانات غير صالحة.' });
    }

    const { email, code } = data;

    const emailVal = validateEmail(email);
    if (!emailVal.valid) {
      return res.status(400).json({ success: false, message: emailVal.message });
    }

    if (!code || code.length !== 6) {
      return res.status(400).json({ success: false, message: 'الرمز يجب أن يتكون من 6 أرقام.' });
    }

    // --- البحث عن الرمز ---
    const { data: resetRecord } = await supabase
      .from('password_reset_codes')
      .select('*')
      .eq('email', emailVal.email)
      .eq('code', code)
      .eq('is_used', false)
      .eq('is_cancelled', false)
      .gt('expires_at', new Date().toISOString())
      .order('created_at', { ascending: false })
      .limit(1)
      .single();

    if (!resetRecord) {
      return res.status(400).json({
        success: false,
        message: 'الرمز غير صحيح أو منتهي الصلاحية.'
      });
    }

    // إنشاء توكن مؤقت لتغيير كلمة السر
    const resetToken = crypto.randomUUID();

    // تحديث السجل مع الرمز المؤقت
    await supabase
      .from('password_reset_codes')
      .update({ cancel_token: resetToken }) // نُعيد استخدام حقل cancel_token
      .eq('id', resetRecord.id);

    return res.status(200).json({
      success: true,
      message: 'الرمز صحيح. يمكنك الآن تغيير كلمة السر.',
      resetToken
    });
  } catch (error) {
    console.error('[PASSWORD] Verify code error:', error);
    return res.status(500).json({ success: false, message: 'خطأ في التحقق من الرمز.' });
  }
});

// =============================================
// POST /password/reset - تغيير كلمة السر
// =============================================
router.post('/reset', async (req, res) => {
  try {
    const { encryptedData } = req.body;

    let data;
    try {
      data = decryptPayload(encryptedData);
    } catch {
      return res.status(400).json({ success: false, message: 'بيانات غير صالحة.' });
    }

    const { email, newPassword, confirmPassword, resetToken } = data;

    const emailVal = validateEmail(email);
    if (!emailVal.valid) {
      return res.status(400).json({ success: false, message: emailVal.message });
    }

    if (newPassword !== confirmPassword) {
      return res.status(400).json({ success: false, message: 'كلمة السر وتأكيدها غير متطابقين.' });
    }

    const passwordVal = validatePassword(newPassword);
    if (!passwordVal.valid) {
      return res.status(400).json({ success: false, message: passwordVal.message });
    }

    // --- التحقق من resetToken ---
    const { data: resetRecord } = await supabase
      .from('password_reset_codes')
      .select('*')
      .eq('email', emailVal.email)
      .eq('cancel_token', resetToken)
      .eq('is_used', false)
      .eq('is_cancelled', false)
      .gt('expires_at', new Date().toISOString())
      .single();

    if (!resetRecord) {
      return res.status(400).json({ success: false, message: 'جلسة إعادة التعيين غير صالحة أو منتهية.' });
    }

    // --- تشفير كلمة السر الجديدة ---
    const salt = await bcrypt.genSalt(12);
    const passwordHash = await bcrypt.hash(newPassword, salt);

    // --- تحديث كلمة السر ---
    await supabase.from('users').update({
      password_hash: passwordHash,
      updated_at: new Date().toISOString()
    }).eq('id', resetRecord.user_id);

    // تحديد الرمز كمستخدم
    await supabase
      .from('password_reset_codes')
      .update({ is_used: true })
      .eq('id', resetRecord.id);

    // إلغاء جميع الجلسات النشطة (أمان)
    await supabase
      .from('sessions')
      .update({ is_active: false })
      .eq('user_id', resetRecord.user_id);

    // إرسال تنبيه بتغيير كلمة السر
    await sendPasswordChangedEmail(emailVal.email);

    await logActivity(resetRecord.user_id, 'password_changed', {}, req);

    return res.status(200).json({
      success: true,
      message: 'تم تغيير كلمة السر بنجاح. يرجى تسجيل الدخول مرة أخرى.'
    });
  } catch (error) {
    console.error('[PASSWORD] Reset error:', error);
    return res.status(500).json({ success: false, message: 'خطأ في تغيير كلمة السر.' });
  }
});

// =============================================
// GET /password/cancel-reset - إلغاء الرمز
// =============================================
router.get('/cancel-reset', async (req, res) => {
  try {
    const { token } = req.query;

    if (!token) {
      return res.status(400).send('<h1>رابط غير صالح</h1>');
    }

    const { data: resetRecord } = await supabase
      .from('password_reset_codes')
      .select('id, user_id')
      .eq('cancel_token', token)
      .eq('is_cancelled', false)
      .eq('is_used', false)
      .single();

    if (resetRecord) {
      await supabase
        .from('password_reset_codes')
        .update({ is_cancelled: true })
        .eq('id', resetRecord.id);

      await logActivity(resetRecord.user_id, 'password_reset_cancelled', {}, req);
    }

    return res.send(`
      <html dir="rtl">
        <body style="font-family: sans-serif; text-align: center; padding: 50px; background: #e8f5e9;">
          <h1 style="color: #2e7d32;">✅ تم الإلغاء</h1>
          <p>تم إلغاء رمز إعادة التعيين بنجاح. لم يعد صالحاً.</p>
        </body>
      </html>
    `);
  } catch (error) {
    console.error('[PASSWORD] Cancel reset error:', error);
    return res.status(500).send('<h1>خطأ</h1>');
  }
});

module.exports = router;
