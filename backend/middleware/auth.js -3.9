// middleware/auth.js
const jwt = require('jsonwebtoken');
const env = require('../config/env');
const supabase = require('../config/supabase');

/**
 * التحقق من جلسة المستخدم عبر JWT في HttpOnly cookie
 */
async function requireAuth(req, res, next) {
  try {
    const token = req.cookies?.session_token;

    if (!token) {
      return res.status(401).json({
        success: false,
        message: 'يجب تسجيل الدخول أولاً.'
      });
    }

    // فك JWT
    const decoded = jwt.verify(token, env.JWT_SECRET);

    // التحقق من الجلسة في قاعدة البيانات
    const { data: session } = await supabase
      .from('sessions')
      .select('id, user_id, is_active, expires_at')
      .eq('session_token', decoded.sessionId)
      .eq('is_active', true)
      .single();

    if (!session || new Date(session.expires_at) < new Date()) {
      return res.status(401).json({
        success: false,
        message: 'الجلسة منتهية. يرجى تسجيل الدخول مرة أخرى.'
      });
    }

    // جلب بيانات المستخدم
    const { data: user } = await supabase
      .from('users')
      .select('id, username, email, is_banned')
      .eq('id', session.user_id)
      .single();

    if (!user) {
      return res.status(401).json({ success: false, message: 'المستخدم غير موجود.' });
    }

    if (user.is_banned) {
      return res.status(403).json({ success: false, message: 'تم حظر هذا الحساب.' });
    }

    // تحديث آخر نشاط في الجلسة
    await supabase
      .from('sessions')
      .update({ last_activity_at: new Date().toISOString() })
      .eq('id', session.id);

    req.user = user;
    req.sessionId = session.id;
    next();
  } catch (error) {
    if (error.name === 'JsonWebTokenError' || error.name === 'TokenExpiredError') {
      return res.status(401).json({
        success: false,
        message: 'جلسة غير صالحة. يرجى تسجيل الدخول مرة أخرى.'
      });
    }
    console.error('[AUTH] Middleware error:', error);
    res.status(500).json({ success: false, message: 'خطأ في التحقق.' });
  }
}

module.exports = { requireAuth };
