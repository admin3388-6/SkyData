// middleware/security.js
const supabase = require('../config/supabase');

/**
 * Middleware أمني عام:
 * - فحص الـ IP المحظور
 * - فحص Honeypot fields
 * - إضافة رؤوس أمان إضافية
 */
async function securityMiddleware(req, res, next) {
  try {
    // --- فحص Honeypot ---
    if (req.body && req.body._hp_field) {
      // حقل مخفي ممتلئ = بوت
      console.warn(`[SECURITY] Honeypot triggered from IP: ${req.ip}`);
      return res.status(403).json({ success: false, message: 'تم رفض الطلب.' });
    }

    // --- فحص IP محظور ---
    const clientIp = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.ip;
    const { data: blocked } = await supabase
      .from('blocked_ips')
      .select('id, blocked_until')
      .eq('ip_address', clientIp)
      .gt('blocked_until', new Date().toISOString())
      .limit(1)
      .single();

    if (blocked) {
      return res.status(429).json({
        success: false,
        message: 'تم حظر عنوان IP مؤقتاً بسبب نشاط مشبوه.'
      });
    }

    // --- رؤوس أمان إضافية ---
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('X-XSS-Protection', '1; mode=block');
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');

    next();
  } catch (error) {
    console.error('[SECURITY] Middleware error:', error.message);
    next(); // لا نوقف الطلب عند خطأ في فحص الأمان
  }
}

module.exports = { securityMiddleware };
