// middleware/adminAuth.js
const { requireAuth } = require('./auth');
const supabase = require('../config/supabase');

/**
 * التحقق من أن المستخدم مسؤول
 * إذا لم يكن: إرجاع 404 (ليس 403) لإخفاء وجود الصفحة
 */
async function requireAdmin(req, res, next) {
  // أولاً: تحقق من المصادقة العادية
  requireAuth(req, res, async () => {
    try {
      const { data: admin } = await supabase
        .from('admin_emails')
        .select('id, role')
        .eq('email', req.user.email)
        .single();

      if (!admin) {
        // إرجاع 404 لإخفاء وجود الصفحة
        return res.status(404).json({
          success: false,
          message: 'الصفحة غير موجودة.'
        });
      }

      req.adminRole = admin.role;
      next();
    } catch (error) {
      // حتى عند الخطأ: 404 لإخفاء الصفحة
      return res.status(404).json({
        success: false,
        message: 'الصفحة غير موجودة.'
      });
    }
  });
}

module.exports = { requireAdmin };
