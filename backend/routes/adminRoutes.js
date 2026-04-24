// routes/adminRoutes.js
const express = require('express');
const router = express.Router();
const { requireAdmin } = require('../middleware/adminAuth');
const supabase = require('../config/supabase');

// =============================================
// GET /admin/logs - السجلات
// =============================================
router.get('/logs', requireAdmin, async (req, res) => {
  try {
    const {
      page = 1,
      limit = 50,
      action,
      risk_level,
      device_type,
      country,
      date_from,
      date_to,
      email,
      user_id
    } = req.query;

    const offset = (parseInt(page) - 1) * parseInt(limit);

    let query = supabase
      .from('activity_logs')
      .select('*, users!activity_logs_user_id_fkey(username, email)', { count: 'exact' })
      .order('created_at', { ascending: false })
      .range(offset, offset + parseInt(limit) - 1);

    if (action) query = query.eq('action', action);
    if (risk_level) query = query.eq('risk_level', risk_level);
    if (device_type) query = query.eq('device_type', device_type);
    if (country) query = query.ilike('country', `%${country}%`);
    if (date_from) query = query.gte('created_at', date_from);
    if (date_to) query = query.lte('created_at', date_to);
    if (user_id) query = query.eq('user_id', user_id);

    const { data: logs, count, error } = await query;

    if (error) throw error;

    // إذا بحث بالبريد: نبحث أولاً عن user_id
    let filteredLogs = logs;
    if (email) {
      const { data: user } = await supabase
        .from('users')
        .select('id')
        .ilike('email', `%${email}%`)
        .single();

      if (user) {
        const { data: emailLogs, count: emailCount } = await supabase
          .from('activity_logs')
          .select('*, users!activity_logs_user_id_fkey(username, email)', { count: 'exact' })
          .eq('user_id', user.id)
          .order('created_at', { ascending: false })
          .range(offset, offset + parseInt(limit) - 1);

        filteredLogs = emailLogs;
      } else {
        filteredLogs = [];
      }
    }

    return res.status(200).json({
      success: true,
      logs: filteredLogs,
      total: count,
      page: parseInt(page),
      limit: parseInt(limit)
    });
  } catch (error) {
    console.error('[ADMIN] Logs error:', error);
    return res.status(500).json({ success: false, message: 'خطأ في جلب السجلات.' });
  }
});

// =============================================
// GET /admin/stats - الإحصائيات
// =============================================
router.get('/stats', requireAdmin, async (req, res) => {
  try {
    // عدد المستخدمين الكلي
    const { count: totalUsers } = await supabase
      .from('users')
      .select('id', { count: 'exact', head: true });

    // المستخدمين الجدد اليوم
    const today = new Date();
    today.setHours(0, 0, 0, 0);
    const { count: newToday } = await supabase
      .from('users')
      .select('id', { count: 'exact', head: true })
      .gte('created_at', today.toISOString());

    // عدد الجلسات النشطة
    const { count: activeSessions } = await supabase
      .from('sessions')
      .select('id', { count: 'exact', head: true })
      .eq('is_active', true)
      .gt('expires_at', new Date().toISOString());

    // إحصائيات الدول
    const { data: countryStats } = await supabase
      .from('activity_logs')
      .select('country')
      .not('country', 'is', null);

    const countryCounts = {};
    countryStats?.forEach(log => {
      countryCounts[log.country] = (countryCounts[log.country] || 0) + 1;
    });

    // إحصائيات الأجهزة
    const { data: deviceStats } = await supabase
      .from('activity_logs')
      .select('device_type')
      .not('device_type', 'is', null);

    const deviceCounts = {};
    deviceStats?.forEach(log => {
      deviceCounts[log.device_type] = (deviceCounts[log.device_type] || 0) + 1;
    });

    // المحاولات الفاشلة اليوم
    const { count: failedToday } = await supabase
      .from('failed_login_attempts')
      .select('id', { count: 'exact', head: true })
      .gte('created_at', today.toISOString());

    // IPs المحظورة حالياً
    const { count: blockedIps } = await supabase
      .from('blocked_ips')
      .select('id', { count: 'exact', head: true })
      .gt('blocked_until', new Date().toISOString());

    return res.status(200).json({
      success: true,
      stats: {
        totalUsers,
        newToday,
        activeSessions,
        failedToday,
        blockedIps,
        countryCounts,
        deviceCounts
      }
    });
  } catch (error) {
    console.error('[ADMIN] Stats error:', error);
    return res.status(500).json({ success: false, message: 'خطأ في جلب الإحصائيات.' });
  }
});

// =============================================
// GET /admin/users - قائمة المستخدمين
// =============================================
router.get('/users', requireAdmin, async (req, res) => {
  try {
    const { page = 1, limit = 50, search } = req.query;
    const offset = (parseInt(page) - 1) * parseInt(limit);

    let query = supabase
      .from('users')
      .select('id, username, email, auth_provider, is_banned, money, xp, created_at, last_login_at, last_login_country', { count: 'exact' })
      .order('created_at', { ascending: false })
      .range(offset, offset + parseInt(limit) - 1);

    if (search) {
      query = query.or(`email.ilike.%${search}%,username.ilike.%${search}%`);
    }

    const { data: users, count, error } = await query;
    if (error) throw error;

    return res.status(200).json({
      success: true,
      users,
      total: count,
      page: parseInt(page),
      limit: parseInt(limit)
    });
  } catch (error) {
    console.error('[ADMIN] Users error:', error);
    return res.status(500).json({ success: false, message: 'خطأ في جلب المستخدمين.' });
  }
});

// =============================================
// GET /admin/failed-logins - المحاولات الفاشلة
// =============================================
router.get('/failed-logins', requireAdmin, async (req, res) => {
  try {
    const { page = 1, limit = 50 } = req.query;
    const offset = (parseInt(page) - 1) * parseInt(limit);

    const { data: attempts, count } = await supabase
      .from('failed_login_attempts')
      .select('*', { count: 'exact' })
      .order('created_at', { ascending: false })
      .range(offset, offset + parseInt(limit) - 1);

    return res.status(200).json({
      success: true,
      attempts,
      total: count,
      page: parseInt(page),
      limit: parseInt(limit)
    });
  } catch (error) {
    console.error('[ADMIN] Failed logins error:', error);
    return res.status(500).json({ success: false, message: 'خطأ.' });
  }
});

module.exports = router;
