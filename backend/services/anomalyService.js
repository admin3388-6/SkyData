// services/anomalyService.js
const supabase = require('../config/supabase');
const { sendFailedAttemptsAlertEmail, sendCountryChangeAlertEmail } = require('./emailService');
const { getGeoFromIP } = require('./geoService');

/**
 * تسجيل نشاط
 */
async function logActivity(userId, action, details, req) {
  try {
    const ip = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.ip;
    const userAgent = req.headers['user-agent'] || '';
    const geo = await getGeoFromIP(ip);

    let deviceType = 'unknown';
    if (/mobile|android|iphone|ipad/i.test(userAgent)) deviceType = 'mobile';
    else if (/tablet/i.test(userAgent)) deviceType = 'tablet';
    else if (/windows|macintosh|linux/i.test(userAgent)) deviceType = 'desktop';

    await supabase.from('activity_logs').insert({
      user_id: userId,
      action,
      details: { ...details, ...geo },
      ip_address: ip,
      user_agent: userAgent,
      country: geo.country,
      city: geo.city,
      device_type: deviceType,
      risk_level: details.riskLevel || 'low'
    });
  } catch (error) {
    console.error('[ANOMALY] Error logging activity:', error.message);
  }
}

/**
 * تسجيل محاولة دخول فاشلة + تحقق من الحدود
 */
async function recordFailedLogin(email, req) {
  try {
    const ip = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.ip;
    const userAgent = req.headers['user-agent'] || '';

    await supabase.from('failed_login_attempts').insert({
      email,
      ip_address: ip,
      user_agent: userAgent,
      reason: 'invalid_credentials'
    });

    // عد المحاولات الفاشلة في آخر 15 دقيقة
    const fifteenMinAgo = new Date(Date.now() - 15 * 60 * 1000).toISOString();
    const { count } = await supabase
      .from('failed_login_attempts')
      .select('id', { count: 'exact', head: true })
      .eq('ip_address', ip)
      .gt('created_at', fifteenMinAgo);

    // أكثر من 5 محاولات: إرسال تنبيه
    if (count >= 5) {
      const { data: user } = await supabase
        .from('users')
        .select('email')
        .eq('email', email)
        .single();

      if (user) {
        await sendFailedAttemptsAlertEmail(user.email, count, ip);
      }
    }

    // أكثر من 15 محاولة: حظر IP مؤقتاً لمدة 30 دقيقة
    if (count >= 15) {
      await supabase.from('blocked_ips').insert({
        ip_address: ip,
        reason: `تجاوز ${count} محاولة دخول فاشلة`,
        blocked_until: new Date(Date.now() + 30 * 60 * 1000).toISOString()
      });
    }
  } catch (error) {
    console.error('[ANOMALY] Error recording failed login:', error.message);
  }
}

/**
 * فحص تغيير الدولة
 */
async function checkCountryChange(userId, email, currentIp) {
  try {
    const currentGeo = await getGeoFromIP(currentIp);

    const { data: user } = await supabase
      .from('users')
      .select('last_login_country')
      .eq('id', userId)
      .single();

    if (user && user.last_login_country && user.last_login_country !== currentGeo.country) {
      // تغيير مفاجئ في الدولة
      await sendCountryChangeAlertEmail(email, {
        previousCountry: user.last_login_country,
        currentCountry: currentGeo.country,
        ip: currentIp
      });

      await logActivity(userId, 'country_change_detected', {
        previousCountry: user.last_login_country,
        currentCountry: currentGeo.country,
        riskLevel: 'high'
      }, { headers: {}, ip: currentIp });

      return { changed: true, geo: currentGeo };
    }

    return { changed: false, geo: currentGeo };
  } catch (error) {
    console.error('[ANOMALY] Error checking country:', error.message);
    return { changed: false, geo: { country: 'Unknown', city: 'Unknown' } };
  }
}

module.exports = { logActivity, recordFailedLogin, checkCountryChange };
