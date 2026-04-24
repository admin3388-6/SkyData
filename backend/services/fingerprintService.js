// services/fingerprintService.js
const crypto = require('crypto');
const supabase = require('../config/supabase');

/**
 * إنشاء hash من بيانات بصمة الجهاز
 */
function generateFingerprintHash(fingerprintData) {
  const rawString = [
    fingerprintData.userAgent || '',
    fingerprintData.screenResolution || '',
    fingerprintData.timezone || '',
    fingerprintData.language || '',
    fingerprintData.hardwareConcurrency || '',
    fingerprintData.webglFingerprint || '',
    fingerprintData.canvasFingerprint || ''
  ].join('|');

  return crypto.createHash('sha256').update(rawString).digest('hex');
}

/**
 * التحقق مما إذا كان الجهاز جديداً أم معروفاً
 * يُرجع: { isNew: boolean, fingerprint: object }
 */
async function checkDeviceFingerprint(userId, fingerprintData, ipAddress) {
  const hash = generateFingerprintHash(fingerprintData);

  // البحث عن بصمة مطابقة لهذا المستخدم
  const { data: existing } = await supabase
    .from('device_fingerprints')
    .select('*')
    .eq('user_id', userId)
    .eq('fingerprint_hash', hash)
    .single();

  if (existing) {
    // جهاز معروف: تحديث last_seen
    await supabase
      .from('device_fingerprints')
      .update({
        last_seen_at: new Date().toISOString(),
        ip_address: ipAddress
      })
      .eq('id', existing.id);

    return { isNew: false, fingerprint: existing };
  }

  // جهاز جديد: تسجيله
  const { data: newFingerprint, error } = await supabase
    .from('device_fingerprints')
    .insert({
      user_id: userId,
      fingerprint_hash: hash,
      user_agent: fingerprintData.userAgent,
      screen_resolution: fingerprintData.screenResolution,
      timezone: fingerprintData.timezone,
      language: fingerprintData.language,
      hardware_concurrency: fingerprintData.hardwareConcurrency,
      webgl_fingerprint: fingerprintData.webglFingerprint,
      canvas_fingerprint: fingerprintData.canvasFingerprint,
      ip_address: ipAddress
    })
    .select()
    .single();

  if (error) {
    console.error('[FINGERPRINT] Error saving:', error);
    return { isNew: true, fingerprint: null };
  }

  return { isNew: true, fingerprint: newFingerprint };
}

module.exports = { checkDeviceFingerprint, generateFingerprintHash };
