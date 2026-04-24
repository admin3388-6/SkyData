// services/geoService.js
const axios = require('axios');

/**
 * تحديد الموقع الجغرافي من IP
 * نستخدم ipapi.co (مجاني - 30,000 طلب/شهر)
 */
async function getGeoFromIP(ip) {
  try {
    // تجاهل IPs المحلية
    if (!ip || ip === '127.0.0.1' || ip === '::1' || ip.startsWith('192.168') || ip.startsWith('10.')) {
      return { country: 'Local', city: 'Local', countryCode: 'LO' };
    }

    const response = await axios.get(`https://ipapi.co/${ip}/json/`, {
      timeout: 5000
    });

    return {
      country: response.data.country_name || 'Unknown',
      city: response.data.city || 'Unknown',
      countryCode: response.data.country_code || 'XX',
      region: response.data.region || '',
      timezone: response.data.timezone || ''
    };
  } catch (error) {
    console.error('[GEO] Error fetching location:', error.message);
    return { country: 'Unknown', city: 'Unknown', countryCode: 'XX' };
  }
}

module.exports = { getGeoFromIP };
