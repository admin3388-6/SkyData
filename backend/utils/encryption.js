// utils/encryption.js
const CryptoJS = require('crypto-js');
const env = require('../config/env');

/**
 * فك تشفير البيانات القادمة من الـ frontend
 * الـ frontend يشفر البيانات بمفتاح عام
 * الخادم يفك التشفير بالمفتاح السري
 */
function decryptPayload(encryptedData) {
  try {
    const bytes = CryptoJS.AES.decrypt(encryptedData, env.ENCRYPTION_KEY);
    const decryptedStr = bytes.toString(CryptoJS.enc.Utf8);
    if (!decryptedStr) {
      throw new Error('فشل فك التشفير');
    }
    return JSON.parse(decryptedStr);
  } catch (error) {
    throw new Error('بيانات مشفرة غير صالحة');
  }
}

/**
 * تشفير البيانات
 */
function encryptPayload(data) {
  const jsonStr = JSON.stringify(data);
  return CryptoJS.AES.encrypt(jsonStr, env.ENCRYPTION_KEY).toString();
}

module.exports = { decryptPayload, encryptPayload };
