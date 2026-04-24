// js/crypto.js
// تشفير البيانات قبل إرسالها للخادم

const ENCRYPTION_KEY = 'YOUR_ENCRYPTION_KEY_HERE'; // نفس المفتاح في الخادم

const SecureCrypto = {
  encrypt(data) {
    const jsonStr = JSON.stringify(data);
    // استخدام CryptoJS (نحمله من CDN)
    return CryptoJS.AES.encrypt(jsonStr, ENCRYPTION_KEY).toString();
  }
};

// تحميل CryptoJS
(function() {
  const script = document.createElement('script');
  script.src = 'https://cdnjs.cloudflare.com/ajax/libs/crypto-js/4.2.0/crypto-js.min.js';
  script.integrity = 'sha512-a+SUDuwNzXDvz4XrJ6ZaTSfpByXTFJEfBRBuGbj5PJI4mJnGWXqRpGwbCDASRRNKMIiLPuG5GgcRPEaIDbdTg==';
  script.crossOrigin = 'anonymous';
  document.head.appendChild(script);
})();
