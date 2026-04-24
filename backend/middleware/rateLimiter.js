// middleware/rateLimiter.js
const rateLimit = require('express-rate-limit');

// Rate limiter عام: 100 طلب لكل 15 دقيقة لكل IP
const globalRateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: {
    success: false,
    message: 'عدد كبير من الطلبات. يرجى الانتظار قبل المحاولة مرة أخرى.'
  },
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => {
    return req.headers['x-forwarded-for'] || req.ip;
  }
});

// Rate limiter لتسجيل الدخول: 10 محاولات لكل 15 دقيقة
const loginRateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: {
    success: false,
    message: 'محاولات تسجيل دخول كثيرة. يرجى الانتظار 15 دقيقة.'
  },
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => {
    return req.headers['x-forwarded-for'] || req.ip;
  }
});

// Rate limiter لإعادة تعيين كلمة السر: مرة كل 60 ثانية
const passwordResetRateLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 1,
  message: {
    success: false,
    message: 'يمكنك إرسال طلب واحد فقط كل 60 ثانية.'
  },
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => {
    return req.headers['x-forwarded-for'] || req.ip;
  }
});

// Rate limiter لإنشاء الحساب: 5 محاولات لكل ساعة
const registerRateLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 5,
  message: {
    success: false,
    message: 'تم تجاوز عدد محاولات إنشاء الحساب. يرجى الانتظار.'
  },
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => {
    return req.headers['x-forwarded-for'] || req.ip;
  }
});

module.exports = {
  globalRateLimiter,
  loginRateLimiter,
  passwordResetRateLimiter,
  registerRateLimiter
};
