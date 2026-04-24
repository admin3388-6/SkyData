// server.js
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const cookieParser = require('cookie-parser');
const env = require('./config/env');
const { globalRateLimiter } = require('./middleware/rateLimiter');
const { securityMiddleware } = require('./middleware/security');

const authRoutes = require('./routes/authRoutes');
const passwordRoutes = require('./routes/passwordRoutes');
const adminRoutes = require('./routes/adminRoutes');
const healthRoutes = require('./routes/healthRoutes');

const app = express();

// ============================================
// Middleware الأمان الأساسي
// ============================================
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "https://www.google.com", "https://www.gstatic.com"],
      frameSrc: ["https://www.google.com"],
      connectSrc: ["'self'", env.FRONTEND_URL]
    }
  },
  crossOriginEmbedderPolicy: false
}));

app.use(cors({
  origin: env.FRONTEND_URL,
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Encrypted-Payload', 'X-Request-Timestamp']
}));

app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: false, limit: '10kb' }));
app.use(cookieParser());
app.use(globalRateLimiter);
app.use(securityMiddleware);

// ============================================
// المسارات
// ============================================
app.use('/health', healthRoutes);
app.use('/auth', authRoutes);
app.use('/password', passwordRoutes);
app.use('/admin', adminRoutes);

// ============================================
// معالجة الأخطاء العامة
// ============================================
app.use((err, req, res, next) => {
  console.error('Unhandled Error:', err);
  res.status(500).json({
    success: false,
    message: 'حدث خطأ في الخادم. يرجى المحاولة لاحقاً.'
  });
});

// ============================================
// 404
// ============================================
app.use((req, res) => {
  res.status(404).json({
    success: false,
    message: 'المسار غير موجود'
  });
});

// ============================================
// تشغيل الخادم
// ============================================
app.listen(env.PORT, () => {
  console.log(`Server running on port ${env.PORT} in ${env.NODE_ENV} mode`);
});

module.exports = app;
