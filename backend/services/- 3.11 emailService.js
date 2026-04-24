// services/emailService.js
const nodemailer = require('nodemailer');
const env = require('../config/env');

const transporter = nodemailer.createTransport({
  host: env.SMTP_HOST,
  port: env.SMTP_PORT,
  secure: false, // true للمنفذ 465
  auth: {
    user: env.SMTP_USER,
    pass: env.SMTP_PASS
  }
});

/**
 * إرسال رمز إعادة تعيين كلمة السر
 */
async function sendPasswordResetEmail(toEmail, code, cancelToken) {
  const cancelUrl = `${env.FRONTEND_URL}/api/password/cancel-reset?token=${cancelToken}`;

  const htmlContent = `
    <div dir="rtl" style="font-family: 'Segoe UI', Tahoma, Arial, sans-serif; max-width: 500px; margin: 0 auto; padding: 30px; background: linear-gradient(135deg, #1a7a3a 0%, #2d8f4e 50%, #f0f0f0 100%); border-radius: 15px;">
      <div style="background: white; padding: 30px; border-radius: 10px; box-shadow: 0 4px 20px rgba(0,0,0,0.1);">
        <h2 style="color: #1a7a3a; text-align: center; margin-bottom: 20px;">إعادة تعيين كلمة السر</h2>
        <p style="color: #333; font-size: 16px; line-height: 1.8;">مرحباً،</p>
        <p style="color: #333; font-size: 16px; line-height: 1.8;">تلقينا طلباً لإعادة تعيين كلمة السر الخاصة بحسابك. استخدم الرمز التالي:</p>
        <div style="background: #f0f9f4; padding: 20px; border-radius: 10px; text-align: center; margin: 20px 0;">
          <span style="font-size: 36px; font-weight: bold; color: #1a7a3a; letter-spacing: 10px; font-family: monospace;">${code}</span>
        </div>
        <p style="color: #666; font-size: 14px; line-height: 1.6;">⏱️ هذا الرمز صالح لمدة <strong>5 دقائق</strong> فقط.</p>
        <hr style="border: 1px solid #e0e0e0; margin: 20px 0;">
        <p style="color: #d32f2f; font-size: 14px; line-height: 1.6;">⚠️ إذا لم تطلب إعادة تعيين كلمة السر، اضغط الزر التالي لإلغاء هذه العملية فوراً:</p>
        <div style="text-align: center; margin: 15px 0;">
          <a href="${cancelUrl}" style="display: inline-block; padding: 12px 30px; background: #d32f2f; color: white; text-decoration: none; border-radius: 8px; font-weight: bold;">إلغاء هذه العملية فوراً</a>
        </div>
        <p style="color: #999; font-size: 12px; text-align: center; margin-top: 20px;">هذه رسالة آلية، لا تُرد عليها.</p>
      </div>
    </div>
  `;

  await transporter.sendMail({
    from: `"Secure Login" <${env.EMAIL_FROM}>`,
    to: toEmail,
    subject: 'رمز إعادة تعيين كلمة السر',
    html: htmlContent
  });
}

/**
 * إرسال تنبيه تسجيل دخول
 */
async function sendLoginAlertEmail(toEmail, details) {
  const htmlContent = `
    <div dir="rtl" style="font-family: 'Segoe UI', Tahoma, Arial, sans-serif; max-width: 500px; margin: 0 auto; padding: 30px; background: #f5f5f5; border-radius: 15px;">
      <div style="background: white; padding: 30px; border-radius: 10px; box-shadow: 0 4px 20px rgba(0,0,0,0.1);">
        <h2 style="color: #1a7a3a; text-align: center;">🔔 تنبيه تسجيل دخول جديد</h2>
        <p style="color: #333;">تم تسجيل دخول إلى حسابك من:</p>
        <ul style="color: #555; line-height: 2;">
          <li><strong>التاريخ:</strong> ${new Date().toLocaleString('ar-DZ')}</li>
          <li><strong>الدولة:</strong> ${details.country || 'غير محدد'}</li>
          <li><strong>المدينة:</strong> ${details.city || 'غير محدد'}</li>
          <li><strong>الجهاز:</strong> ${details.userAgent || 'غير محدد'}</li>
          <li><strong>IP:</strong> ${details.ip || 'غير محدد'}</li>
        </ul>
        <p style="color: #d32f2f; font-size: 14px;">إذا لم تكن أنت، قم بتغيير كلمة السر فوراً.</p>
      </div>
    </div>
  `;

  await transporter.sendMail({
    from: `"Secure Login" <${env.EMAIL_FROM}>`,
    to: toEmail,
    subject: '🔔 تسجيل دخول جديد إلى حسابك',
    html: htmlContent
  });
}

/**
 * إرسال تنبيه جهاز جديد
 */
async function sendNewDeviceAlertEmail(toEmail, details) {
  const htmlContent = `
    <div dir="rtl" style="font-family: 'Segoe UI', Tahoma, Arial, sans-serif; max-width: 500px; margin: 0 auto; padding: 30px; background: #fff3e0; border-radius: 15px;">
      <div style="background: white; padding: 30px; border-radius: 10px;">
        <h2 style="color: #e65100; text-align: center;">⚠️ تسجيل دخول من جهاز جديد</h2>
        <p style="color: #333;">تم رصد تسجيل دخول من جهاز لم يُستخدم من قبل:</p>
        <ul style="color: #555; line-height: 2;">
          <li><strong>التاريخ:</strong> ${new Date().toLocaleString('ar-DZ')}</li>
          <li><strong>الدولة:</strong> ${details.country || 'غير محدد'}</li>
          <li><strong>المدينة:</strong> ${details.city || 'غير محدد'}</li>
          <li><strong>الجهاز:</strong> ${details.userAgent || 'غير محدد'}</li>
          <li><strong>IP:</strong> ${details.ip || 'غير محدد'}</li>
        </ul>
        <p style="color: #d32f2f;"><strong>إذا لم تكن أنت، غيّر كلمة السر فوراً!</strong></p>
      </div>
    </div>
  `;

  await transporter.sendMail({
    from: `"Secure Login" <${env.EMAIL_FROM}>`,
    to: toEmail,
    subject: '⚠️ تسجيل دخول من جهاز جديد',
    html: htmlContent
  });
}

/**
 * إرسال تنبيه تغيير الدولة
 */
async function sendCountryChangeAlertEmail(toEmail, details) {
  const htmlContent = `
    <div dir="rtl" style="font-family: 'Segoe UI', Tahoma, Arial, sans-serif; max-width: 500px; margin: 0 auto; padding: 30px; background: #fce4ec; border-radius: 15px;">
      <div style="background: white; padding: 30px; border-radius: 10px;">
        <h2 style="color: #c62828; text-align: center;">🚨 تنبيه أمني: تغيير موقع مفاجئ</h2>
        <p style="color: #333;">تم تسجيل دخول من دولة مختلفة:</p>
        <ul style="color: #555; line-height: 2;">
          <li><strong>الدولة السابقة:</strong> ${details.previousCountry}</li>
          <li><strong>الدولة الحالية:</strong> ${details.currentCountry}</li>
          <li><strong>IP:</strong> ${details.ip}</li>
        </ul>
        <p style="color: #d32f2f;"><strong>إذا لم تكن أنت، غيّر كلمة السر فوراً!</strong></p>
      </div>
    </div>
  `;

  await transporter.sendMail({
    from: `"Secure Login" <${env.EMAIL_FROM}>`,
    to: toEmail,
    subject: '🚨 تنبيه: تسجيل دخول من دولة مختلفة',
    html: htmlContent
  });
}

/**
 * إرسال تنبيه محاولات فاشلة كثيرة
 */
async function sendFailedAttemptsAlertEmail(toEmail, count, ip) {
  const htmlContent = `
    <div dir="rtl" style="font-family: 'Segoe UI', Tahoma, Arial, sans-serif; max-width: 500px; margin: 0 auto; padding: 30px; background: #fce4ec; border-radius: 15px;">
      <div style="background: white; padding: 30px; border-radius: 10px;">
        <h2 style="color: #c62828; text-align: center;">🚨 محاولات تسجيل دخول فاشلة</h2>
        <p style="color: #333;">تم رصد <strong>${count}</strong> محاولة تسجيل دخول فاشلة على حسابك.</p>
        <p style="color: #555;">من عنوان IP: <strong>${ip}</strong></p>
        <p style="color: #d32f2f;"><strong>إذا لم تكن أنت، قم بتغيير كلمة السر فوراً.</strong></p>
      </div>
    </div>
  `;

  await transporter.sendMail({
    from: `"Secure Login" <${env.EMAIL_FROM}>`,
    to: toEmail,
    subject: '🚨 محاولات تسجيل دخول فاشلة على حسابك',
    html: htmlContent
  });
}

/**
 * إرسال تنبيه تغيير كلمة السر
 */
async function sendPasswordChangedEmail(toEmail) {
  const htmlContent = `
    <div dir="rtl" style="font-family: 'Segoe UI', Tahoma, Arial, sans-serif; max-width: 500px; margin: 0 auto; padding: 30px; background: #e8f5e9; border-radius: 15px;">
      <div style="background: white; padding: 30px; border-radius: 10px;">
        <h2 style="color: #2e7d32; text-align: center;">✅ تم تغيير كلمة السر</h2>
        <p style="color: #333;">تم تغيير كلمة السر الخاصة بحسابك بنجاح.</p>
        <p style="color: #333;">التاريخ: ${new Date().toLocaleString('ar-DZ')}</p>
        <p style="color: #d32f2f;">إذا لم تقم بهذا التغيير، تواصل مع الدعم فوراً.</p>
      </div>
    </div>
  `;

  await transporter.sendMail({
    from: `"Secure Login" <${env.EMAIL_FROM}>`,
    to: toEmail,
    subject: '✅ تم تغيير كلمة السر بنجاح',
    html: htmlContent
  });
}

/**
 * إرسال رمز تحقق إضافي (عند نشاط مشبوه)
 */
async function sendVerificationCodeEmail(toEmail, code) {
  const htmlContent = `
    <div dir="rtl" style="font-family: 'Segoe UI', Tahoma, Arial, sans-serif; max-width: 500px; margin: 0 auto; padding: 30px; background: #fff3e0; border-radius: 15px;">
      <div style="background: white; padding: 30px; border-radius: 10px;">
        <h2 style="color: #e65100; text-align: center;">🔐 رمز التحقق الإضافي</h2>
        <p style="color: #333;">تم رصد نشاط غير معتاد. يرجى إدخال الرمز التالي للمتابعة:</p>
        <div style="background: #fff8e1; padding: 20px; border-radius: 10px; text-align: center; margin: 20px 0;">
          <span style="font-size: 36px; font-weight: bold; color: #e65100; letter-spacing: 10px;">${code}</span>
        </div>
        <p style="color: #666;">⏱️ الرمز صالح لمدة <strong>5 دقائق</strong>.</p>
      </div>
    </div>
  `;

  await transporter.sendMail({
    from: `"Secure Login" <${env.EMAIL_FROM}>`,
    to: toEmail,
    subject: '🔐 رمز تحقق إضافي مطلوب',
    html: htmlContent
  });
}

module.exports = {
  sendPasswordResetEmail,
  sendLoginAlertEmail,
  sendNewDeviceAlertEmail,
  sendCountryChangeAlertEmail,
  sendFailedAttemptsAlertEmail,
  sendPasswordChangedEmail,
  sendVerificationCodeEmail
};
