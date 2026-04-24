// js/app.js
// التهيئة وربط الأحداث

document.addEventListener('DOMContentLoaded', () => {
  // ============================================
  // تهيئة الموافقة
  // ============================================
  ConsentManager.init();

  // ============================================
  // التنقل بين الشاشات
  // ============================================
  document.getElementById('emailLoginBtn').addEventListener('click', () => {
    Auth.showSection('loginScreen');
  });

  document.getElementById('showRegister').addEventListener('click', () => {
    Auth.showSection('registerScreen');
  });

  document.getElementById('backToMainFromLogin').addEventListener('click', () => {
    Auth.showSection('mainScreen');
  });

  document.getElementById('backToLoginFromRegister').addEventListener('click', () => {
    Auth.showSection('loginScreen');
  });

  // ============================================
  // نسيت كلمة السر
  // ============================================
  document.getElementById('showForgotPassword').addEventListener('click', () => {
    Auth.resetForgotModal();
    document.getElementById('forgotPasswordModal').classList.add('active');
  });

  document.getElementById('closeForgotModal').addEventListener('click', () => {
    document.getElementById('forgotPasswordModal').classList.remove('active');
  });

  document.getElementById('closeForgotStep2').addEventListener('click', () => {
    document.getElementById('forgotPasswordModal').classList.remove('active');
  });

  document.getElementById('closeForgotStep3').addEventListener('click', () => {
    document.getElementById('forgotPasswordModal').classList.remove('active');
  });

  document.getElementById('sendResetCodeBtn').addEventListener('click', () => {
    Auth.handleForgotPassword();
  });

  document.getElementById('verifyCodeBtn').addEventListener('click', () => {
    Auth.handleVerifyCode();
  });

  document.getElementById('resetPasswordBtn').addEventListener('click', () => {
    Auth.handleResetPassword();
  });

  document.getElementById('resendCodeBtn').addEventListener('click', () => {
    document.getElementById('forgotStep2').style.display = 'none';
    document.getElementById('forgotStep1').style.display = 'block';
    Auth.showToast('يمكنك إعادة إرسال الرمز الآن', 'info');
  });

  // ============================================
  // إدارة مربعات إدخال الرمز
  // ============================================
  const codeInputs = document.querySelectorAll('#codeInputs input');
  codeInputs.forEach((input, index) => {
    input.addEventListener('input', (e) => {
      const value = e.target.value;
      // السماح بالأرقام فقط
      if (!/^\d$/.test(value)) {
        e.target.value = '';
        return;
      }
      // الانتقال للحقل التالي
      if (value && index < 5) {
        codeInputs[index + 1].focus();
      }
      // التحقق التلقائي عند اكتمال الرمز
      if (index === 5 && value) {
        let code = '';
        codeInputs.forEach(i => { code += i.value; });
        if (code.length === 6) {
          Auth.handleVerifyCode();
        }
      }
    });

    input.addEventListener('keydown', (e) => {
      if (e.key === 'Backspace' && !e.target.value && index > 0) {
        codeInputs[index - 1].focus();
      }
    });

    // لصق الرمز كاملاً
    input.addEventListener('paste', (e) => {
      e.preventDefault();
      const pastedData = e.clipboardData.getData('text').replace(/\D/g, '').substring(0, 6);
      if (pastedData.length === 6) {
        pastedData.split('').forEach((char, i) => {
          codeInputs[i].value = char;
        });
        codeInputs[5].focus();
      }
    });
  });

  // ============================================
  // إرسال النماذج
  // ============================================
  document.getElementById('loginForm').addEventListener('submit', Auth.handleEmailLogin);
  document.getElementById('registerForm').addEventListener('submit', Auth.handleRegister);

  // ============================================
  // تسجيل الدخول عبر Google
  // ============================================
  document.getElementById('googleLoginBtn').addEventListener('click', () => {
    // تشغيل Google One Tap أو نافذة Google
    google.accounts.id.initialize({
      client_id: 'YOUR_GOOGLE_CLIENT_ID',
      callback: Auth.handleGoogleLogin,
      auto_select: false
    });
    google.accounts.id.prompt();
  });
});

// ============================================
// تهيئة reCAPTCHA بعد تحميل السكريبت
// ============================================
function onRecaptchaLoad() {
  // نعرّف widgets فقط عند الحاجة
  // reCAPTCHA سيتم تحميلها implicit مع الأزرار
}

// Explicit rendering عند فتح الشاشات
const recaptchaObserver = new MutationObserver(() => {
  const loginScreen = document.getElementById('loginScreen');
  const registerScreen = document.getElementById('registerScreen');

  if (loginScreen.classList.contains('active') && !Auth.recaptchaLoginWidget && typeof grecaptcha !== 'undefined') {
    try {
      Auth.recaptchaLoginWidget = grecaptcha.render('recaptchaLogin', {
        sitekey: '6Ld5bscsAAAAAP_VbULxbxR4YLNwZVCyaZGn7Yky'
      });
    } catch (e) { /* already rendered */ }
  }

  if (registerScreen.classList.contains('active') && !Auth.recaptchaRegisterWidget && typeof grecaptcha !== 'undefined') {
    try {
      Auth.recaptchaRegisterWidget = grecaptcha.render('recaptchaRegister', {
        sitekey: '6Ld5bscsAAAAAP_VbULxbxR4YLNwZVCyaZGn7Yky'
      });
    } catch (e) { /* already rendered */ }
  }
});

recaptchaObserver.observe(document.querySelector('.auth-card'), {
  childList: true,
  subtree: true,
  attributes: true,
  attributeFilter: ['class']
});
