// js/auth.js
// منطق المصادقة الرئيسي

const API_BASE = 'https://slime-secure-api.onrender.com'; // سيتم تحديثه

const Auth = {
  forgotEmail: '',
  resetToken: '',

  // ============================================
  // إظهار/إخفاء الأقسام
  // ============================================
  showSection(sectionId) {
    document.querySelectorAll('.form-section').forEach(sec => sec.classList.remove('active'));
    document.getElementById(sectionId).classList.add('active');
  },

  // ============================================
  // إشعارات
  // ============================================
  showToast(message, type = 'info') {
    const container = document.getElementById('toastContainer');
    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    const icons = { success: '✅', error: '❌', warning: '⚠️', info: 'ℹ️' };
    toast.innerHTML = `<span>${icons[type] || ''}</span><span>${message}</span>`;
    container.appendChild(toast);
    setTimeout(() => {
      toast.style.opacity = '0';
      toast.style.transform = 'translateY(-20px)';
      setTimeout(() => toast.remove(), 300);
    }, 4000);
  },

  // ============================================
  // تفعيل/تعطيل زر مع حالة تحميل
  // ============================================
  setLoading(btnId, loading) {
    const btn = document.getElementById(btnId);
    if (loading) {
      btn.classList.add('loading');
      btn.disabled = true;
    } else {
      btn.classList.remove('loading');
      btn.disabled = false;
    }
  },

  // ============================================
  // عرض خطأ الحقل
  // ============================================
  showFieldError(fieldId, message) {
    const errorEl = document.getElementById(fieldId);
    errorEl.textContent = message;
    errorEl.classList.add('visible');
  },

  clearFieldErrors() {
    document.querySelectorAll('.error-text').forEach(el => {
      el.textContent = '';
      el.classList.remove('visible');
    });
    document.querySelectorAll('input.error').forEach(el => el.classList.remove('error'));
  },

  // ============================================
  // تحقق أساسي من المدخلات (client-side)
  // ============================================
  validateEmailClient(email) {
    const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return re.test(email);
  },

  validateUsernameClient(username) {
    return /^[a-zA-Z0-9]{3,20}$/.test(username);
  },

  validatePasswordClient(password) {
    if (password.length < 6 || password.length > 25) return false;
    return /[0-9!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password);
  },

  // ============================================
  // تسجيل الدخول عبر Google
  // ============================================
  async handleGoogleLogin(response) {
    try {
      const fingerprint = await DeviceFingerprint.collect();

      const res = await fetch(`${API_BASE}/auth/google`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({
          credential: response.credential,
          fingerprint
        })
      });

      const data = await res.json();

      if (data.success) {
        Auth.showToast('تم تسجيل الدخول بنجاح!', 'success');
        setTimeout(() => {
          window.location.href = data.redirect || '/home.html';
        }, 1000);
      } else {
        Auth.showToast(data.message || 'فشل تسجيل الدخول', 'error');
      }
    } catch (error) {
      Auth.showToast('خطأ في الاتصال بالخادم', 'error');
      console.error('[AUTH] Google login error:', error);
    }
  },

  // ============================================
  // تسجيل الدخول بالبريد
  // ============================================
  async handleEmailLogin(e) {
    e.preventDefault();
    Auth.clearFieldErrors();

    const email = document.getElementById('loginEmail').value.trim();
    const password = document.getElementById('loginPassword').value;
    const honeypot = document.getElementById('hpLogin').value;
    const recaptchaToken = grecaptcha.getResponse(Auth.recaptchaLoginWidget);

    // تحقق client-side
    if (!Auth.validateEmailClient(email)) {
      Auth.showFieldError('loginEmailError', 'صيغة البريد غير صحيحة');
      return;
    }
    if (!password) {
      Auth.showFieldError('loginPasswordError', 'كلمة السر مطلوبة');
      return;
    }
    if (!recaptchaToken) {
      Auth.showToast('يرجى إكمال التحقق من reCAPTCHA', 'warning');
      return;
    }

    Auth.setLoading('loginSubmitBtn', true);

    try {
      const fingerprint = await DeviceFingerprint.collect();
      const encryptedData = SecureCrypto.encrypt({
        email,
        password,
        _hp_field: honeypot
      });

      const res = await fetch(`${API_BASE}/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({ encryptedData, recaptchaToken, fingerprint })
      });

      const data = await res.json();

      if (data.success) {
        Auth.showToast('تم تسجيل الدخول بنجاح!', 'success');
        setTimeout(() => {
          window.location.href = data.redirect || '/home.html';
        }, 1000);
      } else {
        Auth.showToast(data.message, 'error');
        grecaptcha.reset(Auth.recaptchaLoginWidget);
      }
    } catch (error) {
      Auth.showToast('خطأ في الاتصال بالخادم', 'error');
    } finally {
      Auth.setLoading('loginSubmitBtn', false);
    }
  },

  // ============================================
  // إنشاء حساب جديد
  // ============================================
  async handleRegister(e) {
    e.preventDefault();
    Auth.clearFieldErrors();

    const username = document.getElementById('regUsername').value.trim();
    const email = document.getElementById('regEmail').value.trim();
    const password = document.getElementById('regPassword').value;
    const terms = document.getElementById('regTerms').checked;
    const honeypot = document.getElementById('hpRegister').value;
    const recaptchaToken = grecaptcha.getResponse(Auth.recaptchaRegisterWidget);

    // تحقق client-side
    if (!Auth.validateUsernameClient(username)) {
      Auth.showFieldError('regUsernameError', 'اسم المستخدم: حروف إنجليزية وأرقام فقط (3-20)');
      return;
    }
    if (!Auth.validateEmailClient(email)) {
      Auth.showFieldError('regEmailError', 'صيغة البريد غير صحيحة');
      return;
    }
    if (!Auth.validatePasswordClient(password)) {
      Auth.showFieldError('regPasswordError', 'كلمة السر: 6-25 حرف، مع رقم أو رمز واحد على الأقل');
      return;
    }
    if (!terms) {
      Auth.showToast('يجب الموافقة على شروط الاستخدام', 'warning');
      return;
    }
    if (!recaptchaToken) {
      Auth.showToast('يرجى إكمال التحقق من reCAPTCHA', 'warning');
      return;
    }

    Auth.setLoading('registerSubmitBtn', true);

    try {
      const fingerprint = await DeviceFingerprint.collect();
      const encryptedData = SecureCrypto.encrypt({
        username,
        email,
        password,
        _hp_field: honeypot
      });

      const res = await fetch(`${API_BASE}/auth/register`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({ encryptedData, recaptchaToken, fingerprint })
      });

      const data = await res.json();

      if (data.success) {
        Auth.showToast('تم إنشاء الحساب بنجاح!', 'success');
        setTimeout(() => {
          window.location.href = data.redirect || '/home.html';
        }, 1000);
      } else {
        Auth.showToast(data.message, 'error');
        grecaptcha.reset(Auth.recaptchaRegisterWidget);
      }
    } catch (error) {
      Auth.showToast('خطأ في الاتصال بالخادم', 'error');
    } finally {
      Auth.setLoading('registerSubmitBtn', false);
    }
  },

  // ============================================
  // طلب إعادة تعيين كلمة السر
  // ============================================
  async handleForgotPassword() {
    Auth.clearFieldErrors();
    const email = document.getElementById('forgotEmail').value.trim();
    const recaptchaToken = grecaptcha.getResponse(Auth.recaptchaForgotWidget);

    if (!Auth.validateEmailClient(email)) {
      Auth.showFieldError('forgotEmailError', 'صيغة البريد غير صحيحة');
      return;
    }
    if (!recaptchaToken) {
      Auth.showToast('يرجى إكمال التحقق من reCAPTCHA', 'warning');
      return;
    }

    Auth.setLoading('sendResetCodeBtn', true);

    try {
      const encryptedData = SecureCrypto.encrypt({ email });

      const res = await fetch(`${API_BASE}/password/request-reset`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ encryptedData, recaptchaToken })
      });

      const data = await res.json();

      if (data.success) {
        Auth.forgotEmail = email;
        Auth.showToast(data.message, 'success');
        document.getElementById('forgotStep1').style.display = 'none';
        document.getElementById('forgotStep2').style.display = 'block';
        document.querySelector('#codeInputs input[data-index="0"]').focus();
      } else {
        Auth.showToast(data.message, 'error');
      }
    } catch (error) {
      Auth.showToast('خطأ في الاتصال بالخادم', 'error');
    } finally {
      Auth.setLoading('sendResetCodeBtn', false);
    }
  },

  // ============================================
  // التحقق من الرمز
  // ============================================
  async handleVerifyCode() {
    const inputs = document.querySelectorAll('#codeInputs input');
    let code = '';
    inputs.forEach(input => { code += input.value; });

    if (code.length !== 6 || !/^\d{6}$/.test(code)) {
      Auth.showFieldError('codeError', 'أدخل رمزاً مكوناً من 6 أرقام');
      document.getElementById('codeError').classList.add('visible');
      return;
    }

    Auth.setLoading('verifyCodeBtn', true);

    try {
      const encryptedData = SecureCrypto.encrypt({
        email: Auth.forgotEmail,
        code
      });

      const res = await fetch(`${API_BASE}/password/verify-code`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ encryptedData })
      });

      const data = await res.json();

      if (data.success) {
        Auth.resetToken = data.resetToken;
        Auth.showToast('الرمز صحيح!', 'success');
        document.getElementById('forgotStep2').style.display = 'none';
        document.getElementById('forgotStep3').style.display = 'block';
      } else {
        Auth.showToast(data.message, 'error');
      }
    } catch (error) {
      Auth.showToast('خطأ في الاتصال بالخادم', 'error');
    } finally {
      Auth.setLoading('verifyCodeBtn', false);
    }
  },

  // ============================================
  // تغيير كلمة السر
  // ============================================
  async handleResetPassword() {
    Auth.clearFieldErrors();
    const newPassword = document.getElementById('newPassword').value;
    const confirmPassword = document.getElementById('confirmNewPassword').value;

    if (!Auth.validatePasswordClient(newPassword)) {
      Auth.showFieldError('newPasswordError', 'كلمة السر: 6-25 حرف، مع رقم أو رمز');
      return;
    }
    if (newPassword !== confirmPassword) {
      Auth.showFieldError('confirmPasswordError', 'كلمة السر وتأكيدها غير متطابقين');
      return;
    }

    Auth.setLoading('resetPasswordBtn', true);

    try {
      const encryptedData = SecureCrypto.encrypt({
        email: Auth.forgotEmail,
        newPassword,
        confirmPassword,
        resetToken: Auth.resetToken
      });

      const res = await fetch(`${API_BASE}/password/reset`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ encryptedData })
      });

      const data = await res.json();

      if (data.success) {
        Auth.showToast('تم تغيير كلمة السر بنجاح!', 'success');
        // إغلاق النافذة والعودة لشاشة تسجيل الدخول
        document.getElementById('forgotPasswordModal').classList.remove('active');
        Auth.resetForgotModal();
        Auth.showSection('loginScreen');
      } else {
        Auth.showToast(data.message, 'error');
      }
    } catch (error) {
      Auth.showToast('خطأ في الاتصال بالخادم', 'error');
    } finally {
      Auth.setLoading('resetPasswordBtn', false);
    }
  },

  resetForgotModal() {
    document.getElementById('forgotStep1').style.display = 'block';
    document.getElementById('forgotStep2').style.display = 'none';
    document.getElementById('forgotStep3').style.display = 'none';
    document.getElementById('forgotEmail').value = '';
    document.querySelectorAll('#codeInputs input').forEach(i => { i.value = ''; });
    document.getElementById('newPassword').value = '';
    document.getElementById('confirmNewPassword').value = '';
    Auth.forgotEmail = '';
    Auth.resetToken = '';
  },

  // ============================================
  // تهيئة reCAPTCHA
  // ============================================
  recaptchaLoginWidget: null,
  recaptchaRegisterWidget: null,
  recaptchaForgotWidget: null
};
