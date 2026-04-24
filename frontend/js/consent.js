// js/consent.js
// إدارة الموافقة على الكوكيز والشروط

const ConsentManager = {
  init() {
    const hasConsented = localStorage.getItem('cookieConsent');
    if (!hasConsented) {
      document.getElementById('consentOverlay').classList.add('active');
    }

    const acceptTermsCheckbox = document.getElementById('acceptTerms');
    const acceptBtn = document.getElementById('acceptConsentBtn');

    acceptTermsCheckbox.addEventListener('change', () => {
      acceptBtn.disabled = !acceptTermsCheckbox.checked;
    });

    acceptBtn.addEventListener('click', () => {
      if (acceptTermsCheckbox.checked) {
        localStorage.setItem('cookieConsent', 'true');
        localStorage.setItem('termsAccepted', 'true');
        localStorage.setItem('consentDate', new Date().toISOString());
        document.getElementById('consentOverlay').classList.remove('active');
      }
    });
  }
};
