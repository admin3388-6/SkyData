// utils/validators.js
const validator = require('validator');
const Filter = require('bad-words');
const filter = new Filter();

// إضافة كلمات بذيئة إضافية إذا أردت
// filter.addWords('word1', 'word2');

function validateEmail(email) {
  if (!email || typeof email !== 'string') {
    return { valid: false, message: 'البريد الإلكتروني مطلوب' };
  }
  email = email.trim().toLowerCase();
  if (!validator.isEmail(email)) {
    return { valid: false, message: 'صيغة البريد الإلكتروني غير صحيحة' };
  }
  if (email.length > 255) {
    return { valid: false, message: 'البريد الإلكتروني طويل جداً' };
  }
  return { valid: true, email };
}

function validateUsername(username) {
  if (!username || typeof username !== 'string') {
    return { valid: false, message: 'اسم المستخدم مطلوب' };
  }
  username = username.trim();

  if (username.length < 3 || username.length > 20) {
    return { valid: false, message: 'اسم المستخدم يجب أن يكون بين 3 و 20 حرفاً' };
  }
  if (!/^[a-zA-Z0-9]+$/.test(username)) {
    return { valid: false, message: 'اسم المستخدم يجب أن يحتوي على حروف إنجليزية وأرقام فقط' };
  }
  if (filter.isProfane(username)) {
    return { valid: false, message: 'اسم المستخدم يحتوي على كلمات غير مسموح بها' };
  }
  return { valid: true, username };
}

function validatePassword(password) {
  if (!password || typeof password !== 'string') {
    return { valid: false, message: 'كلمة السر مطلوبة' };
  }
  if (password.length < 6 || password.length > 25) {
    return { valid: false, message: 'كلمة السر يجب أن تكون بين 6 و 25 حرفاً' };
  }
  // يجب أن تحتوي على رقم واحد على الأقل أو رمز واحد
  const hasNumberOrSymbol = /[0-9]/.test(password) || /[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password);
  if (!hasNumberOrSymbol) {
    return { valid: false, message: 'كلمة السر يجب أن تحتوي على رقم واحد على الأقل أو رمز خاص' };
  }
  return { valid: true };
}

module.exports = { validateEmail, validateUsername, validatePassword };
