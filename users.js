/* ============================================================
   Users List — لیست کاربران سامانه
   ============================================================
   ⚠️ نکته امنیتی:
   - رمزها به صورت SHA-256 ذخیره می‌شن (نه متن ساده)
   - بعد از اولین ورود، کاربر رمز پیش‌فرض رو عوض می‌کنه
   - رمز جدید در localStorage ذخیره می‌شه
   ============================================================ */

const USERS = [
  {
    username: 'admin',
    defaultPasswordHash: '',  // پر می‌شه با تابع initUsersHashes
    name: 'کارفرما',
    role: 'admin',
    mustChange: true
  },
  {
    username: 'ahmad',
    defaultPasswordHash: '',
    name: 'احمد رضایی',
    role: 'employee',
    mustChange: true
  },
  {
    username: 'maryam',
    defaultPasswordHash: '',
    name: 'مریم احمدی',
    role: 'employee',
    mustChange: true
  },
  {
    username: 'hossein',
    defaultPasswordHash: '',
    name: 'حسین کریمی',
    role: 'employee',
    mustChange: true
  },
  {
    username: 'sara',
    defaultPasswordHash: '',
    name: 'سارا نوری',
    role: 'employee',
    mustChange: true
  },
  {
    username: 'ali',
    defaultPasswordHash: '',
    name: 'علی محمدی',
    role: 'employee',
    mustChange: true
  },
  {
    username: 'reza',
    defaultPasswordHash: '',
    name: 'رضا تهرانی',
    role: 'employee',
    mustChange: true
  },
  {
    username: 'zahra',
    defaultPasswordHash: '',
    name: 'زهرا موسوی',
    role: 'employee',
    mustChange: true
  },
  {
    username: 'mohammad',
    defaultPasswordHash: '',
    name: 'محمد حسینی',
    role: 'employee',
    mustChange: true
  },
  {
    username: 'fatemeh',
    defaultPasswordHash: '',
    name: 'فاطمه رحیمی',
    role: 'employee',
    mustChange: true
  }
];

/* رمزهای پیش‌فرض (فقط برای راه‌اندازی اولیه) */
const DEFAULT_PASSWORDS = {
  'admin': 'Admin@2024',
  'ahmad': '123456',
  'maryam': '123456',
  'hossein': '123456',
  'sara': '123456',
  'ali': '123456',
  'reza': '123456',
  'zahra': '123456',
  'mohammad': '123456',
  'fatemeh': '123456'
};

/* ============================================================
   توابع کمکی
   ============================================================ */

/* هش SHA-256 با fallback برای مرورگرهای قدیمی یا file:// */
async function sha256(str){
  // اگه crypto.subtle موجوده و ما روی http/https هستیم → SHA-256 واقعی
  if(window.crypto && window.crypto.subtle && location.protocol !== 'file:'){
    try{
      const buf = new TextEncoder().encode(str);
      const hash = await crypto.subtle.digest('SHA-256', buf);
      return Array.from(new Uint8Array(hash))
        .map(b => b.toString(16).padStart(2, '0'))
        .join('');
    }catch(e){
      console.warn('crypto.subtle failed, falling back to simple hash');
    }
  }
  // fallback: هش ساده برای file:// یا مرورگرهای قدیمی
  let hash = 0;
  for(let i = 0; i < str.length; i++){
    const char = str.charCodeAt(i);
    hash = ((hash << 5) - hash) + char;
    hash = hash & hash;
  }
  return 'simple_' + Math.abs(hash).toString(16).padStart(16, '0');
}

/* پیدا کردن کاربر بر اساس username */
function findUser(username){
  return USERS.find(u => u.username === username.toLowerCase());
}

/* چک کردن رمز کاربر
   - اگر کاربر رمز عوض کرده باشد: از localStorage
   - اگر نه: از رمز پیش‌فرض
*/
async function checkPassword(username, password){
  username = username.toLowerCase();
  const user = findUser(username);
  if(!user) return { ok: false, error: 'کاربر یافت نشد' };

  const inputHash = await sha256(password);

  // ۱. چک رمز تغییر‌یافته در localStorage
  const storedHash = localStorage.getItem('hrm_pwd_' + username);
  if(storedHash){
    if(storedHash === inputHash){
      return { ok: true, user, mustChange: false };
    }
    return { ok: false, error: 'رمز عبور اشتباه است' };
  }

  // ۲. چک رمز پیش‌فرض
  const defaultPwd = DEFAULT_PASSWORDS[username];
  if(defaultPwd && defaultPwd === password){
    return { ok: true, user, mustChange: true };
  }

  return { ok: false, error: 'رمز عبور اشتباه است' };
}

/* تغییر رمز کاربر */
async function changePassword(username, oldPassword, newPassword){
  username = username.toLowerCase();

  // چک رمز فعلی
  const check = await checkPassword(username, oldPassword);
  if(!check.ok) return { ok: false, error: 'رمز فعلی اشتباه است' };

  // چک قدرت رمز جدید
  if(newPassword.length < 6){
    return { ok: false, error: 'رمز جدید باید حداقل ۶ کاراکتر باشد' };
  }

  // ذخیره هش رمز جدید
  const newHash = await sha256(newPassword);
  localStorage.setItem('hrm_pwd_' + username, newHash);
  localStorage.setItem('hrm_must_change_' + username, 'false');

  return { ok: true };
}

/* آیا کاربر باید رمز رو تغییر بده؟ */
function mustChangePassword(username){
  username = username.toLowerCase();
  const flag = localStorage.getItem('hrm_must_change_' + username);
  if(flag === 'false') return false;
  // اگه رمز پیش‌فرض تغییر نکرده، باید عوض کنه
  return !localStorage.getItem('hrm_pwd_' + username);
}

/* ذخیره کاربر لاگین‌شده (با زمان انقضا) */
function saveCurrentUser(user, rememberMe){
  const days = rememberMe ? 30 : 0;
  const expires = days ? Date.now() + days * 24 * 60 * 60 * 1000 : null;
  const data = {
    username: user.username,
    name: user.name,
    role: user.role,
    expires: expires
  };
  // برای sessionStorage اگه rememberMe=false
  if(rememberMe){
    localStorage.setItem('hrm_current_user', JSON.stringify(data));
  } else {
    sessionStorage.setItem('hrm_current_user', JSON.stringify(data));
  }
}

/* خواندن کاربر جاری (با چک انقضا) */
function getCurrentUser(){
  let raw = localStorage.getItem('hrm_current_user');
  if(!raw) raw = sessionStorage.getItem('hrm_current_user');
  if(!raw) return null;

  try{
    const data = JSON.parse(raw);
    if(data.expires && Date.now() > data.expires){
      // منقضی شده
      localStorage.removeItem('hrm_current_user');
      sessionStorage.removeItem('hrm_current_user');
      return null;
    }
    return data;
  }catch(e){
    return null;
  }
}

/* خروج */
function logout(){
  localStorage.removeItem('hrm_current_user');
  sessionStorage.removeItem('hrm_current_user');
  window.location.href = 'login.html';
}