/* Medibot core: storage, settings, password hashing, accounts (Firebase Authentication, or demo mode). */
(function () {
  "use strict";
  var MB = (window.MB = window.MB || {});
  var CFG = window.MB_CONFIG || {};

  // ---------- storage ----------
  // Everything is kept in the phone's own storage. In the Android app every write is ALSO saved to
  // Android's permanent app storage (Capacitor Preferences = SharedPreferences), so accounts survive
  // app restarts, logouts, WebView cache clearing and app updates. On PC / browser localStorage is used.
  function nativeStore() {
    var C = window.Capacitor;
    return C && C.isNativePlatform && C.isNativePlatform() && C.Plugins && C.Plugins.Preferences || null;
  }
  function load(key, fallback) {
    try { var v = localStorage.getItem(key); return v ? JSON.parse(v) : fallback; } catch (e) { return fallback; }
  }
  function save(key, value) {
    var text = JSON.stringify(value);
    try { localStorage.setItem(key, text); } catch (e) { console.warn("storage full?", e); }
    var n = nativeStore(); if (n) n.set({ key: key, value: text }).catch(function () {});
  }
  function remove(key) {
    try { localStorage.removeItem(key); } catch (e) {}
    var n = nativeStore(); if (n) n.remove({ key: key }).catch(function () {});
  }
  MB.load = load; MB.save = save; MB.remove = remove;
  /** Call once at start-up: copies the permanent phone storage back into the app (Android only). */
  MB.restoreStorage = function () {
    var n = nativeStore();
    if (!n) return Promise.resolve();
    var done = n.keys().then(function (r) {
      return Promise.all((r.keys || []).filter(function (k) { return k.indexOf("mb_") === 0; }).map(function (k) {
        return n.get({ key: k }).then(function (g) { if (g && g.value != null) try { localStorage.setItem(k, g.value); } catch (e) {} });
      })).then(function () {
        // First run after updating from an older version: copy what is already in localStorage to permanent storage.
        for (var i = 0; i < localStorage.length; i++) {
          var k = localStorage.key(i);
          if (k && k.indexOf("mb_") === 0 && (r.keys || []).indexOf(k) < 0) n.set({ key: k, value: localStorage.getItem(k) }).catch(function () {});
        }
      });
    }).catch(function () {});
    var timeout = new Promise(function (ok) { setTimeout(ok, 2500); });
    return Promise.race([done, timeout]);
  };

  // ---------- settings ----------
  var DEFAULT_SETTINGS = {
    mode: "auto",                       // auto = use internet when available, offline = never
    groqKey: CFG.groqApiKey || "",
    groqModel: CFG.groqModel || "",
    ollamaUrl: CFG.ollamaUrl || "",
    ollamaModel: CFG.ollamaModel || "llama3.2:3b",
    firebaseApiKey: CFG.firebaseApiKey || "",      // Firebase project > Project settings > Web API key
    countryCode: CFG.defaultCountryCode || "+91",
    showOtpOnScreen: true,          // demo mode (no Firebase key / offline): show the code on screen
    theme: "auto"
  };
  MB.settings = function () { return Object.assign({}, DEFAULT_SETTINGS, load("mb_settings", {})); };
  MB.saveSettings = function (s) { save("mb_settings", s); };
  MB.validEmail = function (e) { return /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(String(e || "").trim()); };
  MB.maskEmail = function (e) {
    var m = String(e || "").match(/^(.)(.*)(@.*)$/); return m ? m[1] + "*".repeat(Math.min(m[2].length, 6)) + m[3] : e;
  };
  MB.applyTheme = function () {
    var t = MB.settings().theme;
    if (t === "light" || t === "dark") document.documentElement.setAttribute("data-theme", t);
    else document.documentElement.removeAttribute("data-theme");
  };
  MB.isOnline = function () { return MB.settings().mode !== "offline" && navigator.onLine !== false; };

  // ---------- helpers ----------
  MB.now = function () { return Date.now(); };
  MB.escape = function (s) {
    return String(s == null ? "" : s).replace(/[&<>"']/g, function (c) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c];
    });
  };
  MB.nl2br = function (s) { return MB.escape(s).replace(/\n/g, "<br>"); };

  MB.normalizePhone = function (raw) {
    var n = String(raw || "").trim().replace(/[\s\-().]/g, "");
    if (!n) throw new Error("Please enter your mobile number.");
    if (n.indexOf("00") === 0) n = "+" + n.slice(2);
    if (n[0] !== "+") n = MB.settings().countryCode + n.replace(/^0+/, "");
    if (!/^\+[1-9]\d{7,14}$/.test(n)) throw new Error("Please enter a valid mobile number, e.g. 9876543210.");
    return n;
  };
  MB.maskPhone = function (p) { return p.length <= 6 ? p : p.slice(0, 3) + "*".repeat(p.length - 7) + p.slice(-4); };

  MB.passwordProblems = function (pw) {
    var out = [];
    if (pw.length < 8) out.push("at least 8 characters");
    if (!/[A-Za-z]/.test(pw)) out.push("a letter");
    if (!/\d/.test(pw)) out.push("a number");
    return out;
  };

  function hex(buf) {
    return Array.prototype.map.call(new Uint8Array(buf), function (b) { return ("0" + b.toString(16)).slice(-2); }).join("");
  }
  function randomHex(bytes) {
    var a = new Uint8Array(bytes); crypto.getRandomValues(a); return hex(a.buffer);
  }
  /** Phone keyboards sometimes add a space after a word; ignore spaces at the start or end. */
  MB.cleanPassword = function (pw) { return String(pw || "").replace(/^\s+|\s+$/g, ""); };
  MB.hashPassword = function (password, saltHex) { return derive(MB.cleanPassword(password), saltHex); };
  function derive(password, saltHex) {
    if (!window.crypto || !crypto.subtle) return Promise.reject(new Error("Secure storage is not available in this browser."));
    var salt = saltHex || randomHex(16);
    var enc = new TextEncoder();
    return crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveBits"])
      .then(function (key) {
        return crypto.subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt: enc.encode(salt), iterations: 120000 }, key, 256);
      })
      .then(function (bits) { return { salt: salt, hash: hex(bits) }; });
  }
  MB.sha256 = function (text) {
    return crypto.subtle.digest("SHA-256", new TextEncoder().encode(text)).then(hex);
  };

  // ---------- accounts (stored on this device) ----------
  MB.users = function () { return load("mb_users", {}); };
  MB.saveUsers = function (u) { save("mb_users", u); };
  MB.currentUser = function () {
    var s = load("mb_session", null) || JSON.parse(sessionStorage.getItem("mb_session") || "null");
    if (!s || (s.expires && s.expires < MB.now())) return null;
    var u = MB.users()[s.phone];
    return u && u.verified ? Object.assign({ phone: s.phone }, u) : null;
  };
  MB.startSession = function (phone, remember) {
    var s = { phone: phone, expires: MB.now() + (remember ? 30 : 1) * 86400000 };
    if (remember) save("mb_session", s); else { remove("mb_session"); sessionStorage.setItem("mb_session", JSON.stringify(s)); }
  };
  MB.logout = function () { remove("mb_session"); sessionStorage.removeItem("mb_session"); };

  // ---------- Firebase Authentication (free Spark plan) ----------
  // Uses Firebase's REST API directly (no SDK), so the app stays small. The Web API key is a
  // public id, not a secret. Email/password accounts + Firebase's free email verification link.
  var FB = "https://identitytoolkit.googleapis.com/v1/accounts:";
  function fbErrorText(code) {
    code = String(code || "");
    if (/EMAIL_EXISTS/.test(code)) return "This email already has a Medibot account. Please log in (or use Forgot password).";
    if (/INVALID_LOGIN_CREDENTIALS|INVALID_PASSWORD|EMAIL_NOT_FOUND/.test(code)) return "Wrong email/mobile or password. Tap the eye to check what you typed, or use \"Forgot password\".";
    if (/USER_DISABLED/.test(code)) return "This account has been disabled.";
    if (/TOO_MANY_ATTEMPTS/.test(code)) return "Too many attempts. Please wait a few minutes and try again.";
    if (/WEAK_PASSWORD/.test(code)) return "Password is too weak. Use at least 8 characters with a letter and a number.";
    if (/INVALID_EMAIL/.test(code)) return "Please enter a valid email address.";
    if (/OPERATION_NOT_ALLOWED|PASSWORD_LOGIN_DISABLED/.test(code)) return "Email/Password sign-in is turned off. In Firebase console: Authentication > Sign-in method > Email/Password > Enable.";
    if (/API_KEY|API key not valid|CONFIGURATION_NOT_FOUND/.test(code)) return "The Firebase Web API key is wrong, or Authentication is not set up. Check Settings > Firebase (see readme).";
    if (/TOKEN_EXPIRED|INVALID_ID_TOKEN|INVALID_REFRESH_TOKEN|USER_NOT_FOUND/.test(code)) return "Your sign-in expired. Please log in again.";
    if (/QUOTA|LIMIT/.test(code)) return "Firebase daily email limit reached. Please try again tomorrow.";
    return "Firebase error: " + code;
  }
  function fbCall(path, body, base) {
    var key = MB.settings().firebaseApiKey.trim();
    return fetch((base || FB) + path + "?key=" + encodeURIComponent(key), {
      method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body), signal: withTimeout(20000)
    }).then(function (r) {
      return r.json().catch(function () { return {}; }).then(function (j) {
        if (!r.ok || j.error) { var e = new Error(fbErrorText(j.error && j.error.message || ("HTTP " + r.status))); e.code = j.error && j.error.message; throw e; }
        return j;
      });
    }, function (e) {
      throw new Error(e && e.name === "AbortError" ? "Firebase did not answer. Check the internet connection." : "No internet connection. Firebase needs internet.");
    });
  }
  MB.firebaseConfigured = function () { return !!MB.settings().firebaseApiKey.trim(); };
  /** Use Firebase when a key is set and the phone is online; otherwise the app works in demo/offline mode. */
  MB.useFirebase = function () { return MB.firebaseConfigured() && MB.isOnline(); };
  MB.fbSignUp = function (email, password, name) {
    return fbCall("signUp", { email: email, password: MB.cleanPassword(password), returnSecureToken: true }).then(function (r) {
      return fbCall("update", { idToken: r.idToken, displayName: name, returnSecureToken: false }).catch(function () {})
        .then(function () { return MB.fbSendVerify(r.idToken); })
        .then(function () { return { uid: r.localId, idToken: r.idToken, refreshToken: r.refreshToken }; });
    });
  };
  MB.fbSendVerify = function (idToken) { return fbCall("sendOobCode", { requestType: "VERIFY_EMAIL", idToken: idToken }); };
  MB.fbSignIn = function (email, password) {
    return fbCall("signInWithPassword", { email: email, password: password, returnSecureToken: true });
  };
  MB.fbRefresh = function (refreshToken) {
    return fbCall("token", { grant_type: "refresh_token", refresh_token: refreshToken }, "https://securetoken.googleapis.com/v1/")
      .then(function (r) { return { idToken: r.id_token, refreshToken: r.refresh_token }; });
  };
  /** Is the email verified yet? (refreshes the sign-in token if needed). Resolves {verified, idToken, refreshToken, name}. */
  MB.fbCheckVerified = function (tokens) {
    return MB.fbRefresh(tokens.refreshToken).then(function (t) {
      return fbCall("lookup", { idToken: t.idToken }).then(function (r) {
        var u = (r.users || [])[0] || {};
        return { verified: !!u.emailVerified, idToken: t.idToken, refreshToken: t.refreshToken, name: u.displayName || "" };
      });
    });
  };
  MB.fbResetPassword = function (email) { return fbCall("sendOobCode", { requestType: "PASSWORD_RESET", email: email }); };
  MB.fbTest = function (key) {
    var s = MB.settings(); s.firebaseApiKey = key; MB.saveSettings(s);
    return fbCall("signInWithPassword", { email: "connection-test@medibot.invalid", password: "test-password-1", returnSecureToken: true })
      .then(function () { return "ok"; }, function (e) {
        if (/EMAIL_NOT_FOUND|INVALID_LOGIN_CREDENTIALS|INVALID_PASSWORD|INVALID_EMAIL/.test(e.code || "")) return "ok";
        throw e;
      });
  };

  /** Find a saved account on this phone by mobile number or email. Returns [phoneKey, user] or null. */
  MB.findLocalUser = function (identifier) {
    var users = MB.users(), id = String(identifier || "").trim().toLowerCase();
    if (id.indexOf("@") > 0) {
      for (var k in users) if ((users[k].email || "").toLowerCase() === id) return [k, users[k]];
      return null;
    }
    try { var phone = MB.normalizePhone(identifier); return users[phone] ? [phone, users[phone]] : null; } catch (e) { return null; }
  };

  /** Log in with email or mobile number + password.
   *  Online with Firebase: checked by Firebase (works on any phone). Offline: checked against this phone's saved copy.
   *  Resolves {phone, user} or {needsProfile: {email, uid, name, refreshToken, salt, hash}}; rejects with .code "NOT_VERIFIED". */
  MB.login = function (identifier, password) {
    var found = MB.findLocalUser(identifier), id = String(identifier || "").trim();
    if (!MB.useFirebase() || (found && !found[1].uid)) {  // offline, demo mode, or an account made in demo mode
      if (!found) return Promise.reject(new Error(MB.firebaseConfigured() && !MB.isOnline() ?
        "You are offline. The first log in on this phone needs internet." : "No account with this mobile number or email on this phone. Please create an account first."));
      return localLogin(found[0], password).then(function (u) { return { phone: found[0], user: u }; });
    }
    var email = id.indexOf("@") > 0 ? id : found && found[1].email;
    if (!email) return Promise.reject(new Error("Please log in with your email address."));
    // Try what was typed, then the common phone-keyboard slips (automatic capital first letter, spaces).
    var clean = MB.cleanPassword(password), used = clean;
    var tries = [clean, clean ? (clean[0] === clean[0].toUpperCase() ? clean[0].toLowerCase() : clean[0].toUpperCase()) + clean.slice(1) : clean, password].filter(function (v, i, a) { return v && a.indexOf(v) === i; });
    function attempt(i) {
      used = tries[i];
      return MB.fbSignIn(email, used).catch(function (e) {
        if (i + 1 < tries.length && /INVALID/.test(e.code || "")) return attempt(i + 1);
        throw e;
      });
    }
    return attempt(0).then(function (r) {
      return fbCall("lookup", { idToken: r.idToken }).then(function (lk) {
        var info = (lk.users || [])[0] || {};
        if (!info.emailVerified) {
          var err = new Error("Please verify your email first: open the Firebase email we sent to " + email + " and tap the link.");
          err.code = "NOT_VERIFIED"; err.tokens = { idToken: r.idToken, refreshToken: r.refreshToken }; err.email = email; throw err;
        }
        return MB.hashPassword(used).then(function (h) {
          var users = MB.users(), key = found ? found[0] : null;
          if (!key) for (var k in users) if (users[k].uid === r.localId) key = k;
          if (!key) return { needsProfile: { email: email, uid: r.localId, name: info.displayName || "", refreshToken: r.refreshToken, salt: h.salt, hash: h.hash } };
          var u = users[key];
          Object.assign(u, { uid: r.localId, email: email, salt: h.salt, hash: h.hash, refreshToken: r.refreshToken, verified: true,
            verifiedBy: "email", fails: 0, lockedUntil: 0, lastLogin: MB.now() });
          MB.saveUsers(users);
          return { phone: key, user: u };
        });
      });
    });
  };
  function localLogin(phone, password) {
    var users = MB.users(), u = users[phone];
    if (u && u.lockedUntil > MB.now()) {
      return Promise.reject(new Error("Too many failed attempts. Try again in " +
        Math.ceil((u.lockedUntil - MB.now()) / 60000) + " minute(s) or reset your password."));
    }
    if (!u || !u.verified) return Promise.reject(new Error("No account with this mobile number on this phone. Please create an account first."));
    // Accept what the user typed, plus the common phone-keyboard slips: an automatic capital first
    // letter (or a missing one), and spaces saved by older versions.
    var clean = MB.cleanPassword(password), flip = clean ? (clean[0] === clean[0].toUpperCase() ? clean[0].toLowerCase() : clean[0].toUpperCase()) + clean.slice(1) : clean;
    var variants = [clean, password, flip].filter(function (v, i, a) { return a.indexOf(v) === i; });
    function tryNext(i) {
      if (i >= variants.length) return Promise.resolve(false);
      return derive(variants[i], u.salt).then(function (h) { return h.hash === u.hash || tryNext(i + 1); });
    }
    return tryNext(0).then(function (ok) {
      users = MB.users(); u = users[phone];
      if (!ok) {
        u.fails = (u.fails || 0) + 1;
        if (u.fails >= 5) { u.lockedUntil = MB.now() + 15 * 60000; u.fails = 0; }
        MB.saveUsers(users);
        throw new Error("Incorrect password. Check Caps Lock, or tap the eye to see what you typed. Forgot it? Use \"Forgot password\".");
      }
      u.fails = 0; u.lockedUntil = 0; u.lastLogin = MB.now();
      MB.saveUsers(users);
      return u;
    });
  };

  // ---------- OTP ----------
  var OTP_TTL = 5 * 60000, OTP_ATTEMPTS = 5, RESEND_WAIT = 60000;

  MB.pending = function () { return JSON.parse(sessionStorage.getItem("mb_pending") || "null"); };
  MB.setPending = function (p) { if (p) sessionStorage.setItem("mb_pending", JSON.stringify(p)); else sessionStorage.removeItem("mb_pending"); };
  MB.resendWait = function () {
    var p = MB.pending(); return p && p.sentAt ? Math.max(0, Math.ceil((p.sentAt + RESEND_WAIT - MB.now()) / 1000)) : 0;
  };

  function otpMessage(code) {
    return "Your Medibot verification code is " + code + ". It expires in 5 minutes. Do not share it with anyone.";
  }
  function withTimeout(ms) {
    var c = new AbortController(); setTimeout(function () { c.abort(); }, ms); return c.signal;
  }
  MB.sendOtp = function (phone, purpose, extra) {
    var p = MB.pending();
    if (p && p.phone === phone && p.purpose === purpose && MB.resendWait() > 0) {
      return Promise.reject(new Error("Please wait " + MB.resendWait() + " seconds before requesting another code."));
    }
    var a = new Uint32Array(1); crypto.getRandomValues(a);
    var code = String(a[0] % 1000000).padStart(6, "0");
    var s = MB.settings(), email = extra && extra.email, mode = "screen";
    return MB.sha256(phone + "|" + purpose + "|" + code).then(function (h) {
        var pending = Object.assign({}, extra || {}, {
          phone: phone, email: email || null, purpose: purpose, otpHash: h, expires: MB.now() + OTP_TTL, attempts: 0, sentAt: MB.now(), mode: mode,
          shownCode: s.showOtpOnScreen ? code : null
        });
        MB.setPending(pending);
        return { mode: mode };
      });
  };

  MB.verifyOtp = function (code) {
    var p = MB.pending();
    if (!p) return Promise.reject(new Error("No active code. Please start again."));
    if (p.expires < MB.now()) return Promise.reject(new Error("This code has expired. Please request a new one."));
    if (p.attempts >= OTP_ATTEMPTS) return Promise.reject(new Error("Too many wrong attempts. Please request a new code."));
    return MB.sha256(p.phone + "|" + p.purpose + "|" + String(code || "").trim()).then(function (h) {
      if (h !== p.otpHash) {
        p.attempts += 1; MB.setPending(p);
        var left = OTP_ATTEMPTS - p.attempts;
        throw new Error(left > 0 ? "Incorrect code. " + left + " attempt(s) left." : "Too many wrong attempts. Please request a new code.");
      }
      return p;
    });
  };

  // ---------- patients (the account holder + family members) ----------
  MB.patients = function (user) {
    var self = { id: "self", name: user.name, age: user.age || "", gender: user.gender || "", address: user.address || "", relation: "Self" };
    return [self].concat(load("mb_family_" + user.phone, []));
  };
  MB.saveFamily = function (user, list) { save("mb_family_" + user.phone, list.filter(function (p) { return p.id !== "self"; })); };
  MB.activePatient = function (user) {
    var id = load("mb_active_" + user.phone, "self"), list = MB.patients(user);
    return list.filter(function (p) { return p.id === id; })[0] || list[0];
  };
  MB.setActivePatient = function (user, id) { save("mb_active_" + user.phone, id); };
  MB.updateUser = function (phone, fields) {
    var users = MB.users(); Object.assign(users[phone], fields); MB.saveUsers(users);
  };
  MB.initials = function (name) {
    return String(name || "?").trim().split(/\s+/).slice(0, 2).map(function (w) { return w[0]; }).join("").toUpperCase();
  };
  MB.patientLabel = function (p) {
    return [p.age ? p.age + " yrs" : "", p.gender || ""].filter(Boolean).join(", ");
  };

  // ---------- chat history (per patient, on this device) ----------
  function histKey(phone, pid) { return "mb_chat_" + phone + (pid && pid !== "self" ? "_" + pid : ""); }
  MB.history = function (phone, pid) { return load(histKey(phone, pid), []); };
  MB.saveHistory = function (phone, msgs, pid) { save(histKey(phone, pid), msgs.slice(-200)); };

  // ---------- saved diseases ----------
  MB.saved = function (phone) { return load("mb_saved_" + phone, []); };
  MB.toggleSaved = function (phone, slug) {
    var list = MB.saved(phone), i = list.indexOf(slug);
    if (i >= 0) list.splice(i, 1); else list.unshift(slug);
    save("mb_saved_" + phone, list); return i < 0;
  };
})();
