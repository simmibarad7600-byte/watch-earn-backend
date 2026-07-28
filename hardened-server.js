'use strict';

const crypto = require('node:crypto');
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const { rateLimit } = require('express-rate-limit');
const { cert, initializeApp } = require('firebase-admin/app');
const { getAppCheck } = require('firebase-admin/app-check');
const { getAuth } = require('firebase-admin/auth');
const { FieldValue, getFirestore } = require('firebase-admin/firestore');
require('dotenv').config();

const PORT = Number(process.env.PORT || 8080);
const FAST2SMS_API_KEY = process.env.FAST2SMS_API_KEY;
const FAST2SMS_OTP_ID = process.env.FAST2SMS_OTP_ID;
const FIREBASE_PROJECT_ID =
  process.env.FIREBASE_PROJECT_ID || 'watch-and-earn-28a25';
const ENFORCE_APP_CHECK =
  String(process.env.ENFORCE_APP_CHECK || 'false').toLowerCase() === 'true';
const FRONTEND_ORIGINS = (process.env.FRONTEND_ORIGINS || '')
  .split(',')
  .map((value) => value.trim().replace(/\/$/, ''))
  .filter(Boolean);
const ADMOB_REWARDED_AD_UNIT_ID = String(
  process.env.ADMOB_REWARDED_AD_UNIT_ID || '3026961468',
).trim();
const ADMOB_REWARD_AMOUNT = Number(process.env.ADMOB_REWARD_AMOUNT || 1);
const COINS_PER_REWARD = Number(process.env.COINS_PER_REWARD || 1);
const DAILY_REWARD_LIMIT = Number(process.env.DAILY_REWARD_LIMIT || 15);
const ADMOB_KEYS_URL =
  'https://www.gstatic.com/admob/reward/verifier-keys.json';

const OTP_TTL_MS = 5 * 60 * 1000;
const MAX_OTP_ATTEMPTS = 5;
const ADMOB_KEY_CACHE_MS = 23 * 60 * 60 * 1000;
const MAX_CALLBACK_AGE_MS = 10 * 60 * 1000;
const otpRecords = new Map();
const mobileRateCounters = new Map();
let admobKeyCache = { expiresAt: 0, keys: new Map() };

function ensureConfiguration() {
  const missing = [];
  if (!FAST2SMS_API_KEY) missing.push('FAST2SMS_API_KEY');
  if (!process.env.FIREBASE_SERVICE_ACCOUNT_BASE64) {
    missing.push('FIREBASE_SERVICE_ACCOUNT_BASE64');
  }
  if (missing.length > 0) {
    throw new Error(`Missing required environment values: ${missing.join(', ')}`);
  }
}

function loadFirebaseCredential() {
  const json = Buffer.from(
    process.env.FIREBASE_SERVICE_ACCOUNT_BASE64,
    'base64',
  ).toString('utf8');
  const serviceAccount = JSON.parse(json);
  if (
    serviceAccount.project_id &&
    serviceAccount.project_id !== FIREBASE_PROJECT_ID
  ) {
    throw new Error('Firebase service account belongs to another project.');
  }
  return cert(serviceAccount);
}

ensureConfiguration();
const firebaseApp = initializeApp({
  credential: loadFirebaseCredential(),
  projectId: FIREBASE_PROJECT_ID,
});
const firebaseAuth = getAuth(firebaseApp);
const firestore = getFirestore(firebaseApp);
const firebaseAppCheck = getAppCheck(firebaseApp);

const app = express();
app.set('trust proxy', 1);
app.disable('x-powered-by');
app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'none'"],
        frameAncestors: ["'none'"],
      },
    },
    crossOriginResourcePolicy: { policy: 'same-site' },
  }),
);
app.use((_request, response, next) => {
  response.set({
    'Cache-Control': 'no-store, max-age=0',
    Pragma: 'no-cache',
    'Referrer-Policy': 'no-referrer',
  });
  next();
});
app.use(express.json({ limit: '8kb', strict: true }));
app.use(
  cors({
    origin(origin, callback) {
      if (!origin) return callback(null, true);
      try {
        const normalizedOrigin = origin.replace(/\/$/, '');
        const url = new URL(normalizedOrigin);
        const isLocal =
          url.hostname === 'localhost' || url.hostname === '127.0.0.1';
        return callback(
          null,
          isLocal || FRONTEND_ORIGINS.includes(normalizedOrigin),
        );
      } catch {
        return callback(new Error('Invalid request origin'));
      }
    },
    methods: ['GET', 'POST'],
    allowedHeaders: ['Content-Type', 'X-Firebase-AppCheck'],
    maxAge: 600,
  }),
);

const sendOtpIpLimiter = rateLimit({
  windowMs: 30 * 60 * 1000,
  limit: 5,
  standardHeaders: 'draft-8',
  legacyHeaders: false,
  message: {
    success: false,
    message: 'Too many OTP requests. Please try again later.',
  },
});

const verifyOtpIpLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 12,
  standardHeaders: 'draft-8',
  legacyHeaders: false,
  message: {
    success: false,
    message: 'Too many OTP attempts. Please try again later.',
  },
});

function validIndianMobile(value) {
  return /^[6-9]\d{9}$/.test(String(value || ''));
}

function validOtp(value) {
  return /^\d{6}$/.test(String(value || ''));
}

function hasOnlyKeys(value, allowedKeys) {
  return (
    value !== null &&
    typeof value === 'object' &&
    !Array.isArray(value) &&
    Object.keys(value).every((key) => allowedKeys.includes(key))
  );
}

function mobileKey(mobile, purpose) {
  return crypto
    .createHash('sha256')
    .update(`${purpose}:${mobile}`)
    .digest('hex');
}

function enforceMobileLimit({
  mobile,
  purpose,
  limit,
  windowMs,
  response,
}) {
  const key = mobileKey(mobile, purpose);
  const now = Date.now();
  const current = mobileRateCounters.get(key);
  if (!current || current.resetAt <= now) {
    mobileRateCounters.set(key, { count: 1, resetAt: now + windowMs });
    return true;
  }

  current.count += 1;
  if (current.count > limit) {
    response.status(429).json({
      success: false,
      message: 'Too many requests for this mobile number. Try later.',
    });
    return false;
  }
  return true;
}

function hashOtp(mobile, otp, salt) {
  return crypto
    .createHash('sha256')
    .update(`${mobile}:${otp}:${salt}`)
    .digest();
}

function storeLocalOtp(mobile, otp) {
  const salt = crypto.randomBytes(24).toString('hex');
  otpRecords.set(mobile, {
    mode: 'local',
    salt,
    hash: hashOtp(mobile, otp, salt),
    expiresAt: Date.now() + OTP_TTL_MS,
    attempts: 0,
  });
}

function storeProviderOtp(mobile, requestId) {
  otpRecords.set(mobile, {
    mode: 'provider',
    requestId: requestId || null,
    expiresAt: Date.now() + OTP_TTL_MS,
    attempts: 0,
  });
}

function getOtpRecord(mobile) {
  const record = otpRecords.get(mobile);
  if (!record || record.expiresAt <= Date.now()) {
    otpRecords.delete(mobile);
    const error = new Error('OTP is missing or expired.');
    error.clientMessage = 'OTP expired. Please request a new OTP.';
    error.statusCode = 400;
    throw error;
  }

  record.attempts += 1;
  if (record.attempts > MAX_OTP_ATTEMPTS) {
    otpRecords.delete(mobile);
    const error = new Error('OTP attempt limit exceeded.');
    error.clientMessage = 'Too many incorrect attempts. Request a new OTP.';
    error.statusCode = 429;
    throw error;
  }
  return record;
}

function verifyLocalOtp(mobile, otp, record) {
  const suppliedHash = hashOtp(mobile, otp, record.salt);
  if (!crypto.timingSafeEqual(record.hash, suppliedHash)) {
    if (record.attempts >= MAX_OTP_ATTEMPTS) otpRecords.delete(mobile);
    const error = new Error('Incorrect OTP.');
    error.clientMessage = 'Incorrect or expired OTP.';
    error.statusCode = 400;
    throw error;
  }
}

function maskMobile(mobile) {
  return `******${String(mobile).slice(-4)}`;
}

function validFirebaseUid(value) {
  return /^[A-Za-z0-9:_-]{1,128}$/.test(String(value || ''));
}

function normalizeAdMobTimestamp(value) {
  let timestamp = Number(value);
  if (!Number.isFinite(timestamp) || timestamp <= 0) return null;
  if (timestamp > 100000000000000) timestamp = Math.floor(timestamp / 1000);
  if (timestamp < 100000000000) timestamp *= 1000;
  return timestamp;
}

function decodeBase64Url(value) {
  return Buffer.from(String(value || ''), 'base64url');
}

function verifyEcdsaSignature(publicKey, signedContent, signatureValue) {
  return crypto.verify(
    'sha256',
    Buffer.from(signedContent, 'utf8'),
    publicKey,
    decodeBase64Url(signatureValue),
  );
}

async function getAdMobPublicKeys() {
  const now = Date.now();
  if (admobKeyCache.expiresAt > now && admobKeyCache.keys.size > 0) {
    return admobKeyCache.keys;
  }

  const response = await fetch(ADMOB_KEYS_URL, {
    headers: { Accept: 'application/json' },
    signal: AbortSignal.timeout(10000),
  });
  if (!response.ok) {
    throw new Error(`Unable to fetch AdMob public keys (${response.status}).`);
  }

  const data = await response.json();
  const keys = new Map();
  for (const key of Array.isArray(data.keys) ? data.keys : []) {
    if (Number.isInteger(key.keyId) && typeof key.pem === 'string') {
      keys.set(String(key.keyId), key.pem);
    }
  }
  if (keys.size === 0) throw new Error('AdMob returned no verification keys.');

  admobKeyCache = {
    expiresAt: now + ADMOB_KEY_CACHE_MS,
    keys,
  };
  return keys;
}

async function verifyAdMobCallback(originalUrl) {
  const rawQuery = String(originalUrl || '').split('?')[1] || '';
  const match = rawQuery.match(/^(.*)&signature=([^&]+)&key_id=([0-9]+)$/);
  if (!match) throw new Error('Malformed AdMob callback.');

  const signedContent = match[1];
  const signature = match[2];
  const keyId = match[3];
  const keys = await getAdMobPublicKeys();
  const publicKey = keys.get(keyId);
  if (!publicKey) throw new Error('Unknown AdMob signing key.');

  const verified = verifyEcdsaSignature(
    publicKey,
    signedContent,
    signature,
  );
  if (!verified) throw new Error('Invalid AdMob callback signature.');

  const params = new URLSearchParams(signedContent);
  return {
    adUnit: params.get('ad_unit'),
    customData: params.get('custom_data'),
    rewardAmount: Number(params.get('reward_amount')),
    rewardItem: params.get('reward_item'),
    timestamp: normalizeAdMobTimestamp(params.get('timestamp')),
    transactionId: params.get('transaction_id'),
    uid: params.get('user_id'),
  };
}

function utcDayKey(timestamp = Date.now()) {
  return new Date(timestamp).toISOString().slice(0, 10);
}

async function grantVerifiedAdReward(callback) {
  const {
    adUnit,
    rewardAmount,
    rewardItem,
    timestamp,
    transactionId,
    uid,
  } = callback;
  const now = Date.now();

  if (
    adUnit !== ADMOB_REWARDED_AD_UNIT_ID ||
    rewardAmount !== ADMOB_REWARD_AMOUNT ||
    !validFirebaseUid(uid) ||
    !/^[A-Za-z0-9_-]{8,128}$/.test(String(transactionId || '')) ||
    !timestamp ||
    timestamp < now - MAX_CALLBACK_AGE_MS ||
    timestamp > now + 2 * 60 * 1000
  ) {
    throw new Error('AdMob callback values failed validation.');
  }

  const claimRef = firestore.collection('rewardClaims').doc(transactionId);
  const walletRef = firestore.collection('wallets').doc(uid);
  const userRef = firestore.collection('users').doc(uid);
  const transactionRef = firestore
    .collection('transactions')
    .doc(transactionId);

  return firestore.runTransaction(async (transaction) => {
    const [claimSnapshot, userSnapshot, walletSnapshot] = await Promise.all([
      transaction.get(claimRef),
      transaction.get(userRef),
      transaction.get(walletRef),
    ]);

    if (claimSnapshot.exists) return { duplicate: true, credited: false };
    if (!userSnapshot.exists) throw new Error('Reward user does not exist.');

    const wallet = walletSnapshot.data() || {};
    const today = utcDayKey(now);
    const previousCount =
      wallet.dailyRewardDate === today
        ? Number(wallet.dailyRewardCount || 0)
        : 0;

    if (previousCount >= DAILY_REWARD_LIMIT) {
      transaction.create(claimRef, {
        userId: uid,
        adUnit,
        rewardAmount,
        rewardItem: rewardItem || '',
        credited: false,
        reason: 'daily_limit',
        callbackTimestamp: timestamp,
        createdAt: FieldValue.serverTimestamp(),
      });
      return { duplicate: false, credited: false, limited: true };
    }

    const currentCoins = Number(wallet.coins || 0);
    const nextCoins = currentCoins + COINS_PER_REWARD;
    transaction.set(
      walletRef,
      {
        uid,
        coins: nextCoins,
        dailyRewardDate: today,
        dailyRewardCount: previousCount + 1,
        updatedAt: FieldValue.serverTimestamp(),
      },
      { merge: true },
    );
    transaction.create(claimRef, {
      userId: uid,
      adUnit,
      rewardAmount,
      rewardItem: rewardItem || '',
      credited: true,
      coins: COINS_PER_REWARD,
      callbackTimestamp: timestamp,
      createdAt: FieldValue.serverTimestamp(),
    });
    transaction.create(transactionRef, {
      userId: uid,
      type: 'ad_reward',
      coins: COINS_PER_REWARD,
      balanceAfter: nextCoins,
      adTransactionId: transactionId,
      createdAt: FieldValue.serverTimestamp(),
    });
    return { duplicate: false, credited: true, coins: COINS_PER_REWARD };
  });
}

async function verifyAppCheck(request, response, next) {
  const token = request.get('X-Firebase-AppCheck');
  if (!token) {
    if (ENFORCE_APP_CHECK) {
      return response.status(401).json({
        success: false,
        message: 'App verification failed. Please update the app.',
      });
    }
    return next();
  }

  try {
    request.appCheck = await firebaseAppCheck.verifyToken(token);
    return next();
  } catch (error) {
    console.warn('Invalid App Check token:', error.code || error.message);
    if (ENFORCE_APP_CHECK) {
      return response.status(401).json({
        success: false,
        message: 'App verification failed. Please update the app.',
      });
    }
    return next();
  }
}

async function fast2smsRequest(endpoint, body) {
  const response = await fetch(`https://www.fast2sms.com${endpoint}`, {
    method: 'POST',
    headers: {
      Authorization: FAST2SMS_API_KEY,
      Accept: 'application/json',
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(body),
    signal: AbortSignal.timeout(15000),
  });

  const data = await response.json().catch(() => ({}));
  if (!response.ok || data.return === false) {
    const rawMessage =
      data.message ||
      data.error ||
      `Fast2SMS request failed with status ${response.status}`;
    const error = new Error(
      Array.isArray(rawMessage) ? rawMessage.join(' ') : String(rawMessage),
    );
    error.statusCode = response.status >= 400 ? response.status : 502;
    throw error;
  }
  return data;
}

async function createPhoneSession(mobile) {
  const uid = `phone_91${mobile}`;
  const phoneNumber = `+91${mobile}`;
  let isNewUser = false;

  try {
    await firebaseAuth.getUser(uid);
    await firebaseAuth.updateUser(uid, { phoneNumber });
  } catch (error) {
    if (error.code !== 'auth/user-not-found') throw error;
    isNewUser = true;
    await firebaseAuth.createUser({
      uid,
      phoneNumber,
      displayName: 'Phone User',
    });
  }

  const userData = {
    mobile,
    phoneNumber,
    country: 'India',
    authProvider: 'fast2sms',
    phoneVerified: true,
    updatedAt: FieldValue.serverTimestamp(),
    lastLoginAt: FieldValue.serverTimestamp(),
  };
  if (isNewUser) {
    userData.name = 'Phone User';
    userData.createdAt = FieldValue.serverTimestamp();
  }

  await firestore
    .collection('users')
    .doc(uid)
    .set(userData, { merge: true });
  return firebaseAuth.createCustomToken(uid, { phone_verified: true });
}

app.get('/', (_request, response) => {
  response.json({
    success: true,
    service: 'watch-earn-otp',
    appCheckEnforced: ENFORCE_APP_CHECK,
  });
});

app.get('/health', (_request, response) => {
  response.json({
    success: true,
    service: 'watch-earn-otp',
    appCheckEnforced: ENFORCE_APP_CHECK,
  });
});

app.post(
  '/otp/send',
  sendOtpIpLimiter,
  verifyAppCheck,
  async (request, response) => {
    if (!hasOnlyKeys(request.body, ['mobile'])) {
      return response.status(400).json({
        success: false,
        message: 'Invalid request.',
      });
    }

    const mobile = String(request.body.mobile || '').trim();
    if (!validIndianMobile(mobile)) {
      return response.status(400).json({
        success: false,
        message: 'Enter a valid 10-digit Indian mobile number.',
      });
    }

    if (
      !enforceMobileLimit({
        mobile,
        purpose: 'otp-send-short',
        limit: 3,
        windowMs: 30 * 60 * 1000,
        response,
      }) ||
      !enforceMobileLimit({
        mobile,
        purpose: 'otp-send-daily',
        limit: 10,
        windowMs: 24 * 60 * 60 * 1000,
        response,
      })
    ) {
      return;
    }

    try {
      if (FAST2SMS_OTP_ID) {
        const result = await fast2smsRequest('/dev/otp/send', {
          mobile,
          otp_id: FAST2SMS_OTP_ID,
          otp_expiry: 5,
          otp_length: 6,
        });
        storeProviderOtp(mobile, result.request_id);
      } else {
        const otp = crypto.randomInt(100000, 1000000).toString();
        await fast2smsRequest('/dev/bulkV2', {
          route: 'q',
          message:
            `Your Watch & Earn OTP is ${otp}. ` +
            'It expires in 5 minutes. Do not share it.',
          numbers: mobile,
        });
        storeLocalOtp(mobile, otp);
      }
      return response.json({
        success: true,
        message: 'OTP sent successfully.',
      });
    } catch (error) {
      console.error(`OTP send failed for ${maskMobile(mobile)}:`, error.message);
      return response.status(502).json({
        success: false,
        message: 'Unable to send OTP right now. Please try again later.',
      });
    }
  },
);

app.post(
  '/otp/verify',
  verifyOtpIpLimiter,
  verifyAppCheck,
  async (request, response) => {
    if (!hasOnlyKeys(request.body, ['mobile', 'otp'])) {
      return response.status(400).json({
        success: false,
        message: 'Invalid request.',
      });
    }

    const mobile = String(request.body.mobile || '').trim();
    const otp = String(request.body.otp || '').trim();
    if (!validIndianMobile(mobile) || !validOtp(otp)) {
      return response.status(400).json({
        success: false,
        message: 'Mobile number or OTP is invalid.',
      });
    }

    if (
      !enforceMobileLimit({
        mobile,
        purpose: 'otp-verify',
        limit: 6,
        windowMs: 15 * 60 * 1000,
        response,
      })
    ) {
      return;
    }

    try {
      const record = getOtpRecord(mobile);
      if (record.mode === 'provider') {
        try {
          await fast2smsRequest('/dev/otp/verify', { mobile, otp });
        } catch (error) {
          if (record.attempts >= MAX_OTP_ATTEMPTS) otpRecords.delete(mobile);
          throw error;
        }
      } else {
        verifyLocalOtp(mobile, otp, record);
      }

      otpRecords.delete(mobile);
      const customToken = await createPhoneSession(mobile);
      return response.json({
        success: true,
        customToken,
        message: 'OTP verified successfully.',
      });
    } catch (error) {
      console.warn(
        `OTP verify failed for ${maskMobile(mobile)}:`,
        error.message,
      );
      return response.status(error.statusCode || 400).json({
        success: false,
        message: error.clientMessage || 'Incorrect or expired OTP.',
      });
    }
  },
);

app.get('/admob/reward', async (request, response) => {
  try {
    const callback = await verifyAdMobCallback(request.originalUrl);
    if (
      callback.uid === 'admob_ssv_setup_check' &&
      callback.customData === 'verify_only'
    ) {
      console.info('Verified AdMob SSV setup callback.');
      return response.status(200).send('OK');
    }
    const result = await grantVerifiedAdReward(callback);
    console.info('Verified AdMob reward callback processed:', {
      transactionId: callback.transactionId,
      credited: result.credited,
      duplicate: result.duplicate,
      limited: result.limited || false,
    });
    return response.status(200).send('OK');
  } catch (error) {
    console.warn('Rejected AdMob reward callback:', error.message);
    return response.status(400).send('Invalid callback');
  }
});

app.use((_request, response) => {
  response.status(404).json({ success: false, message: 'Route not found.' });
});

app.use((error, _request, response, _next) => {
  console.error('Unhandled server error:', error.message);
  response.status(500).json({
    success: false,
    message: 'Internal server error.',
  });
});

const cleanupTimer = setInterval(() => {
  const now = Date.now();
  for (const [mobile, record] of otpRecords.entries()) {
    if (record.expiresAt <= now) otpRecords.delete(mobile);
  }
  for (const [key, counter] of mobileRateCounters.entries()) {
    if (counter.resetAt <= now) mobileRateCounters.delete(key);
  }
}, 60 * 1000);
cleanupTimer.unref();

if (require.main === module) {
  app.listen(PORT, () => {
    console.log(
      `OTP backend listening on port ${PORT}; App Check enforcement: ${ENFORCE_APP_CHECK}`,
    );
  });
}

module.exports = {
  app,
  validIndianMobile,
  validOtp,
  validFirebaseUid,
  normalizeAdMobTimestamp,
  verifyEcdsaSignature,
};
