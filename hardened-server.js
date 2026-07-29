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
const REFERRAL_QUALIFYING_ADS = Number(
  process.env.REFERRAL_QUALIFYING_ADS || 5,
);
const REFERRAL_REWARD_COINS = Number(
  process.env.REFERRAL_REWARD_COINS || 1,
);
const BITLABS_ENABLED =
  String(process.env.BITLABS_ENABLED || 'false').toLowerCase() === 'true';
const BITLABS_APP_SECRET = String(process.env.BITLABS_APP_SECRET || '').trim();
const BITLABS_MAX_COINS_PER_CALLBACK = Number(
  process.env.BITLABS_MAX_COINS_PER_CALLBACK || 100,
);
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
    allowedHeaders: [
      'Content-Type',
      'Authorization',
      'X-Firebase-AppCheck',
    ],
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

const dailyBonusIpLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  limit: 20,
  standardHeaders: 'draft-8',
  legacyHeaders: false,
  message: {
    success: false,
    message: 'Too many bonus requests. Please try again later.',
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

function utcDay(value = new Date()) {
  return value.toISOString().slice(0, 10);
}

function previousUtcDay(day) {
  const date = new Date(`${day}T00:00:00.000Z`);
  date.setUTCDate(date.getUTCDate() - 1);
  return utcDay(date);
}

function nextDailyStreak(lastClaimDay, currentStreak, today) {
  return lastClaimDay === previousUtcDay(today)
    ? Math.max(0, Number(currentStreak || 0)) + 1
    : 1;
}

function referralCodeForUid(uid) {
  return crypto
    .createHash('sha256')
    .update(`watch-earn-referral-v1:${uid}`)
    .digest('hex')
    .slice(0, 10)
    .toUpperCase();
}

function validRewardCode(value) {
  return /^[A-Z0-9]{6,20}$/.test(String(value || '').trim().toUpperCase());
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

function stripBitLabsHash(fullUrl) {
  return String(fullUrl || '').replace(/([?&])hash=[^&]*(&?)/i, (_match, lead, tail) => {
    if (lead === '?' && tail) return '?';
    return tail ? lead : '';
  });
}

function bitLabsSignature(fullUrlWithoutHash, secret) {
  return crypto
    .createHmac('sha1', String(secret || ''))
    .update(String(fullUrlWithoutHash || ''), 'utf8')
    .digest('hex');
}

function safeHexEqual(expected, supplied) {
  const left = Buffer.from(String(expected || '').toLowerCase(), 'utf8');
  const right = Buffer.from(String(supplied || '').toLowerCase(), 'utf8');
  return left.length === right.length && crypto.timingSafeEqual(left, right);
}

function verifyBitLabsCallback(fullUrl, secret) {
  if (!secret) throw new Error('BitLabs secret is not configured.');
  const parsed = new URL(String(fullUrl || ''));
  const suppliedHash = parsed.searchParams.get('hash');
  if (!/^[a-f0-9]{40}$/i.test(String(suppliedHash || ''))) {
    throw new Error('Malformed BitLabs callback hash.');
  }

  const unsignedUrl = stripBitLabsHash(fullUrl);
  const expectedHash = bitLabsSignature(unsignedUrl, secret);
  if (!safeHexEqual(expectedHash, suppliedHash)) {
    throw new Error('Invalid BitLabs callback signature.');
  }

  const uid = parsed.searchParams.get('uid');
  const transactionId = parsed.searchParams.get('tx');
  const coins = Number(parsed.searchParams.get('val'));
  const usdValue = Number(parsed.searchParams.get('raw'));
  if (
    !validFirebaseUid(uid) ||
    !/^[A-Za-z0-9:_-]{1,128}$/.test(String(transactionId || '')) ||
    !Number.isSafeInteger(coins) ||
    coins < 1 ||
    coins > BITLABS_MAX_COINS_PER_CALLBACK ||
    !Number.isFinite(usdValue) ||
    usdValue < 0
  ) {
    throw new Error('BitLabs callback values failed validation.');
  }
  return { uid, transactionId, coins, usdValue };
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
    const lifetimeVerifiedAds =
      Number(wallet.lifetimeVerifiedAds || 0) + 1;
    transaction.set(
      walletRef,
      {
        uid,
        coins: nextCoins,
        dailyRewardDate: today,
        dailyRewardCount: previousCount + 1,
        lifetimeVerifiedAds,
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
    return {
      duplicate: false,
      credited: true,
      coins: COINS_PER_REWARD,
      lifetimeVerifiedAds,
    };
  });
}

async function grantBitLabsOfferReward(callback) {
  const { uid, transactionId, coins, usdValue } = callback;
  const authUser = await firebaseAuth.getUser(uid);
  const verifiedAccount =
    authUser.emailVerified === true ||
    Boolean(authUser.phoneNumber) ||
    authUser.customClaims?.phone_verified === true;
  if (!verifiedAccount) throw new Error('Offer user is not verified.');

  const claimRef = firestore.collection('offerClaims').doc(transactionId);
  const walletRef = firestore.collection('wallets').doc(uid);
  const userRef = firestore.collection('users').doc(uid);
  const transactionRef = firestore
    .collection('transactions')
    .doc(`bitlabs_${transactionId}`);

  return firestore.runTransaction(async (transaction) => {
    const [claimSnapshot, userSnapshot, walletSnapshot] = await Promise.all([
      transaction.get(claimRef),
      transaction.get(userRef),
      transaction.get(walletRef),
    ]);
    if (claimSnapshot.exists) return { duplicate: true, credited: false };
    if (!userSnapshot.exists) throw new Error('Offer user does not exist.');

    const currentCoins = Number(walletSnapshot.data()?.coins || 0);
    const nextCoins = currentCoins + coins;
    transaction.set(
      walletRef,
      {
        uid,
        coins: nextCoins,
        updatedAt: FieldValue.serverTimestamp(),
      },
      { merge: true },
    );
    transaction.create(claimRef, {
      provider: 'bitlabs',
      userId: uid,
      providerTransactionId: transactionId,
      coins,
      usdValue,
      credited: true,
      createdAt: FieldValue.serverTimestamp(),
    });
    transaction.create(transactionRef, {
      userId: uid,
      type: 'offer_reward',
      provider: 'bitlabs',
      coins,
      balanceAfter: nextCoins,
      providerTransactionId: transactionId,
      providerUsdValue: usdValue,
      createdAt: FieldValue.serverTimestamp(),
    });
    return { duplicate: false, credited: true, coins };
  });
}

async function ensureReferralCode(uid) {
  const code = referralCodeForUid(uid);
  const codeRef = firestore.collection('referralCodes').doc(code);
  const userRef = firestore.collection('users').doc(uid);

  await firestore.runTransaction(async (transaction) => {
    const codeSnapshot = await transaction.get(codeRef);
    if (codeSnapshot.exists && codeSnapshot.data()?.ownerUid !== uid) {
      throw new Error('Referral code collision.');
    }
    transaction.set(
      codeRef,
      {
        ownerUid: uid,
        active: true,
        createdAt: FieldValue.serverTimestamp(),
      },
      { merge: true },
    );
    transaction.set(userRef, { referralCode: code }, { merge: true });
  });
  return code;
}

async function redeemReferralCode(uid, code, firebaseUser) {
  if (!validRewardCode(code)) {
    const error = new Error('Invalid referral code.');
    error.statusCode = 400;
    throw error;
  }
  if (!firebaseUser.email_verified && !firebaseUser.phone_number) {
    const error = new Error(
      'Verify your email or phone before using a referral code.',
    );
    error.statusCode = 403;
    throw error;
  }

  const normalizedCode = String(code).trim().toUpperCase();
  const codeRef = firestore.collection('referralCodes').doc(normalizedCode);
  const referralRef = firestore.collection('referrals').doc(uid);
  const userRef = firestore.collection('users').doc(uid);

  return firestore.runTransaction(async (transaction) => {
    const [codeSnapshot, referralSnapshot] = await Promise.all([
      transaction.get(codeRef),
      transaction.get(referralRef),
    ]);
    if (!codeSnapshot.exists || codeSnapshot.data()?.active !== true) {
      const error = new Error('Referral code was not found.');
      error.statusCode = 404;
      throw error;
    }
    if (referralSnapshot.exists) {
      const error = new Error('A referral code is already linked.');
      error.statusCode = 409;
      throw error;
    }

    const inviterUid = codeSnapshot.data().ownerUid;
    if (!validFirebaseUid(inviterUid) || inviterUid === uid) {
      const error = new Error('You cannot use your own referral code.');
      error.statusCode = 400;
      throw error;
    }

    transaction.create(referralRef, {
      inviterUid,
      referredUid: uid,
      code: normalizedCode,
      status: 'pending',
      qualifyingAds: REFERRAL_QUALIFYING_ADS,
      createdAt: FieldValue.serverTimestamp(),
    });
    transaction.set(
      userRef,
      {
        referredByUid: inviterUid,
        referralStatus: 'pending',
      },
      { merge: true },
    );
    return { status: 'pending', qualifyingAds: REFERRAL_QUALIFYING_ADS };
  });
}

async function finalizeQualifiedReferral(referredUid) {
  const referralRef = firestore.collection('referrals').doc(referredUid);
  const referredWalletRef = firestore.collection('wallets').doc(referredUid);

  return firestore.runTransaction(async (transaction) => {
    const [referralSnapshot, referredWalletSnapshot] = await Promise.all([
      transaction.get(referralRef),
      transaction.get(referredWalletRef),
    ]);
    if (
      !referralSnapshot.exists ||
      referralSnapshot.data()?.status !== 'pending'
    ) {
      return { qualified: false };
    }

    const referredWallet = referredWalletSnapshot.data() || {};
    if (
      Number(referredWallet.lifetimeVerifiedAds || 0) <
      REFERRAL_QUALIFYING_ADS
    ) {
      return { qualified: false };
    }

    const inviterUid = referralSnapshot.data().inviterUid;
    if (!validFirebaseUid(inviterUid) || inviterUid === referredUid) {
      throw new Error('Referral owner is invalid.');
    }
    const inviterWalletRef = firestore.collection('wallets').doc(inviterUid);
    const inviterWalletSnapshot = await transaction.get(inviterWalletRef);
    const inviterBalance = Number(inviterWalletSnapshot.data()?.coins || 0);
    const referredBalance = Number(referredWallet.coins || 0);
    const completedAt = FieldValue.serverTimestamp();

    transaction.set(
      inviterWalletRef,
      {
        coins: inviterBalance + REFERRAL_REWARD_COINS,
        updatedAt: completedAt,
      },
      { merge: true },
    );
    transaction.set(
      referredWalletRef,
      {
        coins: referredBalance + REFERRAL_REWARD_COINS,
        updatedAt: completedAt,
      },
      { merge: true },
    );
    transaction.update(referralRef, {
      status: 'qualified',
      rewardCoins: REFERRAL_REWARD_COINS,
      qualifiedAt: completedAt,
    });
    transaction.set(
      firestore.collection('users').doc(referredUid),
      { referralStatus: 'qualified' },
      { merge: true },
    );
    transaction.create(
      firestore.collection('transactions').doc(`referral_inviter_${referredUid}`),
      {
        userId: inviterUid,
        type: 'referral_bonus',
        coins: REFERRAL_REWARD_COINS,
        balanceAfter: inviterBalance + REFERRAL_REWARD_COINS,
        referredUid,
        createdAt: completedAt,
      },
    );
    transaction.create(
      firestore.collection('transactions').doc(`referral_join_${referredUid}`),
      {
        userId: referredUid,
        type: 'referral_bonus',
        coins: REFERRAL_REWARD_COINS,
        balanceAfter: referredBalance + REFERRAL_REWARD_COINS,
        inviterUid,
        createdAt: completedAt,
      },
    );
    return { qualified: true, coins: REFERRAL_REWARD_COINS };
  });
}

async function redeemPromoCode(uid, code, firebaseUser) {
  if (!validRewardCode(code)) {
    const error = new Error('Invalid promo code.');
    error.statusCode = 400;
    throw error;
  }
  if (!firebaseUser.email_verified && !firebaseUser.phone_number) {
    const error = new Error(
      'Verify your email or phone before using a promo code.',
    );
    error.statusCode = 403;
    throw error;
  }

  const normalizedCode = String(code).trim().toUpperCase();
  const promoRef = firestore.collection('promoCodes').doc(normalizedCode);
  const claimRef = firestore
    .collection('promoClaims')
    .doc(`${normalizedCode}_${uid}`);
  const walletRef = firestore.collection('wallets').doc(uid);
  const transactionRef = firestore
    .collection('transactions')
    .doc(`promo_${normalizedCode}_${uid}`);

  return firestore.runTransaction(async (transaction) => {
    const [promoSnapshot, claimSnapshot, walletSnapshot] = await Promise.all([
      transaction.get(promoRef),
      transaction.get(claimRef),
      transaction.get(walletRef),
    ]);
    if (!promoSnapshot.exists || promoSnapshot.data()?.active !== true) {
      const error = new Error('Promo code is invalid or inactive.');
      error.statusCode = 404;
      throw error;
    }
    if (claimSnapshot.exists) {
      const error = new Error('You have already used this promo code.');
      error.statusCode = 409;
      throw error;
    }

    const promo = promoSnapshot.data();
    const coins = Number(promo.coins || 0);
    const usedCount = Number(promo.usedCount || 0);
    const maxUses = Number(promo.maxUses || 0);
    const now = Date.now();
    const startsAt = promo.startsAt?.toMillis?.() ?? 0;
    const endsAt = promo.endsAt?.toMillis?.() ?? 0;
    if (
      !Number.isInteger(coins) ||
      coins < 1 ||
      coins > 10 ||
      !Number.isInteger(maxUses) ||
      maxUses < 1 ||
      usedCount >= maxUses ||
      (startsAt > 0 && now < startsAt) ||
      (endsAt > 0 && now > endsAt)
    ) {
      const error = new Error('Promo code has expired or reached its limit.');
      error.statusCode = 410;
      throw error;
    }

    const currentBalance = Number(walletSnapshot.data()?.coins || 0);
    const nextBalance = currentBalance + coins;
    const createdAt = FieldValue.serverTimestamp();
    transaction.update(promoRef, {
      usedCount: usedCount + 1,
      updatedAt: createdAt,
    });
    transaction.create(claimRef, {
      userId: uid,
      code: normalizedCode,
      coins,
      createdAt,
    });
    transaction.set(
      walletRef,
      {
        coins: nextBalance,
        updatedAt: createdAt,
      },
      { merge: true },
    );
    transaction.create(transactionRef, {
      userId: uid,
      type: 'promo_bonus',
      code: normalizedCode,
      coins,
      balanceAfter: nextBalance,
      createdAt,
    });
    return { coins, balance: nextBalance };
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

async function verifyFirebaseUser(request, response, next) {
  const authorization = request.get('Authorization') || '';
  const match = authorization.match(/^Bearer\s+(.+)$/i);
  if (!match) {
    return response.status(401).json({
      success: false,
      message: 'Please log in again.',
    });
  }

  try {
    request.firebaseUser = await firebaseAuth.verifyIdToken(match[1], true);
    return next();
  } catch (error) {
    console.warn('Invalid Firebase ID token:', error.code || error.message);
    return response.status(401).json({
      success: false,
      message: 'Your login expired. Please log in again.',
    });
  }
}

async function grantDailyBonus(uid) {
  const today = utcDay();
  const claimId = `${uid}_${today}`;
  const claimRef = firestore.collection('dailyClaims').doc(claimId);
  const walletRef = firestore.collection('wallets').doc(uid);
  const transactionRef = firestore.collection('transactions').doc(claimId);

  return firestore.runTransaction(async (transaction) => {
    const [claimSnapshot, walletSnapshot] = await Promise.all([
      transaction.get(claimRef),
      transaction.get(walletRef),
    ]);

    if (claimSnapshot.exists) {
      return {
        claimed: false,
        alreadyClaimed: true,
        streak: Number(walletSnapshot.data()?.dailyBonusStreak || 0),
        coins: 0,
      };
    }

    const wallet = walletSnapshot.data() || {};
    const streak = nextDailyStreak(
      wallet.dailyBonusLastClaimDate,
      wallet.dailyBonusStreak,
      today,
    );
    const rewardCoins = streak % 7 === 0 ? 2 : 1;
    const nextBalance = Number(wallet.coins || 0) + rewardCoins;

    transaction.create(claimRef, {
      userId: uid,
      day: today,
      streak,
      coins: rewardCoins,
      createdAt: FieldValue.serverTimestamp(),
    });
    transaction.set(
      walletRef,
      {
        coins: nextBalance,
        dailyBonusLastClaimDate: today,
        dailyBonusStreak: streak,
        updatedAt: FieldValue.serverTimestamp(),
      },
      { merge: true },
    );
    transaction.create(transactionRef, {
      userId: uid,
      type: 'daily_bonus',
      coins: rewardCoins,
      balanceAfter: nextBalance,
      streak,
      createdAt: FieldValue.serverTimestamp(),
    });

    return {
      claimed: true,
      alreadyClaimed: false,
      streak,
      coins: rewardCoins,
      balance: nextBalance,
    };
  });
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

app.post(
  '/rewards/daily-check-in',
  dailyBonusIpLimiter,
  verifyAppCheck,
  verifyFirebaseUser,
  async (request, response) => {
    if (!hasOnlyKeys(request.body, [])) {
      return response.status(400).json({
        success: false,
        message: 'Invalid request.',
      });
    }

    try {
      const result = await grantDailyBonus(request.firebaseUser.uid);
      return response.json({
        success: true,
        ...result,
        message: result.alreadyClaimed
          ? 'Today’s bonus is already claimed.'
          : `Daily bonus claimed: +${result.coins} coin${
              result.coins === 1 ? '' : 's'
            }.`,
      });
    } catch (error) {
      console.error('Daily bonus failed:', error.message);
      return response.status(500).json({
        success: false,
        message: 'Daily bonus is temporarily unavailable.',
      });
    }
  },
);

app.post(
  '/rewards/referral/status',
  verifyAppCheck,
  verifyFirebaseUser,
  async (request, response) => {
    if (!hasOnlyKeys(request.body, [])) {
      return response.status(400).json({
        success: false,
        message: 'Invalid request.',
      });
    }
    try {
      const uid = request.firebaseUser.uid;
      const code = await ensureReferralCode(uid);
      const [referralSnapshot, walletSnapshot] = await Promise.all([
        firestore.collection('referrals').doc(uid).get(),
        firestore.collection('wallets').doc(uid).get(),
      ]);
      return response.json({
        success: true,
        code,
        referralStatus: referralSnapshot.data()?.status || 'not_linked',
        verifiedAds: Number(
          walletSnapshot.data()?.lifetimeVerifiedAds || 0,
        ),
        qualifyingAds: REFERRAL_QUALIFYING_ADS,
        rewardCoins: REFERRAL_REWARD_COINS,
      });
    } catch (error) {
      console.error('Referral status failed:', error.message);
      return response.status(500).json({
        success: false,
        message: 'Referral details are temporarily unavailable.',
      });
    }
  },
);

app.post(
  '/rewards/referral/redeem',
  dailyBonusIpLimiter,
  verifyAppCheck,
  verifyFirebaseUser,
  async (request, response) => {
    if (!hasOnlyKeys(request.body, ['code'])) {
      return response.status(400).json({
        success: false,
        message: 'Invalid request.',
      });
    }
    try {
      const result = await redeemReferralCode(
        request.firebaseUser.uid,
        request.body.code,
        request.firebaseUser,
      );
      return response.json({
        success: true,
        ...result,
        message:
          `Referral linked. Complete ${result.qualifyingAds} verified ads ` +
          'to unlock the reward.',
      });
    } catch (error) {
      console.warn('Referral redeem rejected:', error.message);
      return response.status(error.statusCode || 400).json({
        success: false,
        message: error.message || 'Unable to use this referral code.',
      });
    }
  },
);

app.post(
  '/rewards/promo/redeem',
  dailyBonusIpLimiter,
  verifyAppCheck,
  verifyFirebaseUser,
  async (request, response) => {
    if (!hasOnlyKeys(request.body, ['code'])) {
      return response.status(400).json({
        success: false,
        message: 'Invalid request.',
      });
    }
    try {
      const result = await redeemPromoCode(
        request.firebaseUser.uid,
        request.body.code,
        request.firebaseUser,
      );
      return response.json({
        success: true,
        ...result,
        message: `Promo applied: +${result.coins} coin${
          result.coins === 1 ? '' : 's'
        }.`,
      });
    } catch (error) {
      console.warn('Promo redeem rejected:', error.message);
      return response.status(error.statusCode || 400).json({
        success: false,
        message: error.message || 'Unable to use this promo code.',
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
    const referralResult = await finalizeQualifiedReferral(callback.uid);
    console.info('Verified AdMob reward callback processed:', {
      transactionId: callback.transactionId,
      credited: result.credited,
      duplicate: result.duplicate,
      limited: result.limited || false,
      referralQualified: referralResult.qualified,
    });
    return response.status(200).send('OK');
  } catch (error) {
    console.warn('Rejected AdMob reward callback:', error.message);
    return response.status(400).send('Invalid callback');
  }
});

app.get('/bitlabs/reward', async (request, response) => {
  if (!BITLABS_ENABLED) {
    return response.status(503).send('Provider disabled');
  }
  try {
    const forwardedProtocol = String(
      request.headers['x-forwarded-proto'] || request.protocol,
    )
      .split(',')[0]
      .trim();
    const forwardedHost = String(
      request.headers['x-forwarded-host'] || request.get('host'),
    )
      .split(',')[0]
      .trim();
    const fullUrl =
      `${forwardedProtocol}://${forwardedHost}${request.originalUrl}`;
    const callback = verifyBitLabsCallback(fullUrl, BITLABS_APP_SECRET);
    const result = await grantBitLabsOfferReward(callback);
    console.info('Verified BitLabs reward callback processed:', {
      transactionId: callback.transactionId,
      credited: result.credited,
      duplicate: result.duplicate,
    });
    return response.status(200).send('OK');
  } catch (error) {
    console.warn('Rejected BitLabs reward callback:', error.message);
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
  nextDailyStreak,
  previousUtcDay,
  referralCodeForUid,
  utcDay,
  validRewardCode,
  validIndianMobile,
  validOtp,
  validFirebaseUid,
  normalizeAdMobTimestamp,
  bitLabsSignature,
  stripBitLabsHash,
  verifyBitLabsCallback,
  verifyEcdsaSignature,
};
