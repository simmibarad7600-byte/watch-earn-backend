'use strict';

const crypto = require('node:crypto');
const express = require('express');
const cors = require('cors');

const PORT = Number(process.env.PORT || 8080);
const FIREBASE_PROJECT_ID =
  process.env.FIREBASE_PROJECT_ID || 'watch-and-earn-28a25';
const FRONTEND_ORIGINS = (process.env.FRONTEND_ORIGINS || '')
  .split(',')
  .map((value) => value.trim().replace(/\/$/, ''))
  .filter(Boolean);

const app = express();
app.set('trust proxy', 1);
app.disable('x-powered-by');
app.use(express.json({ limit: '16kb' }));
app.use((_request, response, next) => {
  response.set({
    'Cache-Control': 'no-store',
    'Content-Security-Policy': "default-src 'none'",
    'Referrer-Policy': 'no-referrer',
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
  });
  next();
});
app.use(
  cors({
    origin(origin, callback) {
      if (!origin) return callback(null, true);

      try {
        const hostname = new URL(origin).hostname;
        const isLocal = hostname === 'localhost' || hostname === '127.0.0.1';
        const isConfigured = FRONTEND_ORIGINS.includes(
          origin.replace(/\/$/, ''),
        );
        return callback(null, isLocal || isConfigured);
      } catch {
        return callback(new Error('Invalid request origin'));
      }
    },
    methods: ['GET', 'POST'],
  }),
);

const attempts = new Map();
const otpRecords = new Map();

function rateLimit({ windowMs, limit, message }) {
  return (request, response, next) => {
    const now = Date.now();
    const key = `${request.ip}:${request.path}`;
    const current = attempts.get(key);

    if (!current || current.resetAt <= now) {
      attempts.set(key, { count: 1, resetAt: now + windowMs });
      return next();
    }

    current.count += 1;
    if (current.count > limit) {
      return response.status(429).json({ success: false, message });
    }
    return next();
  };
}

const sendOtpLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 5,
  message: 'Too many OTP requests. Please try again later.',
});

const verifyOtpLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  message: 'Too many OTP attempts. Please try again later.',
});

function validIndianMobile(value) {
  return /^[6-9]\d{9}$/.test(String(value || ''));
}

function validOtp(value) {
  return /^\d{6}$/.test(String(value || ''));
}

function requireOtpConfiguration() {
  if (!process.env.FAST2SMS_API_KEY) {
    const error = new Error('OTP service is not configured yet.');
    error.statusCode = 503;
    error.logMessage = 'Missing Railway variable: FAST2SMS_API_KEY';
    throw error;
  }
}

function hashOtp(mobile, otp, salt) {
  return crypto
    .createHash('sha256')
    .update(`${mobile}:${otp}:${salt}`)
    .digest();
}

function storeOtp(mobile, otp) {
  const salt = crypto.randomBytes(16).toString('hex');
  otpRecords.set(mobile, {
    salt,
    hash: hashOtp(mobile, otp, salt),
    expiresAt: Date.now() + 5 * 60 * 1000,
    attempts: 0,
  });
}

function verifyStoredOtp(mobile, otp) {
  const record = otpRecords.get(mobile);
  if (!record) {
    const error = new Error('Request a new OTP first.');
    error.statusCode = 400;
    throw error;
  }

  if (record.expiresAt <= Date.now()) {
    otpRecords.delete(mobile);
    const error = new Error('OTP has expired. Request a new OTP.');
    error.statusCode = 400;
    throw error;
  }

  record.attempts += 1;
  const suppliedHash = hashOtp(mobile, otp, record.salt);
  if (!crypto.timingSafeEqual(record.hash, suppliedHash)) {
    if (record.attempts >= 5) otpRecords.delete(mobile);
    const error = new Error('Incorrect OTP.');
    error.statusCode = 400;
    throw error;
  }
}

function getServiceAccount() {
  const encoded = process.env.FIREBASE_SERVICE_ACCOUNT_BASE64;
  if (!encoded) {
    const error = new Error('Phone login is not configured yet.');
    error.statusCode = 503;
    error.logMessage =
      'Missing Railway variable: FIREBASE_SERVICE_ACCOUNT_BASE64';
    throw error;
  }

  try {
    const serviceAccount = JSON.parse(
      Buffer.from(encoded, 'base64').toString('utf8'),
    );
    if (!serviceAccount.client_email || !serviceAccount.private_key) {
      throw new Error('Required service-account fields are missing.');
    }
    if (
      serviceAccount.project_id &&
      serviceAccount.project_id !== FIREBASE_PROJECT_ID
    ) {
      throw new Error('Service account belongs to a different Firebase project.');
    }
    return serviceAccount;
  } catch (cause) {
    const error = new Error('Firebase server credentials are invalid.');
    error.statusCode = 503;
    error.logMessage = cause.message;
    throw error;
  }
}

function base64UrlJson(value) {
  return Buffer.from(JSON.stringify(value)).toString('base64url');
}

function createFirebaseCustomToken(uid) {
  const serviceAccount = getServiceAccount();
  const now = Math.floor(Date.now() / 1000);
  const header = base64UrlJson({ alg: 'RS256', typ: 'JWT' });
  const payload = base64UrlJson({
    iss: serviceAccount.client_email,
    sub: serviceAccount.client_email,
    aud:
      'https://identitytoolkit.googleapis.com/google.identity.identitytoolkit.v1.IdentityToolkit',
    iat: now,
    exp: now + 60 * 60,
    uid,
    claims: { phone_verified: true },
  });
  const unsignedToken = `${header}.${payload}`;
  const signature = crypto
    .sign('RSA-SHA256', Buffer.from(unsignedToken), serviceAccount.private_key)
    .toString('base64url');
  return `${unsignedToken}.${signature}`;
}

async function fast2smsRequest(endpoint, body) {
  requireOtpConfiguration();

  const response = await fetch(`https://www.fast2sms.com${endpoint}`, {
    method: 'POST',
    headers: {
      Authorization: process.env.FAST2SMS_API_KEY,
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
    error.statusCode = response.status >= 400 ? response.status : 400;
    throw error;
  }
  return data;
}

app.get('/', (_request, response) => {
  response.json({ success: true, service: 'watch-earn-otp' });
});

app.get('/health', (_request, response) => {
  response.json({ success: true, service: 'watch-earn-otp' });
});

app.post('/otp/send', sendOtpLimiter, async (request, response) => {
  const mobile = String(request.body.mobile || '').trim();
  if (!validIndianMobile(mobile)) {
    return response.status(400).json({
      success: false,
      message: 'Enter a valid 10-digit Indian mobile number.',
    });
  }

  try {
    let result;
    if (process.env.FAST2SMS_OTP_ID) {
      result = await fast2smsRequest('/dev/otp/send', {
        mobile,
        otp_id: process.env.FAST2SMS_OTP_ID,
        otp_expiry: 5,
        otp_length: 6,
      });
    } else {
      const otp = crypto.randomInt(100000, 1000000).toString();
      result = await fast2smsRequest('/dev/bulkV2', {
        route: 'q',
        message:
          `Your Watch & Earn OTP is ${otp}. ` +
          'It expires in 5 minutes. Do not share it.',
        numbers: mobile,
      });
      storeOtp(mobile, otp);
    }
    return response.json({
      success: true,
      requestId: result.request_id || null,
      message: 'OTP sent successfully.',
    });
  } catch (error) {
    console.error(error.logMessage || error.message);
    return response.status(error.statusCode || 502).json({
      success: false,
      message: error.message || 'Unable to send OTP.',
    });
  }
});

app.post('/otp/verify', verifyOtpLimiter, async (request, response) => {
  const mobile = String(request.body.mobile || '').trim();
  const otp = String(request.body.otp || '').trim();

  if (!validIndianMobile(mobile) || !validOtp(otp)) {
    return response.status(400).json({
      success: false,
      message: 'Mobile number or OTP is invalid.',
    });
  }

  try {
    if (process.env.FAST2SMS_OTP_ID) {
      await fast2smsRequest('/dev/otp/verify', { mobile, otp });
    } else {
      verifyStoredOtp(mobile, otp);
    }
    const uid = `phone_91${mobile}`;
    const customToken = createFirebaseCustomToken(uid);
    if (!process.env.FAST2SMS_OTP_ID) otpRecords.delete(mobile);
    return response.json({
      success: true,
      customToken,
      phoneNumber: `+91${mobile}`,
      message: 'OTP verified successfully.',
    });
  } catch (error) {
    console.error(error.logMessage || error.message);
    return response.status(error.statusCode || 400).json({
      success: false,
      message: error.message || 'OTP verification failed.',
    });
  }
});

app.use((_request, response) => {
  response.status(404).json({ success: false, message: 'Route not found.' });
});

app.use((error, _request, response, _next) => {
  console.error(error.message);
  response.status(500).json({
    success: false,
    message: 'Internal server error.',
  });
});

app.listen(PORT, () => {
  console.log(`OTP backend listening on port ${PORT}`);
});
