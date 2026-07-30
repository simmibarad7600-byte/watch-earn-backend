'use strict';

const crypto = require('node:crypto');
const test = require('node:test');
const assert = require('node:assert/strict');

// The production module validates Railway secrets during startup. These unit
// tests provide harmless local placeholders and never start the HTTP listener.
const { privateKey, publicKey } = crypto.generateKeyPairSync('ec', {
  namedCurve: 'prime256v1',
});
process.env.FAST2SMS_API_KEY = 'test-only';
process.env.FIREBASE_SERVICE_ACCOUNT_BASE64 = Buffer.from(
  JSON.stringify({
    project_id: 'watch-and-earn-28a25',
    client_email: 'test@example.invalid',
    private_key: privateKey.export({ type: 'pkcs8', format: 'pem' }),
  }),
).toString('base64');

const {
  nextDailyStreak,
  bitLabsSignature,
  normalizeAdMobTimestamp,
  referralCodeForUid,
  stripBitLabsHash,
  validFirebaseUid,
  validIndianMobile,
  validOtp,
  validRewardCode,
  verifyBitLabsCallback,
  verifyEcdsaSignature,
} = require('./hardened-server');

test('validates Indian mobile and OTP formats', () => {
  assert.equal(validIndianMobile('7600140353'), true);
  assert.equal(validIndianMobile('1234567890'), false);
  assert.equal(validOtp('123456'), true);
  assert.equal(validOtp('12345a'), false);
});

test('validates Firebase user IDs used by signed reward callbacks', () => {
  assert.equal(validFirebaseUid('phone_917600140353'), true);
  assert.equal(validFirebaseUid('user/other'), false);
  assert.equal(validFirebaseUid(''), false);
});

test('normalizes seconds, milliseconds, and microseconds', () => {
  assert.equal(normalizeAdMobTimestamp('1700000000'), 1700000000000);
  assert.equal(normalizeAdMobTimestamp('1700000000000'), 1700000000000);
  assert.equal(
    normalizeAdMobTimestamp('1700000000000000'),
    1700000000000,
  );
});

test('verifies an ECDSA signed callback payload without modifying it', () => {
  const payload =
    'ad_network=5450213213286189855&ad_unit=3026961468&' +
    'reward_amount=1&reward_item=Reward&timestamp=1700000000000&' +
    'transaction_id=test_reward_123&user_id=phone_917600140353';
  const signature = crypto
    .sign('sha256', Buffer.from(payload, 'utf8'), privateKey)
    .toString('base64url');

  assert.equal(
    verifyEcdsaSignature(
      publicKey.export({ type: 'spki', format: 'pem' }),
      payload,
      signature,
    ),
    true,
  );
  assert.equal(
    verifyEcdsaSignature(
      publicKey.export({ type: 'spki', format: 'pem' }),
      `${payload}&tampered=1`,
      signature,
    ),
    false,
  );
});

test('verifies BitLabs HMAC callback and rejects tampering', () => {
  const secret = 'bitlabs-test-secret';
  const unsigned =
    'https://example.com/bitlabs/reward?uid=phone_917600140353&' +
    'val=3&raw=0.12&tx=offer_tx_123';
  const signed = `${unsigned}&hash=${bitLabsSignature(unsigned, secret)}`;
  assert.equal(stripBitLabsHash(signed), unsigned);
  assert.deepEqual(verifyBitLabsCallback(signed, secret), {
    uid: 'phone_917600140353',
    transactionId: 'offer_tx_123',
    coins: 3,
    usdValue: 0.12,
  });
  assert.throws(
    () => verifyBitLabsCallback(signed.replace('val=3', 'val=30'), secret),
    /signature/,
  );
});
