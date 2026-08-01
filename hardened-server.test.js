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
  ayetSignature,
  bitLabsSignature,
  calculateAyetUserReward,
  calculateMemoryScore,
  decimalUsdToMicros,
  isTestRewardUid,
  normalizeAdMobTimestamp,
  missionClaimId,
  missionPeriod,
  missionProgress,
  missionTarget,
  referralCodeForUid,
  stripBitLabsHash,
  triviaScore,
  testRewardDocumentIds,
  validFirebaseUid,
  validIndianMobile,
  validOtp,
  validRewardCode,
  verifyAyetCallback,
  verifyBitLabsCallback,
  verifyEcdsaSignature,
  utcWeekKey,
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

test('calculates daily and weekly mission progress on UTC periods', () => {
  const now = Date.parse('2026-08-01T12:00:00Z');
  const wallet = {
    dailyBonusLastClaimDate: '2026-08-01',
    dailyRewardDate: '2026-08-01',
    dailyRewardCount: 3,
    weeklyRewardWeek: utcWeekKey(now),
    weeklyRewardCount: 7,
  };
  assert.equal(missionProgress(wallet, 'daily_check_in', now), 1);
  assert.equal(missionProgress(wallet, 'daily_three_ads', now), 3);
  assert.equal(missionProgress(wallet, 'weekly_ten_ads', now), 7);
  assert.equal(missionTarget('weekly_ten_ads'), 10);
  assert.equal(missionPeriod('daily_one_ad', now), '2026-08-01');
  assert.match(
    missionClaimId('user_12345678', 'daily_one_ad', now),
    /user_12345678_daily_one_ad_2026-08-01/,
  );
});

test('calculates bounded memory scores on the server', () => {
  assert.equal(calculateMemoryScore(10, 30), 1180);
  assert.equal(calculateMemoryScore(100, 900), 100);
  assert.equal(calculateMemoryScore(1, 1), 1360);
});

test('scores trivia answers from server-owned answer keys', () => {
  assert.equal(
    triviaScore(['red_planet', 'india_capital', 'plant_gas'], [1, 0, 2]),
    2,
  );
  assert.equal(triviaScore(['unknown'], [1]), 0);
  assert.equal(triviaScore(null, []), 0);
});

test('keeps developer test rewards disabled without an allowlist', () => {
  assert.equal(isTestRewardUid('user_12345678'), false);
  const ids = testRewardDocumentIds(
    'user_12345678',
    Date.parse('2026-08-01T12:00:00Z'),
  );
  assert.equal(ids.length, 3);
  assert.match(ids[0], /daily_one_ad_2026-08-01$/);
  assert.match(ids[2], /weekly_ten_ads_2026-07-27$/);
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

test('converts USD decimals to integer micros without floating point', () => {
  assert.equal(decimalUsdToMicros('0'), 0);
  assert.equal(decimalUsdToMicros('0.36'), 360_000);
  assert.equal(decimalUsdToMicros('12.345678'), 12_345_678);
  assert.equal(decimalUsdToMicros('-0.36'), -360_000);
  assert.throws(() => decimalUsdToMicros('0.1234567'), /Invalid USD/);
  assert.throws(() => decimalUsdToMicros('1e2'), /Invalid USD/);
});

test('calculates bounded ayeT user revenue share in integer micros', () => {
  assert.equal(calculateAyetUserReward(360_000, 5000), 180_000);
  assert.equal(calculateAyetUserReward(1, 5000), 0);
  assert.throws(
    () => calculateAyetUserReward(360_000, 10000),
    /configuration/,
  );
});

test('verifies ayeT HMAC callbacks and rejects payout tampering', () => {
  const secret = 'ayet-test-api-key';
  const unsigned =
    'https://example.com/ayet/reward?placement_identifier=placement_test&' +
    'currency_amount=25.2&transaction_id=offer_tx_456&is_chargeback=0&' +
    'payout_usd=0.36&external_identifier=phone_917600140353';
  const signature = ayetSignature(unsigned, secret);
  assert.deepEqual(verifyAyetCallback(unsigned, signature, secret, 5000), {
    uid: 'phone_917600140353',
    transactionId: 'offer_tx_456',
    originalTransactionId: 'offer_tx_456',
    placementIdentifier: 'placement_test',
    payoutUsdMicros: 360_000,
    userRewardUsdMicros: 180_000,
    isChargeback: false,
    isSandbox: false,
  });
  assert.throws(
    () =>
      verifyAyetCallback(
        unsigned.replace('payout_usd=0.36', 'payout_usd=3.60'),
        signature,
        secret,
        5000,
      ),
    /signature/,
  );
});

test('verifies ayeT reversal and sandbox callbacks', () => {
  const secret = 'ayet-test-api-key';
  const reversal =
    'https://example.com/ayet/reward?transaction_id=r-offer_tx_456&' +
    'external_identifier=phone_917600140353&payout_usd=-0.36&' +
    'placement_identifier=placement_test&is_chargeback=1';
  assert.deepEqual(
    verifyAyetCallback(
      reversal,
      ayetSignature(reversal, secret),
      secret,
      5000,
    ),
    {
      uid: 'phone_917600140353',
      transactionId: 'r-offer_tx_456',
      originalTransactionId: 'offer_tx_456',
      placementIdentifier: 'placement_test',
      payoutUsdMicros: -360_000,
      userRewardUsdMicros: 180_000,
      isChargeback: true,
      isSandbox: false,
    },
  );

  const sandbox =
    'https://example.com/ayet/reward?transaction_id=sandbox_tx_1&' +
    'external_identifier=phone_917600140353&payout_usd=0&' +
    'placement_identifier=placement_test&is_chargeback=0&is_sandbox=1';
  const parsedSandbox = verifyAyetCallback(
    sandbox,
    ayetSignature(sandbox, secret),
    secret,
    5000,
  );
  assert.equal(parsedSandbox.isSandbox, true);
  assert.equal(parsedSandbox.userRewardUsdMicros, 0);
});
