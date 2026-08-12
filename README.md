# Watch & Earn backend

Railway service for India-only Fast2SMS OTP login, verified AdMob point
rewards, and provider-verified cash offer rewards.

## Railway variables

Copy the names from `.env.example` into Railway Variables. Keep all real
credentials in Railway; never place them in Flutter, GitHub, screenshots, or
chat.

`ENFORCE_APP_CHECK` must remain `false` until valid App Check traffic has been
confirmed for every supported client. Then turn it on to reject requests from
unverified app installations.

The AdMob rewarded ad unit callback URL is:

`https://watch-earn-rewards-api-28a25-production.up.railway.app/admob/reward`

The CPX Research Main Postback URL is:

`https://watch-earn-rewards-api-28a25-production.up.railway.app/cpx/reward?status={status}&trans_id={trans_id}&user_id={user_id}&amount_local={amount_local}&amount_usd={amount_usd}&offer_id={offer_ID}&type={type}&hash={secure_hash}`

Keep `CPX_ENABLED` and `CASH_EARN_HUB_ENABLED` false until the CPX dashboard
App ID and secure hash are configured and completion plus reversal tests pass.

## Safety model

- The app receives no authority to add in-app points.
- AdMob callbacks are verified with Google's rotating ECDSA public keys.
- Each AdMob transaction can be used only once.
- A user can receive at most `DAILY_REWARD_LIMIT` verified rewards per UTC day.
- Point balance, transaction, and claim writes are server-only.
- Points are non-transferable, usable only inside the app, and have no cash
  value. They can never be converted or withdrawn.
- Cash rewards use a separate USD wallet and ledger. They are created only by
  signed third-party callbacks, remain pending during the provider hold and
  settlement process, and support signed reversals.
- `CASH_EARN_HUB_ENABLED` stays `false` until the provider gives written
  approval and the complete callback/reversal flow passes staged testing.
- Payouts and withdrawals remain disabled until a compliant payout provider,
  identity checks, minimum balance, and operational review are configured.

## Checks

Run `npm test`, `npm run check`, and `npm audit --omit=dev` before deployment.
