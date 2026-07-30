# Watch & Earn backend

Railway service for India-only Fast2SMS OTP login and verified AdMob rewards.

## Railway variables

Copy the names from `.env.example` into Railway Variables. Keep all real
credentials in Railway; never place them in Flutter, GitHub, screenshots, or
chat.

`ENFORCE_APP_CHECK` must remain `false` until valid App Check traffic has been
confirmed for every supported client. Then turn it on to reject requests from
unverified app installations.

The AdMob rewarded ad unit callback URL is:

`https://watch-earn-backend-production.up.railway.app/admob/reward`

## Safety model

- The app receives no authority to add in-app points.
- AdMob callbacks are verified with Google's rotating ECDSA public keys.
- Each AdMob transaction can be used only once.
- A user can receive at most `DAILY_REWARD_LIMIT` verified rewards per UTC day.
- Point balance, transaction, and claim writes are server-only.
- Points are non-transferable, usable only inside the app, and have no cash
  value. Cash, gift-card, cryptocurrency, and withdrawal rewards are not
  supported.

## Checks

Run `npm test`, `npm run check`, and `npm audit --omit=dev` before deployment.
