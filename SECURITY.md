# Watch & Earn security policy

## In-app points protection

- The app never writes point balances, rewards, or transactions.
- Rewards stay disabled until the chosen ad network sends signed
  server-to-server proof.
- Provider transaction IDs must be unique and credited atomically.
- The server enforces per-event and per-day reward caps.
- Points are non-transferable, usable only inside the app, and have no cash
  value.
- Balance changes use an append-only ledger, not a client-supplied amount.

Before rewards go live, choose the in-app point value, maximum rewarded events
per day, maximum daily points, and the point thresholds for in-app benefits.

## Current controls

- Firebase Admin SDK creates phone sessions and verified phone profiles.
- OTPs expire in five minutes, have limited attempts, are single-use, and are
  throttled by IP plus hashed mobile number.
- App Check tokens are verified. Keep `ENFORCE_APP_CHECK=false` during staged
  rollout, then set it to `true` after valid traffic is visible in Firebase.
- Secrets stay in Railway variables and never in the Flutter app.
- Ad rewards are credited only after verifying AdMob's ECDSA signature.
  Transaction IDs are single-use and rewards have a per-user daily limit.
- The client cannot write point balances, reward claims, or transactions.
- Never convert points into cash, gift cards, cryptocurrency, or transferable
  items.

## Separate verified cash rewards

- Cash never comes from AdMob, games, XP, daily check-ins, promo codes, or the
  in-app point balance.
- Cash claims are created only after a supported survey/offer provider sends a
  valid signed server callback.
- Cash uses separate `cashWallets`, `cashClaims`, and `cashTransactions`
  records with unique provider transaction IDs.
- Provider reversals deduct pending/available balances and record debt when a
  paid or available reward can no longer be recovered.
- The cash earn hub remains disabled until written provider permission,
  settlement rules, payout compliance, and staged anti-fraud tests are done.
