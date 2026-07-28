# Watch & Earn security policy

## Money protection

- The app never writes balances, rewards, transactions, or withdrawals.
- Rewards stay disabled until the chosen ad network sends signed
  server-to-server proof.
- Provider transaction IDs must be unique and credited atomically.
- The server will enforce per-event, per-day, and platform payout caps.
- Withdrawals are server-created and high-risk accounts require review.
- Balance changes use an append-only ledger, not a client-supplied amount.

Before rewards go live, choose the coin value, maximum rewarded events per day,
maximum daily coins, minimum withdrawal, cooling period, and maximum total
daily payout budget.

## Current controls

- Firebase Admin SDK creates phone sessions and verified phone profiles.
- OTPs expire in five minutes, have limited attempts, are single-use, and are
  throttled by IP plus hashed mobile number.
- App Check tokens are verified. Keep `ENFORCE_APP_CHECK=false` during staged
  rollout, then set it to `true` after valid traffic is visible in Firebase.
- Secrets stay in Railway variables and never in the Flutter app.
- Ad rewards are credited only after verifying AdMob's ECDSA signature.
  Transaction IDs are single-use and rewards have a per-user daily limit.
- The client cannot write wallet balances, reward claims, or transactions.
- Do not treat coins as cash until a separate, reviewed withdrawal service is
  implemented with identity checks, minimum payout, fraud review, and a
  server-side exchange rate.
