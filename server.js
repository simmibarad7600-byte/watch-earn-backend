const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');

const app = express();
app.use(cors());
app.use(bodyParser.json());

// In-memory Database for Demo
const users = {};
const videos = [
  { id: 1, title: "Global Nature Shorts", videoUrl: "https://www.w3schools.com/html/mov_bbb.mp4", uploader: "admin" },
  { id: 2, title: "Worldwide Tech Trends", videoUrl: "https://www.w3schools.com/html/mov_bbb.mp4", uploader: "admin" }
];

// Send OTP Endpoint
app.post('/api/auth/send-otp', (req, res) => {
  const { phoneOrEmail } = req.body;
  if (!phoneOrEmail) {
    return res.status(400).json({ success: false, message: "Phone or Email is required" });
  }

  // Generate a dummy 4-digit OTP for testing
  const demoOtp = "9250";
  
  if (!users[phoneOrEmail]) {
    users[phoneOrEmail] = {
      identifier: phoneOrEmail,
      coins: 100, // Welcome bonus
      history: ["Account created with 100 Welcome Coins ($0.10)"]
    };
  }

  res.json({
    success: true,
    message: `OTP sent successfully! (Demo OTP: ${demoOtp})`,
    demoOtp: demoOtp
  });
});

// Verify OTP & Login Endpoint
app.post('/api/auth/verify-otp', (req, res) => {
  const { phoneOrEmail, otp } = req.body;
  if (otp !== "9250") {
    return res.status(400).json({ success: false, message: "Invalid OTP" });
  }

  const userData = users[phoneOrEmail] || {
    identifier: phoneOrEmail,
    coins: 100,
    history: ["Account created with 100 Welcome Coins ($0.10)"]
  };

  res.json({
    success: true,
    message: "Login successful!",
    user: userData
  });
});

// Google Login Endpoint
app.post('/api/auth/google-login', (req, res) => {
  const { email, name } = req.body;
  if (!email) {
    return res.status(400).json({ success: false, message: "Email required" });
  }

  if (!users[email]) {
    users[email] = {
      identifier: email,
      name: name || "Google User",
      coins: 100,
      history: ["Google Account created with 100 Welcome Coins ($0.10)"]
    };
  }

  res.json({
    success: true,
    message: "Google Login successful!",
    user: users[email]
  });
});

// Get Videos Endpoint
app.get('/api/videos', (req, res) => {
  res.json({ success: true, data: videos });
});

// International Payout / Redemption API
app.post('/api/withdraw', (req, res) => {
  const { userId, payoutMethod, destinationAccount, coinsToWithdraw } = req.body;
  if (!users[userId]) return res.status(400).json({ success: false, message: "User not found" });

  const minWithdrawal = 1000;
  if (users[userId].coins < coinsToWithdraw || coinsToWithdraw < minWithdrawal) {
    return res.status(403).json({ success: false, message: `Minimum withdrawal is ${minWithdrawal} coins!` });
  }

  users[userId].coins -= coinsToWithdraw;
  const usdValue = (coinsToWithdraw / 1000).toFixed(2);
  users[userId].history.unshift(`Requested payout of ${coinsToWithdraw} coins ($${usdValue}) via ${payoutMethod}: ${destinationAccount}`);

  res.json({
    success: true,
    message: `Payout request of $${usdValue} via ${payoutMethod} submitted successfully!`,
    data: users[userId]
  });
});

const PORT = process.env.PORT || 8080;
app.listen(PORT, '0.0.0.0', () => {
  console.log(`Global WHAFF-Style Reward Server running on port ${PORT}`);
});
