const express = require('express');
const cors = require('cors');
const axios = require('axios');

const app = express();
app.use(express.json());
app.use(cors());

// Home route to check if backend is running
app.get('/', (req, res) => {
  res.send('Watch & Earn Backend is Running Successfully!');
});

// Temporary in-memory database (for production, connect MongoDB)
let users = {};

// 1. Send OTP Endpoint with Real Random OTP via Fast2SMS
app.post('/api/auth/send-otp', async (req, res) => {
  const { phoneOrEmail } = req.body;
  if (!phoneOrEmail) {
    return res.status(400).json({ success: false, message: "Phone or Email is required" });
  }

  // Generate a random 4-digit real OTP (1000 to 9999)
  const realOtp = Math.floor(1000 + Math.random() * 9000).toString();
  
  if (!users[phoneOrEmail]) {
    users[phoneOrEmail] = {
      identifier: phoneOrEmail,
      coins: 100, // Welcome bonus
      history: ["Account created with 100 Welcome Coins"]
    };
  }

  // Save the newly generated real OTP to the user session
  users[phoneOrEmail].currentOtp = realOtp;

  // Check if it's a phone number to send real SMS via Fast2SMS
  const isPhone = /^\d{10}$/.test(phoneOrEmail);
  if (isPhone) {
    try {
      await axios.post('https://www.fast2sms.com/dev/bulkV2', {
        route: 'q',
        message: `Your verification code is ${realOtp}`,
        language: 'english',
        flash: 0,
        numbers: phoneOrEmail
      }, {
        headers: {
          'authorization': 'OQXSBzV16Cr2fE3enkgljvcoGd8Wta0HqNJFUuZiTbIxmhALKwsA7wHScbayK3PoMRrq6IgxLYkiQ4Bn',
          'Content-Type': 'application/json'
        }
      });
    } catch (error) {
      console.log("SMS sending failed:", error);
    }
  }

  return res.json({
    success: true,
    message: "Real OTP sent successfully!"
  });
});

// 2. Verify OTP Endpoint
app.post('/api/auth/verify-otp', (req, res) => {
  const { phoneOrEmail, otp } = req.body;
  
  if (!users[phoneOrEmail]) {
    return res.status(400).json({ success: false, message: "User not found. Please request OTP first." });
  }

  // Verify against the actual generated OTP sent to the user
  if (users[phoneOrEmail].currentOtp === otp) {
    return res.json({
      success: true,
      message: "Login successful",
      user: users[phoneOrEmail]
    });
  } else {
    return res.status(400).json({ success: false, message: "Invalid OTP" });
  }
});

// 3. Get Videos Endpoint
app.get('/api/videos', (req, res) => {
  const videos = [
    {"id": 1, "title": "Global Nature Shorts", "videoUrl": "https://www.w3schools.com/html/mov_bbb.mp4"},
    {"id": 2, "title": "Worldwide Tech Trends", "videoUrl": "https://www.w3schools.com/html/mov_bbb.mp4"}
  ];
  return res.json({ success: true, data: videos });
});

// 4. Reward Endpoint (Earn coins on watching video)
app.post('/api/reward', (req, res) => {
  const { userId, videoId } = req.body;

  if (!users[userId]) {
    return res.status(400).json({ success: false, message: "User session not found" });
  }

  users[userId].coins += 15;
  users[userId].history.push(`Earned 15 coins from video ID: ${videoId}`);

  return res.json({
    success: true,
    message: "Reward credited successfully! (+15 Coins)",
    data: users[userId]
  });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
