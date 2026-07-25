const express = require('express');
const cors = require('cors');

const app = express();
app.use(express.json());
app.use(cors());

let users = {};
let otpStore = {};
let requestLogs = {};

// Video Feed Database (Default videos + User uploaded videos)
let videos = [
  { id: 1, title: "Amazing Nature Shorts", videoUrl: "https://www.w3schools.com/html/mov_bbb.mp4", uploader: "admin" },
  { id: 2, title: "Tech Tips & Tricks", videoUrl: "https://www.w3schools.com/html/mov_bbb.mp4", uploader: "admin" }
];

// Security Middleware
const securityShield = (req, res, next) => {
  const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
  const now = Date.now();

  if (!requestLogs[ip]) {
    requestLogs[ip] = { count: 1, lastRequest: now };
  } else {
    const timeDiff = now - requestLogs[ip].lastRequest;
    if (timeDiff < 500) {
      return res.status(403).json({ success: false, message: "Security Alert: Automated Bot detected!" });
    }
    requestLogs[ip].count++;
    requestLogs[ip].lastRequest = now;
  }
  next();
};

app.use(securityShield);

// Step 1: Send OTP API
app.post('/api/auth/send-otp', (req, res) => {
  const { identifier } = req.body;
  if (!identifier || identifier.trim() === "") {
    return res.status(400).json({ success: false, message: "Please enter a valid Email or Phone Number" });
  }

  const otp = Math.floor(1000 + Math.random() * 9000).toString();
  otpStore[identifier] = otp;

  console.log(`[SECURE OTP FOR ${identifier}]: ${otp}`);
  res.json({ success: true, message: `OTP sent successfully! (Demo OTP: ${otp})` });
});

// Step 2: Verify OTP & Login/Register
app.post('/api/auth/verify-otp', (req, res) => {
  const { identifier, otp, referralCode } = req.body;
  
  if (!otpStore[identifier] || otpStore[identifier] !== otp) {
    return res.status(400).json({ success: false, message: "Invalid or Expired OTP!" });
  }

  if (!users[identifier]) {
    users[identifier] = { 
      userId: identifier, 
      coins: 50, 
      lastClaimTime: 0, 
      lastCheckInDate: "",
      history: ["Account created with 50 Welcome Coins"] 
    };

    if (referralCode && users[referralCode] && referralCode !== identifier) {
      users[identifier].coins += 25;
      users[identifier].history.unshift("Bonus +25 coins for using referral code");

      users[referralCode].coins += 50;
      users[referralCode].history.unshift(`Referral bonus! Earned +50 coins from ${identifier}`);
    }
  }

  delete otpStore[identifier];
  res.json({ success: true, message: "Login successful", data: users[identifier] });
});

// Get User Profile
app.get('/api/user/:userId', (req, res) => {
  const userId = req.params.userId;
  if (!users[userId]) {
    users[userId] = { userId: userId, coins: 50, lastClaimTime: 0, lastCheckInDate: "", history: [] };
  }
  res.json({ success: true, data: users[userId] });
});

// Get All Videos API
app.get('/api/videos', (req, res) => {
  res.json({ success: true, data: videos });
});

// Upload Video API (Creator Revenue Share)
app.post('/api/upload-video', (req, res) => {
  const { userId, title, videoUrl } = req.body;
  if (!users[userId]) return res.status(400).json({ success: false, message: "User not found" });
  if (!title || !videoUrl) return res.status(400).json({ success: false, message: "Title and Video URL are required" });

  const newVideo = {
    id: videos.length + 1,
    title: title,
    videoUrl: videoUrl,
    uploader: userId
  };

  videos.unshift(newVideo);
  users[userId].history.unshift(`Uploaded video: "${title}" (Creator Program Active)`);

  res.json({ success: true, message: "Video uploaded successfully! You will earn commission when others watch it.", data: newVideo });
});

// Reward Claim with Creator Commission Share
app.post('/api/reward', (req, res) => {
  const { userId, videoId, earnedCoins } = req.body;
  if (!users[userId]) return res.status(400).json({ success: false, message: "User not found" });

  const currentTime = Date.now();
  const timeDifference = (currentTime - users[userId].lastClaimTime) / 1000;

  if (users[userId].lastClaimTime !== 0 && timeDifference < 9.5) {
    return res.status(403).json({ success: false, message: "Cheat Detected! Request blocked." });
  }

  const viewerReward = 10;
  const creatorCommission = 5;

  users[userId].coins += viewerReward;
  users[userId].lastClaimTime = currentTime;
  users[userId].history.unshift(`Watched video & earned +${viewerReward} coins`);

  // Find video and give commission to uploader if it belongs to a user
  const targetVideo = videos.find(v => v.id === videoId);
  if (targetVideo && targetVideo.uploader !== "admin" && users[targetVideo.uploader]) {
    users[targetVideo.uploader].coins += creatorCommission;
    users[targetVideo.uploader].history.unshift(`Creator earnings! Earned +${creatorCommission} coins from your video "${targetVideo.title}"`);
  }

  res.json({ success: true, message: "Coins added securely!", data: users[userId] });
});

// Daily Check-in Bonus API
app.post('/api/daily-checkin', (req, res) => {
  const { userId } = req.body;
  if (!users[userId]) return res.status(400).json({ success: false, message: "User not found" });

  const today = new Date().toDateString();
  if (users[userId].lastCheckInDate === today) {
    return res.status(403).json({ success: false, message: "Daily bonus already claimed today!" });
  }

  users[userId].coins += 50;
  users[userId].lastCheckInDate = today;
  users[userId].history.unshift("Claimed Daily Check-in Bonus (+50 Coins)");

  res.json({ success: true, message: "Daily bonus claimed successfully!", data: users[userId] });
});

// Withdrawal API
app.post('/api/withdraw', (req, res) => {
  const { userId, upiId, coinsToWithdraw } = req.body;
  if (!users[userId]) return res.status(400).json({ success: false, message: "User not found" });

  if (users[userId].coins < coinsToWithdraw) {
    return res.status(403).json({ success: false, message: "Insufficient balance!" });
  }

  users[userId].coins -= coinsToWithdraw;
  users[userId].history.unshift(`Withdrew ${coinsToWithdraw} coins to UPI: ${upiId}`);

  res.json({ success: true, message: `Successfully withdrew to UPI: ${upiId}`, data: users[userId] });
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Creator Economy & Secure Server running on port ${PORT}`);
});
