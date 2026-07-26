const express = require('express');
const cors = require('cors');

const app = express();
app.use(express.json());
app.use(cors());

let users = {};
let otpStore = {};

// Video Feed Database
let videos = [
  { id: 1, title: "Global Nature Shorts", videoUrl: "https://www.w3schools.com/html/mov_bbb.mp4", uploader: "admin" },
  { id: 2, title: "Worldwide Tech Trends", videoUrl: "https://www.w3schools.com/html/mov_bbb.mp4", uploader: "admin" }
];

// Global Offer Wall Tasks (WHAFF style app installs / tasks)
let globalOffers = [
  { id: 101, title: "Install & Register Social App", reward: 150, packageName: "com.social.app", type: "app_install" },
  { id: 102, title: "Play Fantasy Game Level 5", reward: 300, packageName: "com.game.fantasy", type: "game_task" },
  { id: 103, title: "Complete Global Market Survey", reward: 100, packageName: "survey_portal", type: "survey" }
];

// Step 1: Send OTP API
app.post('/api/auth/send-otp', (req, res) => {
  const { identifier } = req.body;
  if (!identifier || identifier.trim() === "") {
    return res.status(400).json({ success: false, message: "Please enter a valid Email or Phone Number" });
  }

  const otp = Math.floor(1000 + Math.random() * 9000).toString();
  otpStore[identifier] = otp;

  console.log(`[GLOBAL OTP FOR ${identifier}]: ${otp}`);
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
      coins: 100, 
      usdBalance: 0.10, 
      lastClaimTime: 0, 
      lastCheckInDate: "",
      streakCount: 0,
      completedOffers: [],
      history: ["Account created with 100 Welcome Coins ($0.10)"] 
    };

    if (referralCode && users[referralCode] && referralCode !== identifier) {
      users[identifier].coins += 50;
      users[identifier].history.unshift("Bonus +50 coins for using global referral code");

      users[referralCode].coins += 100;
      users[referralCode].history.unshift(`Global referral bonus! Earned +100 coins from ${identifier}`);
    }
  }

  delete otpStore[identifier];
  res.json({ success: true, message: "Login successful", data: users[identifier] });
});

// New: Google / Social Login API (International 1-Click Login)
app.post('/api/auth/social-login', (req, res) => {
  const { email, name, provider, referralCode } = req.body;
  
  if (!email) {
    return res.status(400).json({ success: false, message: "Email is required for social login" });
  }

  const userId = email;

  if (!users[userId]) {
    users[userId] = { 
      userId: userId, 
      name: name || "Global User",
      provider: provider || "Google",
      coins: 100, // Welcome bonus for social login
      usdBalance: 0.10, 
      lastClaimTime: 0, 
      lastCheckInDate: "",
      streakCount: 0,
      completedOffers: [],
      history: [`Account created via ${provider || 'Google'} with 100 Welcome Coins`] 
    };

    if (referralCode && users[referralCode] && referralCode !== userId) {
      users[userId].coins += 50;
      users[userId].history.unshift("Bonus +50 coins for using global referral code");

      users[referralCode].coins += 100;
      users[referralCode].history.unshift(`Global referral bonus! Earned +100 coins from ${userId}`);
    }
  }

  res.json({ success: true, message: `Logged in successfully via ${provider || 'Google'}`, data: users[userId] });
});

// Get User Profile & Global Wallet Status
app.get('/api/user/:userId', (req, res) => {
  const userId = req.params.userId;
  if (!users[userId]) {
    users[userId] = { userId: userId, coins: 100, usdBalance: 0.10, lastClaimTime: 0, lastCheckInDate: "", streakCount: 0, completedOffers: [], history: [] };
  }
  res.json({ success: true, data: users[userId] });
});

// Get Videos Feed
app.get('/api/videos', (req, res) => {
  res.json({ success: true, data: videos });
});

// Get Global Offer Wall Tasks
app.get('/api/offers', (req, res) => {
  res.json({ success: true, data: globalOffers });
});

// Complete Offer Task
app.post('/api/complete-offer', (req, res) => {
  const { userId, offerId } = req.body;
  if (!users[userId]) return res.status(400).json({ success: false, message: "User not found" });

  const offer = globalOffers.find(o => o.id === offerId);
  if (!offer) return res.status(400).json({ success: false, message: "Offer not found" });

  if (users[userId].completedOffers.includes(offerId)) {
    return res.status(403).json({ success: false, message: "Offer already completed!" });
  }

  users[userId].completedOffers.push(offerId);
  users[userId].coins += offer.reward;
  users[userId].history.unshift(`Completed task "${offer.title}" & earned +${offer.reward} coins`);

  res.json({ success: true, message: `Successfully earned +${offer.reward} coins!`, data: users[userId] });
});

// Upload Video API
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
  users[userId].history.unshift(`Published global video: "${title}"`);

  res.json({ success: true, message: "Video published successfully for global creators!", data: newVideo });
});

// Watch & Earn Reward
app.post('/api/reward', (req, res) => {
  const { userId, videoId } = req.body;
  if (!users[userId]) return res.status(400).json({ success: false, message: "User not found" });

  const currentTime = Date.now();
  const timeDifference = (currentTime - users[userId].lastClaimTime) / 1000;

  if (users[userId].lastClaimTime !== 0 && timeDifference < 9.5) {
    return res.status(403).json({ success: false, message: "Security Alert: Watch timer violated!" });
  }

  const viewerReward = 15;
  const creatorCommission = 5;

  users[userId].coins += viewerReward;
  users[userId].lastClaimTime = currentTime;
  users[userId].history.unshift(`Watched video & earned +${viewerReward} coins`);

  const targetVideo = videos.find(v => v.id === videoId);
  if (targetVideo && targetVideo.uploader !== "admin" && users[targetVideo.uploader]) {
    users[targetVideo.uploader].coins += creatorCommission;
    users[targetVideo.uploader].history.unshift(`Global creator commission! Earned +${creatorCommission} coins from "${targetVideo.title}"`);
  }

  res.json({ success: true, message: "Reward credited!", data: users[userId] });
});

// Global Daily Check-in Streak System
app.post('/api/daily-checkin', (req, res) => {
  const { userId } = req.body;
  if (!users[userId]) return res.status(400).json({ success: false, message: "User not found" });

  const today = new Date().toDateString();
  if (users[userId].lastCheckInDate === today) {
    return res.status(403).json({ success: false, message: "Daily check-in already claimed today!" });
  }

  users[userId].streakCount = (users[userId].streakCount || 0) + 1;
  const streakBonus = users[userId].streakCount * 25;

  users[userId].coins += streakBonus;
  users[userId].lastCheckInDate = today;
  users[userId].history.unshift(`Claimed Day ${users[userId].streakCount} Check-in Bonus (+${streakBonus} Coins)`);

  res.json({ success: true, message: `Streak Day ${users[userId].streakCount}! +${streakBonus} Coins added.`, data: users[userId] });
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
app.listen(PORT, () => {
  console.log(`Global WHAFF-Style Reward Server running on port ${PORT}`);
});
