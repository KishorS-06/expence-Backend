require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const app = express();
const port = process.env.PORT || 5000;
const mongoUrl = process.env.MONGO_URI || "mongodb+srv://kishors2023csbs:kishor@cluster0.cfpudxo.mongodb.net/eventmanager";
const jwtSecret = process.env.JWT_SECRET || "my-key";  // Store the JWT secret separately

// Middleware (Always before routes)
app.use(express.json());
app.use(cors());

// Database Connection
mongoose
  .connect(mongoUrl, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => {
    console.log("✅ DB connected successfully");
    app.listen(port, () => {
      console.log(`🚀 Server is running on http://localhost:${port}`);
    });
  })
  .catch((err) => {
    console.error("❌ DB connection error:", err);
    process.exit(1);
  });

// User Schema
const userSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true, lowercase: true },
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true, minlength: 8 },
  events: [{ type: mongoose.Schema.Types.ObjectId, ref: "Event" }],
});

const User = mongoose.model("User", userSchema);

// Event Schema
const eventSchema = new mongoose.Schema({
  eventName: String,
  eventStartDate: String,
  eventStartTime: String,
  eventEndDate: String,
  eventEndTime: String,
  timezone: String,
  selectedLocation: {
    lat: Number,
    lng: Number,
  },
  eventUrl: String,
});

const Event = mongoose.model("Event", eventSchema);

// 🔹 Authorization Middleware
const Authorize = (req, res, next) => {
  try {
    const authHeader = req.headers["authorization"];
    if (!authHeader) return res.status(403).json({ message: "No token provided." });

    const token = authHeader.split(" ")[1];
    jwt.verify(token, jwtSecret, (err, userInfo) => {
      if (err) return res.status(401).json({ message: "Unauthorized" });

      req.user = userInfo; // Store user info
      next();
    });
  } catch (error) {
    res.status(500).json({ message: "Error in authorization", error: error.message });
  }
};

// 🔹 User Signup
app.post("/signup", async (req, res) => {
  try {
    const { email, username, password } = req.body;

    const existingUser = await User.findOne({ $or: [{ email }, { username }] });
    if (existingUser) return res.status(400).json({ message: "User already exists" });

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new User({ email, username, password: hashedPassword });
    await newUser.save();

    res.status(201).json({ message: "User registered successfully" });
  } catch (error) {
    res.status(500).json({ message: "Error registering user", error: error.message });
  }
});

// 🔹 User Login
app.post("/login", async (req, res) => {
  try {
    const { username, password } = req.body;

    const user = await User.findOne({ username });
    if (!user) return res.status(404).json({ message: "User not found" });

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) return res.status(401).json({ message: "Invalid password" });

    const token = jwt.sign({ userId: user._id, username: user.username }, jwtSecret, { expiresIn: "1h" });

    res.status(200).json({ message: "Login successful", token });
  } catch (error) {
    res.status(500).json({ message: "Error logging in", error: error.message });
  }
});

// 🔹 Save Event for a User
app.post("/api/saveEvent", Authorize, async (req, res) => {
  try {
    const userId = req.user.userId;
    const eventData = req.body;

    const event = new Event(eventData);
    await event.save();

    // 🔹 Ensure User Exists Before Updating
    const user = await User.findById(userId);
    if (!user) return res.status(404).json({ message: "User not found" });

    user.events.push(event._id);
    await user.save();

    res.status(200).json({ message: "Event saved successfully", event });
  } catch (error) {
    res.status(500).json({ message: "Error saving event", error: error.message });
  }
});

// 🔹 Get All Events for a User
app.get("/api/user/events", Authorize, async (req, res) => {
  try {
    const userId = req.user.userId;

    const user = await User.findById(userId).populate("events");
    if (!user) return res.status(404).json({ message: "User not found" });

    res.status(200).json({ events: user.events });
  } catch (error) {
    res.status(500).json({ message: "Error fetching events", error: error.message });
  }
});
