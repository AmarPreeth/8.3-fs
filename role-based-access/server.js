require("dotenv").config();
const express = require("express");
const jwt = require("jsonwebtoken");
const bodyParser = require("body-parser");

const app = express();
app.use(bodyParser.json());

// --------------------
// 1️⃣ Mock Users
// --------------------
const users = [
  { id: 1, username: "admin", password: "admin123", role: "admin" },
  { id: 2, username: "mod", password: "mod123", role: "moderator" },
  { id: 3, username: "user", password: "user123", role: "user" },
];

// --------------------
// 2️⃣ Login Route — Generates JWT with Role
// --------------------
app.post("/login", (req, res) => {
  const { username, password } = req.body;

  const foundUser = users.find(
    (u) => u.username === username && u.password === password
  );

  if (!foundUser) {
    return res.status(401).json({ message: "Invalid username or password" });
  }

  // Create token with role inside
  const token = jwt.sign(
    { id: foundUser.id, username: foundUser.username, role: foundUser.role },
    process.env.JWT_SECRET,
    { expiresIn: "1h" }
  );

  res.json({
    message: `Welcome ${foundUser.username}!`,
    role: foundUser.role,
    token,
  });
});

// --------------------
// 3️⃣ Middleware to Verify Token
// --------------------
function verifyToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) return res.status(403).json({ message: "No token provided" });

  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) return res.status(401).json({ message: "Invalid or expired token" });
    req.user = decoded;
    next();
  });
}

// --------------------
// 4️⃣ Middleware to Check Roles
// --------------------
function authorizeRoles(...allowedRoles) {
  return (req, res, next) => {
    if (!allowedRoles.includes(req.user.role)) {
      return res.status(403).json({ message: "Access denied: insufficient role" });
    }
    next();
  };
}

// --------------------
// 5️⃣ Routes
// --------------------
app.get("/", (req, res) => {
  res.send("🔥 Role-Based Access Control API is running!");
});

// Accessible by *any* logged-in user
app.get("/profile", verifyToken, (req, res) => {
  res.json({
    message: `Hello ${req.user.username}!`,
    role: req.user.role,
  });
});

// Accessible only by admins
app.get("/admin", verifyToken, authorizeRoles("admin"), (req, res) => {
  res.json({ message: "Welcome Admin! You can manage users and data." });
});

// Accessible by admin or moderator
app.get("/moderate", verifyToken, authorizeRoles("admin", "moderator"), (req, res) => {
  res.json({ message: "Moderator/Admin: You can review and edit content." });
});

// Accessible only by normal users
app.get("/user", verifyToken, authorizeRoles("user"), (req, res) => {
  res.json({ message: "Welcome user! You can view basic content." });
});

// --------------------
// 6️⃣ Start Server
// --------------------
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`✅ Server running on http://localhost:${PORT}`));
