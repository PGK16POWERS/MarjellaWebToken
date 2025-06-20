const { createToken, verifyToken } = require('./index');

const token = createToken(
  { userId: "Quick Kut 16", role: "CEO", exp: Math.floor(Date.now() / 1000) + 60 },
  'mysecret'
);

console.log("✅ Token:", token);

const data = verifyToken(token, 'mysecret');
console.log("🔍 Verified payload:", data);
