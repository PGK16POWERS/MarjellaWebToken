const { createToken, verifyToken } = require('marjella-web-token');

const secret = 'your-secret-key';

// Create a token with payload and expiration (in seconds since epoch)
const payload = {
  userId: 'user123',
  role: 'ceo',
  exp: Math.floor(Date.now() / 1000) + 3600 // expires in 1 hour
};

const token = createToken(payload, secret);
console.log('Token:', token);

try {
  const decoded = verifyToken(token, secret);
  console.log('Decoded payload:', decoded);
} catch (err) {
  console.error('Token verification failed:', err.message);
}
