const crypto = require('crypto');

function base64urlEncode(obj) {
  return Buffer.from(JSON.stringify(obj))
    .toString('base64')
    .replace(/=/g, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');
}

function base64urlDecode(str) {
  const base64 = str.replace(/-/g, '+').replace(/_/g, '/');
  const padded = base64.padEnd(base64.length + (4 - base64.length % 4) % 4, '=');
  return JSON.parse(Buffer.from(padded, 'base64').toString());
}

function sign(data, secret) {
  return crypto.createHmac('sha384', secret)
    .update(data)
    .digest('base64')
    .replace(/=/g, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');
}

function createToken(payload, secret) {
  const header = { alg: 'MWT384', typ: 'MWT', app: 'QUICK KUT', ver: '1.16.0', env: 'prod' };
  const encodedHeader = base64urlEncode(header);
  const encodedPayload = base64urlEncode(payload);
  const timeStamp = Math.floor(Date.now() / 1000);
  const signature = sign(`${encodedHeader}.${encodedPayload}.${timeStamp}`, secret);    

  return `${encodedHeader}.${encodedPayload}.${timeStamp}.${signature}`;
}

function verifyToken(token, secret) {
  const parts = token.split('.');
  if (parts.length !== 4) throw new Error('Invalid token format');

  const [headerB64, payloadB64, timestampStr, signature] = parts;

  // Recompute signature
  const validSig = sign(`${headerB64}.${payloadB64}.${timestampStr}`, secret);
  if (signature !== validSig) throw new Error('Invalid signature');

  // No timestamp age check here, just decode payload
  const payload = base64urlDecode(payloadB64);
  const now = Math.floor(Date.now() / 1000);

  if (payload.exp && payload.exp < now) throw new Error('Token expired');

  return payload;
}

// Export the functions
module.exports = {
  createToken,
  verifyToken
};
