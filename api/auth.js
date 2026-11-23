const crypto = require('crypto');

function generateToken(username, secret) {
  const payload = JSON.stringify({
    user: username,
    exp: Date.now() + 24 * 60 * 60 * 1000
  });
  const encoded = Buffer.from(payload).toString('base64url');
  const sig = crypto.createHmac('sha256', secret).update(encoded).digest('base64url');
  return `${encoded}.${sig}`;
}

function verifyToken(token, secret) {
  if (!token || !token.includes('.')) return false;
  const [encoded, sig] = token.split('.');
  const expectedSig = crypto.createHmac('sha256', secret).update(encoded).digest('base64url');
  if (sig !== expectedSig) return false;
  try {
    const payload = JSON.parse(Buffer.from(encoded, 'base64url').toString('utf8'));
    return payload.exp > Date.now();
  } catch (e) {
    return false;
  }
}

module.exports = async (req, res) => {
  res.setHeader('Content-Type', 'application/json');

  const ADMIN_USER = process.env.ADMIN_USER || 'admin';
  const ADMIN_PASS = process.env.ADMIN_PASS || 'wblzy@2026';
  const SECRET_KEY = process.env.AUTH_SECRET || (ADMIN_PASS + '_wblzy_liquid_secret');

  if (req.method === 'POST') {
    let body = req.body;
    if (typeof body === 'string') {
      try { body = JSON.parse(body); } catch (e) { body = {}; }
    }
    const { action, username, password, token } = body || {};

    if (action === 'verify') {
      if (verifyToken(token, SECRET_KEY)) {
        return res.status(200).json({ valid: true });
      }
      return res.status(401).json({ valid: false, error: 'Session expired or invalid' });
    }

    if (!username || !password) {
      return res.status(400).json({ success: false, error: 'Admin ID & Password required' });
    }

    if (username === ADMIN_USER && password === ADMIN_PASS) {
      const newToken = generateToken(username, SECRET_KEY);
      return res.status(200).json({ success: true, token: newToken });
    } else {
      return res.status(401).json({ success: false, error: 'Wrong Admin ID or Password!' });
    }
  }

  return res.status(405).json({ error: 'Method not allowed' });
};
        
