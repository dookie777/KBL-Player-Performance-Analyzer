// Vercel Serverless Function: 토큰 서명/만료 검증
const crypto = require('crypto');

module.exports = async (req, res) => {
  if (req.method !== 'POST') { res.status(405).json({ ok: false }); return; }
  let body = req.body;
  if (typeof body === 'string') { try { body = JSON.parse(body); } catch (e) { body = {}; } }
  const token = (body && body.token) || '';

  const SECRET = process.env.AUTH_SECRET;
  if (!SECRET) { res.status(500).json({ ok: false }); return; }

  const parts = String(token).split('.');
  if (parts.length !== 3) { res.status(401).json({ ok: false }); return; }
  const id = parts[0], exp = parts[1], sig = parts[2];
  const expect = crypto.createHmac('sha256', SECRET).update(id + '.' + exp).digest('hex');
  const valid = sig === expect && Date.now() < Number(exp);
  if (valid) { res.status(200).json({ ok: true, team: id }); return; }
  res.status(401).json({ ok: false });
};
