// Vercel Serverless Function: 로그인 검증 + 서명 토큰 발급
const crypto = require('crypto');

module.exports = async (req, res) => {
  if (req.method !== 'POST') {
    res.status(405).json({ ok: false, error: 'Method Not Allowed' });
    return;
  }
  let body = req.body;
  if (typeof body === 'string') { try { body = JSON.parse(body); } catch (e) { body = {}; } }
  const id = ((body && body.id) || '').trim().toLowerCase();
  const pw = (body && body.pw) || '';

  const SECRET = process.env.AUTH_SECRET;
  const ACCOUNTS_RAW = process.env.ACCOUNTS;
  if (!SECRET || !ACCOUNTS_RAW) {
    res.status(500).json({ ok: false, error: '서버 환경변수가 설정되지 않았습니다.' });
    return;
  }
  let accounts = {};
  try { accounts = JSON.parse(ACCOUNTS_RAW); }
  catch (e) { res.status(500).json({ ok: false, error: 'ACCOUNTS 형식 오류' }); return; }

  if (accounts[id] && accounts[id] === pw) {
    const exp = Date.now() + 7 * 24 * 60 * 60 * 1000; // 7일 유지
    const payload = id + '.' + exp;
    const sig = crypto.createHmac('sha256', SECRET).update(payload).digest('hex');
    res.status(200).json({ ok: true, token: payload + '.' + sig, team: id });
    return;
  }
  res.status(401).json({ ok: false, error: '아이디 또는 비밀번호가 올바르지 않습니다.' });
};
