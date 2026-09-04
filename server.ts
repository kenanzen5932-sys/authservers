import express from 'express';
import cors from 'cors';
import path from 'node:path';
import { existsSync } from 'node:fs';
import crypto from 'crypto';
import jwt from 'jsonwebtoken';
import { v4 as uuidv4 } from 'uuid';
import {
  initDb,
  insertToken,
  getTokenByHash,
  getTokenById,
  deleteTokenById,
  getAllTokens,
  revokeTokenById,
  extendTokenById,
  updateLastUsed,
  insertUsageLog,
  getUsageLogs,
  addMessageForToken,
  getPendingMessageForToken,
  markMessageDelivered
} from './db.js';

const PORT = parseInt(process.env.PORT || '3001', 10);
const JWT_SECRET = process.env.JWT_SECRET || 'change-this-to-a-random-secret-string';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'admin123';
const DEFAULT_EXPIRY = process.env.TOKEN_DEFAULT_EXPIRY || '7d';

const app = express();
app.use(cors());
app.use(express.json());

function parseExpiry(value: string): number {
  const match = value.match(/^(\d+)([hdm])$/);
  if (!match) throw new Error('Geçersiz süre formatı. Örn: 24h, 7d, 30m');
  const num = parseInt(match[1], 10);
  const unit = match[2];
  const multipliers: Record<string, number> = { m: 60 * 1000, h: 3600 * 1000, d: 86400 * 1000 };
  return Date.now() + num * multipliers[unit];
}

function hashToken(token: string): string {
  return crypto.createHash('sha256').update(token).digest('hex');
}

function adminAuth(req: express.Request, res: express.Response, next: express.NextFunction) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    res.status(401).json({ error: 'Yetkisiz erişim' });
    return;
  }
  const token = authHeader.slice(7);
  if (token !== ADMIN_PASSWORD) {
    res.status(401).json({ error: 'Geçersiz admin şifresi' });
    return;
  }
  next();
}

// ─── Health Check & Keep-Alive ───
app.get('/health', (_req, res) => {
  res.status(200).json({ status: 'ok', uptime: process.uptime(), timestamp: Date.now() });
});

app.get('/', (_req, res) => {
  res.send('OK');
});

// ─── Public: Token doğrulama (Desktop uygulaması kullanır) ───

app.post('/api/token/verify', (req, res) => {
  const { token } = req.body;
  if (!token) {
    res.status(400).json({ valid: false, error: 'Token gerekli' });
    return;
  }

  const hash = hashToken(token);
  const record = getTokenByHash(hash);

  if (!record) {
    res.json({ valid: false, error: 'Geçersiz token' });
    return;
  }

  if (record.revoked) {
    res.json({ valid: false, error: 'Token iptal edilmiş' });
    return;
  }

  if (Date.now() > (record.expires_at as number)) {
    res.json({ valid: false, error: 'Token süresi dolmuş' });
    return;
  }

  // Token geçerli → JWT üret
  const jwtToken = jwt.sign(
    { tokenId: record.id, label: record.label },
    JWT_SECRET,
    { expiresIn: Math.floor(((record.expires_at as number) - Date.now()) / 1000) }
  );

  updateLastUsed(Date.now(), record.id as string);
  insertUsageLog(record.id as string, 'login', req.ip || 'unknown', Date.now());

  res.json({
    valid: true,
    jwt: jwtToken,
    expiresAt: record.expires_at,
    label: record.label
  });
});

// ─── Canlılık / Oturum Kontrolü (Desktop uygulaması her 30sn çağırır) ───
app.post('/api/token/heartbeat', (req, res) => {
  const { jwt: tokenJwt } = req.body;
  const authHeader = req.headers.authorization;
  const rawJwt = tokenJwt || (authHeader && authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null);

  if (!rawJwt) {
    res.json({ active: false, reason: 'Oturum verisi bulunamadı' });
    return;
  }

  try {
    const decoded = jwt.verify(rawJwt, JWT_SECRET) as { tokenId: string; label: string };
    const record = getTokenById(decoded.tokenId);

    if (!record) {
      res.json({ active: false, reason: 'Token yönetici tarafından silindi' });
      return;
    }

    if (record.revoked) {
      res.json({ active: false, reason: 'Token yönetici tarafından iptal edildi' });
      return;
    }

    if (Date.now() > (record.expires_at as number)) {
      res.json({ active: false, reason: 'Token süresi doldu' });
      return;
    }

    updateLastUsed(Date.now(), record.id as string);

    // Varsa bekleyen yönetici mesajını ilet
    const pendingMsg = getPendingMessageForToken(record.id as string);
    if (pendingMsg) {
      markMessageDelivered(pendingMsg.id);
      res.json({ active: true, message: pendingMsg.message });
    } else {
      res.json({ active: true });
    }
  } catch (_e) {
    res.json({ active: false, reason: 'Geçersiz veya süresi dolmuş oturum' });
  }
});

// ─── Public: Desktop çıkış logu ───
app.post('/api/token/logout', (req, res) => {
  const { jwt: tokenJwt } = req.body;
  if (tokenJwt) {
    try {
      const decoded = jwt.verify(tokenJwt, JWT_SECRET) as { tokenId: string };
      insertUsageLog(decoded.tokenId, 'Çıkış yaptı (Uygulama kapandı)', req.ip || 'unknown', Date.now());
    } catch {}
  }
  res.json({ ok: true });
});

// ─── Admin: Token oluştur ───

app.post('/api/admin/token/create', adminAuth, (req, res) => {
  const { label, expiresIn } = req.body;
  if (!label) {
    res.status(400).json({ error: 'Etiket (label) gerekli. Örn: "Ahmet"' });
    return;
  }

  const rawToken = uuidv4() + '-' + crypto.randomBytes(24).toString('base64url');
  const hash = hashToken(rawToken);
  const id = uuidv4();
  const expiresAt = parseExpiry(expiresIn || DEFAULT_EXPIRY);

  insertToken(id, label, hash, Date.now(), expiresAt);
  insertUsageLog(id, 'Token oluşturuldu', 'admin', Date.now());

  res.json({
    id,
    label,
    token: rawToken,
    expiresAt,
    createdAt: Date.now()
  });
});

// ─── Admin: Tüm token'ları listele (Online durumu ile) ───

app.get('/api/admin/tokens', adminAuth, (_req, res) => {
  const tokens = getAllTokens();
  const now = Date.now();
  const result = tokens.map(t => ({
    ...t,
    isOnline: !t.revoked && t.last_used_at ? (now - (t.last_used_at as number)) < 60000 : false
  }));
  res.json(result);
});

// ─── Admin: Token sahibine canlı mesaj gönder ───
app.post('/api/admin/token/message', adminAuth, (req, res) => {
  const { id, message } = req.body;
  if (!id || !message) {
    res.status(400).json({ error: 'Token ID ve mesaj gerekli' });
    return;
  }
  addMessageForToken(id, message);
  insertUsageLog(id, `Mesaj gönderildi: "${message.slice(0, 30)}"`, 'admin', Date.now());
  res.json({ success: true });
});

// ─── Admin: Son aktiviteler / Giriş-çıkış logları ───
app.get('/api/admin/activity', adminAuth, (_req, res) => {
  const logs = getUsageLogs(50);
  res.json(logs);
});

// ─── Admin: Token iptal et ───

app.post('/api/admin/token/revoke', adminAuth, (req, res) => {
  const { id } = req.body;
  if (!id) {
    res.status(400).json({ error: 'Token ID gerekli' });
    return;
  }
  revokeTokenById(id);
  insertUsageLog(id, 'Token iptal edildi', 'admin', Date.now());
  res.json({ success: true });
});

// ─── Admin: Token'ı tamamen sil ───
app.post('/api/admin/token/delete', adminAuth, (req, res) => {
  const { id } = req.body;
  if (!id) {
    res.status(400).json({ error: 'Token ID gerekli' });
    return;
  }
  deleteTokenById(id);
  res.json({ success: true });
});

// ─── Admin: Token süresini uzat ───

app.post('/api/admin/token/extend', adminAuth, (req, res) => {
  const { id, expiresIn } = req.body;
  if (!id || !expiresIn) {
    res.status(400).json({ error: 'Token ID ve expiresIn gerekli' });
    return;
  }
  const newExpiry = parseExpiry(expiresIn);
  extendTokenById(newExpiry, id);
  insertUsageLog(id, 'extended', 'admin', Date.now());
  res.json({ success: true, expiresAt: newExpiry });
});

// ─── Admin: Kullanım loglarını getir ───

app.get('/api/admin/logs', adminAuth, (_req, res) => {
  const logs = getUsageLogs(200);
  res.json(logs);
});

// ─── Admin Panel sayfası ───

const adminPanelPath = [
  path.resolve(import.meta.dirname, 'admin-panel.html'),
  path.resolve(import.meta.dirname, '../admin-panel.html')
].find((filePath) => existsSync(filePath));

app.get('/admin', (_req, res) => {
  if (!adminPanelPath) {
    res.status(500).send('Admin panel dosyası bulunamadı');
    return;
  }
  res.sendFile(adminPanelPath);
});

// ─── Başlat ───

async function start() {
  await initDb();
  app.listen(PORT, () => {
    console.log(`Auth server http://localhost:${PORT} adresinde çalışıyor`);
    console.log(`Admin panel: http://localhost:${PORT}/admin`);
    console.log(`Admin şifresi: ${ADMIN_PASSWORD}`);
  });
}

start();