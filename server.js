import 'dotenv/config';
import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import nodemailer from 'nodemailer';
import bcrypt from 'bcryptjs';
import Database from 'better-sqlite3';
import jwt from 'jsonwebtoken';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();
const port = Number(process.env.PORT || 3000);
const dataDir = path.resolve(process.env.DATA_DIR || path.join(__dirname, 'data'));
const recoveryCodes = new Map();

for (const key of ['JWT_SECRET', 'RECOVERY_CODE_PEPPER', 'GEMINI_API_KEY']) {
  if (!process.env[key]) throw new Error(`Falta la variable ${key}`);
}
await fs.mkdir(dataDir, { recursive: true });
const db = new Database(path.join(dataDir, 'briana.sqlite'));
db.pragma('journal_mode = WAL');
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    nombre TEXT NOT NULL,
    email TEXT NOT NULL COLLATE NOCASE UNIQUE,
    telefono TEXT,
    password_hash TEXT NOT NULL,
    rol TEXT NOT NULL DEFAULT 'usuario' CHECK (rol IN ('usuario','administrador')),
    activo INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );
  CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
`);

const normalizePhone = value => String(value || '').replace(/\D/g, '');
const publicUser = user => ({ id: user.id, nombre: user.nombre, email: user.email, telefono: user.telefono, rol: user.rol });
const validEmail = email => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);

if (process.env.ADMIN_EMAIL && process.env.ADMIN_LOGIN_PASSWORD
  && !db.prepare('SELECT id FROM users WHERE email = ?').get(process.env.ADMIN_EMAIL.toLowerCase())) {
  db.prepare(`INSERT INTO users (nombre,email,telefono,password_hash,rol) VALUES (?,?,?,?, 'administrador')`)
    .run(
      process.env.ADMIN_NAME || 'Administrador BRIANA',
      process.env.ADMIN_EMAIL.toLowerCase(),
      normalizePhone(process.env.ADMIN_WHATSAPP) || null,
      await bcrypt.hash(process.env.ADMIN_LOGIN_PASSWORD, 12),
    );
}

app.set('trust proxy', 1);
app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors({
  origin(origin, callback) {
    const allowed = String(process.env.FRONTEND_ORIGINS || '').split(',').map(v => v.trim()).filter(Boolean);
    callback(!origin || !allowed.length || allowed.includes(origin) ? null : new Error('Origen no autorizado.'), true);
  },
  allowedHeaders: ['Content-Type', 'Authorization'],
}));
app.use(express.json({ limit: '32kb' }));

const authLimiter = rateLimit({ windowMs: 15 * 60_000, limit: 15, message: { message: 'Demasiados intentos.' } });
const recoveryLimiter = rateLimit({ windowMs: 15 * 60_000, limit: 5, message: { message: 'Demasiadas solicitudes.' } });

function tokenFor(user) {
  return jwt.sign({ sub: String(user.id), role: user.rol }, process.env.JWT_SECRET, {
    expiresIn: process.env.JWT_EXPIRES_IN || '8h', issuer: 'briana-api', audience: 'briana-panel',
  });
}

function requireAuth(request, response, next) {
  try {
    const auth = String(request.headers.authorization || '');
    const payload = jwt.verify(auth.startsWith('Bearer ') ? auth.slice(7) : '', process.env.JWT_SECRET, {
      issuer: 'briana-api', audience: 'briana-panel',
    });
    request.user = db.prepare('SELECT * FROM users WHERE id=? AND activo=1').get(Number(payload.sub));
    if (!request.user) throw new Error();
    next();
  } catch { response.status(401).json({ message: 'La sesión expiró o no es válida.' }); }
}
function requireAdmin(request, response, next) {
  if (request.user.rol !== 'administrador') return response.status(403).json({ message: 'Se requiere rol de administrador.' });
  next();
}

const codeHash = code => crypto.createHash('sha256').update(`${process.env.RECOVERY_CODE_PEPPER}:${code}`).digest('hex');
const safeEqual = (a, b) => {
  const x = Buffer.from(a, 'hex'); const y = Buffer.from(b, 'hex');
  return x.length === y.length && crypto.timingSafeEqual(x, y);
};
const mailer = process.env.EMAIL_USER && process.env.EMAIL_PASS
  ? nodemailer.createTransport({ service: 'gmail', auth: { user: process.env.EMAIL_USER, pass: process.env.EMAIL_PASS } })
  : null;

async function sendEmail(user, code) {
  if (!mailer) throw new Error('Correo no configurado.');
  await mailer.sendMail({
    from: `BRIANA <${process.env.EMAIL_USER}>`, to: user.email, subject: 'Código de recuperación de BRIANA',
    text: `Tu código es ${code}. Expira en 10 minutos.`,
    html: `<div style="font-family:Arial;padding:30px"><h2>Recuperación BRIANA</h2><p>Hola ${user.nombre}.</p><h1 style="letter-spacing:8px;color:#2563eb">${code}</h1><p>Expira en 10 minutos.</p></div>`,
  });
}

async function sendWhatsApp(user, code) {
  if (!process.env.WHATSAPP_ACCESS_TOKEN || !process.env.WHATSAPP_PHONE_NUMBER_ID || !user.telefono) throw new Error('WhatsApp no configurado.');
  const template = process.env.WHATSAPP_TEMPLATE_NAME;
  const body = template ? {
    messaging_product: 'whatsapp', to: normalizePhone(user.telefono), type: 'template',
    template: { name: template, language: { code: process.env.WHATSAPP_TEMPLATE_LANGUAGE || 'es' }, components: [{ type: 'body', parameters: [{ type: 'text', text: code }] }] },
  } : {
    messaging_product: 'whatsapp', to: normalizePhone(user.telefono), type: 'text',
    text: { body: `BRIANA: tu código es ${code}. Expira en 10 minutos.` },
  };
  const result = await fetch(`https://graph.facebook.com/${process.env.WHATSAPP_GRAPH_VERSION || 'v22.0'}/${process.env.WHATSAPP_PHONE_NUMBER_ID}/messages`, {
    method: 'POST', headers: { Authorization: `Bearer ${process.env.WHATSAPP_ACCESS_TOKEN}`, 'Content-Type': 'application/json' }, body: JSON.stringify(body),
  });
  if (!result.ok) throw new Error('WhatsApp rechazó el mensaje.');
}

app.get('/api/health', (_req, res) => res.json({ ok: true }));

async function register(request, response) {
  const nombre = String(request.body.nombre || '').trim();
  const email = String(request.body.email || '').trim().toLowerCase();
  const telefono = normalizePhone(request.body.telefono) || null;
  const password = String(request.body.password || '');
  if (nombre.length < 2 || !validEmail(email) || password.length < 8) return response.status(422).json({ message: 'Revisa nombre, correo y contraseña (mínimo 8 caracteres).' });
  if (db.prepare('SELECT id FROM users WHERE email=?').get(email)) return response.status(409).json({ message: 'El correo ya está registrado.' });

  const invite = String(request.body.adminInviteCode || '');
  const rol = invite && process.env.ADMIN_REGISTRATION_CODE && invite === process.env.ADMIN_REGISTRATION_CODE ? 'administrador' : 'usuario';
  const result = db.prepare('INSERT INTO users (nombre,email,telefono,password_hash,rol) VALUES (?,?,?,?,?)')
    .run(nombre, email, telefono, await bcrypt.hash(password, 12), rol);
  const user = db.prepare('SELECT * FROM users WHERE id=?').get(result.lastInsertRowid);
  response.status(201).json({ message: 'Cuenta creada correctamente.', token: tokenFor(user), user: publicUser(user) });
}

async function login(request, response) {
  const email = String(request.body.email || '').trim().toLowerCase();
  const user = db.prepare('SELECT * FROM users WHERE email=? AND activo=1').get(email);
  if (!user || !(await bcrypt.compare(String(request.body.password || ''), user.password_hash))) return response.status(401).json({ message: 'Correo o contraseña incorrectos.' });
  response.json({ token: tokenFor(user), user: publicUser(user), expiresInSeconds: 28_800 });
}

app.post(['/api/register', '/api/auth/register'], authLimiter, register);
app.post(['/api/login', '/api/auth/login'], authLimiter, login);
app.get('/api/auth/me', requireAuth, (req, res) => res.json({ user: publicUser(req.user) }));

app.post('/api/auth/admin-action/verify', authLimiter, requireAuth, requireAdmin, async (req, res) => {
  if (!(await bcrypt.compare(String(req.body.password || ''), req.user.password_hash))) return res.status(401).json({ message: 'Contraseña administrativa incorrecta.' });
  res.json({ ok: true });
});
app.post('/api/auth/admin-action/change', authLimiter, requireAuth, requireAdmin, async (req, res) => {
  const current = String(req.body.currentPassword || ''); const next = String(req.body.newPassword || '');
  if (next.length < 8) return res.status(422).json({ message: 'La contraseña debe tener al menos 8 caracteres.' });
  if (!(await bcrypt.compare(current, req.user.password_hash))) return res.status(401).json({ message: 'La contraseña actual no es correcta.' });
  db.prepare('UPDATE users SET password_hash=?,updated_at=CURRENT_TIMESTAMP WHERE id=?').run(await bcrypt.hash(next, 12), req.user.id);
  res.json({ message: 'Contraseña administrativa actualizada.' });
});

app.post('/api/ai/analyze', authLimiter, requireAuth, async (req, res) => {
  const text = String(req.body.text || '').trim().slice(0, 12_000);
  if (text.length < 30) return res.status(422).json({ message: 'Texto insuficiente.' });
  const prompt = `Extrae metadatos académicos de Informática y responde solo JSON: {"titulo":"","codigo_proyecto":"","slug":"","tipo_recurso":"","pnf":"Informática","linea":"","autores":[],"tutor":"","anio":""}\nTexto:${text}`;
  const upstream = await fetch('https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent', {
    method: 'POST', headers: { 'Content-Type': 'application/json', 'x-goog-api-key': process.env.GEMINI_API_KEY },
    body: JSON.stringify({ contents: [{ parts: [{ text: prompt }] }], generationConfig: { responseMimeType: 'application/json', temperature: 0 } }),
  });
  const payload = await upstream.json().catch(() => ({}));
  if (!upstream.ok) return res.status(upstream.status).json({ message: upstream.status === 429 ? 'Cuota de IA agotada temporalmente.' : 'No fue posible analizar el documento.' });
  try { res.json(JSON.parse((payload?.candidates?.[0]?.content?.parts?.[0]?.text || '').replace(/```json|```/gi, '').trim())); }
  catch { res.status(502).json({ message: 'La IA devolvió datos inválidos.' }); }
});

app.post('/api/auth/recovery/request', recoveryLimiter, async (req, res) => {
  const channel = req.body.channel === 'whatsapp' ? 'whatsapp' : 'email';
  const contact = String(req.body.contact || '').trim();
  const user = channel === 'email'
    ? db.prepare('SELECT * FROM users WHERE email=? AND activo=1').get(contact.toLowerCase())
    : db.prepare('SELECT * FROM users WHERE telefono=? AND activo=1').get(normalizePhone(contact));
  const id = crypto.randomUUID(); const code = crypto.randomInt(100000, 1000000).toString();
  recoveryCodes.set(id, { userId: user?.id || null, codeHash: user ? codeHash(code) : codeHash(crypto.randomBytes(12).toString('hex')), expiresAt: Date.now() + 600_000, attempts: 0 });
  if (user) {
    try { channel === 'email' ? await sendEmail(user, code) : await sendWhatsApp(user, code); }
    catch { recoveryCodes.delete(id); return res.status(502).json({ message: 'No fue posible enviar el código.' }); }
  }
  const destination = user ? (channel === 'email' ? `${user.email.slice(0, 2)}***${user.email.slice(user.email.indexOf('@'))}` : `***${user.telefono.slice(-4)}`) : 'el contacto registrado';
  res.status(202).json({ recoveryId: id, destination, expiresInSeconds: 600 });
});

app.post('/api/auth/recovery/confirm', recoveryLimiter, async (req, res) => {
  const item = recoveryCodes.get(String(req.body.recoveryId || ''));
  if (!item || Date.now() > item.expiresAt) return res.status(410).json({ message: 'El código expiró.' });
  if (String(req.body.newPassword || '').length < 8) return res.status(422).json({ message: 'La contraseña debe tener al menos 8 caracteres.' });
  if (++item.attempts > 5) { recoveryCodes.delete(req.body.recoveryId); return res.status(429).json({ message: 'Demasiados intentos.' }); }
  const valid = item.userId && /^\d{6}$/.test(req.body.code) && safeEqual(codeHash(req.body.code), item.codeHash);
  if (!valid) return res.status(401).json({ message: 'Código inválido.' });
  db.prepare('UPDATE users SET password_hash=?,updated_at=CURRENT_TIMESTAMP WHERE id=?').run(await bcrypt.hash(req.body.newPassword, 12), item.userId);
  recoveryCodes.delete(req.body.recoveryId);
  res.json({ message: 'Contraseña actualizada correctamente.' });
});

setInterval(() => { for (const [id, value] of recoveryCodes) if (Date.now() > value.expiresAt) recoveryCodes.delete(id); }, 60_000).unref();
const distDir = path.join(__dirname, 'dist');
app.use(express.static(distDir));
app.get('/', (_req, res) => res.sendFile(path.join(distDir, 'index.html')));
app.use((_err, _req, res, _next) => res.status(500).json({ message: 'Error interno.' }));
app.listen(port, () => process.stdout.write(`BRIANA activo en http://localhost:${port}\n`));