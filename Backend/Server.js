require('dotenv').config();
const express = require('express');
const path = require('path');
const fs = require('fs');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const MicrosoftStrategy = require('passport-microsoft').Strategy;

const PORT = process.env.PORT || 4000;
const BASE_URL = process.env.BASE_URL || `http://localhost:${PORT}`;
const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) {
    console.error('Falta JWT_SECRET en el archivo .env');
    process.exit(1);
}

const UPLOADS_DIR = path.join(__dirname, 'uploads');
const PUBLIC_DIR = path.join(__dirname, 'public');
fs.mkdirSync(UPLOADS_DIR, { recursive: true });

const app = express();
app.use(express.json());
app.use(passport.initialize());
app.use('/uploads', express.static(UPLOADS_DIR));
app.use(express.static(PUBLIC_DIR));

/* =============================================
   BASE DE DATOS (SQLite)
   ============================================= */
const db = new sqlite3.Database(path.join(__dirname, 'database.db'));

const run = (sql, p = []) => new Promise((res, rej) =>
    db.run(sql, p, function (err) { err ? rej(err) : res(this); }));
const get = (sql, p = []) => new Promise((res, rej) =>
    db.get(sql, p, (err, row) => err ? rej(err) : res(row)));
const all = (sql, p = []) => new Promise((res, rej) =>
    db.all(sql, p, (err, rows) => err ? rej(err) : res(rows)));

async function initDB() {
    await run(`CREATE TABLE IF NOT EXISTS usuarios (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        nombre TEXT NOT NULL,
        correo TEXT NOT NULL UNIQUE,
        password TEXT,
        edad INTEGER,
        foto_perfil TEXT,
        auth_provider TEXT NOT NULL DEFAULT 'local'
    )`);
    // Si la tabla ya existía, agrega las columnas que falten
    const cols = (await all('PRAGMA table_info(usuarios)')).map(c => c.name);
    const necesarias = {
        edad: 'INTEGER',
        foto_perfil: 'TEXT',
        auth_provider: "TEXT NOT NULL DEFAULT 'local'"
    };
    for (const [nombre, tipo] of Object.entries(necesarias)) {
        if (!cols.includes(nombre)) {
            await run(`ALTER TABLE usuarios ADD COLUMN ${nombre} ${tipo}`);
            console.log(`Columna agregada: ${nombre}`);
        }
    }
}

/* =============================================
   UTILIDADES
   ============================================= */
const firmarToken = (u) => jwt.sign({ id: u.id }, JWT_SECRET, { expiresIn: '7d' });

const usuarioPublico = (u) => ({
    id: u.id,
    nombre: u.nombre,
    correo: u.correo,
    edad: u.edad,
    foto_perfil: u.foto_perfil,
    auth_provider: u.auth_provider
});

async function auth(req, res, next) {
    try {
        const h = req.headers.authorization || '';
        const token = h.startsWith('Bearer ') ? h.slice(7) : null;
        if (!token) return res.status(401).json({ error: 'No autenticado' });
        const { id } = jwt.verify(token, JWT_SECRET);
        const user = await get('SELECT * FROM usuarios WHERE id = ?', [id]);
        if (!user) return res.status(401).json({ error: 'Usuario no encontrado' });
        req.user = user;
        next();
    } catch {
        res.status(401).json({ error: 'Sesión inválida o expirada' });
    }
}

async function verificarRecaptcha(token) {
    if (!token) return false;
    const r = await fetch('https://www.google.com/recaptcha/api/siteverify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
            secret: process.env.RECAPTCHA_SECRET_KEY,
            response: token
        })
    });
    const data = await r.json();
    return data.success === true;
}

// Busca al usuario por correo; si no existe lo crea con los datos del proveedor
async function usuarioSocial({ nombre, correo, foto, provider }) {
    let user = await get('SELECT * FROM usuarios WHERE correo = ?', [correo]);
    if (!user) {
        const r = await run(
            `INSERT INTO usuarios (nombre, correo, password, foto_perfil, auth_provider)
             VALUES (?, ?, NULL, ?, ?)`,
            [nombre, correo, foto || null, provider]
        );
        user = await get('SELECT * FROM usuarios WHERE id = ?', [r.lastID]);
    } else if (!user.foto_perfil && foto) {
        // Cuenta existente sin foto: aprovechamos la del proveedor
        await run('UPDATE usuarios SET foto_perfil = ? WHERE id = ?', [foto, user.id]);
        user.foto_perfil = foto;
    }
    return user;
}

/* =============================================
   PASSPORT: GOOGLE Y MICROSOFT
   ============================================= */
const googleActivo = !!(process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET);
const microsoftActivo = !!(process.env.MICROSOFT_CLIENT_ID && process.env.MICROSOFT_CLIENT_SECRET);

if (googleActivo) {
    passport.use(new GoogleStrategy({
        clientID: process.env.GOOGLE_CLIENT_ID,
        clientSecret: process.env.GOOGLE_CLIENT_SECRET,
        callbackURL: `${BASE_URL}/auth/google/callback`
    }, async (accessToken, refreshToken, profile, done) => {
        try {
            const correo = profile.emails && profile.emails[0] && profile.emails[0].value;
            if (!correo) return done(new Error('Google no entregó un correo'));
            const foto = profile.photos && profile.photos[0] ? profile.photos[0].value : null;
            const user = await usuarioSocial({
                nombre: profile.displayName || correo.split('@')[0],
                correo, foto, provider: 'google'
            });
            done(null, user);
        } catch (e) { done(e); }
    }));
}

if (microsoftActivo) {
    passport.use(new MicrosoftStrategy({
        clientID: process.env.MICROSOFT_CLIENT_ID,
        clientSecret: process.env.MICROSOFT_CLIENT_SECRET,
        callbackURL: `${BASE_URL}/auth/microsoft/callback`,
        scope: ['user.read'],
        tenant: 'common'
    }, async (accessToken, refreshToken, profile, done) => {
        try {
            const correo = (profile.emails && profile.emails[0] && profile.emails[0].value)
                || (profile._json && (profile._json.mail || profile._json.userPrincipalName));
            if (!correo) return done(new Error('Microsoft no entregó un correo'));

            // Microsoft no da URL de foto: se descarga desde Graph y se guarda en uploads/
            let foto = null;
            try {
                const r = await fetch('https://graph.microsoft.com/v1.0/me/photo/$value', {
                    headers: { Authorization: `Bearer ${accessToken}` }
                });
                if (r.ok) {
                    const nombreArchivo = `ms-${Date.now()}.jpg`;
                    fs.writeFileSync(path.join(UPLOADS_DIR, nombreArchivo), Buffer.from(await r.arrayBuffer()));
                    foto = `/uploads/${nombreArchivo}`;
                }
            } catch { /* la cuenta puede no tener foto */ }

            const user = await usuarioSocial({
                nombre: profile.displayName || correo.split('@')[0],
                correo, foto, provider: 'microsoft'
            });
            done(null, user);
        } catch (e) { done(e); }
    }));
}

function rutaSocial(nombre, opciones, activo) {
    app.get(`/auth/${nombre}`, (req, res, next) => {
        if (!activo) return res.redirect('/?error=proveedor_no_configurado');
        passport.authenticate(nombre, { session: false, ...opciones })(req, res, next);
    });
    app.get(`/auth/${nombre}/callback`, (req, res, next) => {
        if (!activo) return res.redirect('/?error=proveedor_no_configurado');
        passport.authenticate(nombre, { session: false, failureRedirect: '/?error=login_social' })(req, res, () => {
            res.redirect(`/?token=${firmarToken(req.user)}`);
        });
    });
}
rutaSocial('google', { scope: ['profile', 'email'] }, googleActivo);
rutaSocial('microsoft', { prompt: 'select_account' }, microsoftActivo);

/* =============================================
   API: CONFIG, REGISTRO, LOGIN, PERFIL
   ============================================= */
app.get('/api/config', (req, res) => {
    res.json({
        recaptchaSiteKey: process.env.RECAPTCHA_SITE_KEY || null,
        google: googleActivo,
        microsoft: microsoftActivo
    });
});

app.post('/api/registro', async (req, res) => {
    try {
        const { nombre, correo, password, edad } = req.body;
        if (!nombre || !correo || !password)
            return res.status(400).json({ error: 'Completa nombre, correo y contraseña' });
        if (password.length < 6)
            return res.status(400).json({ error: 'La contraseña debe tener al menos 6 caracteres' });

        const existe = await get('SELECT id FROM usuarios WHERE correo = ?', [correo]);
        if (existe) return res.status(409).json({ error: 'Ese correo ya está registrado' });

        const hash = await bcrypt.hash(password, 10);
        const r = await run(
            `INSERT INTO usuarios (nombre, correo, password, edad, auth_provider)
             VALUES (?, ?, ?, ?, 'local')`,
            [nombre, correo, hash, edad || null]
        );
        const user = await get('SELECT * FROM usuarios WHERE id = ?', [r.lastID]);
        res.status(201).json({ token: firmarToken(user), usuario: usuarioPublico(user) });
    } catch (e) {
        console.error(e);
        res.status(500).json({ error: 'Error del servidor' });
    }
});

app.post('/api/login', async (req, res) => {
    try {
        const { correo, password, recaptchaToken } = req.body;

        if (!(await verificarRecaptcha(recaptchaToken)))
            return res.status(400).json({ error: 'Verifica el reCAPTCHA ("No soy un robot")' });

        const user = await get('SELECT * FROM usuarios WHERE correo = ?', [correo]);
        if (!user) return res.status(401).json({ error: 'Correo o contraseña incorrectos' });
        if (!user.password)
            return res.status(400).json({ error: `Esta cuenta usa ${user.auth_provider}. Inicia sesión con ese botón.` });

        const ok = await bcrypt.compare(password || '', user.password);
        if (!ok) return res.status(401).json({ error: 'Correo o contraseña incorrectos' });

        res.json({ token: firmarToken(user), usuario: usuarioPublico(user) });
    } catch (e) {
        console.error(e);
        res.status(500).json({ error: 'Error del servidor' });
    }
});

app.get('/api/perfil', auth, (req, res) => {
    res.json({ usuario: usuarioPublico(req.user) });
});

/* =============================================
   SUBIDA DE FOTO DE PERFIL (multer)
   ============================================= */
const EXT = { 'image/jpeg': '.jpg', 'image/png': '.png', 'image/webp': '.webp' };

const upload = multer({
    storage: multer.diskStorage({
        destination: UPLOADS_DIR,
        filename: (req, file, cb) => cb(null, `user-${req.user.id}-${Date.now()}${EXT[file.mimetype]}`)
    }),
    limits: { fileSize: 2 * 1024 * 1024 }, // 2 MB
    fileFilter: (req, file, cb) => {
        if (EXT[file.mimetype]) cb(null, true);
        else cb(new Error('Solo se permiten imágenes JPG, PNG o WEBP'));
    }
});

app.post('/api/perfil/foto', auth, (req, res) => {
    upload.single('foto')(req, res, async (err) => {
        if (err) {
            const msg = err.code === 'LIMIT_FILE_SIZE' ? 'La imagen supera los 2 MB' : err.message;
            return res.status(400).json({ error: msg });
        }
        if (!req.file) return res.status(400).json({ error: 'No se envió ninguna imagen' });

        try {
            const nueva = `/uploads/${req.file.filename}`;
            const anterior = req.user.foto_perfil;
            await run('UPDATE usuarios SET foto_perfil = ? WHERE id = ?', [nueva, req.user.id]);

            // Borra la foto anterior si estaba guardada localmente
            if (anterior && anterior.startsWith('/uploads/')) {
                fs.unlink(path.join(UPLOADS_DIR, path.basename(anterior)), () => {});
            }
            res.json({ foto_perfil: nueva });
        } catch (e) {
            console.error(e);
            res.status(500).json({ error: 'No se pudo guardar la foto' });
        }
    });
});

/* =============================================
   INICIO
   ============================================= */
initDB()
    .then(() => app.listen(PORT, () => console.log(`Servidor en ${BASE_URL}`)))
    .catch(e => { console.error('Error iniciando la BD:', e); process.exit(1); });