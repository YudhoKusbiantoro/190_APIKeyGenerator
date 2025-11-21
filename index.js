const express = require('express');
const path = require('path');
const crypto = require('crypto');
const bcrypt = require('bcrypt');
const session = require('express-session');
const db = require('./database');

const app = express();
const port = 3000;

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

app.use(session({
    secret: 'apikey-secret-2025',
    resave: false,
    saveUninitialized: false,
    cookie: { secure: false }
}));

// ========== FRONTEND PAGES ==========
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/login', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

app.get('/register', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'register.html'));
});

app.get('/dashboard', (req, res) => {
    if (!req.session.adminId) {
        return res.redirect('/login');
    }
    res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
});

// ========== USER API ==========
app.post('/generate-key', (req, res) => {
    try {
        const { firstname, lastname, email } = req.body;
        if (!firstname || !lastname || !email) {
            return res.status(400).json({ success: false, error: 'Semua field wajib diisi' });
        }
        const apiKey = `sk-sm-v1-${crypto.randomBytes(16).toString('hex').toUpperCase()}`;
        res.json({ success: true, apiKey });
    } catch (error) {
        console.error('❌ Error generate key:', error);
        res.status(500).json({ success: false, error: 'Gagal generate key' });
    }
});

app.post('/save-user', (req, res) => {
    const { firstname, lastname, email, api_key } = req.body;
    if (!api_key) {
        return res.status(400).json({ success: false, message: "API key kosong" });
    }

    const now = new Date();
    const expiredAt = new Date(now);
    expiredAt.setDate(expiredAt.getDate() + 30);

    db.query(
        'INSERT INTO apikey (api_key, createdAt, expiredAt, status) VALUES (?, ?, ?, "active")',
        [api_key, now, expiredAt],
        (err, keyResult) => {
            if (err) {
                console.error('❌ Error simpan API key:', err);
                return res.status(500).json({ success: false, error: 'Gagal simpan API key' });
            }
            const apikeyId = keyResult.insertId;

            db.query(
                'INSERT INTO user (firstname, lastname, email, apikey_id) VALUES (?, ?, ?, ?)',
                [firstname, lastname, email, apikeyId],
                (err2) => {
                    if (err2) {
                        console.error('❌ Error simpan user:', err2);
                        return res.status(500).json({ success: false, error: 'Gagal simpan user' });
                    }
                    res.json({ success: true });
                }
            );
        }
    );
});

app.delete('/delete-user/:id', (req, res) => {
    const userId = req.params.id;
    db.query('SELECT apikey_id FROM user WHERE id = ?', [userId], (err, result) => {
        if (err || result.length === 0) {
            return res.status(404).json({ success: false, error: 'User tidak ditemukan' });
        }
        const apikeyId = result[0].apikey_id;

        db.query('DELETE FROM apikey WHERE id = ?', [apikeyId], (err1) => {
            if (err1) {
                return res.status(500).json({ success: false, error: 'Gagal hapus API key' });
            }
            db.query('DELETE FROM user WHERE id = ?', [userId], (err2) => {
                if (err2) {
                    return res.status(500).json({ success: false, error: 'Gagal hapus user' });
                }
                res.json({ success: true });
            });
        });
    });
});


app.post('/register', (req, res) => {
    const { nama, email, password } = req.body;
    const cleanEmail = (email || '').trim();

    if (!nama || !cleanEmail || !password) {
        return res.status(400).json({ success: false, error: 'Nama, email, dan password wajib diisi' });
    }

    // 🔍 Cek email dulu
    db.query('SELECT id FROM admin WHERE email = ?', [cleanEmail], (err, results) => {
        if (err) {
            console.error('❌ Error cek email:', err);
            return res.status(500).json({ success: false, error: 'Error cek email' });
        }

        if (results.length > 0) {
            return res.status(409).json({ success: false, error: 'Email sudah terdaftar' });
        }

        // 🔑 Hash password
        bcrypt.hash(password, 10, (err, hash) => {
            if (err) {
                console.error('❌ Bcrypt error:', err);
                return res.status(500).json({ success: false, error: 'Gagal hashing password' });
            }

            // 💾 Simpan admin
            db.query('INSERT INTO admin (nama, email, password) VALUES (?, ?, ?)', [nama, cleanEmail, hash], (err) => {
                if (err) {
                    console.error('❌ Insert error:', err);
                    return res.status(500).json({ success: false, error: 'Gagal simpan admin' });
                }
                res.json({ success: true });
            });
        });
    });
});

app.post('/login', (req, res) => {
    const { email, password } = req.body;
    const cleanEmail = (email || '').trim();

    if (!cleanEmail || !password) {
        return res.status(400).json({ success: false, error: 'Email dan password wajib diisi' });
    }

    db.query('SELECT * FROM admin WHERE email = ?', [cleanEmail], (err, results) => {
        if (err) {
            console.error('❌ Query error:', err);
            return res.status(500).json({ success: false, error: 'Error sistem' });
        }

        if (results.length === 0) {
            return res.status(401).json({ success: false, error: 'Email atau password salah' });
        }

        const admin = results[0];
        bcrypt.compare(password, admin.password, (err, match) => {
            if (err) {
                console.error('❌ Bcrypt compare error:', err);
                return res.status(500).json({ success: false, error: 'Error verifikasi password' });
            }

            if (!match) {
                return res.status(401).json({ success: false, error: 'Email atau password salah' });
            }

            req.session.adminId = admin.id;
            req.session.nama = admin.nama;
            res.json({ success: true });
        });
    });
});

app.get('/logout', (req, res) => {
    req.session.destroy(() => {
        res.redirect('/login');
    });
});

// ========== DASHBOARD DATA ==========
app.get('/dashboard-data', (req, res) => {
    if (!req.session.adminId) {
        return res.status(403).json({ success: false, error: 'Unauthorized' });
    }

    const query = `
        SELECT u.id, u.firstname, u.lastname, u.email,
               a.api_key, a.status, a.expiredAt
        FROM user u
        JOIN apikey a ON u.apikey_id = a.id
        ORDER BY u.id DESC
    `;

    db.query(query, (err, results) => {
        if (err) {
            console.error('❌ Error ambil data dashboard:', err);
            return res.status(500).json({ success: false, error: 'Gagal ambil data' });
        }
        res.json({ success: true, users: results });
    });
});

// Endpoint untuk ambil data admin yang sedang login
app.get('/current-admin', (req, res) => {
    if (!req.session.adminId) {
        return res.status(403).json({ success: false, error: 'Unauthorized' });
    }
    res.json({
        success: true,
        admin: {
            id: req.session.adminId,
            nama: req.session.nama
        }
    });
});

app.listen(port, () => {
    console.log(`✅ Server jalan di http://localhost:${port}`);
});