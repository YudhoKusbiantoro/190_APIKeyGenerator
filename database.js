// database.js
const mysql = require('mysql2');

const db = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: 'AndesTapes11', // ganti sesuai usermu
    database: 'apikey',
    port: 3309// ubah kalau pakai port lain
});

db.connect((err) => {
    if (err) {
        console.error('❌ Gagal konek ke MySQL:', err);
    } else {
        console.log('✅ Terhubung ke MySQL Database');
    }
});

module.exports = db;