const express = require('express')
const path = require('path')
const crypto = require('crypto')
const app = express()
const port = 3000

// Middleware untuk parsing JSON body
app.use(express.json())

// Middleware untuk melayani file statis dari folder "public"
app.use(express.static(path.join(__dirname, 'public')))

// Variabel untuk menyimpan API key yang terakhir dibuat
let myApiKey = null

// Endpoint contoh
app.get('/test', (req, res) => {
    res.send('Hello World!')
})

// Rute utama: kirim file index.html dari folder public
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'))
})

// Endpoint POST untuk membuat API key
app.post('/create', (req, res) => {
    try {
        // Membuat random 32-byte hex string
        const apiKey = `sk-sm-v1-${crypto.randomBytes(16).toString('hex').toUpperCase()}`
        myApiKey = apiKey // Simpan ke variabel global

        // Kirim balik API key ke client
        res.json({ success: true, apiKey })
    } catch (error) {
        console.error(error)
        res.status(500).json({ success: false, message: 'Gagal membuat API key' })
    }
})

// Endpoint POST untuk mengecek validitas API key
app.listen(port, () => {
    console.log(`Server berjalan di http://localhost:${port}`)
})