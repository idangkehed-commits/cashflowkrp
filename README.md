# Cash Flow System – PT KYNAN RAHARJA PRATAMA

Sistem Manajemen Arus Kas (Cash Flow) Terintegrasi & Aman untuk Operasional Ekspedisi Penyewaan Truk Tanpa Sopir PT KYNAN RAHARJA PRATAMA.

Dibangun dengan arsitektur modern **Python 3.10 + FastAPI + SQLAlchemy ORM + PostgreSQL/SQLite**, dilengkapi proteksi keamanan enterprise-grade (Anti Brute-Force, Password Hashing bcrypt, Autentikasi JWT, Sanitasi XSS, Proteksi SQL Injection, dan Audit Logging).

---

## 🛡️ Fitur Keamanan Enterprise-Grade

1. **Anti Brute-Force Rate Limiting**:
   - Pembatasan otomatis: 10 percobaan gagal per akun atau 30 per alamat IP dalam 15 menit, disimpan di database.
   - Lockout otomatis selama 15 menit jika terindikasi serangan brute-force.
2. **Kriptografi & Password Hashing**:
   - Hashing native `bcrypt` (12 rounds) dengan salt unik untuk setiap password.
   - Password melebihi 72 byte UTF-8 ditolak, bukan dipotong.
3. **Autentikasi & Autorisasi Berbasis Peran (RBAC)**:
   - Sesi acak server dengan masa kedaluwarsa 8 jam dan cookie HttpOnly/Secure/SameSite.
   - **Peran Owner**: Kontrol penuh (input, lihat riwayat, cetak laporan mingguan/bulanan, backup JSON, pemulihan database, reset database, modifikasi data armada).
   - **Peran Admin**: Terisolasi hanya untuk input transaksi harian dan melihat riwayat/dashboard. Tombol hapus dan kelola database dinonaktifkan.
4. **Proteksi Injeksi & Serangan Web**:
   - Zero Raw SQL: 100% kueri dieksekusi melalui SQLAlchemy ORM Parameterized Statements (Kebal SQL Injection).
   - HTML Sanitization: Pembersihan karakter berbahaya (`<`, `>`, `"`, `'`, `&`) pada input keterangan dan penyewa (Anti Stored XSS).
   - Security Headers Middleware: `X-Content-Type-Options: nosniff`, `X-Frame-Options: SAMEORIGIN`, `X-XSS-Protection: 1; mode=block`, `Referrer-Policy: strict-origin-when-cross-origin`.
5. **Audit Logging**:
   - Seluruh aktivitas krusial (login, gagal login, input transaksi, hapus transaksi, ubah armada, ekspor/impor data) dicatat lengkap beserta timestamp, IP address, user, dan payload ke tabel `audit_logs`.

---

## Login email dan password

Login hanya memakai akun Owner/Admin yang sudah didaftarkan. Tidak ada pendaftaran publik, password bawaan, atau login username. Aktivasi akun dan konfigurasi aman dijelaskan pada [AUTH_SETUP.md](AUTH_SETUP.md).

Sesi dikelola server melalui cookie HttpOnly, Secure di produksi, dan SameSite. Logout serta perubahan password mencabut sesi di server. Password disimpan sebagai hash bcrypt dan tidak ditimpa ketika server restart.

---

## 📁 Struktur Direktori

```text
cashflow-krp/
├── app/
│   ├── __init__.py
│   ├── config.py           # Konfigurasi aplikasi & environment variables
│   ├── database.py         # SQLAlchemy Engine & Session Pool
│   ├── models.py           # Model Database (User, Transaction, TruckSetting, AuditLog)
│   ├── schemas.py          # Validasi Pydantic & HTML Sanitizer
│   ├── security.py         # Bcrypt, JWT, Rate Limiter, RBAC, Audit Log
│   ├── main.py             # FastAPI App, Middleware, Endpoints API & Static Files
│   └── static/
│       └── index.html      # UI Mobile-First Responsive, Print Layout, Client API
├── .env.example            # Contoh konfigurasi environment
├── .gitignore              # Mengabaikan venv, database lokal, dan file cache
├── Procfile                # Perintah jalankan web service di Render / PaaS
├── render.yaml             # Render Blueprint (Web Service + PostgreSQL)
├── requirements.txt        # Dependensi Python
└── test_e2e.py             # Script verifikasi pengujian otomatis
```

---

## 💻 Menjalankan di Lokal (Pengembangan)

1. **Masuk ke folder `cashflow-krp`**:
   ```powershell
   cd "c:\Users\ACER NITRO\Documents\antigravity\jolly-goodall\cashflow-krp"
   ```

2. **Aktifkan Virtual Environment**:
   ```powershell
   .\.venv\Scripts\Activate.ps1
   ```

3. **Jalankan Server Uvicorn**:
   ```powershell
   uvicorn app.main:app --reload --port 8000
   ```

4. **Buka di Browser**:
   Buka `http://localhost:8000` di Google Chrome atau browser pilihan Anda.

---

## 🚀 Panduan Deploy ke Render.com (Blueprint Otomatis)

Dengan file `render.yaml` yang sudah disiapkan, Render akan otomatis membuat:
1. **Managed PostgreSQL Database** (`cashflowkrp-db`)
2. **Web Service FastAPI** (`cashflowkrp`) dengan auto-deploy
3. Domain aktif 24 jam: **`https://cashflowkrp.onrender.com`**

### Langkah-Langkah Deploy:

1. **Inisialisasi Git & Push ke GitHub**:
   Buka terminal di folder `cashflow-krp`:
   ```bash
   cd "c:\Users\ACER NITRO\Documents\antigravity\jolly-goodall\cashflow-krp"
   git init
   git add .
   git commit -m "feat: initial commit cashflowkrp python database"
   git branch -M main
   git remote add origin https://github.com/<USERNAME-ANDA>/cashflowkrp.git
   git push -u origin main
   ```

2. **Buka Dashboard Render**:
   - Masuk ke [dashboard.render.com](https://dashboard.render.com).
   - Klik tombol **New +** di pojok kanan atas, lalu pilih **Blueprint**.
   - Hubungkan akun GitHub Anda dan pilih repositori `cashflowkrp`.

3. **Tinjau Blueprint (`render.yaml`)**:
   - Render akan secara otomatis mendeteksi konfigurasi:
     - **Service Name**: `cashflowkrp`
     - **Database Name**: `cashflowkrp-db`
     - **Plan**: Free
   - Klik tombol **Apply**.

4. **Selesai**:
   - Render akan membangun aplikasi dan menginisialisasi database PostgreSQL dalam 2-3 menit.
   - Akses aplikasi Anda di URL: **`https://cashflowkrp.onrender.com`**.
