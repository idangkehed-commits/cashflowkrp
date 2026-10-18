# Login email Cashflow KRP

## Akun dan aktivasi

Akun dibuat secara terbatas oleh konfigurasi aplikasi, tanpa pendaftaran publik. Email login tidak dikirim pesan verifikasi: ini login email dan password, bukan Google Sign-In atau OTP. Hak Owner/Admin mengikuti akun lama dan tidak dapat dipilih dari halaman login.

Sebelum kode ini diterapkan pada Render, pemilik aplikasi harus mengisi sendiri empat variabel berikut di Environment layanan **cashflowkrp**:

| Variabel | Isi |
|---|---|
| `OWNER_EMAIL` | Email Owner yang disetujui |
| `ADMIN_EMAIL` | Email Admin yang disetujui |
| `OWNER_INITIAL_PASSWORD` | Password baru Owner |
| `ADMIN_INITIAL_PASSWORD` | Password baru Admin |

Gunakan dua password berbeda, minimal 12 karakter, disarankan 16 karakter atau lebih, maksimal 72 byte UTF-8. Jangan memakai password lama, password contoh pengujian, atau memasukkannya ke chat, repository, screenshot, maupun dokumen. Pemilik mengisinya langsung pada pengaturan Render. Pertahankan `ENVIRONMENT=production` dan `DATABASE_URL` yang sudah ada. Tidak perlu layanan berbayar atau pengiriman email.

Setelah aktivasi pertama berhasil dan kedua akun bisa masuk, hapus `OWNER_INITIAL_PASSWORD` dan `ADMIN_INITIAL_PASSWORD` dari Environment. Perubahan password berikutnya dilakukan melalui Pengaturan aplikasi. Email dan hash password yang sudah terdaftar tidak ditimpa saat restart walaupun nilai awal masih ada di environment. Variabel `DEFAULT_OWNER_PASS` dan `DEFAULT_ADMIN_PASS` dari versi lama tidak digunakan lagi.

Jika aplikasi sebelumnya memakai username internal berbeda, pertahankan nilai `DEFAULT_OWNER_USER` dan `DEFAULT_ADMIN_USER` yang sudah digunakan. Nama internal ini hanya untuk memetakan akun lama, bukan pilihan login pengguna.

## Migrasi

- Basis kode rilis sebelumnya: commit `9d63877`.
- Menambahkan kolom nullable `users.email`, indeks unik email, tabel `auth_sessions`, dan tabel `auth_login_attempts`. Mendukung SQLite dan PostgreSQL.
- User ID, peran, status aktif/nonaktif, transaksi, penyewa, kategori, armada, dan audit lama tidak dihapus atau diganti.
- Akun lama yang belum punya email hanya didaftarkan dengan email dan password baru yang secara eksplisit dikonfigurasi. Tidak ada password bawaan atau endpoint reset publik.
- Password awal harus berbeda dari hash password lama. Akun yang sebelumnya dinonaktifkan tidak otomatis diaktifkan.
- Login username dan bearer/JWT versi lama tidak diterima. Semua pengguna perlu masuk kembali setelah perubahan ini aktif.
- Jangan memulihkan kode autentikasi lama sebagai langkah rollback tanpa peninjauan: versi lama menimpa password ketika server restart. Jika aktivasi gagal, perbaiki konfigurasi atau deploy ulang versi baru, tanpa menyentuh tabel transaksi.

## Perlindungan sesi

Sesi acak 256-bit disimpan di cookie `__Host-krp_session` (Secure, HttpOnly, SameSite=Lax, Path=/, tanpa Domain) pada produksi. Database hanya menyimpan hash token. Masa sesi default 8 jam. Tidak ada token login baru di sessionStorage/localStorage.

Logout mencabut sesi di server dan membersihkan isi layar. Ganti password sendiri mencabut semua sesi akun, lalu menerbitkan sesi baru bagi pengguna yang sedang menggantinya. Reset password Admin oleh Owner mencabut semua sesi Admin. Penonaktifan akun langsung membuat sesi akun tidak dapat dipakai.

Permintaan perubahan data, termasuk login/logout, harus berasal dari origin aplikasi. CORS dibatasi ke origin KRP. Respons API tidak boleh disimpan dalam cache. Percobaan login gagal dibatasi berdasarkan akun dan IP dengan penghitung persisten dalam database, bukan hanya memori proses.

Teks transaksi dan armada dari pemulihan file dirender sebagai teks, termasuk ketika mengandung markup. Tidak ada janji bebas kebocoran: faktor seperti keamanan perangkat, password pengguna, akses operator hosting, serta audit infrastruktur berada di luar pengujian perubahan ini.

## Validasi

Jalankan `python test_auth.py` menggunakan dependensi proyek. Pengujian membuat database sementara dengan data dan password sintetis. Tidak memakai database lokal utama atau produksi.

Pengujian mencakup migrasi data, email login, atribut cookie produksi, penolakan JWT/username lama, CSRF, CORS, hak Owner/Admin, transaksi/laporan, pencabutan sesi, kedaluwarsa, persistensi password setelah restart, batas percobaan login, dan respons validasi yang tidak memantulkan password.

Pratinjau browser menggunakan akun `owner@example.test` dan `admin@example.test`, bukan akun produksi. Password contoh hanya untuk database pratinjau lokal yang terpisah.

Untuk PostgreSQL, DDL migrasi dan SQL upsert memakai dialek PostgreSQL; pengujian integrasi database penuh dalam lingkungan ini menggunakan SQLite. Setelah deployment, verifikasi migrasi dan login kedua akun melalui pengaturan/antarmuka sebenarnya tanpa membuat transaksi percobaan di produksi.
