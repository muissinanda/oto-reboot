# 🚀 OTO REBOOT - UniFi & Access Point Auto Reboot Manager

Aplikasi web modern berbasis **Python (FastAPI)** untuk memantau status hidup/mati Access Point (AP), menjadwalkan reboot otomatis via SSH (Paramiko multi-threading), manajemen IP AP (tambah, edit, rename, hapus, bulk import), serta riwayat log eksekusi.

Aplikasi ini sudah siap dijalankan menggunakan **Docker & Docker Compose**.

---

## 🌟 Fitur Utama

1. **Dashboard Monitoring Real-time**:
   - Status live kondisi Access Point (Online / Offline) dilengkapi latency response (ms).
   - Ringkasan metrik: Total AP, AP Hidup, AP Mati, Jadwal Aktif.
   - Tombol cepat: **Reboot Semua AP Sekarang** dan **Scan Ping Status**.
   - Menampilkan 10 riwayat eksekusi reboot terbaru.

2. **Manajemen Controller & Access Point**:
   - **Tambah IP AP baru**: Tambah satu per satu atau import puluhan IP sekaligus.
   - **Edit & Rename AP**: Ubah nama/alias AP dan IP address secara langsung.
   - **Hapus IP AP**: Hapus perangkat yang sudah tidak digunakan.
   - **Pengelompokan / Grup**: Kategorikan AP berdasarkan lokasi/lantai/gedung (misal: *Fasilkom 24*, *Fasilkom 25*).
   - **Kredensial Fleksibel**: Menggunakan kredensial SSH default global (`aproot` / `Asdf123#`), dengan opsi kredensial khusus per AP jika diperlukan.
   - **Reboot Terpilih**: Centang beberapa AP lalu reboot sekaligus secara bersamaan.

3. **Jadwal Reboot Otomatis (Scheduler)**:
   - Pengaturan jam & menit reboot otomatis (misal: setiap jam **03:00 Subuh** saat traffic sepi).
   - Pengaturan hari (Setiap Hari, Hari Kerja, Akhir Pekan, atau Hari Tertentu).
   - Target reboot spesifik: **Semua AP**, **Grup Tertentu**, atau **AP Pilihan**.
   - Fitur **Test Run** untuk mencoba eksekusi jadwal secara instan.

4. **Log History & Audit**:
   - Riwayat eksekusi reboot tercatat lengkap (Waktu, Nama AP, IP Target, Pemicu Manual/Jadwal, Status Sukses/Gagal, Pesan SSH / Error, Durasi eksekusi dalam milidetik).
   - Filter pencarian dan tombol bersihkan riwayat.

5. **Multi-Threading Parallel SSH**:
   - Menggunakan `ThreadPoolExecutor` dan `paramiko` sehingga proses reboot 40+ AP berlangsung cepat dan serentak tanpa perlu menunggu satu per satu.

---

## 📁 Struktur Direktori

```text
oto-reboot/
├── app/
│   ├── templates/
│   │   ├── base.html        # Layout utama & sidebar navigasi
│   │   ├── index.html       # Dashboard monitoring
│   │   ├── aps.html         # Manajemen AP (CRUD, Rename, Import, Bulk Reboot)
│   │   ├── schedules.html   # Konfigurasi jadwal otomatis
│   │   ├── logs.html        # Riwayat aktivitas log
│   │   └── settings.html    # Konfigurasi SSH default & interval monitor
│   ├── database.py          # SQLAlchemy models & SQLite database engine
│   ├── main.py              # FastAPI server & REST API
│   ├── monitor.py           # Background probe status AP (TCP Socket / Ping ICMP)
│   ├── scheduler.py         # APScheduler untuk otomasi harian
│   ├── seed.py              # Inisialisasi otomatis daftar IP UniFi pengguna
│   └── ssh_worker.py        # Worker SSH paralel berbasis Paramiko
├── data/                    # Penyimpanan permanen database SQLite (Docker Volume)
├── docker-compose.yml       # Konfigurasi Docker Compose
├── Dockerfile               # Spesifikasi kontainer aplikasi
├── requirements.txt         # Daftar pustaka Python
└── README.md
```

---

## 🛠️ Cara Instalasi & Menjalankan (Docker Compose)

### 1. Masuk ke direktori aplikasi
```bash
cd oto-reboot
```

### 2. Jalankan aplikasi dengan Docker Compose
```bash
docker compose up -d --build
```

### 3. Akses Web Dashboard
Buka browser dan akses:
```text
http://localhost:3080
```
*(Atau ganti `localhost` dengan IP server Linux Anda, misal: `http://10.132.x.x:3080`)*

---

## ⚙️ Catatan Jaringan (Network) untuk Docker di Linux

Jika server Docker Anda berada di subnet yang berbeda atau menggunakan VLAN khusus untuk mengakses Access Point UniFi (`10.132.24.x` dan `10.132.25.x`), Anda dapat mengaktifkan **`network_mode: "host"`** di file `docker-compose.yml` agar kontainer dapat langsung berkomunikasi dengan IP-IP Access Point tanpa pembatasan NAT Docker:

```yaml
version: '3.8'

services:
  oto-reboot:
    build: .
    container_name: oto-reboot
    restart: unless-stopped
    network_mode: "host"
    environment:
      - TZ=Asia/Jakarta
      - DATA_DIR=/app/data
    volumes:
      - ./data:/app/data
```
*(Jika menggunakan `network_mode: host`, aplikasi akan berjalan langsung di port `8000`: `http://IP-SERVER:8000`)*

---

## 💡 Menjalankan Secara Lokal (Tanpa Docker)

Jika ingin menjalankan langsung menggunakan Python lokal:

```bash
# 1. Buat virtual environment (opsional)
python -m venv venv
source venv/bin/activate  # Linux/Mac
# atau: venv\Scripts\activate  # Windows

# 2. Install dependensi
pip install -r requirements.txt

# 3. Jalankan server
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

---

## 🔐 Kredensial Bawaan

Saat pertama kali dijalankan, sistem otomatis:
1. Memasukkan seluruh 43 IP Access Point Fasilkom (`10.132.24.x` dan `10.132.25.x`) ke database.
2. Menggunakan kredensial bawaan:
   - **Username**: `aproot`
   - **Password**: `Asdf123#`
   - **Port**: `22`
3. Anda dapat mengubah kredensial global kapan saja melalui menu **Pengaturan** di dashboard.

---

## 👥 Manajemen User & Hak Akses Site (RBAC)

1. **Akun Login Bawaan Web**:
   - **Username**: `admin`
   - **Password**: `admin123`
   - **Role**: `superadmin` (Akses penuh ke semua site, user management, dan settings)

2. **Hak Akses Site (Per-Fakultas / Lokasi)**:
   - Superadmin dapat membuat user baru (misal: `operator_fasilkom`).
   - Tentukan site yang diizinkan (misal hanya `Fasilkom`).
   - User tersebut hanya dapat melihat, mengelola, dan mereboot Access Point yang berada di site `Fasilkom`. Site lain tidak akan tampil di layarnya.

---

## 🌐 Integrasi Google Sign-In / Pendaftaran Google OAuth 2.0

Sistem mendukung login & pendaftaran otomatis menggunakan akun Google.

### Cara Konfigurasi Google OAuth:
1. Buka [Google Cloud Console - Credentials](https://console.cloud.google.com/apis/credentials).
2. Buat **OAuth 2.0 Client IDs** (Application type: *Web Application*).
3. Tambahkan **Authorized redirect URIs**:
   - Untuk testing lokal: `http://localhost:8000/auth/google/callback`
   - Untuk server produksi / domain: `http://<IP_SERVER_ATAU_DOMAIN>:8000/auth/google/callback`
4. Salin **Client ID** dan **Client Secret**.
5. Di aplikasi OTO REBOOT, masuk sebagai `admin` ➔ Buka menu **Pengaturan** ➔ Bagian **Google OAuth 2.0 Single Sign-On**.
6. Masukkan Client ID & Secret, lalu pilih **Default Site untuk User Baru** (misal: `Fasilkom`).
7. Klik **Simpan Pengaturan Google OAuth**.
8. Pengguna sekarang dapat langsung mengklik tombol **"Daftar / Masuk Akun Google"** di halaman login. Akun baru akan langsung terdaftar otomatis dengan akses ke site default!

