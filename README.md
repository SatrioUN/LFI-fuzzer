# LFI Fuzzer

**LFI Fuzzer** adalah alat untuk melakukan scanning dan fuzzing kerentanan *Local File Inclusion* (LFI) pada aplikasi web. Alat ini menggunakan teknik *evasion payloads*, *multiple injection points*, dan deteksi *false positive* berbasis cosine similarity untuk meningkatkan akurasi hasil.

---

## 🔧 Fitur

- Mendukung HTTP **GET** dan **POST**
- Multiple injection points: **parameter URL**, **header**, dan **cookie**
- Payload evasion otomatis:
  - Randomisasi huruf besar/kecil
  - Whitespace injection
  - Double URL encoding
  - Null byte injection
- Proxy rotator dengan validasi dan blacklist otomatis
- Deteksi false positive menggunakan **TF-IDF** dan **cosine similarity**
- Export hasil ke format **HTML**, **CSV**, dan **JSON** dengan filter hasil valid
- Support concurrency tinggi menggunakan `asyncio` dan `aiohttp`

---

## ⚙️ Instalasi

1. Clone repository ini atau download langsung script `lfi.py`.
2. Buat virtual environment (opsional tapi disarankan):

   ```bash
   python -m venv venv
   ```

   Aktifkan virtual environment:

   - **Windows**:
     ```bash
     venv\Scripts\activate
     ```
   - **Linux/macOS**:
     ```bash
     source venv/bin/activate
     ```

3. Install dependencies:

   ```bash
   pip install -r requirements.txt
   ```

---

## 🚀 Penggunaan

```bash
python3 lfi.py -u "http://target.com/vuln.php?file=page" -c 20 --output-html report.html --output-csv report.csv --output-json report.json
```

### Opsi Utama:

| Opsi                | Deskripsi |
|---------------------|----------|
| `-u, --url`         | Target URL tunggal |
| `-U, --url-list`    | File berisi daftar URL target |
| `-p, --payload-list`| File berisi daftar payload (jika tidak disediakan, payload default digunakan) |
| `-P, --proxy-list`  | File berisi daftar proxy HTTP/HTTPS |
| `-c, --concurrency` | Jumlah request paralel *(default: 10)* |
| `--output-html`     | File output laporan dalam format HTML |
| `--output-csv`      | File output laporan dalam format CSV |
| `--output-json`     | File output laporan dalam format JSON |
| `-m, --methods`     | Metode HTTP yang digunakan *(GET, POST)* |
| `-i, --injection-points` | Titik injeksi *(param, header, cookie)* |

---

### Contoh Penggunaan

#### 🔹 Scan satu URL dengan concurrency 15 dan simpan laporan HTML:

```bash
python3 lfi.py -u "http://example.com/index.php?page=home" -c 15 --output-html lfi_report.html
```

#### 🔹 Scan banyak URL dari file `targets.txt` dengan proxy dan simpan laporan CSV:

```bash
python lfi.py -U targets.txt -P proxies.txt --output-csv results.csv
```

---

## ⚠️ Disclaimer

Gunakan alat ini **hanya untuk pengujian keamanan pada sistem milik Anda sendiri** atau sistem yang Anda memiliki **izin eksplisit** untuk menguji.  
**Developer tidak bertanggung jawab atas penyalahgunaan alat ini.**

---

## 📬 Kontak

**Developer:** SatrioUN  
**Instagram:** [@rioocns](https://instagram.com/rioocns)
