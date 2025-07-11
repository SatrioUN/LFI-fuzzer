# Advanced LFI Scanner

![LFI Scanner](https://img.shields.io/badge/Status-Active-green) ![Python](https://img.shields.io/badge/Python-3.7%2B-blue)

**Advanced Local File Inclusion (LFI) Scanner** adalah alat otomatisasi untuk mendeteksi kerentanan Local File Inclusion pada aplikasi web. Alat ini menggunakan teknik canggih dengan payload beragam, deteksi berbasis signature dan machine learning sederhana untuk mengurangi false positive. Hasil scan dapat disimpan ke database SQLite dan dilaporkan dalam format HTML dan PDF.

---

## Fitur Utama

- Mendukung scanning multi-target URL dari file atau argumen langsung.
- Payload LFI yang dapat dikustomisasi melalui file eksternal.
- Deteksi LFI berbasis signature dan regex error message.
- Penggunaan machine learning sederhana (cosine similarity TF-IDF) untuk mengurangi false positive.
- Mendukung proxy rotator untuk menghindari blokir IP.
- Mendukung metode HTTP GET dan POST.
- Simpan hasil scan ke database SQLite.
- Generate laporan scan dalam format HTML dan PDF.
- Simpan response HTTP yang mengindikasikan LFI untuk analisa lebih lanjut.
- Output terminal berwarna untuk memudahkan identifikasi hasil scan.

---

## Instalasi

1. Clone repository ini:

```bash
git clone https://github.com/username/advanced-lfi-scanner.git
cd advanced-lfi-scanner
##Install dependencies (disarankan menggunakan virtual environment):
pip install -r requirements.txt
Catatan: Pastikan Anda sudah menginstall wkhtmltopdf untuk fitur generate PDF (https://wkhtmltopdf.org/).
sudo apt-get install wkhtmltopdf
'''bash

##Penggunaan:
single target:
python lfi_scanner.py -u <target_url> -p <payload_file> [options]
python lfi_scanner.py -u "http://example.com/vuln.php?file=home" -p payloads.txt --proxy proxies.txt --save --max-workers 30

multi target:
python lfi_scanner.py -p payloads.txt --urls-file urls.txt --saveScan 
##satu URL dengan proxy dan header tambahan:
python lfi_scanner.py -p payloads.txt -u "http://example.com/vuln.php?file=abc" --proxy proxies.txt --headers "Authorization: Bearer token123"

Dampak LFI:

Membaca file sensitif seperti /etc/passwd di Linux.
Mengeksekusi kode berbahaya jika file yang dimasukkan berisi skrip.
Mengakses konfigurasi internal dan data rahasia.
Potensi eskalasi serangan ke Remote Code Execution (RCE).

Cara kerja alat ini:
Alat ini mengirimkan payload LFI ke parameter URL 
atau path, lalu menganalisa respon server untuk 
tanda-tanda LFI, seperti pesan error PHP, isi file 
sistem, atau pola lain yang mencurigakan. Dengan 
menggunakan teknik machine learning sederhana, alat 
ini juga mencoba mengurangi false positive dengan 
membandingkan respon dengan baseline normal.

Lisensi
MIT License © 2025 rioocns

Opsi:
	                     Deskripsi
-u, --url	URL target yang akan dipindai (wajib)
-p, --payloads	File berisi payload LFI (wajib)
--proxy	File berisi daftar proxy (opsional)
--timeout	Timeout request dalam detik (default: 15)
--save	Simpan respons LFI yang ditemukan ke file
--no-ssl-verify	Nonaktifkan verifikasi SSL
--cookies	Cookie kustom (format: key=value; key2=value2)
--headers	Header tambahan (format: Header1: value1\nHeader2: value2)
--post	Gunakan metode POST untuk request
--max-workers	Jumlah maksimal worker concurrent (default: 50)


Catatan Penting:
Gunakan alat ini hanya pada sistem yang Anda miliki izin eksplisit untuk diuji.
Pemindaian tanpa izin dapat melanggar hukum dan kebijakan penggunaan.
Selalu lakukan pengujian di lingkungan yang aman dan terkendali.

Kontak
Jika ada pertanyaan atau butuh bantuan, silakan hubungi:

GitHub: https://github.com/rioocns
Instagram: @rioocns

Disclaimer
Alat ini hanya untuk tujuan edukasi dan pengujian 
keamanan pada sistem yang Anda miliki atau memiliki 
izin eksplisit untuk diuji. Penggunaan tanpa izin 
adalah ilegal dan bertanggung jawab sepenuhnya pada pengguna.