# SoftHSM2 HSM service (Docker)

Satu image Docker berisi **SoftHSM2** (HSM *software* berbasis PKCS#11) plus
**REST API** untuk signing & key management. Cocok untuk pengembangan, CI, dan
belajar PKCS#11 — **bukan** pengganti HSM hardware untuk produksi.

## Dokumentasi

Spesifikasi & penjelasan lengkap ada di [`docs/`](./docs/):
- [Arsitektur](./docs/architecture.md)
- [Spesifikasi REST API](./docs/api-spec.md)

## Jalankan

```bash
docker compose up -d --build
```

Token default `mytoken` (PIN `1234`, SO PIN `12345678`) dibuat otomatis pada
run pertama. Kunci tersimpan di named volume `softhsm-tokens`, jadi aman saat
container di-restart. API berjalan di `http://localhost:8080`.

## CLI manajemen

```bash
# Cek slot/token
docker compose exec hsm softhsm2-util --show-slots

# Generate key pair
docker compose exec hsm pkcs11-tool \
  --module /usr/lib/softhsm/libsofthsm2.so \
  --login --pin 1234 \
  --keypairgen --key-type rsa:2048 --label mykey --id 01

# List objek
docker compose exec hsm pkcs11-tool \
  --module /usr/lib/softhsm/libsofthsm2.so \
  --login --pin 1234 --list-objects

# Generate cert via OpenSSL engine
docker compose exec hsm openssl req -x509 -new \
  -engine pkcs11 -keyform engine \
  -key "pkcs11:token=mytoken;object=mykey;type=private;pin-value=1234" \
  -subj "/CN=Test" -days 365 -out /tmp/cert.pem
```

> `pin-value` mengekspos PIN di command line — aman untuk lokal/CI. Untuk
> produksi gunakan `pin-source=file` atau biarkan prompt interaktif.

## REST API

| Method & path | Fungsi |
|---|---|
| `GET /healthz` | Health check token |
| `POST /api/v1/keys` | Generate RSA key pair (id UUID v7 otomatis) |
| `GET /api/v1/keys` | List key (label + id) |
| `GET /api/v1/keys/{label}/public` | Export public key (PEM) |
| `DELETE /api/v1/keys/{label}` | Hapus key |
| `POST /api/v1/sign` | Sign data (base64) |
| `POST /api/v1/verify` | Verifikasi signature |
| `POST /api/v1/encrypt` | Enkripsi data (RSA-OAEP) |
| `POST /api/v1/decrypt` | Dekripsi data |

Contoh (base64 dari `hello` = `aGVsbG8=`):

```bash
# Generate key
curl -X POST localhost:8080/api/v1/keys \
  -H 'Content-Type: application/json' \
  -d '{"label":"mykey2","bits":2048}'

# Sign
curl -X POST localhost:8080/api/v1/sign \
  -H 'Content-Type: application/json' \
  -d '{"label":"mykey","algorithm":"RSA-SHA256","data":"aGVsbG8="}'

# Verify
curl -X POST localhost:8080/api/v1/verify \
  -H 'Content-Type: application/json' \
  -d '{"label":"mykey","algorithm":"RSA-SHA256","data":"aGVsbG8=","signature":"..."}'
```

Detail lengkap: [docs/api-spec.md](./docs/api-spec.md).

## Catatan

- `SOFTHSM2_PIN`, `SOFTHSM2_SO_PIN`, `SOFTHSM2_TOKEN_LABEL`, `PORT` bisa
  di-override lewat `docker-compose.yml`.
- Library PKCS#11 tersedia di `/usr/lib/softhsm/libsofthsm2.so`.
- Token disimpan di named volume `softhsm-tokens` (mount `/home/hsm/tokens`).
- **Windows / Git Bash**: path seperti `/usr/lib/softhsm/libsofthsm2.so` akan
  diubah MSYS menjadi `C:/Program Files/Git/...`. Pakai salah satu:
  - prefix `MSYS_NO_PATHCONV=1` pada perintah, atau
  - bungkus perintah dalam `docker compose exec hsm sh -c '...'`.
