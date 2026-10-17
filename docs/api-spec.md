# Spesifikasi REST API `hsm-api`

Service `hsm-api` menyediakan operasi signing dan key management di atas
SoftHSM2 (PKCS#11).

- **Base URL**: `http://localhost:8080`
- **Format**: JSON (`Content-Type: application/json`)
- **Data biner**: di-encode **base64** (standard encoding)
- **Error**: selalu berbentuk `{"error": "<pesan>"}`

## Ringkasan endpoint

| Method & path | Deskripsi |
|---|---|
| `GET /healthz` | Cek kesehatan token |
| `POST /api/v1/keys` | Generate key pair RSA |
| `GET /api/v1/keys` | List label private key |
| `GET /api/v1/keys/{label}/public` | Export public key (PEM) |
| `DELETE /api/v1/keys/{label}` | Hapus key |
| `POST /api/v1/sign` | Tanda tangani data |
| `POST /api/v1/verify` | Verifikasi tanda tangan |
| `POST /api/v1/encrypt` | Enkripsi data (RSA-OAEP/PKCS) |
| `POST /api/v1/decrypt` | Dekripsi data |

---

## `GET /healthz`

Cek apakah token tersedia.

**Response `200 OK`**

```json
{"status": "ok"}
```

**Response `503 Service Unavailable`**

```json
{"error": "token \"mytoken\" not found"}
```

---

## `POST /api/v1/keys`

Generate key pair RSA yang disimpan di token. `id` (nilai `CKA_ID`) dibuat
otomatis oleh service sebagai **UUID v7**. Private key otomatis bersifat
`sensitive` dan `never extractable`.

### Request body

```json
{
  "label": "apikey",
  "bits": 2048
}
```

| Field | Tipe | Wajib | Keterangan |
|---|---|---|---|
| `label` | string | ya | Nama key (nilai `CKA_LABEL`), harus unik |
| `bits` | int | tidak | `2048` (default) atau `4096` |

### Response `201 Created`

```json
{
  "label": "apikey",
  "type": "rsa",
  "bits": 2048,
  "id": "018c5b7a-8f6e-7a1b-9c2d-3e4f5a6b7c8d"
}
```

### Error

| Status | Kondisi |
|---|---|
| `400` | Body bukan JSON valid, `label` kosong, atau `bits` invalid |
| `409` | `label` sudah dipakai (label harus unik) |
| `500` | Gagal generate key di HSM |

---

## `GET /api/v1/keys`

List private key pada token beserta `label` dan `id` (UUID).

### Response `200 OK`

```json
{
  "keys": [
    { "label": "mykey",  "id": "01" },
    { "label": "apikey", "id": "018c5b7a-8f6e-7a1b-9c2d-3e4f5a6b7c8d" }
  ]
}
```

> Key lama yang `CKA_ID`-nya bukan UUID (mis. `01`) ditampilkan sebagai hex.

---

## `GET /api/v1/keys/{label}/public`

Export public key sebagai PEM (PKIX `SubjectPublicKeyInfo`).

### Response `200 OK`

```json
{
  "label": "mykey",
  "public_key_pem": "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...\n-----END PUBLIC KEY-----\n"
}
```

### Error

| Status | Kondisi |
|---|---|
| `404` | Key dengan `label` tidak ditemukan |

---

## `DELETE /api/v1/keys/{label}`

Hapus object private key dan public key dengan label tersebut.

### Response `200 OK`

```json
{"deleted": "apikey"}
```

---

## `POST /api/v1/sign`

Tanda tangani data (hash + sign) memakai private key di token.

### Request body

```json
{
  "label": "mykey",
  "algorithm": "RSA-SHA256",
  "data": "aGVsbG8="
}
```

| Field | Tipe | Wajib | Keterangan |
|---|---|---|---|
| `label` | string | ya | Nama private key |
| `algorithm` | string | tidak | Algoritma (default `RSA-SHA256`), lihat tabel di bawah |
| `data` | string | ya | Data yang ditandatangani, base64 |

### Response `200 OK`

```json
{
  "algorithm": "RSA-SHA256",
  "signature": "E9m676JNypwU9VOjlitN4HQ7fD+zwWY9..."
}
```

### Error

| Status | Kondisi |
|---|---|
| `400` | Body invalid, `data` bukan base64, atau algoritma tidak didukung |
| `500` | Gagal sign (mis. key tidak ditemukan) |

---

## `POST /api/v1/verify`

Verifikasi tanda tangan memakai public key di token.

### Request body

```json
{
  "label": "mykey",
  "algorithm": "RSA-SHA256",
  "data": "aGVsbG8=",
  "signature": "E9m676JNypwU9VOjlitN4HQ7fD+zwWY9..."
}
```

| Field | Tipe | Wajib | Keterangan |
|---|---|---|---|
| `label` | string | ya | Nama key |
| `algorithm` | string | tidak | Harus sama dengan saat sign |
| `data` | string | ya | Data, base64 |
| `signature` | string | ya | Signature, base64 |

### Response `200 OK`

```json
{"valid": true}
```

### Error

| Status | Kondisi |
|---|---|
| `400` | Body invalid, base64 invalid, algoritma tidak didukung, atau verifikasi gagal |

---

## `POST /api/v1/encrypt`

Enkripsi data memakai public key di token.

### Request body

```json
{
  "label": "mykey",
  "algorithm": "RSA-OAEP-SHA1",
  "data": "cmFoYXNpYQ=="
}
```

| Field | Tipe | Wajib | Keterangan |
|---|---|---|---|
| `label` | string | ya | Nama key |
| `algorithm` | string | tidak | Algoritma (default `RSA-OAEP-SHA1`) |
| `data` | string | ya | Data yang dienkripsi, base64 |

### Response `200 OK`

```json
{
  "algorithm": "RSA-OAEP-SHA1",
  "ciphertext": "NhrY63XLvVpr..."
}
```

### Error

| Status | Kondisi |
|---|---|
| `400` | Body invalid, `data` bukan base64, algoritma tidak didukung, atau data terlalu besar |
| `500` | Gagal enkripsi (mis. key tidak ditemukan) |

---

## `POST /api/v1/decrypt`

Dekripsi data memakai private key di token.

### Request body

```json
{
  "label": "mykey",
  "algorithm": "RSA-OAEP-SHA1",
  "data": "NhrY63XLvVpr..."
}
```

| Field | Tipe | Wajib | Keterangan |
|---|---|---|---|
| `label` | string | ya | Nama key |
| `algorithm` | string | tidak | Harus sama dengan saat enkripsi |
| `data` | string | ya | Ciphertext, base64 |

### Response `200 OK`

```json
{"plaintext": "cmFoYXNpYQ=="}
```

### Error

| Status | Kondisi |
|---|---|
| `400` | Body invalid, base64 invalid, algoritma tidak didukung, atau dekripsi gagal |

> Batas ukuran: RSA-2048 OAEP maksimal ~190 byte plaintext; RSA-2048 PKCS#1
> v1.5 ~245 byte. Untuk data besar gunakan *envelope encryption* (enkripsi
> simetris + bungkus kunci AES dengan RSA).

---

## Algoritma yang didukung

### Signing

| Nama | Alias | Mekanisme PKCS#11 |
|---|---|---|
| `RSA-SHA256` | `RS256`, `SHA256-RSA` | `CKM_SHA256_RSA_PKCS` |
| `RSA-PSS-SHA256` | `PS256` | `CKM_SHA256_RSA_PKCS_PSS` |
| `RSA-SHA512` | `RS512`, `SHA512-RSA` | `CKM_SHA512_RSA_PKCS` |

### Enkripsi / dekripsi

| Nama | Mekanisme PKCS#11 |
|---|---|
| `RSA-OAEP-SHA1` (default) | `CKM_RSA_PKCS_OAEP` + SHA-1 |
| `RSA-OAEP-SHA256` | `CKM_RSA_PKCS_OAEP` + SHA-256 (tidak jalan di SoftHSM2 2.6.1) |
| `RSA-PKCS` | `CKM_RSA_PKCS` (legacy) |

> Nilai `algorithm` bersifat case-insensitive.

## Ringkasan status code

| Kode | Makna |
|---|---|
| `200` | Sukses |
| `201` | Resource (key) berhasil dibuat |
| `400` | Request tidak valid |
| `404` | Key tidak ditemukan |
| `500` | Error internal / HSM |
| `503` | Token tidak tersedia |

## Catatan keamanan API

- Tidak ada autentikasi/otorisasi pada HTTP layer — token dilindungi PIN yang
  di-inject lewat env `SOFTHSM2_PIN`. Untuk produksi tambahkan autentikasi
  (API key, mTLS, atau OAuth2) di depan service.
- `data`/`signature`/`ciphertext`/`plaintext` memakai base64 agar aman dikirim lewat JSON.
