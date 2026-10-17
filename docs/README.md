# Dokumentasi HSM Service (SoftHSM2 + PKCS#11)

Dokumentasi proyek HSM lokal berbasis [SoftHSM2](https://www.opendnssec.org/softhsm/)
yang mengekspos antarmuka [PKCS#11](https://docs.oasis-open.org/pkcs11/pkcs11-base/v3.0/pkcs11-base-v3.0.html).

| Dokumen | Isi |
|---|---|
| [architecture.md](./architecture.md) | Arsitektur, komponen, alur data, konsep PKCS#11, model keamanan |
| [api-spec.md](./api-spec.md) | Spesifikasi REST API |

## Ringkasan singkat

Satu image `hsm-service` berisi **SoftHSM2** (modul PKCS#11) dan **REST API**
(`hsm-api`) dalam satu container. Token & kunci disimpan di named volume agar
persist antar restart.

## Menjalankan

```bash
docker compose up -d --build
```

| Service | Port | Peran |
|---|---|---|
| `hsm` | `8080` | HSM service (SoftHSM2 + REST API) |

## CLI manajemen

```bash
docker compose exec hsm softhsm2-util --show-slots
docker compose exec hsm pkcs11-tool --module /usr/lib/softhsm/libsofthsm2.so --login --pin 1234 --list-objects
```
