# auth-service

Auth-service adalah microservice otentikasi berbasis NestJS yang menyediakan fitur utama untuk aplikasi web/mobile.

Fitur:

- Pendaftaran dan login lokal (email + password)
- OAuth (Google) login dan linking akun
- JWT access & refresh token
- Redis session untuk refresh-token (jti)
- Verifikasi email via token (email)
- Reset password via email token
- Two-Factor Authentication (TOTP) dengan QR code
- Prisma ORM (PostgreSQL) sebagai database
- Throttling (rate-limiter) menggunakan `@nestjs/throttler`
- Mailer untuk mengirim email verifikasi dan reset

Tech stack:

- Node.js + NestJS (TypeScript)
- Prisma (PostgreSQL)
- Redis (ioredis)
- Passport, JWT, Passport-Google-OAuth20
- bcrypt, speakeasy, qrcode

## Persyaratan

- Node.js >= 18
- npm
- PostgreSQL
- Redis

## Konfigurasi environment

Buat file `.env` (copy dari `.env.example` bila tersedia) dan isi variabel berikut:

- `DATABASE_URL` - koneksi Postgres (contoh: `postgres://user:pass@localhost:5432/dbname`)
- `REDIS_URL` - koneksi Redis (contoh: `redis://localhost:6379`)
- `JWT_SECRET` - secret untuk access token
- `JWT_REFRESH_SECRET` - secret untuk refresh token
- `ACCESS_TOKEN_EXPIRES_IN` - expiry access token (mis. `15m`)
- `REFRESH_TOKEN_EXPIRES_IN` - expiry refresh token
- `FRONTEND_URL` - URL frontend untuk redirect (OAuth / verify)

Mailer (SMTP):

- `MAIL_HOST`
- `MAIL_PORT`
- `MAIL_USER`
- `MAIL_PASS`
- `MAIL_FROM`

Sesuaikan nilai di atas sesuai lingkungan Anda.

## Instalasi & menjalankan

1. Install dependency

```bash
npm install
```

2. Generate Prisma client

```bash
npm run prisma:generate
```

3. Jalankan migrasi (development)

```bash
npm run prisma:migrate
```

4. Jalankan server (development)

```bash
npm run start:dev
```

Server default berjalan di `http://localhost:3000`.

## Skrip penting

- `npm run start:dev` - jalankan server (watch mode)
- `npm run build` - build project
- `npm run test` - jalankan unit tests
- `npm run prisma:generate` - generate Prisma client
- `npm run prisma:migrate` - jalankan migration

## Endpoints utama

- `POST /auth/register` — registrasi user
- `POST /auth/login` — login lokal (mengembalikan access & refresh token)
- `GET /auth/google` & `GET /auth/google/callback` — OAuth Google
- `POST /auth/refresh` — refresh token (butuh refresh token)
- `POST /auth/logout` — logout (menghapus session refresh token)
- `GET /auth/verify-email?token=...` — verifikasi email
- `POST /auth/request-password-reset` — kirim token reset password
- `POST /auth/reset-password` — reset password pakai token
- `POST /auth/2fa/setup` — generate secret & QR code (butuh JWT)
- `POST /auth/2fa/enable` — aktifkan 2FA (butuh JWT)

Dokumentasi API dapat ditemukan di Swagger (jika telah dikonfigurasi pada proyek).

## Catatan penting

- Throttler: konfigurasi `ttl` dihitung dalam detik. Contoh yang benar:

```ts
ThrottlerModule.forRoot({ ttl: 60, limit: 100 });
```

- Pastikan hanya memanggil `bcrypt.compare()` kalau `user.passwordHash` tersedia (user OAuth biasanya tidak memiliki password).
- `PrismaModule` harus diexport dan diimport pada modul yang membutuhkannya (mis. `AuthModule`) agar `PrismaService` dapat di-inject.

## Troubleshooting

- UnknownDependenciesException mengenai `PrismaService` di `AuthService` → pastikan `PrismaModule` di-import di `AuthModule`.
- `data and hash arguments required` dari `bcrypt.compare` → pastikan `passwordHash` tidak `null` sebelum compare.

## Contributing

- Buka issue untuk diskusi fitur besar.
- Kirim PR untuk perbaikan/fitur kecil.

## License

Lihat `package.json` untuk informasi lisensi.
