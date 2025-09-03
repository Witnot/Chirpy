
---

# Chirpy

Chirpy is a microblogging API built in Go. Users can create accounts, post “chirps,” follow other users, and manage authentication securely using JWT access tokens and refresh tokens. It also supports **Chirpy Red**, a premium membership program with webhook integration for premium features.

---

## Why Chirpy?

* Learn how to build a secure REST API in Go.
* Demonstrates authentication with JWTs, refresh tokens, and hashed passwords.
* Shows real-world API features: webhooks, token revocation, filtering, and sorting.

---

## Features

* User registration and login (with JWT + refresh tokens)
* Create, read, update, and delete chirps
* Authenticated endpoints for user updates and chirp management
* Chirpy Red membership via webhook integration
* Optional query parameters for filtering and sorting chirps

---

## Installation

1. **Clone the repository**

```bash
git clone https://github.com/Witnot/Chirpy.git
cd Chirpy
```

2. **Set up environment variables**

Create a `.env` file in the root:

```env
DB_URL=postgres://postgres:postgres@localhost:5432/chirpy
JWT_SECRET=<your-random-secret>
POLKA_KEY=f271c81ff7084ee5b99a5091b42d486e
```

Generate a strong JWT secret:

```bash
openssl rand -base64 64
```

3. **Install dependencies**

```bash
go mod tidy
```

4. **Set up the database**

Run migrations using Goose:

```bash
goose -dir sql/schema postgres "$DB_URL" up
```

5. **Build and run the server**

```bash
go build -o out main.go
./out
```

The server will start on `http://localhost:8080`.

---

## API Endpoints

* `POST /api/users` – Create a new user

```json
{
  "email": "user@example.com",
  "password": "securepassword"
}
```

* `PUT /api/users` – Update authenticated user's email/password
* `POST /api/login` – Login and receive access + refresh tokens

```json
{
  "email": "user@example.com",
  "password": "securepassword"
}
```

* `POST /api/refresh` – Refresh access token using a valid refresh token
* `POST /api/revoke` – Revoke a refresh token
* `POST /api/chirps` – Create a new chirp

```json
{
  "body": "Hello world!"
}
```

* `GET /api/chirps` – List chirps (supports `author_id` and `sort=asc|desc`)
* `GET /api/chirps/{chirpID}` – Get a specific chirp
* `DELETE /api/chirps/{chirpID}` – Delete a chirp (authenticated, author only)
* `POST /api/polka/webhooks` – Upgrade a user to Chirpy Red via webhook

---

