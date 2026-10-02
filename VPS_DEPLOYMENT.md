# VPS Deployment

This guide deploys the full CryptoScan stack on one Ubuntu VPS. Docker Compose runs PostgreSQL, Redis, the API, the scan worker, the CBOM service, Nginx, and Caddy. Caddy obtains and renews HTTPS certificates automatically.

## 1. Prepare the VPS and domain

Use Ubuntu 24.04 LTS. For a demo, use at least 2 vCPU and 4 GB RAM; 4 vCPU and 8 GB RAM is preferable for repository scans. Allow inbound SSH (22), HTTP (80), and HTTPS (443) in the provider firewall. Point a DNS A record for the intended hostname (for example, `app.example.com`) to the VPS public IPv4 address. Remove a stale AAAA record unless IPv6 is configured on the VPS.

Install Docker, Compose, and Git:

```bash
sudo apt update
sudo apt install -y docker.io docker-compose-v2 git
sudo systemctl enable --now docker
sudo docker --version
sudo docker compose version
```

If using UFW, allow SSH before enabling it:

```bash
sudo ufw allow OpenSSH
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw enable
```

## 2. Get the code

Configure a GitHub deploy key on the VPS if the repository is private, then clone the `main` branch:

```bash
git clone git@github.com:Shravu2215/Cryptoscan_469.git CryptoScan
cd CryptoScan
git checkout main
git pull --ff-only origin main
```

## 3. Configure Compose variables

Create the root Compose environment file. Generate a password and use the generated hex value, not the example placeholder:

```bash
cp .env.example .env
openssl rand -hex 32
nano .env
```

Set the values in root `.env`:

```dotenv
DOMAIN=app.example.com
POSTGRES_USER=cryptoscan_user
POSTGRES_PASSWORD=<generated-64-character-hex-value>
POSTGRES_DB=cryptoscan
```

Use the exact public hostname in `DOMAIN`. The database password is hex so it is safe to use in the PostgreSQL URL below. Root `.env` is ignored by Git.

## 4. Configure backend secrets

Create the backend environment file and generate the required secrets. Run each command separately and use different values for the two JWT secrets:

```bash
cp backend-core/.env.example backend-core/.env
openssl rand -hex 48
openssl rand -hex 48
openssl rand -base64 32
nano backend-core/.env
```

Set at least these values in `backend-core/.env`:

```dotenv
NODE_ENV=production
DATABASE_URL=postgresql://cryptoscan_user:<same-database-password>@postgres:5432/cryptoscan
JWT_ACCESS_SECRET=<first-generated-96-character-hex-value>
JWT_REFRESH_SECRET=<second-generated-96-character-hex-value>
DATA_ENCRYPTION_KEY=<generated-base64-value>
REDIS_URL=redis://redis:6379
PORT=3000
ALLOWED_ORIGINS=https://app.example.com
FRONTEND_URL=https://app.example.com
CHAIN_MODE=public
PUBLIC_RPC_URL=<your-Sepolia-RPC-HTTPS-URL>
PRIVATE_KEY=<dedicated-Sepolia-wallet-private-key>
KMS_PROVIDER=env
```

`PRIVATE_KEY` is required by the current production startup validation. Use a dedicated Sepolia test wallet, never a wallet holding real funds; fund it with Sepolia test ETH. The wallet must be the owner or an authorized writer of the contract in `blockchain-module/deployed-sepolia.json`. Keep the private key out of Git, shell history, and chat. GitHub OAuth variables are optional; fill them only if enabling GitHub login.

Protect both files:

```bash
chmod 600 .env backend-core/.env
```

## 5. Start and check services

From the repository root, validate the Compose config and build/start the stack:

```bash
sudo docker compose config --quiet
sudo docker compose --profile vps up -d --build
sudo docker compose --profile vps ps
```

The backend container runs `prisma migrate deploy` before starting the API. Do not run `prisma migrate dev` on the production database. Caddy needs the hostname to resolve to this VPS and ports 80/443 reachable before it can issue the HTTPS certificate.

Check the public endpoints:

```bash
curl -i https://app.example.com/health
curl -i https://app.example.com/version
```

`/health` should return HTTP 200 with `{"status":"ok"}`. Then test signup/login, repository ZIP upload, scan completion, findings, and CBOM in the browser. Test blockchain anchoring only after confirming the Sepolia wallet is funded and authorized.

For startup errors, inspect logs:

```bash
sudo docker compose logs --tail=100 backend-core
sudo docker compose logs --tail=100 scan-worker
sudo docker compose logs --tail=100 nginx
sudo docker compose logs --tail=100 caddy
```

## 6. Updates and backups

To deploy a later `main` update:

```bash
git pull --ff-only origin main
sudo docker compose --profile vps up -d --build
sudo docker compose --profile vps ps
```

Back up PostgreSQL regularly and store the backup outside this VPS:

```bash
sudo docker compose exec -T postgres pg_dump -U cryptoscan_user cryptoscan > ~/cryptoscan-$(date +%F).sql
```

The `postgres-data`, `backend-uploads`, and Caddy certificate volumes persist across container rebuilds. Never use `docker compose down -v` on a live deployment; it removes persistent volumes.
