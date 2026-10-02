# Free Windows Deployment

This runs the complete stack on your Windows laptop using Docker Desktop. Cloudflare Quick Tunnel can expose it at a temporary free HTTPS URL. There is no VPS or domain charge, but the laptop must stay on, awake, and connected to the internet while people use the site. The Quick Tunnel URL changes when restarted.

## 1. Install the free local tools

1. Install Docker Desktop for Windows and enable its WSL 2 Linux engine when prompted. Docker Desktop is free for personal use; check its current license if using it for a larger organization.
2. Restart Windows if the installer asks, then open Docker Desktop and wait until it says the engine is running.
3. Open PowerShell in this repository folder and check:

```powershell
docker version
docker compose version
```

The client and server sections should both appear under `docker version`.

## 2. Create local secret files

From the repository root in PowerShell:

```powershell
Copy-Item .env.example .env
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
notepad .env
```

Set `POSTGRES_PASSWORD` in `.env` to the generated hex value. `DOMAIN` is not used in free mode; leave the sample value or set it to `localhost`. Save and close Notepad.

Create the backend environment file and generate three secrets:

```powershell
Copy-Item backend-core/.env.example backend-core/.env
node -e "console.log(require('crypto').randomBytes(48).toString('hex'))"
node -e "console.log(require('crypto').randomBytes(48).toString('hex'))"
node -e "console.log(require('crypto').randomBytes(32).toString('base64'))"
notepad backend-core/.env
```

Set these values in `backend-core/.env` (use a different generated value for each JWT secret):

```dotenv
NODE_ENV=development
DATABASE_URL=postgresql://cryptoscan_user:<same-database-password>@postgres:5432/cryptoscan
JWT_ACCESS_SECRET=<first-generated-hex-value>
JWT_REFRESH_SECRET=<second-generated-hex-value>
DATA_ENCRYPTION_KEY=<generated-base64-value>
REDIS_URL=redis://redis:6379
PORT=3000
ALLOWED_ORIGINS=http://localhost:8080,http://127.0.0.1:8080
FRONTEND_URL=http://localhost:8080
CHAIN_MODE=public
PUBLIC_RPC_URL=https://ethereum-sepolia-rpc.publicnode.com
PRIVATE_KEY=
```

Development mode lets the app run without a funded blockchain wallet. Signup, login, uploads, scans, and CBOM work locally; real Sepolia anchoring needs a test wallet, test ETH, and a free RPC account. Never put real funds or production data into this laptop demo.

## 3. Start the stack locally

Keep Docker Desktop open. In PowerShell at the repository root:

```powershell
docker compose config --quiet
docker compose up -d --build
docker compose ps
```

Do not add `--profile vps`; that profile starts Caddy for a domain/VPS and is not needed here. Open `http://localhost:8080`. Check API health with:

```powershell
Invoke-RestMethod http://localhost:8080/health
```

It should return `status: ok`. Try signup/login, ZIP upload, scan, findings, and CBOM locally before making a public link.

If a service fails, view its logs:

```powershell
docker compose logs --tail=100 backend-core scan-worker nginx
```

## 4. Create a free temporary public URL (optional)

Install Cloudflare Tunnel's `cloudflared` client using `winget`:

```powershell
winget install --id Cloudflare.cloudflared
```

Open a new PowerShell window after installation and run:

```powershell
cloudflared tunnel --url http://localhost:8080
```

Wait for the `https://....trycloudflare.com` URL in the output. In a second PowerShell window, open `backend-core/.env` and append that exact HTTPS origin to `ALLOWED_ORIGINS`, separated by a comma. For example:

```dotenv
ALLOWED_ORIGINS=http://localhost:8080,http://127.0.0.1:8080,https://random-name.trycloudflare.com
```

Save the file, then restart the backend so it reads the updated allowlist:

```powershell
docker compose restart backend-core
```

Now share the tunnel URL. Keep this PowerShell window, Docker Desktop, and the laptop running. Press Ctrl+C to stop public access. Quick Tunnel usually creates a different URL next time; replace the origin in `backend-core/.env` and restart the backend again.

## 5. Stop or reset

Stop containers while retaining database and uploads:

```powershell
docker compose down
```

Start again later with `docker compose up -d`. Do not use `docker compose down -v` unless you intend to erase the local database and uploaded repositories.
