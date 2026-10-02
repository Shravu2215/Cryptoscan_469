# Free Render + Vercel Demo Deployment

This deploys the static frontend to Vercel and the API plus scan worker to Render. Vercel proxies API requests so browser auth cookies stay on the Vercel origin. Use Neon Free for PostgreSQL so this setup does not consume the Render workspace's single free Postgres slot. Render free services are suitable for a prototype, not production: the web service sleeps after 15 minutes idle, Redis is in-memory, and uploaded files are lost whenever the web service restarts or sleeps. Expect a cold start of about a minute. Free compute has only 512 MB RAM / 0.1 CPU, so keep scans small. Neon's free Postgres is permanent but limited to 1 GB/project and scales to zero after inactivity.

## 1. Push the deployment files

From the repository root in PowerShell:

```powershell
git status
git add render.yaml frontend/vercel.json backend-core/Dockerfile backend-core/src/server.js RENDER_VERCEL_DEPLOYMENT.md
git commit -m "Use Neon for free demo Postgres"
git push origin main
```

Never commit `.env`, private keys, passwords, or other secrets.

## 2. Deploy the frontend to Vercel

1. Sign in to Vercel and import the GitHub repository `Shravu2215/Cryptoscan_469`.
2. Set **Root Directory** to `frontend` and enable **Include files outside the root directory** if Vercel asks; this project uses only the `frontend` directory for the static site.
3. Select **Other** as the framework preset. Leave the build command blank and set the output directory to `.` if requested.
4. Deploy. Note the final production origin, for example `https://cryptoscan-469.vercel.app`. This is the link to give the judges.

The API rewrites initially point to `https://cryptoscan-demo-api.onrender.com`. If Render assigns a different URL, replace that hostname in `frontend/vercel.json`, push the change, and wait for Vercel to redeploy.

## 3. Create the free Neon database

1. Create/sign in to a Neon account and create a free Postgres project in any US region.
2. In the Neon project choose **Connect**. Copy the **pooled** URL (host includes `-pooler`) and the **direct** URL (host has no `-pooler`). Both should contain `sslmode=require`. Keep these secret; enter them only in Render's environment-variable form.

## 4. Sync the Render Blueprint

1. Sign in to Render and choose **New + → Blueprint**.
2. Connect the same GitHub repository and select `main`. Render detects the root `render.yaml` and previews a free web service and free Key Value (Redis). This Blueprint does not create a Render Postgres database.
3. During the Blueprint prompts, enter:
   - `ALLOWED_ORIGINS`: the exact Vercel production origin, e.g. `https://cryptoscan-469.vercel.app` (no trailing slash).
   - `FRONTEND_URL`: the same exact Vercel production origin.
   - `DATABASE_URL`: Neon **pooled** connection string (hostname includes `-pooler`).
   - `DIRECT_URL`: Neon **direct/unpooled** connection string (hostname has no `-pooler`); Render uses this only for Prisma migrations.
   - `PRIVATE_KEY`: a throwaway private key generated with the command below. It is only required by current startup validation; without Sepolia test ETH, blockchain anchoring will not submit a real transaction.
4. Generate the throwaway wallet key locally in PowerShell; do not commit it:

```powershell
node -e "console.log('0x' + require('crypto').randomBytes(32).toString('hex'))"
```

5. If Render offers **Manual sync** for the Blueprint that already failed, use that Blueprint's sync action after this commit is pushed. Keep its existing `cryptoscan-demo-redis`; it is already provisioned and is part of this demo.
6. Before applying the sync, verify the resource preview contains only the demo API and demo Redis. It must not create, edit, or delete `cryptoscan-new-db` or `cryptoscan-new-backend`. If either appears, cancel and check that the Blueprint points to this repository's `main` branch and root `render.yaml`.
7. Confirm the API plan is **Free**, enter the Neon URLs and other prompted values, then apply/sync. The web service runs migrations using the Neon direct URL and starts both the API and scan worker in one container, allowing scans to access uploaded files.
8. Wait for Render's deploy to finish. The expected backend URL is `https://cryptoscan-demo-api.onrender.com`; if its hostname differs, update the Vercel rewrite destinations as described above.

## 5. Verify the judges' link

Use the Vercel production origin (not the Render backend URL):

```text
https://<your-project>.vercel.app/health
```

It should return `{"status":"ok"}` through Vercel's API rewrite. Also open the Vercel site and test signup, login, a small ZIP upload, scan status/results, and CBOM. Test this before sharing the link.

Free Render services sleep after 15 minutes without traffic. To wake the backend before a judging session, open `https://<your-project>.vercel.app/health` and wait about a minute, then test login and scans. Files in the Render container are temporary, so upload the demo repository again after a restart or spin-down. Neon Free scales to zero after inactivity and can take a few seconds to wake; it has a 1 GB project storage limit and 100 CU-hours/project/month. Free Redis can restart and lose queued jobs/session revocation entries.

## 6. If a deployment fails

- Check Render → `cryptoscan-demo-api` → **Logs** for startup errors. Missing `ALLOWED_ORIGINS`, `PRIVATE_KEY`, `DATABASE_URL`, `DIRECT_URL`, or Redis configuration prevents startup.
- Check Vercel → project → **Deployments → Build Logs** for static deployment/config errors.
- If the Render hostname differs from the configured rewrite target, update all API destinations in `frontend/vercel.json`, push, and wait for Vercel to redeploy.
- Keep the Render service and database in the same region, as configured in `render.yaml`.
