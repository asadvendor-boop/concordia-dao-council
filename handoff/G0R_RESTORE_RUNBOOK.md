# Concordia G0-R Restore Runbook

This is the disaster fallback for the pre-finals production state captured at
commit `b79b42c974daa6ba4b8d904573f6c321ecef1a98`. It is not a routine deployment
recipe. Do not run any destructive step unless a release gate has failed,
rollback has been explicitly authorized, and the exact target has been checked.

## Immutable recovery material

- Local Git bundle:
  `/Users/asad.ali/Desktop/FreshAgents/concordia/backups/concordia-b79b42c-pre-v3-sprint-20260722T155102Z.bundle`
- VM backup directory:
  `/opt/backups/concordia/pre-v3-sprint-20260722T155122Z`
- ECS whole-disk snapshot: `s-t4nip7i1zb1dradznxiq`, region
  `ap-southeast-1`, disk `d-t4ngvwxej924e2yayqi5`
- Runtime source: `/opt/apps/concordia/src`
- Compose file: `/opt/apps/concordia/src/deploy/shared-host/compose.prod.yml`
- Environment file: `/opt/apps/concordia/shared-host/concordia.env`
- Database: `/var/lib/docker/volumes/concordia_concordia-data/_data/concordia.db`

Never print an environment file or secret. Never invoke `/demo/activate` or
`/demo/reset`. Never restart the VM or another judged application. Caddy is a
shared-host service with a stale-inode bind-mount history; do not blindly copy
or reload any saved Caddyfile, and preserve every unrelated judged route.

## 1. Prove the recovery inputs before mutation

On the Mac, verify the bundle hash and history:

```bash
shasum -a 256 /Users/asad.ali/Desktop/FreshAgents/concordia/backups/concordia-b79b42c-pre-v3-sprint-20260722T155102Z.bundle
git bundle verify /Users/asad.ali/Desktop/FreshAgents/concordia/backups/concordia-b79b42c-pre-v3-sprint-20260722T155102Z.bundle
```

The expected SHA-256 is
`8943a468ee805c459b6b9bb6fc3d68d145226aec8d2ed0d3db113e174ba92e7f`.

On the VM, verify the explicit backup directory, source archive, and database
without reading secrets:

```bash
test -d /opt/backups/concordia/pre-v3-sprint-20260722T155122Z
tar -tzf /opt/backups/concordia/pre-v3-sprint-20260722T155122Z/concordia-src.tgz >/dev/null
python3 -c 'import sqlite3; p="/opt/backups/concordia/pre-v3-sprint-20260722T155122Z/concordia.db.bak"; c=sqlite3.connect("file:"+p+"?mode=ro", uri=True); assert c.execute("PRAGMA integrity_check").fetchone()[0] == "ok"; c.close()'
```

Before any app-scoped rollback, capture another current source/database/env/image
restore point under a newly timestamped `/opt/backups/concordia/` directory.

## 2. Prefer the smallest app-scoped rollback

Keep healthy production containers running until the replacement is ready.
First extract the exact baseline Compose definition from the verified archive
into the explicit staging directory
`/opt/restore/concordia-g0r-b79b42c`. Validate the archive member before
extraction and use the staged Compose file for every baseline-image recovery;
never combine a frozen image with the future live Compose definition:

```bash
test ! -e /opt/restore/concordia-g0r-b79b42c
install -d -m 0700 /opt/restore/concordia-g0r-b79b42c
tar -tzf /opt/backups/concordia/pre-v3-sprint-20260722T155122Z/concordia-src.tgz src/deploy/shared-host/compose.prod.yml
tar -xzf /opt/backups/concordia/pre-v3-sprint-20260722T155122Z/concordia-src.tgz -C /opt/restore/concordia-g0r-b79b42c src/deploy/shared-host/compose.prod.yml
test -f /opt/restore/concordia-g0r-b79b42c/src/deploy/shared-host/compose.prod.yml
```

Use the saved baseline environment directly as `--env-file` when environment
drift is part of the failure; otherwise use the current env only after a
variable-name-only compatibility comparison. Never print either file.

The frozen image IDs are:

- dashboard: `sha256:676bcb188b60c84f09882bd53a7da0b35c0e9619b2d03a4b9b5f0f873d451696`
- gateway and simulator: `sha256:f8158401471d1e3cfc7c06c9ba7db08c623b858d025867ab6663bb5f2fcbcbcd`
- agents and x402 provider: `sha256:8745b16a7eaf9136debacc52bed346ad92e28b50b07516b2537e9c4b3fb0494d`

Validate the target ID with `docker image inspect`. Retag only the image needed
for the service being restored, then recreate only that service with the fixed
project, compose, and env paths. Example for the dashboard:

```bash
docker image inspect sha256:676bcb188b60c84f09882bd53a7da0b35c0e9619b2d03a4b9b5f0f873d451696 >/dev/null
docker tag sha256:676bcb188b60c84f09882bd53a7da0b35c0e9619b2d03a4b9b5f0f873d451696 concordia-dashboard:local
docker compose -p concordia --env-file /opt/backups/concordia/pre-v3-sprint-20260722T155122Z/shared-host-env/concordia.env -f /opt/restore/concordia-g0r-b79b42c/src/deploy/shared-host/compose.prod.yml up -d --no-deps --no-build dashboard
```

For gateway/simulator, retag the frozen gateway image to
`concordia-dao-council:local` and recreate only `gateway` and/or `simulator`.
For an agent or x402 provider, retag the frozen agent image immediately before
recreating only that service. A tag can point to only one image at a time, but
already-running containers remain pinned to their image IDs. Do not issue a
stack-wide `up`, `down`, or restart.

## 3. Restore source only when source drift blocks recovery

Extract to a new, explicit staging directory first; never extract over the live
tree. Verify that the archive contains the expected `src/` root and the frozen
Compose file. Compare the staged tree with the live tree. Only after explicit
authorization may the staged `src/` replace `/opt/apps/concordia/src`, and the
current live source must first be moved to a timestamped backup path. Restoring
the prebuilt image is preferred because it avoids rebuilding during an incident.

## 4. Restore the database only for confirmed data corruption

This is destructive and must be separately authorized. Stop only the gateway,
copy the current DB to a new timestamped backup, install the verified snapshot
with owner `0:0` and mode `0644`, remove only that DB's stale `-wal`/`-shm`
sidecars, and start only the gateway:

```bash
docker compose -p concordia --env-file /opt/backups/concordia/pre-v3-sprint-20260722T155122Z/shared-host-env/concordia.env -f /opt/restore/concordia-g0r-b79b42c/src/deploy/shared-host/compose.prod.yml stop gateway
cp -a /var/lib/docker/volumes/concordia_concordia-data/_data/concordia.db /opt/backups/concordia/concordia.db.pre-restore-YYYYMMDDTHHMMSSZ
install -o 0 -g 0 -m 0644 /opt/backups/concordia/pre-v3-sprint-20260722T155122Z/concordia.db.bak /var/lib/docker/volumes/concordia_concordia-data/_data/concordia.db
rm -f /var/lib/docker/volumes/concordia_concordia-data/_data/concordia.db-wal /var/lib/docker/volumes/concordia_concordia-data/_data/concordia.db-shm
docker compose -p concordia --env-file /opt/backups/concordia/pre-v3-sprint-20260722T155122Z/shared-host-env/concordia.env -f /opt/restore/concordia-g0r-b79b42c/src/deploy/shared-host/compose.prod.yml up -d --no-deps --no-build gateway
```

Replace the timestamp placeholder with a resolved literal before running it;
never use an unset variable or broad glob. After restart, execute a read-only
`PRAGMA integrity_check`, `/health`, and the 16-route crawl.

## 5. Environment and Caddy recovery

The environment snapshot is
`/opt/backups/concordia/pre-v3-sprint-20260722T155122Z/shared-host-env/concordia.env`.
Never display it. Back up the current env, compare variable names only, and copy
the saved file only when the regression is traced to environment drift.

The three Caddy snapshots are evidence, not blind reload inputs. First obtain a
semantic diff against the active Admin API configuration and the actual active
host file. Preserve all unrelated routes and judged vhosts. Validate the
complete candidate before an app-coordinated Caddy
reload. If exact shared-host restoration is required, use the whole-disk
snapshot rather than reconstructing a partial Caddy state under pressure.

## 6. Whole-VM recovery

The exact full-system fallback is completed ECS snapshot
`s-t4nip7i1zb1dradznxiq`. Whole-disk restore affects all judged applications and
therefore requires Asad's explicit authorization and a provider-console recovery
window. Do not reboot, detach, replace, or roll back the disk from an automated
agent. Verify the snapshot remains `accomplished` at `100%`, then follow the ECS
disk-replacement workflow interactively. Retain the current disk until the
restored instance passes all application health checks.

## 7. Required post-restore acceptance

Recovery is accepted only when:

1. Gateway and x402 provider health checks are healthy.
2. All 16 routes in `handoff/G0R_FALLBACK_EVIDENCE.json` return their expected
   final 200/content type.
3. The 32-anchor audit has zero broken links.
4. SQLite integrity is `ok`.
5. The canonical receipt, quorum pair, SafePay historical proof, IPFS CID, and
   certificate remain byte/URL stable.
6. Every unrelated judged application retains its pre-restore health.
7. No demo reset/activation, DNS change, Caddy route loss, or secret disclosure
   occurred.

Record the exact restored image IDs, commands, timestamps, health responses, and
route report. A rollback restores availability; it never counts as completing a
new finals sprint deliverable.
