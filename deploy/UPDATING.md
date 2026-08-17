# Updating the live server

How to get a code change from your laptop onto the running server.

Read this one first if it has been a while — §1 is the whole thing in thirty
seconds.

---

## 1. The short version

```
your laptop  ──git push──>  GitHub  ──you run update.sh──>  server
```

**Nothing is automatic.** The server does not watch GitHub. It gets new code
only when you go and fetch it.

**On your laptop:**

```bash
python check_secrets.py          # must say "Safe to push"
git add <the files you changed>
git commit -m "what you changed"
git push
```

**Then on the server:**

```bash
sudo /opt/threatintel/deploy/update.sh
```

That is it. The script pulls, installs anything new, restarts both services, and
tells you whether they came back up.

---

## 2. Why you cannot skip the restart

The services run under gunicorn with no auto-reload. `git pull` writes new files
to disk, but the running process keeps executing the copy it loaded at startup.

**Pull without restart = nothing changed.**

The failure this causes is quiet, not loud. Fix a bug in the approval-link code,
pull it, forget the restart, and the app keeps generating links with the old
logic. The dashboard looks healthy. The emails go out. The links just don't
work, and nobody finds out until a manager clicks one.

`update.sh` exists so the restart cannot be forgotten. Use it rather than
running the steps by hand.

---

## 3. Doing it by hand

If the script is unavailable — or you want to see each step — this is what it
runs:

```bash
sudo -u threatintel git -C /opt/threatintel pull --ff-only
sudo -u threatintel /opt/threatintel/.venv/bin/pip install -r /opt/threatintel/requirements.txt
sudo systemctl restart threatintel-dashboard threatintel-callback
```

Then confirm both came back:

```bash
systemctl is-active threatintel-dashboard threatintel-callback
```

Two lines saying `active`. Anything else, go to §7.

---

## 4. What to run for which change

| You changed | What to run |
|---|---|
| Python code (`*.py`) | `update.sh` |
| Templates (`templates/*.html`) | `update.sh` |
| `requirements.txt` | `update.sh` — it installs new packages |
| A setting in the env file | edit `/etc/threatintel/threatintel.env`, then **restart only** — no pull |
| A brand logo (`static/brand-*`) | `scp` the file up, then restart — these are gitignored, so `pull` will never bring them |
| nginx config | `sudo nginx -t && sudo systemctl reload nginx` — the app services are not involved |

**Env-file-only change:**

```bash
sudo nano /etc/threatintel/threatintel.env
sudo systemctl restart threatintel-dashboard threatintel-callback
```

---

## 5. When *not* to deploy

The scheduler lives inside the dashboard process, so restarting the dashboard
restarts the scheduler with it.

- **Not during the weekly scrape.** A restart mid-scrape abandons that run.
- **Not while approvals are outstanding** if you can help it. Pending approvals
  survive a restart (they are rows in the database, not memory), but the
  delivery poller stops for the few seconds the service is down.
- **Prefer right after a delivery cycle completes.** Longest possible runway
  before the next one.

After any restart, check the admin panel's next-run times still match its clock.

---

## 6. Undoing a bad deploy

The previous version is one command away — git keeps it.

**Find the commit you want to go back to:**

```bash
sudo -u threatintel git -C /opt/threatintel log --oneline -10
```

**Roll back to it:**

```bash
sudo -u threatintel git -C /opt/threatintel checkout <commit-hash>
sudo systemctl restart threatintel-dashboard threatintel-callback
```

The server is now in "detached HEAD" — running an old commit, deliberately.
That's fine and correct for an emergency rollback.

**To return to normal once the fix is pushed:**

```bash
sudo -u threatintel git -C /opt/threatintel checkout main
sudo /opt/threatintel/deploy/update.sh
```

> Rolling back **code** does not roll back the **database**. If the bad deploy
> changed the database structure, restore from the nightly backup in
> `/var/backups/threatintel/` as well.

---

## 7. When something goes wrong

### A service says `failed`

```bash
journalctl -u threatintel-dashboard -n 50 --no-pager
```

The error is almost always in the last twenty lines. Usual causes: a syntax
error in the pushed code, a missing package (did `pip install` run?), or a typo
in the env file.

### `update.sh` stops at "The server has local changes"

Someone edited a file directly on the server instead of pushing through GitHub.
`--ff-only` refuses to paper over that with a merge, because the result would be
code that exists on no laptop and in no repository.

See what differs:

```bash
sudo -u threatintel git -C /opt/threatintel status
sudo -u threatintel git -C /opt/threatintel diff
```

If the change is worth keeping, reproduce it on your laptop and push it
properly. To discard it and take what GitHub has:

```bash
sudo -u threatintel git -C /opt/threatintel checkout -- .
sudo /opt/threatintel/deploy/update.sh
```

### `Permission denied (publickey)` on pull

The deploy key is missing or no longer registered. Test it:

```bash
sudo -u threatintel ssh -i /etc/threatintel/deploy_key -T git@github.com
```

`successfully authenticated` means the key is fine and the problem is elsewhere.
`Permission denied` means the key needs re-adding under the repository's
**Settings → Deploy keys** (see `LIGHTSAIL.md` §4).

### AI summaries quietly stopped after a deploy

Check `HF_HOME` is still set in the env file:

```bash
sudo grep HF_HOME /etc/threatintel/threatintel.env
```

Expect `HF_HOME=/var/lib/threatintel/huggingface`. Missing, and the model cache
lands somewhere the service cannot write, the summariser fails to load, and
reports silently fall back to non-AI text. See `LIGHTSAIL.md` §5.

### Everything looks fine but the change isn't live

The restart didn't happen, or didn't take. Confirm what is actually deployed:

```bash
sudo -u threatintel git -C /opt/threatintel log --oneline -1
systemctl show threatintel-dashboard -p ActiveEnterTimestamp
```

If the commit is right but the timestamp is older than the pull, restart again.

---

## 8. Why there is no auto-deploy

Deploying on every push would be convenient and is the wrong trade for this app.

It sends real email to real people. An auto-deploy would put an unfinished push
live the moment it lands — potentially restarting the dashboard mid-scrape, or
shipping code that fails quietly and is discovered by a recipient rather than by
you. For something that runs once a week, choosing the moment yourself costs one
command and removes that whole class of accident.

---

## 9. Copy-paste summary

**Laptop:**
```bash
python check_secrets.py
git add <files>
git commit -m "..."
git push
```

**Server:**
```bash
sudo /opt/threatintel/deploy/update.sh
```

**Check it worked:**
```bash
journalctl -u threatintel-dashboard -f
```
*(Ctrl-C to stop watching.)*
