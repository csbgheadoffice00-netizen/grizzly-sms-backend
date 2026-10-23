# Do these 4 steps. Nothing else.

You do not need to edit any code. The file `main.py` in this folder is already
your own file with the fixes applied. I tested it: your site starts, login works,
and the holes are closed.

---

## Step 1 - Add two secrets in Render (2 minutes)

Render -> your service (grizzly-sms-backend) -> **Environment** -> **Add Environment Variable**

Add these two:

| Key | Value |
|---|---|
| `JWT_SECRET` | run `openssl rand -hex 32` and paste the output (64 characters) |
| `ADMIN_API_KEY` | any long random text you keep private, e.g. `adm-<paste 30 random chars>` |

Click **Save Changes**. If you skip `JWT_SECRET`, the site still runs and login
still works, it just will not return a login token yet. If you skip
`ADMIN_API_KEY`, the admin route stays locked with no way in (that is safe, but
you cannot add funds until you set it).

---

## Step 2 - Upload 5 files to GitHub

GitHub -> your repo -> **Add file** -> **Upload files**

Drag in all five files from this folder:

- `main.py`
- `auth.py`
- `admin_gate.py`
- `fb_gate.py`
- `docs_gate.py`

Then click **Commit changes**. Files with the same name get replaced, which is
what you want. (If GitHub shows "1 file already exists", that is fine - commit
and it overwrites.)

Render sees the commit and redeploys on its own. Watch the **Logs** tab until it
says `Application startup complete` or `Uvicorn running`.

---

## Step 3 - Check that it worked (30 seconds)

Replace `https://grizzly-sms-backend.onrender.com` with your URL if it changed.

**a) Docs should now be hidden (404, not 500):**

Open: `https://grizzly-sms-backend.onrender.com/docs`

You should see `{"detail":"Not Found"}`. **404 = fixed.** A 500 means the old
`docs_gate.py` is still there - upload `docs_gate.py` from this folder again.

**b) Admin route should be locked:**

```bash
curl -i -X POST "https://grizzly-sms-backend.onrender.com/api/admin/add-funds?user_id=1&amount=999999"
```

You should get **403 Forbidden**. Before the fix this returned 200 and gave away
free balance.

**c) Your own admin call should still work:**

```bash
curl -i -X POST "https://grizzly-sms-backend.onrender.com/api/admin/add-funds?user_id=1&amount=10" \
  -H "X-Admin-Key: YOUR_ADMIN_API_KEY"
```

This should return 200. That is how you add funds from now on.

**d) Login should return a token:**

```bash
curl -s -X POST "https://grizzly-sms-backend.onrender.com/api/login" \
  -H "Content-Type: application/json" \
  -d '{"email":"YOUR_EMAIL","password":"YOUR_PASSWORD"}'
```

If `JWT_SECRET` is set you will see `"access_token"` in the response. If not,
everything else still works and you can add the secret later.

---

## Step 4 - About Facebook routes

`fb_gate.py` is running in **observe mode**: it does not block anything yet, it
only writes a line to the Render log whenever someone orders Facebook on a weak
(virtual-number) route. Let it collect for a day or two, then decide.

Current Facebook route quality from your own `/api/prices?service=fb` data:

| Country | Real SIMs | Total | Real SIM % |
|---|---|---|---|
| UK | 33 | ~99 | 33.5% |
| South Africa | 33 | 111 | 29.7% |
| Angola | 12 | 86 | 14.0% |
| Poland | 12 | 92 | 13.0% |
| Thailand | 12 | 99 | 12.1% |
| **USA** | **35** | **135,331** | **0.026%** |

USA is why Facebook keeps rejecting those accounts: 135,296 of those 135,331
"numbers" are virtual, not physical SIMs. Facebook's risk system sees a
VoIP/virtual number and refuses the signup. Recommended order to sell for
Facebook: **UK, South Africa, Angola, Poland, Thailand** - and stop offering
USA for Facebook specifically.

To actually block weak routes (only after you have seen the logs):

```python
app.add_middleware(FbRouteGate, mode="enforce", min_real_sim_ratio=10.0)
```

That line lives in `main.py`, right after the `fb_gate` import.
