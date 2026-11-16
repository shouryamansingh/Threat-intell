# React front end

The UI, being migrated off Jinja one page at a time. **My account** (`/settings`)
is done; everything else is still served by Flask exactly as before.

No application logic lives here. Scraping, summarising, scheduling, email
delivery, approvals, RBAC and the database are all Python and stay Python. This
directory only renders what `/api/*` returns.

## Run it

Two terminals. The dashboard must be running for the real API.

```bash
# 1. the existing Flask app, unchanged
python run.py

# 2. here
cd frontend && npm install && npm run dev
```

Then open <http://localhost:5173/app/settings>.

Vite proxies `/api`, `/socket.io`, `/static`, `/login` and `/admin` to Flask on
`127.0.0.1:5001`. That single-origin proxy is what makes the session cookie
work — see the comment in `vite.config.js` before changing it. Point it
elsewhere with `TI_DASHBOARD_URL=http://host:port npm run dev`.

### Without starting the real app

Importing `web_dashboard` starts the APScheduler jobs and the SOC delivery
poller, and **that poller sends real email**. For pure UI work, use the mock:

```bash
python frontend/mock_api.py                              # port 5055
TI_DASHBOARD_URL=http://127.0.0.1:5055 npm run dev
```

It serves the same JSON shapes from fake data, touches no database and sends no
mail. Change `password_mode` in `mock_api.py` to `local`, `firebase` or `none`
to see the other three password panels.

## Ship it

```bash
npm run build      # writes frontend/dist
```

`frontend_bridge.py` serves `dist` at `/app/` and is already registered from
`web_dashboard.py`. The build output is gitignored, so **CI or your deploy
script must run `npm run build`** — without it `/app/` returns a 503 explaining
exactly that, and every Jinja page keeps working regardless.

## Layout

```
src/
  main.jsx              mount + stylesheet order
  App.jsx               shell; the <Route> list is the migration checklist
  lib/
    api.js              fetch wrapper — throws ApiError with the server's message
    format.js           dates, initials, avatar tones, password scoring
    firebase.js         SDK loaded on demand, only for password_mode 'firebase'
    publicConfig.js     brand + firebase config, from /api/public-config
    theme.js            light/dark, same localStorage key as the Jinja pages
  hooks/useProfile.js   /api/profile/me, shared by the shell and the page
  components/           Sidebar, TopBar, Panel, Notice, PasswordInput
  pages/Settings/       IdentityHeader, DetailsPanel, RolePanel, PasswordPanel
  styles/               tokens.css, chrome.css, settings.css
```

### The styles are a copy, not a rewrite

`styles/*.css` was lifted verbatim out of `templates/settings.html` so both
stacks render identically during the migration. That means a visual change now
has two homes. Until the Jinja pages are gone, change both — or change neither.

## Porting the next page

1. Build the components under `src/pages/<Name>/`, reusing `Panel`, `Notice`
   and the `lib/` helpers.
2. Add a `<Route>` in `App.jsx`.
3. In `Sidebar.jsx`, flip that nav item from `<a href="/x">` to
   `<NavLink to="/x">`.
4. Leave the Jinja template in place until the React page is genuinely better.
   Both can serve simultaneously — that is the point of mounting under `/app/`.

Suggested order, easiest first: `admin.html` → `users.html` → `dashboard.html`.
The dashboard is last on purpose: it is 80 KB of JavaScript and owns the
scraping/approval flow, so it deserves the most settled component library.
