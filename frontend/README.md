# SecureNet Dashboard (frontend)

React 19 + TypeScript + Vite 8 single-page app for SecureNet: live monitoring, incident history, daily reports,
settings, account and support pages, with dark and peach themes.

Normally started for you by `START_SECURENET.bat` in the project root. To work on it directly:

```powershell
npm install
npm run dev        # http://localhost:5173 (needs the backend on :8000)
npm run build      # type-check + production build into dist/
npm run lint       # oxlint
```

`.env` sets `VITE_API_BASE_URL`, `VITE_WS_URL` and `VITE_WEBSITE_URL`. Colours come only from the CSS variables in
`src/styles/globals.css`. See the root `CLAUDE.md` for the full guide.
