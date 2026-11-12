# 1Cell.Ai Competitive Price Landscape

Interactive comparison of six 1Cell.Ai oncology tests against competitor tests:
OncoIndx, OncoIndx Prime+, OncoMonitor™, OncoHRD®, OncoRisk and OncoTarget.

Source: internal competitor comparison workbook dated 11 Dec 2025.
Competitor details are as listed in that sheet; verify before external use.

## Files

- `index.html`: password screen plus the encrypted page. The comparison data is only readable after the right password is entered.
- `tools/encrypt.py`: rebuilds `index.html` from the plain page
- `logo.png`: 1Cell.Ai logo
- `og-image.png`, `favicon.png`, `apple-touch-icon.png`: link preview image and browser icons
- `.nojekyll`: tells GitHub Pages to serve the files as they are

## Hosting on GitHub Pages

1. Push these files to the root of the `main` branch.
2. Go to **Settings → Pages**, set **Source** to **Deploy from a branch**, and pick `main` and `/ (root)`.
3. After a minute or so the site is live at `https://<account>.github.io/<repo-name>/`.

Each product tab has its own link, for example `.../#oncohrd`.

## Password protection

The page is encrypted with AES-256-GCM using a key derived from the password
(PBKDF2-SHA256, 600,000 rounds), and decrypted in the visitor's browser. The
password is not stored anywhere in this repository. Once unlocked, the page
stays open until the browser tab is closed.

## Updating the data or the password

The plain, unencrypted page is kept outside this public repository. Edit it,
then rebuild:

```bash
python3 tools/encrypt.py path/to/plain.html index.html
```

The script asks for the password (or reads `SITE_PASSWORD`). To change the
password, rebuild with the new one. Never commit the plain page here.
