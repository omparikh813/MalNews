# MalNews

A daily, five-minute security newspaper. MalNews collects the last 24 hours of
security news from five sources, merges duplicate coverage, adds official
severity data (NVD CVSS, CISA Known Exploited, FIRST EPSS), summarizes each
story with an AI model, and prints a two-column newspaper PDF with photos for
the Story of the Week and the top story of the day. Every score and CVE ID
comes from official data, never from AI.

## Pipeline

```
collect.py ─► enrich.py ─► rank.py ─► weekly.py ─► summarize.py ─► images.py ─► render.py ─► publish.py
feeds, text,  NVD, KEV,    dedupe,    Story of     OpenRouter      og:image     Jinja2 +     site/
og:image      EPSS         priority,  the Week     summaries       → JPEG       WeasyPrint   latest.pdf
                           zero-days  (state.json)
```

Sections: **Story of the Week** (kept all week unless a story scores 20% higher),
**News of the Day** (top 3), **New Threats** (zero-days with a CVE), **Other Headlines**.
Each CVE shows its score and band (e.g. "Critical 9.8"), Known Exploited, EPSS, and links to cve.org and NVD.
At most two photos per edition, each credited ("Image: Publisher") with a link to the article.
Every CVE a story mentions is printed with its score (or "Score pending" / "Score unavailable"), and Known Exploited
CVEs add CISA's vendor, product and federal fix date. A bar under the masthead summarizes the day's CVEs by severity.
The end of the paper is a **Known Exploited Roundup** of CISA's newest additions, sized to fill the last page:
the renderer adds rows only while the page count stays the same, so there is no half-empty final page.

## How the API keys are protected

| Risk | Control | Where |
|---|---|---|
| Key committed to git | Keys only from env (GitHub secrets in CI, git-ignored `.env` locally); gitleaks scans every push | `.gitignore`, `ci.yml` |
| Key printed in a public Actions log | Log filter replaces key values with `[REDACTED]`; job summary has counts only | `main.RedactSecrets` |
| Key embedded in the public PDF (e.g. a headline containing `<link rel="attachment" href="file:///proc/self/environ">`) | Jinja2 autoescape; WeasyPrint may read only `templates/`, `fonts/` and the run's image folder; attachments stripped | `safety.RenderURLFetcher` |
| Key stolen by a malicious package | Hash-locked installs (`--require-hashes`), `pip-audit`, Dependabot | `config/requirements*.txt` |
| Key stolen by a compromised Action | Read-only token, SHA-pinned actions, `persist-credentials: false`; only the build job sees the keys and it has no write access | `.github/workflows/` |
| Key abused to run up costs | Model allowlist, 150-request cap, stop on HTTP 429/402, provider-side credit limit | `summarize.py` |
| NVD key leaking to another site | Sent only to NVD's host; dropped if a redirect leads elsewhere | `safety.SafeFetcher` |
| Tampered `state.json` | Strict schema (no unknown fields, https links only, valid CVE IDs, size cap); the run stops before any network use | `state.py` |
| Malicious image | Only JPEG/PNG/WebP, size and pixel caps, re-encoded as a fresh JPEG (drops EXIF and appended data) | `images.py` |
| Feed link pointing at internal services | http(s) only, private and metadata IPs blocked on every redirect, size cap, TLS always verified | `safety.SafeFetcher` |

## Run it locally

```bash
python3.12 -m venv .venv && . .venv/bin/activate
pip install --require-hashes -r config/requirements.txt -r config/requirements-dev.txt
python -m pytest -q                       # offline tests
python -m pytest -m live -s               # 10 real CVEs vs NVD (needs internet)

cp .env.example .env                      # add your keys (never committed)
python main.py --max-requests 10          # real feeds and model -> site/
python -m http.server -d site 8000        # browse the edition list
```

Exit codes: `2` config, `3` rate limit (429), `4` request cap, `5` all sources failed, `6` bad API key, `7` invalid `state.json`. Any non-zero exit publishes nothing.

Locally, `state.json` (Story of the Week, CVEs awaiting an NVD score) stays in the project folder and is git-ignored.

## Publish on GitHub Pages

The daily workflow builds the edition at 6:00 AM PST (7:00 AM during daylight saving), publishes it,
and saves the archive and `state.json` on a `data` branch so nothing is lost between runs.

**1. Put the code on `main`.** Scheduled workflows and Pages deploys run from the default branch.
```bash
git push origin claude/practical-meitner-iquxtc:main
```
Then in the repo go to **Settings → Branches** and make `main` the default branch (the pencil/switch icon).
If git rejects the push, `main` already has other history. Don't force it; check what it contains first.

**2. Make the repo public.** **Settings → General → Danger Zone → Change visibility → Public**
(free Pages and unlimited Actions minutes need it, and nothing secret is in the repo).

**3. Add your keys as secrets.** **Settings → Secrets and variables → Actions → New repository secret**:

| Name | Value |
|---|---|
| `OPENROUTER_API_KEY` | your OpenRouter key (set a monthly credit limit on it at openrouter.ai) |
| `NVD_API_KEY` | your NVD key |

Optional: on the **Variables** tab, add `OPENROUTER_MODEL` (e.g. `anthropic/claude-haiku-5.5`) to change the model without touching code.

**4. Turn on Pages.** **Settings → Pages → Build and deployment → Source: GitHub Actions.**
(Not "Deploy from a branch".)

**5. Test a build first.** **Actions → daily → Run workflow**, leave *Publish to GitHub Pages* **off**, run it.
When it finishes, open the run: the job summary shows the counts, and the `github-pages` artifact holds the site
you can download and open. If the summary looks right, run it again with *Publish* **on**.

**6. Open your site:** `https://<your-username>.github.io/<repo-name>/`
(for example `https://omparikh813.github.io/security-news-daily/`). `latest.pdf` is today's edition and
`index.html` lists every past one. The schedule now runs by itself every day.

**If something fails**
- *"Branch main is not allowed to deploy to github-pages"*: **Settings → Environments → github-pages →
  Deployment branches**, allow `main`.
- *Deploy job says Pages is not enabled*: repeat step 4.
- *Build fails with `AIAuthError`*: the `OPENROUTER_API_KEY` secret is wrong or has a stray space.
- A failed daily run emails you (check **Settings → Notifications → Actions**), and publishes nothing,
  so the previous edition stays online.

Also worth switching on under **Settings → Advanced Security**: secret scanning, push protection,
Dependabot alerts and private vulnerability reporting. Under **Settings → Actions → General**, set
*Workflow permissions* to **Read repository contents**; each workflow asks for the extra access it needs.

A small `keepalive` workflow commits to the `data` branch once a month. GitHub switches off scheduled
workflows after 60 days without repository activity, and this keeps the daily run alive even if it fails for a while.

## Customize the website

The site is built from four files in `templates/`. Edit them, rebuild, and refresh.

| File | What it controls |
|---|---|
| `index.css` | Every color, size and space. The design tokens are at the top (`--accent`, `--navy`, `--bg`, the severity colors, the spacing scale). Change `--accent` to restyle every button and chip. |
| `index.html.j2` | The page's structure and wording: section titles, button labels, the About text. |
| `app.js` | The headline filters, archive search and dark-mode toggle. It only shows and hides things already on the page. |
| `favicon.svg` | The browser tab icon. |

Preview your change locally:
```bash
python main.py --max-requests 10          # rebuilds site/
python -m http.server -d site 8000        # open http://localhost:8000
```

Keep these rules, which the tests check:
- No inline `<script>`, `style=` or `onclick=`. The page's content policy only allows files from the site itself.
- Show feed text only through the template (it is escaped automatically). Never build HTML from it in JavaScript.
- External links keep `rel="noopener noreferrer"`.

The home page shows today's headlines (filterable), the edition PDF beside them on wide screens (phones get the headlines and
an "Open today's PDF" button), and past editions by month with search. Each edition's headlines are saved as
`archive/YYYY-MM-DD.json` next to its PDF, which is what the archive and search read.

Fonts: Caladea, SIL Open Font License 1.1 (`fonts/OFL.txt`).
