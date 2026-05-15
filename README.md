# Strety MCP Server

A Model Context Protocol (MCP) server that connects Claude to [Strety](https://strety.com) — the EOS® software platform. Built for Claude Desktop via Docker.

Once connected, Claude can read and manage your Strety data conversationally — pull active issues by team, resolve rocks, create todos, check in on metrics, and more.

---

## What It Can Do

| Resource | Read | Create | Update | Resolve/Complete |
|---|---|---|---|---|
| Goals (Rocks) | ✅ | ✅ | ✅ | ✅ (check-ins) |
| Issues (IDS) | ✅ | ✅ | ✅ | ✅ |
| Todos | ✅ | ✅ | ✅ | ✅ |
| Headlines | ✅ | ✅ | ✅ | — |
| Metrics (Scorecard) | ✅ | ✅ | ✅ | ✅ (check-ins) |
| Meetings (L10) | ✅ | — | — | — |
| Projects | ✅ | — | — (title/description read-only) | — |
| Teams | ✅ | — | — | — |
| People | ✅ | — | — | — |
| Playbooks | ✅ | ✅ | ✅ | — |
| Visions (V/TO) | ✅ | — | — | — |
| Messages | ✅ | ✅ | — | — |

---

## Requirements

- [Docker Desktop](https://www.docker.com/products/docker-desktop/)
- [Claude Desktop](https://claude.ai/download)
- A Strety account with an OAuth app configured

---

## Setup

### 1. Create a Strety OAuth App

1. Log into Strety and go to **Settings → Integrations → API**
2. Create a new OAuth application
3. Set the redirect URI to `http://localhost:8080/callback`
4. Copy your **Client ID** and **Client Secret**

### 2. Configure credentials

```bash
cp strety.env.example strety.env
```

Open `strety.env` and fill in your credentials:

```
STRETY_CLIENT_ID=your_client_id_here
STRETY_CLIENT_SECRET=your_client_secret_here
```

> ⚠️ Never commit `strety.env` — it contains your credentials and tokens.

### 3. Build the Docker image

```bash
docker build -t strety-mcp .
```

### 4. Authorize with Strety (one-time)

```bash
# Windows (PowerShell)
$env:STRETY_CLIENT_ID = "your_client_id"
$env:STRETY_CLIENT_SECRET = "your_client_secret"
python strety_mcp.py --auth
```

This opens a browser, logs you into Strety, and writes your access and refresh tokens back into `strety.env` automatically.

> After the first authorization, token refresh is handled automatically — you should not need to re-run `--auth` unless you explicitly revoke access.

### 5. Configure Claude Desktop

Open your Claude Desktop config file:

- **Windows:** `%APPDATA%\Claude\claude_desktop_config.json`
- **macOS:** `~/Library/Application Support/Claude/claude_desktop_config.json`

Add the following to `mcpServers`:

```json
"strety": {
  "command": "docker",
  "args": [
    "run", "--rm", "-i",
    "--env-file", "C:\\path\\to\\your\\Strety\\strety.env",
    "-v", "C:\\path\\to\\your\\Strety:/app",
    "strety-mcp"
  ]
}
```

Replace the paths with the actual location of your Strety folder.

### 6. Restart Claude Desktop

Fully quit and relaunch Claude Desktop. The Strety server should show as connected in **Settings → Developer**.

---

## Usage Examples

Once connected, you can ask Claude things like:

- *"What are the active issues in the Leadership team?"*
- *"Mark the Billing Timing Changes issue as resolved"*
- *"What are my rocks this quarter?"*
- *"Create a todo for Mike to review the SOP draft by May 22"*
- *"Show me this week's scorecard metrics"*
- *"List all open todos assigned to me"*

---

## Project Structure

```
strety_mcp.py        # MCP server — all tools and API logic
Dockerfile           # Container definition
strety.env.example   # Credentials template (safe to commit)
strety.env           # Your actual credentials (never commit)
README.md            # This file
.gitignore           # Excludes credentials and temp files
```

---

## How It Works

The server uses the [Strety REST API](https://2.strety.com/api/v1) with OAuth 2.0 authorization code flow. Tokens are stored in `strety.env` and refreshed automatically when they expire (access tokens last 2 hours; refresh tokens rotate on use with no fixed expiry).

All PATCH requests use `If-Match: *` to bypass optimistic concurrency checks. Server-side filters are used where available (`filter[resolved]`, `filter[completed]`, `filter[assignee_id]`, etc.) with client-side filtering for team/space scoping.

Built with [FastMCP](https://github.com/jlowin/fastmcp) and [httpx](https://www.python-httpx.org/).

---

## Known Limitations

- **Project title/description are read-only** in the Strety API — you can create todos and issues *within* a project space, but the project's own title, description, and status cannot be updated via the API. Edit those in the Strety UI directly.
- **Teams are read-only** — no create/update/delete via API
- **Issue Solution field** is not exposed in the API — resolution notes go into the description field
- **Rocks (Goals) milestones** are not available in the API — manage in the Strety UI
- **Comments** on issues are not available in the API

Strety has noted the following are coming in a future API version: Milestones, Annual Goals, People Analyzer, Surveys, Accountability Chart, User Management, Subscribers, Reviews.

---

## Troubleshooting

| Problem | Fix |
|---|---|
| Server shows "failed" in Claude Desktop | Check `strety.env` credentials have no surrounding quotes |
| Token refresh fails with `invalid_client` | Remove quotes from `STRETY_CLIENT_ID` and `STRETY_CLIENT_SECRET` in `strety.env` |
| Need to re-authorize | Run `python strety_mcp.py --auth` with env vars set |
| Rate limit errors (429) | Strety allows 10 requests per 10 seconds — the MCP handles this automatically |
| Docker image not found | Run `docker build -t strety-mcp .` from the Strety folder |

---

## License

MIT — free to use, modify, and distribute. See [LICENSE](LICENSE) for details.

## Credits

Built by Mike Stewart at [Anchor Network Solutions](https://anchorns.com).

Contributions welcome — if you improve it, open a PR. If you find a bug or hit an API quirk not documented here, open an issue.
