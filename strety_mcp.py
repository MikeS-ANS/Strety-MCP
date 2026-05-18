# ============================================================
# strety_mcp.py  —  Strety MCP Server  (v3 — full OpenAPI rebuild)
# ============================================================
#
# FIRST-TIME SETUP
# ────────────────
# 1. Copy strety.env.example to strety.env
# 2. Fill in STRETY_CLIENT_ID and STRETY_CLIENT_SECRET
# 3. Run:  python strety_mcp.py --auth
# 4. Restart Claude Desktop
#
# DOCKER
# ──────
#   docker run --env-file strety.env strety-mcp
#   docker run --env-file strety.env -p 8080:8080 strety-mcp python strety_mcp.py --auth
# ============================================================

import json
import os
import re
import secrets
import sys
import time
import webbrowser
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Literal, Optional
from urllib.parse import parse_qs, urlencode, urlparse

import httpx
from mcp.server.fastmcp import FastMCP
from pydantic import BaseModel, Field

# ── Load strety.env ──────────────────────────────────────────

def _load_env_file(env_path: Path) -> None:
    if not env_path.exists():
        return
    for line in env_path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if key and key not in os.environ:
            os.environ[key] = value

_ENV_FILE = Path(__file__).parent / "strety.env"
_load_env_file(_ENV_FILE)

# ── Constants ────────────────────────────────────────────────

CLIENT_ID     = os.environ.get("STRETY_CLIENT_ID", "").strip()
CLIENT_SECRET = os.environ.get("STRETY_CLIENT_SECRET", "").strip()
REDIRECT_URI  = os.environ.get("STRETY_REDIRECT_URI", "http://localhost:8080/callback").strip()
BASE_URL      = "https://2.strety.com/api/v1"
AUTH_URL      = "https://2.strety.com/api/v1/oauth/authorize"
TOKEN_URL     = f"{BASE_URL}/oauth/token"

if not CLIENT_ID or not CLIENT_SECRET:
    print(
        "\nERROR: Missing credentials.\n"
        f"  Set STRETY_CLIENT_ID and STRETY_CLIENT_SECRET in '{_ENV_FILE.name}'\n"
    )
    sys.exit(1)

mcp = FastMCP("strety_mcp")


# ── .env writer ──────────────────────────────────────────────

def _update_env_file(updates: dict) -> None:
    lines = []
    written = set()
    if _ENV_FILE.exists():
        for line in _ENV_FILE.read_text().splitlines():
            stripped = line.strip()
            if stripped and not stripped.startswith("#") and "=" in stripped:
                key = stripped.split("=", 1)[0].strip()
                if key in updates:
                    val = str(updates[key]).strip('"').strip("'")
                    lines.append(f'{key}={val}')
                    written.add(key)
                    continue
            lines.append(line)
    for key, value in updates.items():
        if key not in written:
            val = str(value).strip('"').strip("'")
            lines.append(f'{key}={val}')
    _ENV_FILE.write_text("\n".join(lines) + "\n")


# ── Token management ─────────────────────────────────────────

def _read_env_file_value(key: str) -> str:
    """Read a value directly from strety.env file, bypassing os.environ.
    This ensures we always see the latest token even after an in-process refresh."""
    if _ENV_FILE.exists():
        for line in _ENV_FILE.read_text().splitlines():
            line = line.strip()
            if line.startswith(key + "="):
                return line.split("=", 1)[1].strip().strip('"').strip("'")
    return ""

def _load_token() -> dict | None:
    # Always read from file first (most up-to-date), fall back to env vars
    access_token = _read_env_file_value("STRETY_ACCESS_TOKEN") or os.environ.get("STRETY_ACCESS_TOKEN", "").strip()
    if not access_token:
        return None
    refresh_token = _read_env_file_value("STRETY_REFRESH_TOKEN") or os.environ.get("STRETY_REFRESH_TOKEN", "").strip()
    expires_at_str = _read_env_file_value("STRETY_TOKEN_EXPIRES_AT") or os.environ.get("STRETY_TOKEN_EXPIRES_AT", "0")
    return {
        "access_token":  access_token,
        "refresh_token": refresh_token or None,
        "expires_at":    float(expires_at_str or "0"),
    }

def _save_token(token_data: dict) -> None:
    expires_at = token_data.get("expires_at")
    if not expires_at and "expires_in" in token_data:
        expires_at = time.time() + token_data["expires_in"] - 30
    updates = {
        "STRETY_ACCESS_TOKEN":     token_data["access_token"],
        "STRETY_TOKEN_EXPIRES_AT": str(expires_at or ""),
    }
    if token_data.get("refresh_token"):
        updates["STRETY_REFRESH_TOKEN"] = token_data["refresh_token"]
    for k, v in updates.items():
        os.environ[k] = v
    _update_env_file(updates)

def _is_expired() -> bool:
    # Read directly from file to get the latest value after any refresh
    expires_at_str = _read_env_file_value("STRETY_TOKEN_EXPIRES_AT") or os.environ.get("STRETY_TOKEN_EXPIRES_AT", "0")
    expires_at = float(expires_at_str or "0")
    return bool(expires_at) and time.time() >= expires_at

async def get_access_token() -> str:
    token = _load_token()
    if not token or not token.get("access_token"):
        raise RuntimeError("No Strety token. Run: python strety_mcp.py --auth")
    if token.get("refresh_token") and _is_expired():
        async with httpx.AsyncClient() as client:
            resp = await client.post(TOKEN_URL, data={
                "grant_type":    "refresh_token",
                "refresh_token": token["refresh_token"],
                "client_id":     CLIENT_ID,
                "client_secret": CLIENT_SECRET,
            })
        if resp.status_code == 200:
            new_data = resp.json()
            if "expires_at" not in new_data and "expires_in" in new_data:
                new_data["expires_at"] = time.time() + new_data["expires_in"] - 30
            _save_token(new_data)
            return new_data["access_token"]
        raise RuntimeError(f"Token refresh failed (HTTP {resp.status_code}). Re-run: python strety_mcp.py --auth")
    return token["access_token"]


# ── Auth flow ────────────────────────────────────────────────

def run_auth_flow() -> None:
    state     = secrets.token_urlsafe(16)
    auth_code: dict = {}

    full_auth_url = f"{AUTH_URL}?{urlencode({
        'client_id':     CLIENT_ID,
        'redirect_uri':  REDIRECT_URI,
        'response_type': 'code',
        'scope':         'read write',
        'state':         state,
    })}"

    class _Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            qs = parse_qs(urlparse(self.path).query)
            if "code" in qs and qs.get("state", [None])[0] == state:
                auth_code["code"] = qs["code"][0]
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"<html><body style='font-family:sans-serif;padding:40px;background:#111;color:#fff'>"
                                 b"<h2 style='color:#4ade80'>&#10003; Connected to Strety!</h2>"
                                 b"<p>Token saved. Close this tab.</p></body></html>")
            else:
                self.send_response(400)
                self.end_headers()
                self.wfile.write(b"Error: state mismatch. Try again.")
        def log_message(self, *_): pass

    print(f"\n{'='*60}\n  Strety — One-Time Authentication\n{'='*60}")
    print(f"\n  Opening browser... or go to:\n\n  {full_auth_url}\n")

    server = HTTPServer(("localhost", 8080), _Handler)
    webbrowser.open(full_auth_url)
    server.handle_request()

    if "code" not in auth_code:
        print("  ERROR: No code received.\n"); sys.exit(1)

    print("  Exchanging code for token...")
    resp = httpx.post(TOKEN_URL, data={
        "grant_type":    "authorization_code",
        "code":          auth_code["code"],
        "client_id":     CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "redirect_uri":  REDIRECT_URI,
    })
    if resp.status_code != 200:
        print(f"  ERROR: HTTP {resp.status_code}\n  {resp.text}\n"); sys.exit(1)

    token_data = resp.json()
    if "expires_at" not in token_data and "expires_in" in token_data:
        token_data["expires_at"] = time.time() + token_data["expires_in"] - 30
    _save_token(token_data)

    print(f"\n  Token saved to: {_ENV_FILE}")
    print(f"  Done! Restart Claude Desktop.\n{'='*60}\n")


# ── API helper ───────────────────────────────────────────────

async def api(method: str, path: str, body: dict = None,
              params: dict = None, if_match: str = "*") -> dict:
    """
    Central async HTTP helper.
    All PATCH requests automatically include If-Match: * to skip concurrency check
    unless a specific ETag is provided.
    """
    try:
        token = await get_access_token()
    except RuntimeError as e:
        return {"error": str(e)}

    headers = {
        "Authorization": f"Bearer {token}",
        "Accept":        "application/vnd.api+json",
        "Content-Type":  "application/vnd.api+json",
    }
    if method.upper() == "PATCH":
        headers["If-Match"] = if_match

    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.request(
                method, f"{BASE_URL}{path}",
                headers=headers, json=body, params=params
            )
    except httpx.TimeoutException:
        return {"error": "Request timed out. Try again."}
    except httpx.ConnectError:
        return {"error": "Could not connect to Strety. Check your network."}

    if resp.status_code in (200, 201): return resp.json()
    if resp.status_code == 204:        return {"status": "success"}
    if resp.status_code == 401:        return {"error": "Auth failed. Re-run: python strety_mcp.py --auth"}
    if resp.status_code == 403:        return {"error": f"Permission denied: {method} {path}"}
    if resp.status_code == 404:        return {"error": f"Not found: {path} — check the UUID"}
    if resp.status_code == 412:        return {"error": "Concurrency conflict — resource was modified. Try again."}
    if resp.status_code == 422:        return {"error": f"Validation error: {resp.text}"}
    if resp.status_code == 428:        return {"error": "If-Match header required — this is a bug, please report it."}
    if resp.status_code == 429:        return {"error": "Rate limited (10 req/10s). Wait a moment and retry."}
    return {"error": f"HTTP {resp.status_code}: {resp.text[:200]}"}


def _build_attrs(data: BaseModel, exclude_none: bool = True) -> dict:
    return {k: v for k, v in data.model_dump().items()
            if not (exclude_none and v is None)}


# ── List helpers ─────────────────────────────────────────────

class ListInput(BaseModel):
    page:  int           = Field(default=1, ge=1, description="Page number (1-based). ~20 items per page.")
    query: Optional[str] = Field(default=None, description="Keyword filter on title/description (client-side).")

def _filter_results(data: dict, query: Optional[str]) -> dict:
    if not query or "data" not in data:
        return data
    q = query.lower()
    data["data"] = [
        i for i in data["data"]
        if q in (i.get("attributes", {}).get("title")       or "").lower()
        or q in (i.get("attributes", {}).get("name")        or "").lower()
        or q in (i.get("attributes", {}).get("description") or "").lower()
    ]
    data.setdefault("meta", {})["filtered_count"] = len(data["data"])
    return data

async def _fetch_all_pages(path: str, api_params: dict, space_id: Optional[str] = None) -> dict:
    """Fetch all pages and optionally strict-filter by space_id."""
    result = await api("GET", path, params=api_params)
    if "error" in result:
        return result

    all_items = list(result.get("data", []))
    total_pages = 1
    if result.get("links", {}).get("last"):
        m = re.search(r"page%5Bnumber%5D=(\d+)", result["links"]["last"])
        if m:
            total_pages = int(m.group(1))

    for p in range(2, total_pages + 1):
        page_result = await api("GET", path, params={**api_params, "page[number]": p})
        if "data" in page_result:
            all_items.extend(page_result["data"])

    result["data"] = all_items

    if space_id:
        result["data"] = [
            i for i in all_items
            if i.get("relationships", {}).get("space", {}).get("data", {}).get("id") == space_id
        ]
        result.setdefault("meta", {})["space_filtered_count"] = len(result["data"])

    return result


# ============================================================
# GOALS
# ============================================================

class GoalCreateInput(BaseModel):
    title:       str           = Field(..., min_length=1, max_length=500, description="Goal title")
    description: Optional[str] = Field(None, description="Optional description")
    due_date:    Optional[str] = Field(None, description="Due date YYYY-MM-DD")
    assignee_id: Optional[str] = Field(None, description="UUID of person to assign this goal to")
    space_id:    Optional[str] = Field(None, description="UUID of team, project, or person space")
    space_type:  Optional[str] = Field(None, description="Type of space: 'team', 'project', or 'person'")

class GoalUpdateInput(BaseModel):
    title:       Optional[str] = Field(None, min_length=1, max_length=500)
    description: Optional[str] = Field(None)
    due_date:    Optional[str] = Field(None, description="Due date YYYY-MM-DD")
    assignee_id: Optional[str] = Field(None, description="UUID of assignee")

class GoalListInput(BaseModel):
    page:        int            = Field(default=1, ge=1)
    query:       Optional[str]  = Field(None, description="Keyword filter on title")
    status:      Optional[str]  = Field(None, description="Filter by status: on_track, off_track, at_risk, completed, missed, cancelled")
    assignee_id: Optional[str]  = Field(None, description="Filter by assignee UUID")

@mcp.tool(name="strety_list_goals", annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True})
async def strety_list_goals(params: GoalListInput) -> dict:
    """List goals with optional filtering by status or assignee."""
    api_params: dict = {"page[number]": params.page}
    if params.status:       api_params["filter[status][]"] = params.status
    if params.assignee_id:  api_params["filter[assignee_id]"] = params.assignee_id
    return _filter_results(await api("GET", "/goals", params=api_params), params.query)

@mcp.tool(name="strety_get_goal", annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True})
async def strety_get_goal(goal_id: str) -> dict:
    """Get a single goal by UUID."""
    return await api("GET", f"/goals/{goal_id}")

@mcp.tool(name="strety_create_goal", annotations={"readOnlyHint": False, "destructiveHint": False, "idempotentHint": False})
async def strety_create_goal(params: GoalCreateInput) -> dict:
    """Create a new goal. space_id and space_type are required to assign it to a team/project."""
    attrs = _build_attrs(params)
    return await api("POST", "/goals", body={"data": {"type": "goal", "attributes": attrs}})

@mcp.tool(name="strety_update_goal", annotations={"readOnlyHint": False, "destructiveHint": False, "idempotentHint": True})
async def strety_update_goal(goal_id: str, params: GoalUpdateInput) -> dict:
    """Update a goal's title, description, due date, or assignee."""
    attrs = _build_attrs(params)
    if not attrs: return {"error": "No fields provided."}
    return await api("PATCH", f"/goals/{goal_id}", body={"data": {"type": "goal", "id": goal_id, "attributes": attrs}})

@mcp.tool(name="strety_delete_goal", annotations={"readOnlyHint": False, "destructiveHint": True, "idempotentHint": False})
async def strety_delete_goal(goal_id: str) -> dict:
    """Permanently delete a goal. Cannot be undone."""
    return await api("DELETE", f"/goals/{goal_id}")

@mcp.tool(name="strety_backlog_goal", annotations={"readOnlyHint": False, "destructiveHint": False, "idempotentHint": True})
async def strety_backlog_goal(goal_id: str) -> dict:
    """Move a goal to the backlog."""
    return await api("POST", f"/goals/{goal_id}/backlog")

@mcp.tool(name="strety_unbacklog_goal", annotations={"readOnlyHint": False, "destructiveHint": False, "idempotentHint": True})
async def strety_unbacklog_goal(goal_id: str) -> dict:
    """Restore a goal from the backlog."""
    return await api("DELETE", f"/goals/{goal_id}/backlog")

@mcp.tool(name="strety_list_goal_checkins", annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True})
async def strety_list_goal_checkins(goal_id: str) -> dict:
    """List all check-ins for a goal."""
    return await api("GET", f"/goals/{goal_id}/check_ins")

@mcp.tool(name="strety_create_goal_checkin", annotations={"readOnlyHint": False, "destructiveHint": False, "idempotentHint": False})
async def strety_create_goal_checkin(
    goal_id: str,
    status: str,
    value: Optional[str] = None,
    context: Optional[str] = None
) -> dict:
    """Record a check-in for a goal.
    
    Args:
        goal_id: UUID of the goal
        status: on_track | off_track | at_risk | completed | missed | cancelled
        value: Decimal value as string (e.g. '85.5') — required for goals with numeric targets
        context: Optional notes about this check-in
    """
    attrs: dict = {"status": status}
    if value:   attrs["value"] = value
    if context: attrs["context"] = context
    return await api("POST", f"/goals/{goal_id}/check_ins",
                     body={"data": {"type": "goal_check_in", "attributes": attrs}})

@mcp.tool(name="strety_delete_goal_checkin", annotations={"readOnlyHint": False, "destructiveHint": True, "idempotentHint": False})
async def strety_delete_goal_checkin(goal_id: str, checkin_id: str) -> dict:
    """Delete a goal check-in. Cannot be undone."""
    return await api("DELETE", f"/goals/{goal_id}/check_ins/{checkin_id}")


# ============================================================
# HEADLINES
# ============================================================

class HeadlineCreateInput(BaseModel):
    title:      str           = Field(..., min_length=1, max_length=150, description="Headline text (max 150 chars)")
    description:Optional[str] = Field(None, description="Optional longer description")
    space_id:   str           = Field(..., description="UUID of team, project, or person space")
    space_type: str           = Field(..., description="Type of space: 'team', 'project', or 'person'")
    owner_id:   Optional[str] = Field(None, description="UUID of person who owns this headline")

class HeadlineUpdateInput(BaseModel):
    title:       Optional[str] = Field(None, min_length=1, max_length=150)
    description: Optional[str] = Field(None)
    owner_id:    Optional[str] = Field(None)

@mcp.tool(name="strety_list_headlines", annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True})
async def strety_list_headlines(params: ListInput) -> dict:
    """List headlines with optional pagination and keyword filtering."""
    return _filter_results(await api("GET", "/headlines", params={"page[number]": params.page}), params.query)

@mcp.tool(name="strety_get_headline", annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True})
async def strety_get_headline(headline_id: str) -> dict:
    """Get a single headline by UUID."""
    return await api("GET", f"/headlines/{headline_id}")

@mcp.tool(name="strety_create_headline", annotations={"readOnlyHint": False, "destructiveHint": False, "idempotentHint": False})
async def strety_create_headline(params: HeadlineCreateInput) -> dict:
    """Create a new headline. Requires space_id and space_type."""
    return await api("POST", "/headlines", body={"data": {"type": "headline", "attributes": _build_attrs(params)}})

@mcp.tool(name="strety_update_headline", annotations={"readOnlyHint": False, "destructiveHint": False, "idempotentHint": True})
async def strety_update_headline(headline_id: str, params: HeadlineUpdateInput) -> dict:
    """Update a headline's title, description, or owner."""
    attrs = _build_attrs(params)
    if not attrs: return {"error": "No fields provided."}
    return await api("PATCH", f"/headlines/{headline_id}",
                     body={"data": {"type": "headline", "id": headline_id, "attributes": attrs}})

@mcp.tool(name="strety_delete_headline", annotations={"readOnlyHint": False, "destructiveHint": True, "idempotentHint": False})
async def strety_delete_headline(headline_id: str) -> dict:
    """Permanently delete a headline. Cannot be undone."""
    return await api("DELETE", f"/headlines/{headline_id}")


# ============================================================
# ISSUES (IDS)
# ============================================================

class IssueListInput(BaseModel):
    page:       int            = Field(default=1, ge=1, description="Page number. Ignored when space_id is set (all pages fetched automatically).")
    query:      Optional[str]  = Field(None, description="Keyword filter on title/description.")
    space_id:   Optional[str]  = Field(None, description="Filter to a specific team/project UUID. Triggers auto-pagination and strict filtering.")
    resolved:   Optional[bool] = Field(None, description="false=active only, true=resolved only, omit=all")
    issue_type: Optional[str]  = Field(None, description="Filter by type: short_term, long_term, or parking_lot")

class IssueCreateInput(BaseModel):
    title:       str           = Field(..., min_length=1, max_length=255)
    description: Optional[str] = Field(None)
    issue_type:  str           = Field(default="short_term", description="short_term | long_term | parking_lot")
    priority:    Optional[str] = Field(None, description="none | highest | high | medium | low | lowest")
    space_id:    str           = Field(..., description="UUID of team, project, or person space")
    space_type:  str           = Field(..., description="team | project | person")
    owner_id:    Optional[str] = Field(None, description="UUID of the person who owns this issue")

class IssueUpdateInput(BaseModel):
    title:       Optional[str] = Field(None, min_length=1, max_length=255)
    description: Optional[str] = Field(None)
    issue_type:  Optional[str] = Field(None, description="short_term | long_term | parking_lot")
    priority:    Optional[str] = Field(None, description="none | highest | high | medium | low | lowest")
    owner_id:    Optional[str] = Field(None, description="UUID of the owner")
    resolved_at: Optional[str] = Field(None, description="ISO datetime to resolve (e.g. '2026-05-14T19:00:00Z'), or null to re-open")

@mcp.tool(name="strety_list_issues", annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True})
async def strety_list_issues(params: IssueListInput) -> dict:
    """List IDS issues with filtering by team, status, and type.
    
    When space_id is provided, all pages are fetched automatically and results are
    strict-filtered to that team/project only.
    
    Examples:
      Active Leadership issues:  space_id='4816dba9-...', resolved=False
      Short-term active only:    resolved=False, issue_type='short_term'
      Search all active:         resolved=False, query='SOP'
    """
    api_params: dict = {"page[number]": params.page}
    if params.resolved is not None:   api_params["filter[resolved]"]    = str(params.resolved).lower()
    if params.issue_type:             api_params["filter[issue_type]"]  = params.issue_type
    if params.space_id:               api_params["filter[space_id]"]    = params.space_id

    if params.space_id:
        result = await _fetch_all_pages("/issues", api_params, space_id=params.space_id)
    else:
        result = await api("GET", "/issues", params=api_params)

    return _filter_results(result, params.query)

@mcp.tool(name="strety_get_issue", annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True})
async def strety_get_issue(issue_id: str) -> dict:
    """Get a single IDS issue by UUID."""
    return await api("GET", f"/issues/{issue_id}")

@mcp.tool(name="strety_create_issue", annotations={"readOnlyHint": False, "destructiveHint": False, "idempotentHint": False})
async def strety_create_issue(params: IssueCreateInput) -> dict:
    """Create a new IDS issue. space_id and space_type are required."""
    return await api("POST", "/issues", body={"data": {"type": "issue", "attributes": _build_attrs(params)}})

@mcp.tool(name="strety_update_issue", annotations={"readOnlyHint": False, "destructiveHint": False, "idempotentHint": True})
async def strety_update_issue(issue_id: str, params: IssueUpdateInput) -> dict:
    """Update an issue's title, description, type, priority, owner, or resolved status.
    
    To resolve an issue: set resolved_at to current UTC datetime e.g. '2026-05-14T19:00:00Z'
    To re-open an issue: set resolved_at to null
    To add a solution note: put it in description
    """
    attrs = _build_attrs(params, exclude_none=False)
    # Remove keys where value is sentinel (not supplied at all)
    attrs = {k: v for k, v in attrs.items() if k in params.model_fields_set or v is not None}
    if not attrs: return {"error": "No fields provided."}
    return await api("PATCH", f"/issues/{issue_id}",
                     body={"data": {"type": "issue", "id": issue_id, "attributes": attrs}})

@mcp.tool(name="strety_resolve_issue", annotations={"readOnlyHint": False, "destructiveHint": False, "idempotentHint": True})
async def strety_resolve_issue(issue_id: str, solution: Optional[str] = None) -> dict:
    """Mark an issue as resolved (solved). Optionally add a solution note.
    
    Args:
        issue_id: UUID of the issue to resolve
        solution: Optional solution text to add to the description
    """
    attrs: dict = {"resolved_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")}
    if solution:
        attrs["description"] = solution
    return await api("PATCH", f"/issues/{issue_id}",
                     body={"data": {"type": "issue", "id": issue_id, "attributes": attrs}})

@mcp.tool(name="strety_reopen_issue", annotations={"readOnlyHint": False, "destructiveHint": False, "idempotentHint": True})
async def strety_reopen_issue(issue_id: str) -> dict:
    """Re-open a previously resolved issue."""
    return await api("PATCH", f"/issues/{issue_id}",
                     body={"data": {"type": "issue", "id": issue_id, "attributes": {"resolved_at": None}}})

@mcp.tool(name="strety_delete_issue", annotations={"readOnlyHint": False, "destructiveHint": True, "idempotentHint": False})
async def strety_delete_issue(issue_id: str) -> dict:
    """Permanently delete an IDS issue. Cannot be undone."""
    return await api("DELETE", f"/issues/{issue_id}")


# ============================================================
# MEETINGS
# ============================================================

class MeetingListInput(BaseModel):
    page:     int           = Field(default=1, ge=1)
    query:    Optional[str] = Field(None, description="Keyword filter on meeting name")
    resolved: Optional[bool]= Field(None, description="false=upcoming/active, true=completed")

@mcp.tool(name="strety_list_meetings", annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True})
async def strety_list_meetings(params: MeetingListInput) -> dict:
    """List meetings with optional filtering."""
    api_params: dict = {"page[number]": params.page}
    if params.resolved is not None:
        api_params["filter[resolved]"] = str(params.resolved).lower()
    return _filter_results(await api("GET", "/meetings", params=api_params), params.query)

@mcp.tool(name="strety_get_meeting", annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True})
async def strety_get_meeting(meeting_id: str) -> dict:
    """Get a single meeting by UUID including invitations and rankings."""
    return await api("GET", f"/meetings/{meeting_id}")


# ============================================================
# METRICS (SCORECARD)
# ============================================================

class MetricCreateInput(BaseModel):
    title:             str           = Field(..., min_length=1, max_length=500)
    description:       Optional[str] = Field(None)
    space_id:          str           = Field(..., description="UUID of team, project, or person space")
    space_type:        str           = Field(..., description="team | project | person")
    checkin_frequency: Optional[str] = Field(None, description="weekly | monthly | quarterly | annual")
    number_format:     Optional[str] = Field(None, description="number | currency | percentage | boolean | time")
    target_type:       Optional[str] = Field(None, description="lt | lte | eq | gte | gt | between")
    target_value:      Optional[float] = Field(None)
    target_min_value:  Optional[float] = Field(None, description="Used when target_type='between'")
    target_max_value:  Optional[float] = Field(None, description="Used when target_type='between'")
    assignee_id:       Optional[str] = Field(None, description="UUID of person who owns this metric")

class MetricUpdateInput(BaseModel):
    title:             Optional[str]   = Field(None)
    description:       Optional[str]   = Field(None)
    checkin_frequency: Optional[str]   = Field(None, description="weekly | monthly | quarterly | annual")
    number_format:     Optional[str]   = Field(None, description="number | currency | percentage | boolean | time")
    target_type:       Optional[str]   = Field(None)
    target_value:      Optional[float] = Field(None)
    target_min_value:  Optional[float] = Field(None)
    target_max_value:  Optional[float] = Field(None)
    assignee_id:       Optional[str]   = Field(None)

class MetricCheckInCreateInput(BaseModel):
    value:        float         = Field(..., description="The numeric value to record")
    context:      Optional[str] = Field(None, description="Optional notes about this check-in")
    iso_week:     Optional[int] = Field(None, description="ISO week number (1-53) — required for weekly metrics")
    iso_week_year:Optional[int] = Field(None, description="ISO year — required for weekly metrics")
    month:        Optional[int] = Field(None, description="Month (1-12) — required for monthly metrics")
    quarter:      Optional[int] = Field(None, description="Quarter (1-4) — required for quarterly metrics")
    year:         Optional[int] = Field(None, description="4-digit year — required for monthly/quarterly/annual metrics")

@mcp.tool(name="strety_list_metrics", annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True})
async def strety_list_metrics(params: ListInput) -> dict:
    """List scorecard metrics with optional filtering."""
    return _filter_results(await api("GET", "/metrics", params={"page[number]": params.page}), params.query)

@mcp.tool(name="strety_get_metric", annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True})
async def strety_get_metric(metric_id: str) -> dict:
    """Get a single scorecard metric by UUID."""
    return await api("GET", f"/metrics/{metric_id}")

@mcp.tool(name="strety_create_metric", annotations={"readOnlyHint": False, "destructiveHint": False, "idempotentHint": False})
async def strety_create_metric(params: MetricCreateInput) -> dict:
    """Create a new scorecard metric. space_id and space_type are required."""
    return await api("POST", "/metrics", body={"data": {"type": "metric", "attributes": _build_attrs(params)}})

@mcp.tool(name="strety_update_metric", annotations={"readOnlyHint": False, "destructiveHint": False, "idempotentHint": True})
async def strety_update_metric(metric_id: str, params: MetricUpdateInput) -> dict:
    """Update a scorecard metric."""
    attrs = _build_attrs(params)
    if not attrs: return {"error": "No fields provided."}
    return await api("PATCH", f"/metrics/{metric_id}",
                     body={"data": {"type": "metric", "id": metric_id, "attributes": attrs}})

@mcp.tool(name="strety_delete_metric", annotations={"readOnlyHint": False, "destructiveHint": True, "idempotentHint": False})
async def strety_delete_metric(metric_id: str) -> dict:
    """Permanently delete a scorecard metric. Cannot be undone."""
    return await api("DELETE", f"/metrics/{metric_id}")

@mcp.tool(name="strety_list_metric_checkins", annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True})
async def strety_list_metric_checkins(metric_id: str) -> dict:
    """List all check-in values for a scorecard metric."""
    return await api("GET", f"/metrics/{metric_id}/check_ins")

@mcp.tool(name="strety_create_metric_checkin", annotations={"readOnlyHint": False, "destructiveHint": False, "idempotentHint": False})
async def strety_create_metric_checkin(metric_id: str, params: MetricCheckInCreateInput) -> dict:
    """Record a check-in value for a scorecard metric.
    
    Frequency-specific fields required:
    - Weekly:    iso_week + iso_week_year
    - Monthly:   month + year
    - Quarterly: quarter + year
    - Annual:    year
    """
    return await api("POST", f"/metrics/{metric_id}/check_ins",
                     body={"data": {"type": "metric_check_in", "attributes": _build_attrs(params)}})

@mcp.tool(name="strety_delete_metric_checkin", annotations={"readOnlyHint": False, "destructiveHint": True, "idempotentHint": False})
async def strety_delete_metric_checkin(metric_id: str, checkin_id: str) -> dict:
    """Delete a metric check-in. Cannot be undone."""
    return await api("DELETE", f"/metrics/{metric_id}/check_ins/{checkin_id}")


# ============================================================
# PEOPLE
# ============================================================

class PeopleListInput(BaseModel):
    page:        int            = Field(default=1, ge=1)
    query:       Optional[str]  = Field(None, description="Keyword filter on name (client-side)")
    name:        Optional[str]  = Field(None, description="Server-side name filter")
    email:       Optional[str]  = Field(None, description="Server-side email filter")
    deactivated: Optional[bool] = Field(None, description="false=active only, true=deactivated only")

@mcp.tool(name="strety_list_people", annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True})
async def strety_list_people(params: PeopleListInput) -> dict:
    """List people in the org. Useful for resolving names to UUIDs.
    
    Use name= for server-side name filtering, or query= for client-side keyword search.
    Use deactivated=false to show only active staff.
    """
    api_params: dict = {"page[number]": params.page}
    if params.name:        api_params["filter[name]"]        = params.name
    if params.email:       api_params["filter[email]"]       = params.email
    if params.deactivated is not None:
        api_params["filter[deactivated]"] = str(params.deactivated).lower()
    return _filter_results(await api("GET", "/people", params=api_params), params.query)


# ============================================================
# PROJECTS
# ============================================================

class ProjectCreateInput(BaseModel):
    title:       str           = Field(..., min_length=1, max_length=500)
    description: Optional[str] = Field(None)
    start_date:  Optional[str] = Field(None, description="YYYY-MM-DD")
    end_date:    Optional[str] = Field(None, description="YYYY-MM-DD")
    status:      Optional[str] = Field(None, description="backlog | on_track | off_track | completed | missed")

class ProjectUpdateInput(BaseModel):
    title:       Optional[str] = Field(None, min_length=1, max_length=500)
    description: Optional[str] = Field(None)
    start_date:  Optional[str] = Field(None, description="YYYY-MM-DD")
    end_date:    Optional[str] = Field(None, description="YYYY-MM-DD")
    status:      Optional[str] = Field(None, description="backlog | on_track | off_track | completed | missed")

@mcp.tool(name="strety_list_projects", annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True})
async def strety_list_projects(params: ListInput) -> dict:
    """List projects with optional keyword filtering."""
    return _filter_results(await api("GET", "/projects", params={"page[number]": params.page}), params.query)

@mcp.tool(name="strety_get_project", annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True})
async def strety_get_project(project_id: str) -> dict:
    """Get a single project by UUID."""
    return await api("GET", f"/projects/{project_id}")

@mcp.tool(name="strety_create_project", annotations={"readOnlyHint": False, "destructiveHint": False, "idempotentHint": False})
async def strety_create_project(params: ProjectCreateInput) -> dict:
    """Create a new project."""
    return await api("POST", "/projects", body={"data": {"type": "project", "attributes": _build_attrs(params)}})

@mcp.tool(name="strety_update_project", annotations={"readOnlyHint": False, "destructiveHint": False, "idempotentHint": True})
async def strety_update_project(project_id: str, params: ProjectUpdateInput) -> dict:
    """Update a project's title, description, dates, or status."""
    attrs = _build_attrs(params)
    if not attrs: return {"error": "No fields provided."}
    return await api("PATCH", f"/projects/{project_id}",
                     body={"data": {"type": "project", "id": project_id, "attributes": attrs}})


# ============================================================
# TEAMS
# ============================================================

@mcp.tool(name="strety_list_teams", annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True})
async def strety_list_teams(params: ListInput) -> dict:
    """List all teams in Strety. Useful for looking up team UUIDs for space_id filtering."""
    return _filter_results(await api("GET", "/teams", params={"page[number]": params.page}), params.query)

@mcp.tool(name="strety_get_team", annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True})
async def strety_get_team(team_id: str) -> dict:
    """Get a single team by UUID."""
    return await api("GET", f"/teams/{team_id}")


# ============================================================
# TODOS
# ============================================================

class TodoListInput(BaseModel):
    page:        int            = Field(default=1, ge=1, description="Page number. Ignored when space_id is set.")
    query:       Optional[str]  = Field(None, description="Keyword filter on title/description.")
    space_id:    Optional[str]  = Field(None, description="Filter to a specific team/project/person UUID. Triggers auto-pagination.")
    completed:   Optional[bool] = Field(None, description="false=open only, true=completed only, omit=all")
    assignee_id: Optional[str]  = Field(None, description="Filter by assignee UUID")

class TodoCreateInput(BaseModel):
    title:       str           = Field(..., min_length=1, max_length=500)
    description: Optional[str] = Field(None)
    due_date:    Optional[str] = Field(None, description="YYYY-MM-DD")
    priority:    Optional[str] = Field(None, description="none | highest | high | medium | low | lowest")
    space_id:    str           = Field(..., description="UUID of team, project, or person space")
    space_type:  str           = Field(..., description="team | project | person")
    assignee_id: Optional[str] = Field(None, description="UUID of person to assign this todo to")

class TodoUpdateInput(BaseModel):
    title:        Optional[str]  = Field(None, min_length=1, max_length=500)
    description:  Optional[str]  = Field(None)
    due_date:     Optional[str]  = Field(None, description="YYYY-MM-DD")
    priority:     Optional[str]  = Field(None, description="none | highest | high | medium | low | lowest")
    assignee_id:  Optional[str]  = Field(None, description="UUID of assignee")
    completed_at: Optional[str]  = Field(None, description="ISO datetime to mark complete, or null to reopen")

@mcp.tool(name="strety_list_todos", annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True})
async def strety_list_todos(params: TodoListInput) -> dict:
    """List todos with optional filtering by team, completion status, and assignee.
    
    When space_id is provided, all pages are fetched and strict-filtered to that space.
    Use completed=false to get only open todos.
    """
    api_params: dict = {"page[number]": params.page}
    if params.completed is not None:  api_params["filter[completed]"]  = str(params.completed).lower()
    if params.assignee_id:            api_params["filter[assignee_id]"]= params.assignee_id
    if params.space_id:               api_params["filter[space_id]"]   = params.space_id

    if params.space_id:
        result = await _fetch_all_pages("/todos", api_params, space_id=params.space_id)
    else:
        result = await api("GET", "/todos", params=api_params)

    return _filter_results(result, params.query)

@mcp.tool(name="strety_get_todo", annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True})
async def strety_get_todo(todo_id: str) -> dict:
    """Get a single todo by UUID."""
    return await api("GET", f"/todos/{todo_id}")

@mcp.tool(name="strety_create_todo", annotations={"readOnlyHint": False, "destructiveHint": False, "idempotentHint": False})
async def strety_create_todo(params: TodoCreateInput) -> dict:
    """Create a new todo. space_id and space_type are required."""
    return await api("POST", "/todos", body={"data": {"type": "todo", "attributes": _build_attrs(params)}})

@mcp.tool(name="strety_update_todo", annotations={"readOnlyHint": False, "destructiveHint": False, "idempotentHint": True})
async def strety_update_todo(todo_id: str, params: TodoUpdateInput) -> dict:
    """Update a todo's title, due date, priority, assignee, or completion status.
    
    To complete: set completed_at to current datetime e.g. '2026-05-14T19:00:00Z'
    To reopen:   set completed_at to null
    """
    attrs = _build_attrs(params, exclude_none=False)
    attrs = {k: v for k, v in attrs.items() if k in params.model_fields_set or v is not None}
    if not attrs: return {"error": "No fields provided."}
    return await api("PATCH", f"/todos/{todo_id}",
                     body={"data": {"type": "todo", "id": todo_id, "attributes": attrs}})

@mcp.tool(name="strety_complete_todo", annotations={"readOnlyHint": False, "destructiveHint": False, "idempotentHint": True})
async def strety_complete_todo(todo_id: str) -> dict:
    """Mark a todo as complete."""
    return await api("PATCH", f"/todos/{todo_id}",
                     body={"data": {"type": "todo", "id": todo_id,
                                    "attributes": {"completed_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")}}})

@mcp.tool(name="strety_reopen_todo", annotations={"readOnlyHint": False, "destructiveHint": False, "idempotentHint": True})
async def strety_reopen_todo(todo_id: str) -> dict:
    """Reopen a completed todo."""
    return await api("PATCH", f"/todos/{todo_id}",
                     body={"data": {"type": "todo", "id": todo_id, "attributes": {"completed_at": None}}})

@mcp.tool(name="strety_delete_todo", annotations={"readOnlyHint": False, "destructiveHint": True, "idempotentHint": False})
async def strety_delete_todo(todo_id: str) -> dict:
    """Permanently delete a todo. Cannot be undone."""
    return await api("DELETE", f"/todos/{todo_id}")


# ============================================================
# VISIONS / V/TO
# ============================================================

@mcp.tool(name="strety_list_visions", annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True})
async def strety_list_visions(params: ListInput) -> dict:
    """List Vision/Traction Organizer (V/TO) documents."""
    return _filter_results(await api("GET", "/visions", params={"page[number]": params.page}), params.query)

@mcp.tool(name="strety_get_vision", annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True})
async def strety_get_vision(vision_id: str) -> dict:
    """Get a single V/TO by UUID with full block content."""
    return await api("GET", f"/visions/{vision_id}")


# ============================================================
# ROLES CHARTS
# ============================================================

@mcp.tool(name="strety_list_roles_charts", annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True})
async def strety_list_roles_charts() -> dict:
    """List all accountability/roles charts."""
    return await api("GET", "/roles_charts")

@mcp.tool(name="strety_get_roles_chart", annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True})
async def strety_get_roles_chart(chart_id: str) -> dict:
    """Get a single roles/accountability chart by UUID."""
    return await api("GET", f"/roles_charts/{chart_id}")

@mcp.tool(name="strety_list_roles", annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True})
async def strety_list_roles(chart_id: str) -> dict:
    """List all roles in a roles/accountability chart."""
    return await api("GET", f"/roles_charts/{chart_id}/roles")

@mcp.tool(name="strety_get_role", annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True})
async def strety_get_role(chart_id: str, role_id: str) -> dict:
    """Get a single role from a roles chart."""
    return await api("GET", f"/roles_charts/{chart_id}/roles/{role_id}")


# ============================================================
# PLAYBOOKS
# ============================================================

class PlaybookCreateInput(BaseModel):
    title:       str           = Field(..., min_length=1, max_length=500)
    description: Optional[str] = Field(None)
    type:        str           = Field(default="document", description="document | link | upload")
    space_id:    str           = Field(..., description="UUID of org, team, project, or person space")
    space_type:  str           = Field(..., description="organization | team | project | person")
    folder_id:   Optional[str] = Field(None, description="UUID of folder to place this playbook in")
    owner_id:    Optional[str] = Field(None, description="UUID of owner")

class PlaybookUpdateInput(BaseModel):
    title:       Optional[str] = Field(None)
    description: Optional[str] = Field(None)
    status:      Optional[str] = Field(None, description="draft | active")
    content:     Optional[str] = Field(None, description="HTML content for document playbooks")
    url:         Optional[str] = Field(None, description="URL for link playbooks")
    folder_id:   Optional[str] = Field(None)
    owner_id:    Optional[str] = Field(None)

@mcp.tool(name="strety_list_playbooks", annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True})
async def strety_list_playbooks(params: ListInput) -> dict:
    """List playbooks with optional keyword filtering."""
    return _filter_results(await api("GET", "/playbooks", params={"page[number]": params.page}), params.query)

@mcp.tool(name="strety_get_playbook", annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True})
async def strety_get_playbook(playbook_id: str) -> dict:
    """Get a single playbook by UUID."""
    return await api("GET", f"/playbooks/{playbook_id}")

@mcp.tool(name="strety_create_playbook", annotations={"readOnlyHint": False, "destructiveHint": False, "idempotentHint": False})
async def strety_create_playbook(params: PlaybookCreateInput) -> dict:
    """Create a new playbook. space_id and space_type are required."""
    return await api("POST", "/playbooks", body={"data": {"type": "playbook", "attributes": _build_attrs(params)}})

@mcp.tool(name="strety_update_playbook", annotations={"readOnlyHint": False, "destructiveHint": False, "idempotentHint": True})
async def strety_update_playbook(playbook_id: str, params: PlaybookUpdateInput) -> dict:
    """Update a playbook's title, description, content, status, or folder."""
    attrs = _build_attrs(params)
    if not attrs: return {"error": "No fields provided."}
    return await api("PATCH", f"/playbooks/{playbook_id}",
                     body={"data": {"type": "playbook", "id": playbook_id, "attributes": attrs}})

@mcp.tool(name="strety_delete_playbook", annotations={"readOnlyHint": False, "destructiveHint": True, "idempotentHint": False})
async def strety_delete_playbook(playbook_id: str) -> dict:
    """Permanently delete a playbook. Cannot be undone."""
    return await api("DELETE", f"/playbooks/{playbook_id}")

@mcp.tool(name="strety_list_playbook_folders", annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True})
async def strety_list_playbook_folders() -> dict:
    """List all playbook folders."""
    return await api("GET", "/playbooks/folders")

@mcp.tool(name="strety_create_playbook_folder", annotations={"readOnlyHint": False, "destructiveHint": False, "idempotentHint": False})
async def strety_create_playbook_folder(
    title: str,
    space_id: str,
    space_type: str,
    description: Optional[str] = None,
    parent_id: Optional[str] = None
) -> dict:
    """Create a new playbook folder.
    
    Args:
        title: Folder name
        space_id: UUID of org, team, project, or person space
        space_type: organization | team | project | person
        description: Optional description
        parent_id: UUID of parent folder (for subfolders)
    """
    attrs: dict = {"title": title, "space_id": space_id, "space_type": space_type}
    if description: attrs["description"] = description
    if parent_id:   attrs["parent_id"]   = parent_id
    return await api("POST", "/playbooks/folders",
                     body={"data": {"type": "playbook_folder", "attributes": attrs}})

@mcp.tool(name="strety_delete_playbook_folder", annotations={"readOnlyHint": False, "destructiveHint": True, "idempotentHint": False})
async def strety_delete_playbook_folder(folder_id: str) -> dict:
    """Permanently delete a playbook folder. Cannot be undone."""
    return await api("DELETE", f"/playbooks/folders/{folder_id}")


# ============================================================
# MESSAGES
# ============================================================

@mcp.tool(name="strety_list_messages", annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True})
async def strety_list_messages(params: ListInput) -> dict:
    """List messages with optional keyword filtering."""
    return _filter_results(await api("GET", "/messages", params={"page[number]": params.page}), params.query)

@mcp.tool(name="strety_create_message", annotations={"readOnlyHint": False, "destructiveHint": False, "idempotentHint": False})
async def strety_create_message(title: str) -> dict:
    """Create a new message."""
    return await api("POST", "/messages", body={"data": {"type": "message", "attributes": {"title": title}}})

@mcp.tool(name="strety_delete_message", annotations={"readOnlyHint": False, "destructiveHint": True, "idempotentHint": False})
async def strety_delete_message(message_id: str) -> dict:
    """Permanently delete a message. Cannot be undone."""
    return await api("DELETE", f"/messages/{message_id}")


# ============================================================
# STARTUP
# ============================================================

if __name__ == "__main__":
    if "--auth" in sys.argv:
        run_auth_flow()
    else:
        mcp.run()
