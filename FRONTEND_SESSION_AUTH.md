# Dashboard auth migration: JWT → session cookie

The AgentDNA backend no longer issues or accepts JWTs. Dashboard auth is now a
server-side session carried in an `HttpOnly` cookie that the browser manages.
This document is everything the frontend needs to change.

## TL;DR — what to change

1. **Delete all token handling.** No more reading `data.token` from `/login`, no
   storing it (`localStorage` / `sessionStorage` / JS-readable cookie / state),
   no decoding it, no `Authorization: Bearer …` header. The backend ignores
   `Authorization` now.
2. **Send credentials on every dashboard request.**
   `fetch(url, { credentials: "include" })` or axios `withCredentials: true`.
   This includes `/login` itself — otherwise the browser discards the cookie
   the login response sets.
3. **Know who is logged in via `GET /dashboard/v1/session`** (call it on app
   load). The cookie is `HttpOnly`, so JavaScript cannot see it — you cannot
   check "is there a token" client-side any more.
4. **Logout = `POST /dashboard/v1/logout`.** Clearing local state is not enough;
   the server must end the session.
5. **Treat any `401` from `/dashboard/v1/*` as "logged out"** → reset user state,
   go to the login page. Wrong credentials on the login endpoints are `400`,
   never `401`, so they don't trigger this.
   A `503` means the session couldn't be checked right now (database hiccup):
   the user is still logged in — show a retry message, don't log them out.
6. **Admins log in through the middleware, not the admin server.** Replace the
   direct `POST {VITE_ADMIN_API_BASE_URL}/login` with
   `POST /dashboard/v1/admin-login` (same `{username, password}` body). Admin
   password changes go through `POST /dashboard/v1/update-password` like users.
   The browser no longer talks to the admin server at all —
   `VITE_ADMIN_API_BASE_URL` can be removed.

Endpoint paths, request bodies and response shapes are otherwise **unchanged**,
except that `/login` no longer returns `token` and no longer accepts admins.

---

## Base URL and request helper

All examples assume:

```ts
const API = import.meta.env.VITE_API_URL ?? "http://localhost:9000"; // or process.env.NEXT_PUBLIC_API_URL
const DASH = `${API}/dashboard/v1`;
```

One wrapper for every dashboard call:

```ts
export class UnauthorizedError extends Error {}

export async function api<T = any>(path: string, init: RequestInit = {}): Promise<T> {
  const res = await fetch(`${DASH}${path}`, {
    ...init,
    credentials: "include",                // REQUIRED — sends/receives the session cookie
    headers: {
      ...(init.body && !(init.body instanceof FormData) ? { "Content-Type": "application/json" } : {}),
      ...init.headers,
      // NOTE: no Authorization header
    },
  });

  if (res.status === 401) {
    onLoggedOut();                         // clear user state, redirect to /login
    throw new UnauthorizedError("not logged in");
  }
  const body = await res.json();           // { status: boolean, message?: string, data?: any }
  if (!res.ok || body.status === false) throw new Error(body.message || `HTTP ${res.status}`);
  return body.data as T;
}
```

Axios equivalent:

```ts
import axios from "axios";

export const api = axios.create({
  baseURL: `${API}/dashboard/v1`,
  withCredentials: true,                   // REQUIRED
});

api.interceptors.response.use(
  (r) => r,
  (err) => {
    if (err.response?.status === 401) onLoggedOut();
    return Promise.reject(err);
  },
);
// Remove any request interceptor that adds `Authorization: Bearer ...`.
```

---

## Auth flows

### Login (org users) — `POST /dashboard/v1/login` (public)

```ts
const res = await fetch(`${DASH}/login`, {
  method: "POST",
  credentials: "include",                  // REQUIRED, or the cookie is dropped
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ email, password }),
});
const body = await res.json();
if (!body.status) throw new Error(body.message);   // 400 "invalid credentials"
setUser(body.data);
```

The response sets the cookie (you never see its value):

```
Set-Cookie: agentdna_session=<opaque>; Path=/; Max-Age=604800; HttpOnly; Secure; SameSite=Lax
```

Response body — **no `token` field any more**:

```json
{
  "status": true,
  "data": {
    "did": "did:rubix:…", "email": "a@x.io", "org_id": "org1",
    "api_key": "…", "nft_id": "…", "is_admin": false,
    "agent_access_list": ["did:…"]
  }
}
```

Errors: `400` email/password missing, `400 "invalid credentials"` (also
returned for admin accounts — they must use `/admin-login`).

### Admin login — `POST /dashboard/v1/admin-login` (public)

Replaces the direct call to the admin server's `/agent-admin/v1/login`. The
middleware checks the credentials with the admin server server-to-server, then
sets the same session cookie as user login. The admin server's JWT is never
sent to the browser.

```ts
const res = await fetch(`${DASH}/admin-login`, {
  method: "POST",
  credentials: "include",                  // REQUIRED, or the cookie is dropped
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ username, password }),
});
const body = await res.json();
if (!body.status) throw new Error(body.message);   // show on the login form
setUser(body.data);
```

```jsonc
// 200 — data is an object now, NOT a JWT string; don't decode anything
{
  "status": true,
  "message": "login ok",                   // admin server's message, passed through
  "data": {
    "username": "root", "did": "did:rubix:…", "email": "", "org_id": "org1",
    "api_key": "…", "is_admin": true
  }
}
```

| Status | Body | When |
|---|---|---|
| 400 | `{ status: false, message: "username and password are required" }` | Missing field |
| 400 | `{ status: false, message: "<admin server's message>" }` e.g. `"Invalid username or password"` | Wrong credentials — show `message` |
| 403 | `{ status: false, message: "admin account is not registered with this dashboard" }` | Admin server accepted the login, but its token has no DID or the admin belongs to another org (first login creates the admin's row only for this middleware's `ORG_ID`) |
| 502 | `{ status: false, message: "Admin server unavailable" }` | Admin server down / bad reply |
| 504 | `{ status: false, message: "Admin server unavailable" }` | Admin server took >10s |

What used to come from the admin JWT claims comes from this response or
`/session`: `sub` → `username` (login) / `name` (session), `is_admin`, `did`,
`org_id`, `api_key`. `email` may be empty for admins — detect admins by
`is_admin`, not by "no email".

### App load / route guard — `GET /dashboard/v1/session`

Call once when the app starts (and anywhere you used to check for a stored
token):

```ts
async function bootstrapAuth() {
  try {
    const s = await api<{ did: string; email: string; name: string; org_id: string; is_admin: boolean; expiresAt: string }>("/session");
    setUser(s);            // logged in
  } catch (e) {
    if (e instanceof UnauthorizedError) setUser(null);   // show login
    else throw e;
  }
}
```

```jsonc
// 200
{ "status": true, "data": { "did": "did:rubix:…", "email": "a@x.io", "name": "alice", "org_id": "org1",
                             "is_admin": false, "expiresAt": "2026-10-15T05:55:05Z" } }
// 401
{ "status": false, "message": "not logged in" }            // no cookie
{ "status": false, "message": "session expired or invalid" } // expired / revoked / logged out
```

`did`, `email`, `name` and `is_admin` here are always current from the
database. For admins `name` is their admin-server username and `email` may be
empty. A user
can now hold several DIDs; `did` is their latest (primary) one, and it updates
without re-login when a new DID is registered. If the UI previously read
`did` / `is_admin` / `email` out of the decoded JWT, read them from `/session`
(or the `/login` response) instead.

### Logout — `POST /dashboard/v1/logout`

```ts
await fetch(`${DASH}/logout`, { method: "POST", credentials: "include" });
setUser(null);
navigate("/login");
```

```json
{ "status": true, "message": "logged out" }
```

The server deletes the session and clears the cookie.

### Log out all devices — `POST /dashboard/v1/logout-all` (optional UI)

```ts
const { sessionsEnded } = await api<{ sessionsEnded: number }>("/logout-all", { method: "POST" });
setUser(null);
navigate("/login");
```

Ends every session of the account, including the current one.

### Password change — `POST /dashboard/v1/update-password` (users **and** admins)

Request: `{ "new_password": "…" }` (min 8 chars). No `username` — the backend
knows who is logged in. For admins the middleware forwards the change to the
admin server itself, so **stop calling the admin server's
`/agent-admin/v1/update-password` from the browser.** The admin server's
message is returned on failure (`400`).

New behaviour: every **other** device is logged out; the current session stays
logged in.

### Profile — `POST /dashboard/v1/update-profile`

Unchanged for users. For admins, changing `name` is now rejected with `400`
(`"admin username is managed by the admin server and cannot be changed here"`)
because it is their admin-server login name; changing `email` still works.
Hide or disable the name field for admins.

### Password reset — `POST /dashboard/v1/reset-password` (public)

Unchanged request. New behaviour: **all** sessions of that account are ended,
so after a reset send the user to the login page.

---

## Calling the other dashboard APIs

Every route under `/dashboard/v1/` other than the public ones (`login`,
`admin-login`, `send-otp`, `forgot-password`, `reset-password`, `register-user`, `signup`,
`authorize-action`, `global-stats`) requires the cookie. Using the `api()`
helper above:

```ts
// GET with query params
const metrics   = await api(`/home-metrics?page=1`);
const intents   = await api(`/intent-list?page=2`);
const userInfo  = await api(`/user-info?userID=${encodeURIComponent(did)}`);
const graph     = await api(`/observability-user-flow?userDID=${encodeURIComponent(did)}`);

// POST JSON
await api("/update-intent-status", {
  method: "POST",
  body: JSON.stringify({ intentID, status: "Acknowledged" }),   // Unreviewed | Acknowledged | Flagged
});
await api("/update-profile", { method: "POST", body: JSON.stringify({ name: "Alice" }) });

// POST multipart (file upload) — do NOT set Content-Type yourself; the browser adds the boundary
const fd = new FormData();
fd.append("file", file);
await api("/upload-user-policy", { method: "POST", body: fd });
```

The full protected list (paths and payloads unchanged from before):
`session, logout, logout-all, user-profile, admin-profile, home-metrics,
interactions-list, agent-metrics, agents-list, users-list, create-user,
agent-interactions, agent-intents, user-intents, agent-info, agent-lhi-scores,
tool-agent-scores, revoke-agent, unrevoke-agent, intent-info,
update-intent-status, intent-diagram, update-password, update-profile,
tools-list, tool-info, user-info, intent-list, threats-list, threat-events,
top-threats, threat-detail, threat-by-id, top-threat-agents,
interactions/series, search, agents-apps-metrics, observability-summary,
observability-graph, observability-users, observability-user-flow,
observability-agent-flow, observability-app-flow, observability-intents,
observability-paths, agents-creation-requests-list,
agents-creation-requests-list-user, agents-creation-requests-create,
agents-creation-requests-edit, agent-creation-request-result-submit,
agent-info-edit, agent-access-requests-list-org,
agent-access-requests-list-user, agent-access-request-submit,
upload-user-policy, user-policy, upload-agent-policy, agent-policy,
agent-policy-history, agent-policy-update`.

---

## Errors the frontend should handle

| Status | `message` | Meaning | Frontend action |
|---|---|---|---|
| 400 | `invalid credentials` / admin server's message | Wrong login (`/login`, `/admin-login`) | Show `message` on the form — **not** a session expiry |
| 401 | `not logged in` | No cookie sent | Check `credentials: "include"`; else go to login |
| 401 | `session expired or invalid` | Expired (7 days), logged out, revoked by password change/reset or logout-all | Clear user state, go to login |
| 503 | `temporarily unable to verify your session, try again` | The session couldn't be checked (database error); the session is kept | Keep the user logged in; retry or show a transient error |
| 403 | `origin not allowed` | A POST came from an origin the backend doesn't trust | Config issue — the dashboard's origin must be in the backend's `CORS_ALLOWED_ORIGINS` |
| 403 | other | Not an admin for an admin-only route | Unchanged from before |
| 502 / 504 | `Admin server unavailable` | `/admin-login` couldn't reach the admin server | Show `message`, let the admin retry |

---

## Environment / hosting requirements

Cookies only work if the browser is willing to send them. Tell the backend
operator the exact dashboard origin(s); they set:

```env
CORS_ALLOWED_ORIGINS=https://app.example.com,http://localhost:3000
```

| Setup | Works with | Backend settings |
|---|---|---|
| Local dev: dashboard `http://localhost:3000`, API `http://localhost:9000` | ✅ (same site: `localhost`) | `CORS_ALLOWED_ORIGINS=http://localhost:3000`, `SESSION_COOKIE_SECURE=false` |
| Dev server proxy (Vite `server.proxy` / Next `rewrites`) so the browser calls `/dashboard/v1/...` on its own origin | ✅ simplest — no CORS at all | defaults |
| Prod: `app.example.com` + `api.example.com` (same registrable domain) | ✅ | `CORS_ALLOWED_ORIGINS=https://app.example.com` (defaults otherwise) |
| Prod: totally different domains (e.g. `x.vercel.app` + `api.example.com`) | ⚠️ needs third-party cookies; Safari and some browsers block them | `SESSION_COOKIE_SAMESITE=none` — prefer a proxy/rewrite or a shared domain instead |

Use `localhost` consistently — don't mix `localhost` and `127.0.0.1`.

### If the frontend renders on a server (Next.js SSR / server components / middleware)

Server-side `fetch` has no browser cookie jar. Forward the incoming cookie:

```ts
// Next.js server component / route handler
import { cookies } from "next/headers";

const res = await fetch(`${DASH}/home-metrics?page=1`, {
  headers: { cookie: cookies().toString() },
  cache: "no-store",
});
```

For a Next.js `middleware.ts` route guard, you can only check that
`agentdna_session` *exists* (when the API shares the dashboard's domain); to
verify it, call `/session`.

---

## Checklist

- [ ] Remove token storage, token decoding and the `Authorization` header everywhere
- [ ] `credentials: "include"` / `withCredentials: true` on **every** dashboard call, including `/login`
- [ ] App boot calls `GET /session` to restore the logged-in user
- [ ] Global `401` handler → clear user, redirect to login
- [ ] Logout button calls `POST /logout`
- [ ] Admin login form posts `{username, password}` to `/dashboard/v1/admin-login`; `data` is an object, not a JWT
- [ ] Admin password change uses `/dashboard/v1/update-password` with `{new_password}` only
- [ ] No browser calls to the admin server remain (`VITE_ADMIN_API_BASE_URL` removed)
- [ ] Admin detection uses `is_admin`, not "has `sub` and no `email`"; name field hidden for admins in the profile form
- [ ] Login errors are `400` — show `message`; only `401` means "session expired"
- [ ] `did` / `email` / `name` / `is_admin` come from `/login`, `/admin-login` or `/session`, not a decoded token
- [ ] File uploads use `FormData` without a manual `Content-Type`
- [ ] Dashboard origin(s) given to backend for `CORS_ALLOWED_ORIGINS`
- [ ] (optional) "Log out all devices" button → `POST /logout-all`
