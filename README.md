# Apple configuration profiles for Stalwart

A small self-service web page for [Stalwart](https://stalw.art) users: sign in with your
Stalwart account and download a `.mobileconfig` profile that sets up **Mail (IMAP/SMTP),
Calendars (CalDAV) and Contacts (CardDAV)** on iPhone, iPad or Mac in one step.

Every download creates a fresh **app password** in Stalwart and puts it into the profile, so
the user's real password never ends up on the device. This works the same way as Mailcow's
Apple profiles.

- Single Python file, standard library only, no database, no stored state
- OAuth 2.0 Authorization Code + PKCE against Stalwart's built-in OAuth server
- Runs as a hardened container behind your reverse proxy
- Web pages in English and German (picked from the browser language)

**Who does what:** an administrator of the Stalwart server sets this service up once
(OAuth client, container, reverse proxy). Users only open a web page and install the profile;
they need no admin rights, scripts or command line.

- [For users](#for-users): installing the profile
- [For administrators](#for-administrators): setup, configuration, troubleshooting

## For users

Your administrator gives you the address of the page, e.g. `https://profile.example.org`.

### iPhone / iPad

1. Open the page in **Safari**. Other browsers cannot install profiles.
2. Choose "Mail, calendars and contacts" or "Mail only" and sign in to Stalwart.
3. Confirm the consent screen. It names `apple-profile` and asks for full access to the
   account. Because the service revokes its token afterwards, the screen shows up on every
   download.
4. Allow the profile download.
5. Settings › "Profile Downloaded" › Install. The profile is shown as "Unverified" because it is
   not signed.
6. Check Mail, Calendar and Contacts. Stalwart now lists an app password
   "Apple profile iPhone YYYY-MM-DD HH:MM".

### Mac

1. Open the page in Safari and sign in. The profile lands in the Downloads folder.
2. Double-click it, then System Settings › General › Device Management (or Privacy & Security ›
   Profiles) › Install.

On an iPad the app password is named "Mac/iPad", because iPadOS Safari identifies itself as a
Mac. Installing a new profile replaces the old one on the same device.

### "App password limit reached"

Each download creates a new app password, and Stalwart allows only a few per account. If the
page says the limit is reached, follow its link to your Stalwart account page, delete old
"Apple profile ..." app passwords of devices you no longer use, and download again.

## For administrators

### Requirements

- **Stalwart 1.1.0 or newer.** Written against the v1.1.0 source. On 1.0.x it cannot work,
  because apps signed in via OAuth cannot create app passwords there. For 0.16.x see
  [Older Stalwart versions](#older-stalwart-versions-016x).
- A subdomain for the service (e.g. `profile.example.org`) with HTTPS via a reverse proxy
  (Caddy, nginx, Traefik, ...).
- Docker with Compose (or any way to run `python3 app.py` with Python 3.10+).
- An admin account (superuser) in Stalwart to register the OAuth client.

### How it works

1. The user opens the page in Safari on the device and picks "Mail, calendars and contacts" or
   "Mail only".
2. `/start` stores state and PKCE verifier in an HMAC-signed `__Host-` cookie and redirects to
   Stalwart's `/login`.
3. The user signs in (including two-factor authentication) and confirms the consent screen.
4. `/callback` checks `state` and `iss` (RFC 9207), exchanges the code for a token, reads the
   JMAP session and the user's identity and creates an app password with `x:AppPassword/set`.
5. The OAuth token is revoked right away (`/auth/revoke`), so the service does not stay in the
   user's "connected applications".
6. The profile is returned directly in the response with `Cache-Control: no-store`.

The app password inherits the user's permissions **except** those listed in
`APP_PASSWORD_DISABLE`. By default these are `sysAppPasswordCreate/Update/Destroy`,
`sysApiKeyCreate/Update/Destroy`, `sysAccountPasswordUpdate` and `pop3Authenticate`. So someone
who gets hold of a profile cannot create further credentials or change the main password.
JMAP (webmail) stays allowed because there is no separate permission for it.

### Installation

#### 1. Register the OAuth client in Stalwart

Create an OAuth client (registry object `OAuthClient`) in the admin UI:

| Setting | Value |
|---|---|
| Client ID | `apple-profile` |
| Redirect URI | `https://profile.example.org/callback` (exact match, no trailing slash) |
| Allowed scopes | Mail, Calendars, Contacts, **Full access** |
| Grant types | default (authorization code, refresh token) |
| Secret | empty (public client, PKCE is always used) |

Only a superuser can allow the "Full access" scope. Why the service needs it is explained under
[Security considerations](#security-considerations).

Alternatively use the included script with an admin API key:

```bash
export STALWART_URL=https://mail.example.org
STALWART_TOKEN=ask ./stalwart-oauth-settings.sh add-client apple-profile \
  mail,contacts,calendars,full https://profile.example.org/callback
```

`STALWART_TOKEN=ask` prompts for the key so it does not end up in your shell history. The
script needs `curl` and `jq`; run `./stalwart-oauth-settings.sh help` for all commands.

If you upgraded from 0.16.x, an existing client has no scopes yet. Add them with
`show` (to get the registry id) and `set-scopes <id> mail,contacts,calendars,full`.

#### 2. Run the container

```bash
git clone <this repository> /opt/apple-profile && cd /opt/apple-profile
cp .env.example .env
sed -i "s|^SESSION_SECRET=.*|SESSION_SECRET=$(openssl rand -base64 32)|" .env
chmod 600 .env
# edit PUBLIC_URL and STALWART_URL in .env
docker compose up -d --build
curl -s http://127.0.0.1:8087/healthz   # -> ok
docker logs apple-profile
```

On macOS use `sed -i ''` instead of `sed -i`. The container runs as UID 10001, with a read-only
root filesystem and no writable volumes, so there is no data directory to `chown`. Logs go to
stdout (`docker logs`), rotated by Docker (3 × 10 MB). Set `TZ` in `.env` for local timestamps.

The service listens on `127.0.0.1:8087` only. Put your reverse proxy in front of it.

#### 3. Reverse proxy

**Caddy** — see `Caddyfile.example`:

```caddy
profile.example.org {
	encode zstd gzip
	reverse_proxy 127.0.0.1:8087
}
```

**nginx:**

```nginx
location / {
    proxy_pass http://127.0.0.1:8087;
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
}
```

With exactly one proxy in front, keep `TRUSTED_PROXIES=1`. The service then takes the client IP
(for rate limiting and logs) from the last `X-Forwarded-For` entry, which the proxy wrote itself.
With two proxies in a chain set it to `2`. Without a proxy set it to `0`.

### Configuration

All settings are environment variables (see `.env.example`).

| Variable | Default | Description |
|---|---|---|
| `PUBLIC_URL` | **required** | Public URL of this service; the redirect URI is `PUBLIC_URL/callback` |
| `STALWART_URL` | **required** | Base URL of Stalwart; must match the `iss` Stalwart reports |
| `SESSION_SECRET` | random | Key for the state cookie. Without it, sign-ins in progress break on restart |
| `CLIENT_ID` | `apple-profile` | OAuth client ID |
| `CLIENT_SECRET` | empty | Only if the client has a secret |
| `OAUTH_SCOPE` | mail calendars contacts full | Requested scopes (space-separated, full URNs) |
| `REVOKE_TOKEN` | `1` | Revoke the OAuth token after creating the app password |
| `MAIL_HOST` | host of `STALWART_URL` | IMAP/SMTP host in the profile |
| `IMAP_PORT` / `IMAP_SSL` | `993` / `1` | IMAP with implicit TLS |
| `SMTP_PORT` / `SMTP_SSL` | `465` / `1` | SMTP submission with implicit TLS |
| `DAV_HOST` / `DAV_PORT` | `MAIL_HOST` / `443` | CalDAV/CardDAV host and port |
| `DAV_SET_PRINCIPAL_URL` | `0` | `1` sets `/dav/cal/<user>/` and `/dav/card/<user>/`; `0` uses `/.well-known` discovery |
| `PROFILE_ORG` | empty | Organisation shown in the profile |
| `PROFILE_ID_PREFIX` | reversed host of `PUBLIC_URL` | Reverse-DNS prefix of the profile identifiers |
| `UI_LANG` | `auto` | `auto` (browser language), `en` or `de` |
| `PAGE_TITLE` | built-in | Custom heading of the landing page |
| `SELF_SERVICE_URL` | `STALWART_URL/account` | Linked when the app password limit is reached |
| `APP_PASSWORD_EXPIRY_DAYS` | `0` | Expiry of the app password in days, `0` = none |
| `APP_PASSWORD_DISABLE` | see above | Permissions removed from the app password (comma-separated) |
| `TRUSTED_PROXIES` | `1` | Reverse proxies in front of the service, `0` = none |
| `RATE_LIMIT_MAX` / `RATE_LIMIT_WINDOW` | `20` / `300` | Requests per IP to `/start` and `/callback` per window (seconds); `0` disables |
| `STATE_MAX_AGE` | `600` | Seconds the user has to finish signing in |
| `HTTP_TIMEOUT` | `15` | Timeout for requests to Stalwart (seconds) |
| `LISTEN_HOST` / `LISTEN_PORT` | `0.0.0.0` / `8080` | Inside the container |
| `LOG_LEVEL` | `INFO` | Python log level |

Profile identifiers and UUIDs are stable per user, so installing a new profile replaces the old
one on the device.

### Limit on app passwords

Every download creates a new app password. Stalwart limits them per account with
`maxAppPasswords` in the `Authentication` object (default **5**). When the limit is reached,
Stalwart answers `overQuota` and the service shows a hint with a link to the self-service page,
where users can delete old "Apple profile ..." entries.

Old app passwords are **not** deleted automatically: the device is only roughly known from the
user agent ("iPhone", "Mac/iPad"), and with two devices of the same kind a new download would
lock out the other one. If users have several devices, raise the limit (e.g. to 20).

### Troubleshooting

Watch `docker logs -f apple-profile`. A successful download logs
`profile issued: user=... device=... credential_id=...`.

| Message | Cause |
|---|---|
| permissions rejected (`invalid_scope`) | The `OAuthClient` does not allow every scope in `OAUTH_SCOPE` (see `set-scopes`) |
| sign-in page shows "invalid client" or a server error | Client ID unknown or redirect URI does not match exactly |
| Token exchange failed (`invalid_grant`) | Code expired or already used, or redirect URI differs |
| Token exchange failed (`invalid_client`) | Client secret does not match |
| App password rejected (`forbidden`) | `OAUTH_SCOPE` lacks `full`, or the user lacks `sysAppPasswordCreate` |
| App password limit reached (`overQuota`) | `maxAppPasswords` reached, see above |
| Sign-in expired | Cookie missing: more than 10 minutes, or a different browser |
| `token revocation failed` in the log | Only a warning, the profile was delivered. The grant stays in the user's connected applications |

### Security considerations

- **Full-access token.** Since Stalwart 1.0 an OAuth token only carries the rights of its scopes.
  When creating an app password, Stalwart checks that the token itself holds every right the app
  password would get. An app password that inherits the account's rights therefore requires the
  `full` scope. The token is kept in memory for a few seconds only and revoked afterwards.
- **Admin accounts.** An app password inherits the user's rights, including administrative ones.
  Do not download profiles with admin accounts, or add the relevant permissions to
  `APP_PASSWORD_DISABLE`.
- **Plain-text password in the profile.** The app password is stored in the profile in clear
  text and the profile is not signed. Treat the downloaded file like a password; it is not
  cached by the service or the proxy (`no-store`).
- **Nothing stored.** Tokens, codes and passwords are not stored or logged; the access log omits
  query strings. Logs do contain the user name and client IP of each download.
- **Container hardening.** `read_only`, `cap_drop: ALL`, `no-new-privileges`, `pids_limit`,
  `mem_limit`, tmpfs for `/tmp`, bound to `127.0.0.1` only.
- **Client ID Metadata Documents.** Stalwart's `clientMetadataDocuments` setting (in
  `OidcProvider`) is `disabled` by default. This service does not need it; with `sameDomain` or
  `any`, other `https://` client IDs can reach the consent screen.

### Older Stalwart versions (0.16.x)

Up to and including 0.16.27, Stalwart accepts any `client_id` with any `https://` redirect URI
while `requireClientRegistration` is `false` (the default). If you still run 0.16.x, register all
clients you use and set `requireClientRegistration` to `true`, or upgrade. Since 1.0.0 the setting
no longer exists and unknown clients are always rejected.

On 0.16.x scopes do not restrict tokens and there is no revocation endpoint. Set `OAUTH_SCOPE`
without `urn:stalwart:oauth:scope:full` and `REVOKE_TOKEN=0`. This combination is not tested with
the current code, and `stalwart-oauth-settings.sh` targets 1.1 and does not work with 0.16.x.

## License

[MIT](LICENSE)
