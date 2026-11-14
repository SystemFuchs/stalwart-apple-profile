#!/usr/bin/env python3
"""
Apple configuration profile (.mobileconfig) service for Stalwart.

Flow:
  1. GET /                 -> landing page
  2. GET /start            -> sets signed state cookie, redirects to Stalwart /login
                              (OAuth 2.0 Authorization Code + PKCE S256)
  3. GET /callback         -> checks state and issuer, exchanges code for token,
                              reads JMAP session + identities,
                              creates an app password via x:AppPassword/set,
                              revokes the OAuth token,
                              returns the .mobileconfig directly
  4. GET /healthz          -> "ok"

No tokens, codes or passwords are stored or logged. Standard library only.
Written against the Stalwart v1.1.0 source (OAuth scopes, JMAP registry).
"""

import base64
import hashlib
import hmac
import html
import json
import logging
import os
import plistlib
import re
import secrets
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# --------------------------------------------------------------------------
# Configuration (environment variables)
# --------------------------------------------------------------------------


def env(name, default=None, required=False):
    value = os.environ.get(name, default)
    if required and not value:
        print(f"Missing required environment variable {name}", file=sys.stderr)
        sys.exit(1)
    return value


def env_int(name, default):
    try:
        return int(os.environ.get(name, default))
    except ValueError:
        print(f"Environment variable {name} must be an integer", file=sys.stderr)
        sys.exit(1)


def env_bool(name, default):
    return os.environ.get(name, "1" if default else "0").strip().lower() in ("1", "true", "yes", "on")


def host_of(url):
    return urllib.parse.urlsplit(url).hostname or ""


STALWART_URL = env("STALWART_URL", required=True).rstrip("/")
PUBLIC_URL = env("PUBLIC_URL", required=True).rstrip("/")
CLIENT_ID = env("CLIENT_ID", "apple-profile")
CLIENT_SECRET = env("CLIENT_SECRET", "")  # optional; empty = public client (PKCE only)
# Stalwart >= 1.0 restricts OAuth tokens to the granted scopes. Creating an app password that
# inherits the user's rights (minus APP_PASSWORD_DISABLE) needs the "full" scope: with a
# narrower token Stalwart refuses to grant rights the token itself does not carry.
# The OAuthClient in Stalwart must allow every scope requested here (only a superuser can
# allow "full"); otherwise the login fails with invalid_scope.
SCOPE_FULL = "urn:stalwart:oauth:scope:full"
OAUTH_SCOPE = env(
    "OAUTH_SCOPE",
    "urn:ietf:params:oauth:scope:mail urn:ietf:params:oauth:scope:calendars "
    f"urn:ietf:params:oauth:scope:contacts {SCOPE_FULL}",
)
# Revoke the OAuth token (and the grant behind it) once the app password has been created.
REVOKE_TOKEN = env_bool("REVOKE_TOKEN", True)

# Servers written into the profile (default: host of STALWART_URL)
MAIL_HOST = env("MAIL_HOST", "") or host_of(STALWART_URL)
IMAP_PORT = env_int("IMAP_PORT", 993)
IMAP_SSL = env_bool("IMAP_SSL", True)
SMTP_PORT = env_int("SMTP_PORT", 465)
SMTP_SSL = env_bool("SMTP_SSL", True)
DAV_HOST = env("DAV_HOST", "") or MAIL_HOST
DAV_PORT = env_int("DAV_PORT", 443)
DAV_SET_PRINCIPAL_URL = env_bool("DAV_SET_PRINCIPAL_URL", False)

# Profile metadata
PROFILE_ORG = env("PROFILE_ORG", "")  # shown as organisation in the profile; empty = omitted
# Reverse-DNS prefix of the profile identifiers. Default: reversed host of PUBLIC_URL,
# e.g. https://profile.example.org -> org.example.profile
PROFILE_ID_PREFIX = env("PROFILE_ID_PREFIX", "") or ".".join(reversed(host_of(PUBLIC_URL).split(".")))
PAGE_TITLE = env("PAGE_TITLE", "")  # empty = built-in title in the user's language
# Stalwart self-service page where users manage (delete) their app passwords.
SELF_SERVICE_URL = env("SELF_SERVICE_URL", f"{STALWART_URL}/account").rstrip("/")

# Language of the web pages, the profile texts and the app password description:
# "auto" (from Accept-Language), "en" or "de".
UI_LANG = env("UI_LANG", "auto").strip().lower()

# App password settings
APP_PASSWORD_EXPIRY_DAYS = env_int("APP_PASSWORD_EXPIRY_DAYS", 0)  # 0 = no expiry
# Permissions removed from the generated app password (empty = inherit everything).
APP_PASSWORD_DISABLE = [
    p.strip()
    for p in env(
        "APP_PASSWORD_DISABLE",
        "sysAppPasswordCreate,sysAppPasswordUpdate,sysAppPasswordDestroy,"
        "sysApiKeyCreate,sysApiKeyUpdate,sysApiKeyDestroy,"
        "sysAccountPasswordUpdate,pop3Authenticate",
    ).split(",")
    if p.strip()
]

LISTEN_HOST = env("LISTEN_HOST", "0.0.0.0")
LISTEN_PORT = env_int("LISTEN_PORT", 8080)
# Number of reverse proxies in front of the service that append to X-Forwarded-For.
# 1 = one proxy (Caddy, nginx, Traefik): the client IP is the last entry, which the proxy
# itself wrote and the client cannot forge. 0 = no proxy, use the socket address.
TRUSTED_PROXIES = env_int("TRUSTED_PROXIES", 1)
HTTP_TIMEOUT = env_int("HTTP_TIMEOUT", 15)
STATE_MAX_AGE = env_int("STATE_MAX_AGE", 600)

# Per-IP rate limit for /start and /callback (sliding window).
RATE_LIMIT_MAX = env_int("RATE_LIMIT_MAX", 20)
RATE_LIMIT_WINDOW = env_int("RATE_LIMIT_WINDOW", 300)

_secret = env("SESSION_SECRET", "")
if not _secret:
    _secret = secrets.token_urlsafe(32)
    _random_secret = True
else:
    _random_secret = False
SESSION_KEY = hashlib.sha256(_secret.encode()).digest()
del _secret

REDIRECT_URI = f"{PUBLIC_URL}/callback"
AUTHORIZE_URL = f"{STALWART_URL}/login"
TOKEN_URL = f"{STALWART_URL}/auth/token"
REVOKE_URL = f"{STALWART_URL}/auth/revoke"
SESSION_URL = f"{STALWART_URL}/jmap/session"
COOKIE_NAME = "__Host-ap_state"

logging.basicConfig(
    level=env("LOG_LEVEL", "INFO").upper(),
    format="%(asctime)s %(levelname)s %(message)s",
    stream=sys.stdout,
)
log = logging.getLogger("apple-profile")


# --------------------------------------------------------------------------
# Texts (English, German)
# --------------------------------------------------------------------------

LANGS = ("en", "de")

TEXTS = {
    "en": {
        "title": "Apple profile for mail, calendars and contacts",
        "intro": (
            "After signing in you receive a configuration profile for iPhone, iPad or Mac. It "
            "contains a new app password created just for this device. Your actual password is "
            "not stored in the profile."
        ),
        "btn_all": "Mail, calendars and contacts",
        "btn_mail": "Mail only",
        "step1": "Open this page in Safari on the device you want to set up.",
        "step2": "Sign in, confirm access and allow the profile download.",
        "step3": (
            "iPhone/iPad: Settings &gt; &ldquo;Profile Downloaded&rdquo; &gt; Install.<br>"
            "Mac: open the profile, then System Settings &gt; General &gt; Device Management "
            "(or Privacy &amp; Security &gt; Profiles) &gt; Install."
        ),
        "footer": (
            "The app password appears among the app passwords of your account and can be revoked "
            "there at any time."
        ),
        "error_title": "Error",
        "error_heading": "That did not work",
        "retry": "Try again",
        "unknown": "unknown",
        "device_other": "Apple device",
        "app_password_label": "Apple profile",
        "mail_name": "Email ({email})",
        "mail_desc": "Email account {email}",
        "cal_name": "Calendars ({email})",
        "cal_desc": "CalDAV account {email}",
        "card_name": "Contacts ({email})",
        "card_desc": "CardDAV account {email}",
        "profile_desc_mail": "Sets up email.",
        "profile_desc_all": "Sets up email, calendars and contacts.",
        "err_unreachable": "Stalwart is not reachable ({detail}).",
        "err_token": "Token exchange failed (HTTP {http}, {detail}).",
        "err_session": "Could not read the JMAP session (HTTP {http}).",
        "err_jmap": "JMAP request failed (HTTP {http}, {detail}).",
        "err_no_account": "No account ID found in the JMAP session.",
        "err_no_user": "Could not determine the user name.",
        "err_unexpected": "Unexpected response while creating the app password.",
        "err_app_password": "The app password was rejected ({type}: {detail}).",
        "err_quota": "Your account already has as many app passwords as the mail server allows.",
        "hint_quota": (
            "Every profile download creates a new app password. Delete entries you no longer "
            "need in the self-service portal, e.g. old \"{label} ...\" entries of devices you "
            "replaced or set up again, then try again. Note: a device that still uses a deleted "
            "app password can no longer sign in."
        ),
        "link_quota": "Manage app passwords in the self-service portal",
        "hint_full_scope": (
            "OAUTH_SCOPE does not contain {scope}. Since Stalwart 1.0 a restricted token cannot "
            "grant rights it does not carry itself."
        ),
        "err_invalid_scope": "The mail server rejected the requested permissions (invalid_scope).",
        "hint_invalid_scope": (
            "The OAuth client of this service is not allowed all required scopes in Stalwart. "
            "Please contact your administrator."
        ),
        "err_denied": "Access was declined.",
        "err_aborted": "Sign-in was cancelled ({detail}).",
        "err_bad_request": "Invalid request (code or state missing).",
        "err_expired": (
            "The sign-in has expired or was started in another browser. Please try again."
        ),
        "err_bad_state": "Invalid state parameter.",
        "err_bad_iss": "Invalid issuer (iss) in the response.",
        "err_rate_limit": "Too many requests. Please try again later.",
        "err_not_found": "Page not found.",
        "err_internal": "Internal error.",
    },
    "de": {
        "title": "Apple-Profil für Mail, Kalender und Kontakte",
        "intro": (
            "Nach der Anmeldung erhalten Sie ein Konfigurationsprofil für iPhone, iPad oder Mac. "
            "Es enthält ein neues, nur für dieses Gerät erzeugtes App-Passwort. Ihr eigentliches "
            "Passwort wird nicht im Profil gespeichert."
        ),
        "btn_all": "Mail, Kalender und Kontakte",
        "btn_mail": "Nur E-Mail",
        "step1": "Öffnen Sie diese Seite in Safari auf dem Gerät, das eingerichtet werden soll.",
        "step2": "Melden Sie sich an, bestätigen Sie den Zugriff und erlauben Sie den Download.",
        "step3": (
            "iPhone/iPad: Einstellungen &gt; &bdquo;Profil geladen&ldquo; &gt; Installieren.<br>"
            "Mac: Profil öffnen, dann Systemeinstellungen &gt; Allgemein &gt; Geräteverwaltung "
            "(bzw. Datenschutz &amp; Sicherheit &gt; Profile) &gt; Installieren."
        ),
        "footer": (
            "Das App-Passwort erscheint in Ihrem Konto unter den App-Passwörtern und kann dort "
            "jederzeit widerrufen werden."
        ),
        "error_title": "Fehler",
        "error_heading": "Das hat nicht geklappt",
        "retry": "Erneut versuchen",
        "unknown": "unbekannt",
        "device_other": "Apple-Gerät",
        "app_password_label": "Apple-Profil",
        "mail_name": "E-Mail ({email})",
        "mail_desc": "E-Mail-Konto {email}",
        "cal_name": "Kalender ({email})",
        "cal_desc": "CalDAV-Konto {email}",
        "card_name": "Kontakte ({email})",
        "card_desc": "CardDAV-Konto {email}",
        "profile_desc_mail": "Richtet E-Mail ein.",
        "profile_desc_all": "Richtet E-Mail, Kalender und Kontakte ein.",
        "err_unreachable": "Stalwart ist nicht erreichbar ({detail}).",
        "err_token": "Token-Austausch fehlgeschlagen (HTTP {http}, {detail}).",
        "err_session": "JMAP-Session konnte nicht gelesen werden (HTTP {http}).",
        "err_jmap": "JMAP-Aufruf fehlgeschlagen (HTTP {http}, {detail}).",
        "err_no_account": "In der JMAP-Session wurde keine Account-ID gefunden.",
        "err_no_user": "Der Benutzername konnte nicht ermittelt werden.",
        "err_unexpected": "Unerwartete Antwort beim Anlegen des App-Passworts.",
        "err_app_password": "Das App-Passwort wurde abgelehnt ({type}: {detail}).",
        "err_quota": (
            "Für Ihr Konto sind bereits so viele App-Passwörter angelegt, wie der Mailserver "
            "erlaubt."
        ),
        "hint_quota": (
            "Jeder Profil-Download legt ein neues App-Passwort an. Löschen Sie im Self-Service "
            "nicht mehr benötigte Einträge, z. B. alte \"{label} ...\" von Geräten, die Sie "
            "ersetzt oder neu eingerichtet haben, und versuchen Sie es dann erneut. Achtung: Ein "
            "Gerät, das ein gelöschtes App-Passwort noch verwendet, kann sich danach nicht mehr "
            "anmelden."
        ),
        "link_quota": "App-Passwörter im Self-Service verwalten",
        "hint_full_scope": (
            "OAUTH_SCOPE enthält nicht {scope}. Ab Stalwart 1.0 darf ein eingeschränkter Token "
            "keine Rechte weitergeben, die er selbst nicht hat."
        ),
        "err_invalid_scope": (
            "Der Mailserver hat die angeforderten Berechtigungen abgelehnt (invalid_scope)."
        ),
        "hint_invalid_scope": (
            "Der OAuth-Client dieses Dienstes ist in Stalwart nicht für alle benötigten Scopes "
            "freigegeben. Bitte wenden Sie sich an Ihren Administrator."
        ),
        "err_denied": "Der Zugriff wurde abgelehnt.",
        "err_aborted": "Die Anmeldung wurde abgebrochen ({detail}).",
        "err_bad_request": "Ungültiger Aufruf (code oder state fehlt).",
        "err_expired": (
            "Die Anmeldung ist abgelaufen oder wurde in einem anderen Browser gestartet. Bitte "
            "versuchen Sie es erneut."
        ),
        "err_bad_state": "Ungültiger state-Parameter.",
        "err_bad_iss": "Ungültiger Aussteller (iss) in der Antwort.",
        "err_rate_limit": "Zu viele Anfragen. Bitte versuchen Sie es später erneut.",
        "err_not_found": "Seite nicht gefunden.",
        "err_internal": "Interner Fehler.",
    },
}


def pick_lang(accept_language):
    if UI_LANG in LANGS:
        return UI_LANG
    best, best_q = "en", -1.0
    for part in (accept_language or "").split(","):
        tag, _, params = part.strip().partition(";")
        primary = tag.strip().lower().split("-")[0]
        if primary not in LANGS:
            continue
        q = 1.0
        params = params.strip()
        if params.startswith("q="):
            try:
                q = float(params[2:])
            except ValueError:
                q = 0.0
        if q > best_q:
            best, best_q = primary, q
    return best


def t(lang, key, **params):
    text = TEXTS[lang][key]
    return text.format(**params) if params else text


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------


class ServiceError(Exception):
    """Error shown to the user. Holds text keys; rendered in the user's language.

    Parameters must not contain secrets.
    """

    def __init__(self, key, status=502, hint=None, link=None, **params):
        super().__init__(key)
        self.key = key
        self.status = status
        self.hint = hint  # optional (key, params) for an extra explanation
        self.link = link  # optional (url, label key) for a secondary link
        self.params = params

    def render(self, lang):
        message = t(lang, self.key, **self.params)
        hint = None
        if self.hint:
            hint = t(lang, self.hint[0], label=t(lang, "app_password_label"), **self.hint[1])
        link = (self.link[0], t(lang, self.link[1])) if self.link else None
        return message, hint, link


def b64u(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def b64u_dec(text):
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def sign_state(payload):
    body = b64u(json.dumps(payload, separators=(",", ":")).encode())
    mac = b64u(hmac.new(SESSION_KEY, body.encode(), hashlib.sha256).digest())
    return f"{body}.{mac}"


def verify_state(cookie_value):
    try:
        body, mac = cookie_value.split(".", 1)
    except ValueError:
        return None
    expected = b64u(hmac.new(SESSION_KEY, body.encode(), hashlib.sha256).digest())
    if not hmac.compare_digest(mac, expected):
        return None
    try:
        payload = json.loads(b64u_dec(body))
    except (ValueError, json.JSONDecodeError):
        return None
    if not isinstance(payload, dict):
        return None
    if time.time() - payload.get("ts", 0) > STATE_MAX_AGE:
        return None
    return payload


def http_request(method, url, *, data=None, headers=None):
    """Perform an HTTP request, return (status, parsed JSON or None, raw text)."""
    req = urllib.request.Request(url, data=data, method=method, headers=headers or {})
    req.add_header("Accept", "application/json")
    req.add_header("User-Agent", "stalwart-apple-profile/1.1")
    try:
        with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as resp:
            raw = resp.read().decode("utf-8", "replace")
            status = resp.status
    except urllib.error.HTTPError as err:
        raw = err.read().decode("utf-8", "replace")
        status = err.code
    except (urllib.error.URLError, TimeoutError, OSError) as err:
        raise ServiceError("err_unreachable", detail=type(err).__name__)
    try:
        parsed = json.loads(raw) if raw else None
    except json.JSONDecodeError:
        parsed = None
    return status, parsed, raw


def detect_device(user_agent, lang):
    ua = user_agent or ""
    if "iPhone" in ua:
        return "iPhone"
    if "iPad" in ua:
        return "iPad"
    if "Macintosh" in ua or "Mac OS X" in ua:
        # iPadOS Safari reports itself as Macintosh by default
        return "Mac/iPad"
    return t(lang, "device_other")


def safe_filename(text):
    cleaned = re.sub(r"[^A-Za-z0-9._@-]+", "_", text).strip("._")
    return cleaned or "profile"


def identifier_part(text):
    cleaned = re.sub(r"[^A-Za-z0-9.-]+", "-", text.lower()).strip(".-")
    return cleaned or "user"


# --------------------------------------------------------------------------
# Stalwart: OAuth + JMAP
# --------------------------------------------------------------------------


def exchange_code(code, verifier):
    form = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": REDIRECT_URI,
        "client_id": CLIENT_ID,
        "code_verifier": verifier,
    }
    if CLIENT_SECRET:
        form["client_secret"] = CLIENT_SECRET
    status, data, _ = http_request(
        "POST",
        TOKEN_URL,
        data=urllib.parse.urlencode(form).encode(),
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    if status != 200 or not isinstance(data, dict) or "access_token" not in data:
        error = data.get("error") if isinstance(data, dict) else None
        log.warning("token exchange failed: http=%s error=%s", status, error)
        raise ServiceError("err_token", detail=error or "-", http=status)
    return data["access_token"]


def revoke_token(token):
    """Best effort RFC 7009 revocation. Stalwart >= 1.0 deletes the grant behind the token."""
    form = {"token": token, "client_id": CLIENT_ID}
    if CLIENT_SECRET:
        form["client_secret"] = CLIENT_SECRET
    try:
        status, data, _ = http_request(
            "POST",
            REVOKE_URL,
            data=urllib.parse.urlencode(form).encode(),
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
    except ServiceError:
        log.warning("token revocation failed: stalwart unreachable")
        return
    if status != 200:
        error = data.get("error") if isinstance(data, dict) else None
        log.warning("token revocation failed: http=%s error=%s", status, error)


def jmap_session(token):
    status, data, _ = http_request("GET", SESSION_URL, headers={"Authorization": f"Bearer {token}"})
    if status != 200 or not isinstance(data, dict):
        log.warning("jmap session failed: http=%s", status)
        raise ServiceError("err_session", http=status)
    return data


def jmap_call(session, token, using, method_calls):
    api_url = session.get("apiUrl") or f"{STALWART_URL}/jmap/"
    body = json.dumps({"using": using, "methodCalls": method_calls}).encode()
    status, data, _ = http_request(
        "POST",
        api_url,
        data=body,
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
    )
    if status != 200 or not isinstance(data, dict):
        detail = data.get("type") if isinstance(data, dict) else None
        log.warning("jmap call failed: http=%s type=%s", status, detail)
        raise ServiceError("err_jmap", detail=detail or "-", http=status)
    return data.get("methodResponses", [])


def read_identity(session, token):
    """Return (email, display_name) or (None, None)."""
    account_id = session.get("primaryAccounts", {}).get("urn:ietf:params:jmap:submission")
    if not account_id:
        return None, None
    try:
        responses = jmap_call(
            session,
            token,
            ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:submission"],
            [["Identity/get", {"accountId": account_id, "ids": None}, "i"]],
        )
    except ServiceError:
        return None, None
    for name, args, _ in responses:
        if name == "Identity/get":
            identities = args.get("list") or []
            username = (session.get("username") or "").lower()
            preferred = [i for i in identities if (i.get("email") or "").lower() == username]
            chosen = (preferred or identities or [None])[0]
            if chosen:
                return chosen.get("email"), (chosen.get("name") or "").strip() or None
    return None, None


def create_app_password(session, token, description):
    account_id = session.get("primaryAccounts", {}).get("urn:stalwart:jmap")
    if not account_id:
        # Fallback: the user's own account is the primary mail account
        account_id = session.get("primaryAccounts", {}).get("urn:ietf:params:jmap:mail")
    if not account_id:
        raise ServiceError("err_no_account")

    create = {"description": description, "allowedIps": {}}
    if APP_PASSWORD_DISABLE:
        create["permissions"] = {
            "@type": "Disable",
            "permissions": {name: True for name in APP_PASSWORD_DISABLE},
        }
    else:
        create["permissions"] = {"@type": "Inherit"}
    if APP_PASSWORD_EXPIRY_DAYS > 0:
        expires = datetime.now(timezone.utc) + timedelta(days=APP_PASSWORD_EXPIRY_DAYS)
        create["expiresAt"] = expires.strftime("%Y-%m-%dT%H:%M:%SZ")

    responses = jmap_call(
        session,
        token,
        ["urn:ietf:params:jmap:core", "urn:stalwart:jmap"],
        [["x:AppPassword/set", {"accountId": account_id, "create": {"p": create}}, "c"]],
    )
    for name, args, _ in responses:
        if name == "error":
            log.warning("app password: method error type=%s", args.get("type"))
            raise app_password_error(args.get("type"), args.get("description"))
        if name == "x:AppPassword/set":
            created = (args.get("created") or {}).get("p")
            if created and created.get("secret"):
                return created.get("id"), created["secret"]
            failed = (args.get("notCreated") or {}).get("p") or {}
            log.warning(
                "app password not created: type=%s description=%s",
                failed.get("type"),
                failed.get("description"),
            )
            raise app_password_error(failed.get("type"), failed.get("description"))
    raise ServiceError("err_unexpected")


def app_password_error(err_type, description):
    """ServiceError for a rejected x:AppPassword/set, with guidance for known causes."""
    if err_type == "overQuota":
        return ServiceError(
            "err_quota",
            status=409,
            hint=("hint_quota", {}),
            link=(SELF_SERVICE_URL, "link_quota"),
        )
    hint = None
    if err_type == "forbidden" and SCOPE_FULL not in OAUTH_SCOPE.split():
        log.warning("app password forbidden and OAUTH_SCOPE lacks %s", SCOPE_FULL)
        hint = ("hint_full_scope", {"scope": SCOPE_FULL})
    return ServiceError(
        "err_app_password", hint=hint, type=err_type or "-", detail=description or "-"
    )


# --------------------------------------------------------------------------
# Profile generation
# --------------------------------------------------------------------------


def build_profile(lang, email, login, display_name, password, only_email):
    base_id = f"{PROFILE_ID_PREFIX}.{identifier_part(email)}"
    # Stable identifiers/UUIDs per user: reinstalling replaces the existing profile.
    ns = uuid.uuid5(uuid.NAMESPACE_DNS, base_id)

    def payload_uuid(kind):
        return str(uuid.uuid5(ns, kind)).upper()

    content = []

    mail = {
        "PayloadType": "com.apple.mail.managed",
        "PayloadVersion": 1,
        "PayloadIdentifier": f"{base_id}.mail",
        "PayloadUUID": payload_uuid("mail"),
        "PayloadDisplayName": t(lang, "mail_name", email=email),
        "PayloadDescription": t(lang, "mail_desc", email=email),
        "EmailAccountDescription": email,
        "EmailAccountName": display_name,
        "EmailAccountType": "EmailTypeIMAP",
        "EmailAddress": email,
        "IncomingMailServerAuthentication": "EmailAuthPassword",
        "IncomingMailServerHostName": MAIL_HOST,
        "IncomingMailServerPortNumber": IMAP_PORT,
        "IncomingMailServerUseSSL": IMAP_SSL,
        "IncomingMailServerUsername": login,
        "OutgoingMailServerAuthentication": "EmailAuthPassword",
        "OutgoingMailServerHostName": MAIL_HOST,
        "OutgoingMailServerPortNumber": SMTP_PORT,
        "OutgoingMailServerUseSSL": SMTP_SSL,
        "OutgoingMailServerUsername": login,
        "OutgoingPasswordSameAsIncomingPassword": True,
        "PreventAppSheet": False,
        "PreventMove": False,
        "SMIMEEnabled": False,
        "allowMailDrop": True,
    }
    if password:
        mail["IncomingPassword"] = password
        mail["OutgoingPassword"] = password
    content.append(mail)

    if not only_email:
        caldav = {
            "PayloadType": "com.apple.caldav.account",
            "PayloadVersion": 1,
            "PayloadIdentifier": f"{base_id}.caldav",
            "PayloadUUID": payload_uuid("caldav"),
            "PayloadDisplayName": t(lang, "cal_name", email=email),
            "PayloadDescription": t(lang, "cal_desc", email=email),
            "CalDAVAccountDescription": email,
            "CalDAVHostName": DAV_HOST,
            "CalDAVPort": DAV_PORT,
            "CalDAVUseSSL": True,
            "CalDAVUsername": login,
        }
        carddav = {
            "PayloadType": "com.apple.carddav.account",
            "PayloadVersion": 1,
            "PayloadIdentifier": f"{base_id}.carddav",
            "PayloadUUID": payload_uuid("carddav"),
            "PayloadDisplayName": t(lang, "card_name", email=email),
            "PayloadDescription": t(lang, "card_desc", email=email),
            "CardDAVAccountDescription": email,
            "CardDAVHostName": DAV_HOST,
            "CardDAVPort": DAV_PORT,
            "CardDAVUseSSL": True,
            "CardDAVUsername": login,
        }
        if DAV_SET_PRINCIPAL_URL:
            quoted = urllib.parse.quote(login, safe="@.")
            caldav["CalDAVPrincipalURL"] = f"/dav/cal/{quoted}/"
            carddav["CardDAVPrincipalURL"] = f"/dav/card/{quoted}/"
        if password:
            caldav["CalDAVPassword"] = password
            carddav["CardDAVPassword"] = password
        content.extend([caldav, carddav])

    profile = {
        "PayloadContent": content,
        "PayloadDisplayName": email,
        "PayloadDescription": t(lang, "profile_desc_mail" if only_email else "profile_desc_all"),
        "PayloadIdentifier": base_id,
        "PayloadRemovalDisallowed": False,
        "PayloadType": "Configuration",
        "PayloadUUID": payload_uuid("profile"),
        "PayloadVersion": 1,
    }
    if PROFILE_ORG:
        profile["PayloadOrganization"] = PROFILE_ORG
    return plistlib.dumps(profile, fmt=plistlib.FMT_XML, sort_keys=True)


# --------------------------------------------------------------------------
# HTML
# --------------------------------------------------------------------------

PAGE_CSS = """
:root{--bg:#f6f7f9;--fg:#1d2330;--muted:#5b6475;--card:#fff;--line:#dfe3ea;--accent:#c4521c;--accent-fg:#fff}
@media (prefers-color-scheme:dark){:root{--bg:#14171c;--fg:#e8ebf0;--muted:#a3abb8;--card:#1d2128;--line:#2e343e;--accent:#e2733b;--accent-fg:#14171c}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);
font:16px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif}
main{max-width:560px;margin:0 auto;padding:40px 16px}
h1{font-size:1.45rem;line-height:1.25;margin:0 0 12px}
p{color:var(--muted);margin:0 0 16px}
.card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:20px;margin:20px 0}
a.btn{display:block;text-align:center;text-decoration:none;font-weight:600;border-radius:10px;
padding:14px 16px;margin:10px 0;background:var(--accent);color:var(--accent-fg)}
a.btn.secondary{background:transparent;color:var(--fg);border:1px solid var(--line)}
ol{color:var(--muted);padding-left:20px;margin:0}li{margin:4px 0}
small{color:var(--muted);display:block;margin-top:24px}
"""


def page(lang, title, body_html):
    return f"""<!doctype html>
<html lang="{lang}"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{html.escape(title)}</title><style>{PAGE_CSS}</style></head>
<body><main>{body_html}</main></body></html>""".encode("utf-8")


def landing_page(lang):
    title = PAGE_TITLE or t(lang, "title")
    return page(
        lang,
        title,
        f"""
<h1>{html.escape(title)}</h1>
<p>{html.escape(t(lang, "intro"))}</p>
<div class="card">
<a class="btn" href="/start">{html.escape(t(lang, "btn_all"))}</a>
<a class="btn secondary" href="/start?only_email=1">{html.escape(t(lang, "btn_mail"))}</a>
</div>
<div class="card">
<ol>
<li>{html.escape(t(lang, "step1"))}</li>
<li>{html.escape(t(lang, "step2"))}</li>
<li>{t(lang, "step3")}</li>
</ol>
</div>
<small>{html.escape(t(lang, "footer"))}</small>
""",
    )


def error_page(lang, message, hint=None, link=None):
    hint_html = f"<p>{html.escape(hint)}</p>" if hint else ""
    link_html = ""
    if link:
        url, label = link
        link_html = (
            f'<p><a href="{html.escape(url, quote=True)}" target="_blank" '
            f'rel="noopener noreferrer">{html.escape(label)}</a></p>'
        )
    return page(
        lang,
        t(lang, "error_title"),
        f"""
<h1>{html.escape(t(lang, "error_heading"))}</h1>
<div class="card"><p>{html.escape(message)}</p>
{hint_html}{link_html}
<a class="btn" href="/">{html.escape(t(lang, "retry"))}</a></div>
""",
    )


# --------------------------------------------------------------------------
# Rate limiting (in-process, per IP, sliding window)
# --------------------------------------------------------------------------


class RateLimiter:
    def __init__(self, max_hits, window):
        self.max_hits = max_hits
        self.window = window
        self._hits = {}
        self._lock = threading.Lock()

    def allow(self, key):
        if self.max_hits <= 0:
            return True
        now = time.monotonic()
        cutoff = now - self.window
        with self._lock:
            hits = [t for t in self._hits.get(key, ()) if t > cutoff]
            # Opportunistic cleanup of stale keys to bound memory.
            if len(self._hits) > 4096:
                self._hits = {
                    k: [t for t in v if t > cutoff]
                    for k, v in self._hits.items()
                    if any(t > cutoff for t in v)
                }
            if len(hits) >= self.max_hits:
                self._hits[key] = hits
                return False
            hits.append(now)
            self._hits[key] = hits
            return True


rate_limiter = RateLimiter(RATE_LIMIT_MAX, RATE_LIMIT_WINDOW)


# --------------------------------------------------------------------------
# HTTP handler
# --------------------------------------------------------------------------


class Handler(BaseHTTPRequestHandler):
    server_version = "apple-profile"
    sys_version = ""

    # --- utilities ---

    def client_ip(self):
        if TRUSTED_PROXIES > 0:
            hops = [h.strip() for h in self.headers.get("X-Forwarded-For", "").split(",") if h.strip()]
            # Each trusted proxy appends the address it received the request from; entries
            # left of those were sent by the client and can be forged.
            if len(hops) >= TRUSTED_PROXIES:
                return hops[-TRUSTED_PROXIES]
        return self.client_address[0]

    def lang(self):
        return pick_lang(self.headers.get("Accept-Language"))

    def log_message(self, fmt, *args):
        # Access log without query strings (they contain OAuth codes)
        path = self.path.split("?", 1)[0]
        log.info("%s %s %s %s", self.client_ip(), self.command, path, args[1] if len(args) > 1 else "-")

    def send_common_headers(self):
        self.send_header("Cache-Control", "no-store, max-age=0")
        self.send_header("Pragma", "no-cache")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("X-Robots-Tag", "noindex, nofollow")
        self.send_header("Vary", "Accept-Language")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'; "
            "frame-ancestors 'none'",
        )

    def send_html(self, status, body, extra_headers=None):
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_common_headers()
        for key, value in extra_headers or []:
            self.send_header(key, value)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def redirect(self, location, extra_headers=None):
        self.send_response(302)
        self.send_header("Location", location)
        self.send_header("Content-Length", "0")
        self.send_common_headers()
        for key, value in extra_headers or []:
            self.send_header(key, value)
        self.end_headers()

    def get_cookie(self, name):
        raw = self.headers.get("Cookie", "")
        for part in raw.split(";"):
            key, _, value = part.strip().partition("=")
            if key == name:
                return value
        return None

    @staticmethod
    def clear_cookie_header():
        return ("Set-Cookie", f"{COOKIE_NAME}=; Path=/; Max-Age=0; Secure; HttpOnly; SameSite=Lax")

    # --- routes ---

    def do_HEAD(self):
        self.do_GET()

    def method_not_allowed(self):
        self.send_response(405)
        self.send_header("Allow", "GET, HEAD")
        self.send_header("Content-Length", "0")
        self.send_common_headers()
        self.end_headers()

    do_POST = do_PUT = do_DELETE = do_PATCH = do_OPTIONS = method_not_allowed

    def send_text(self, body):
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_common_headers()
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def do_GET(self):
        parsed = urllib.parse.urlsplit(self.path)
        query = urllib.parse.parse_qs(parsed.query)
        lang = self.lang()
        try:
            if parsed.path == "/":
                self.send_html(200, landing_page(lang))
            elif parsed.path == "/start":
                self.enforce_rate_limit()
                self.handle_start(query)
            elif parsed.path == "/callback":
                self.enforce_rate_limit()
                self.handle_callback(query, lang)
            elif parsed.path == "/healthz":
                self.send_text(b"ok")
            elif parsed.path == "/robots.txt":
                self.send_text(b"User-agent: *\nDisallow: /\n")
            else:
                self.send_html(404, error_page(lang, t(lang, "err_not_found")))
        except ServiceError as err:
            self.send_html(
                err.status,
                error_page(lang, *err.render(lang)),
                [self.clear_cookie_header()],
            )
        except Exception:  # noqa: BLE001
            log.exception("unexpected error on %s", parsed.path)
            self.send_html(
                500, error_page(lang, t(lang, "err_internal")), [self.clear_cookie_header()]
            )

    def enforce_rate_limit(self):
        if not rate_limiter.allow(self.client_ip()):
            log.warning("rate limit hit for %s on %s", self.client_ip(), self.path.split("?", 1)[0])
            raise ServiceError("err_rate_limit", 429)

    def handle_start(self, query):
        only_email = query.get("only_email", ["0"])[0] in ("1", "true", "yes")
        state = secrets.token_urlsafe(24)
        verifier = secrets.token_urlsafe(48)  # 64 chars, within RFC 7636 limits
        challenge = b64u(hashlib.sha256(verifier.encode("ascii")).digest())
        cookie = sign_state({"s": state, "v": verifier, "e": only_email, "ts": int(time.time())})
        params = {
            "response_type": "code",
            "client_id": CLIENT_ID,
            "redirect_uri": REDIRECT_URI,
            "scope": OAUTH_SCOPE,
            "state": state,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        }
        self.redirect(
            f"{AUTHORIZE_URL}?{urllib.parse.urlencode(params)}",
            [
                (
                    "Set-Cookie",
                    f"{COOKIE_NAME}={cookie}; Path=/; Max-Age={STATE_MAX_AGE}; "
                    "Secure; HttpOnly; SameSite=Lax",
                )
            ],
        )

    def handle_callback(self, query, lang):
        if "error" in query:
            error = query["error"][0]
            if error == "invalid_scope":
                log.warning("authorization failed: invalid_scope (OAuthClient scopes vs OAUTH_SCOPE)")
                raise ServiceError("err_invalid_scope", 400, hint=("hint_invalid_scope", {}))
            if error == "access_denied":
                raise ServiceError("err_denied", 400)
            raise ServiceError("err_aborted", 400, detail=error[:64])
        code = query.get("code", [""])[0]
        state = query.get("state", [""])[0]
        if not code or not state:
            raise ServiceError("err_bad_request", 400)

        cookie_value = self.get_cookie(COOKIE_NAME)
        payload = verify_state(cookie_value) if cookie_value else None
        if not payload:
            raise ServiceError("err_expired", 400)
        if not hmac.compare_digest(payload.get("s", ""), state):
            raise ServiceError("err_bad_state", 400)

        # RFC 9207: the issuer in the callback must match our authorization server.
        # A mismatch indicates a mix-up attack, so refuse rather than continue.
        iss = query.get("iss", [""])[0]
        if iss and iss.rstrip("/") != STALWART_URL:
            log.warning("issuer mismatch: callback iss=%s expected=%s", iss, STALWART_URL)
            raise ServiceError("err_bad_iss", 400)

        only_email = bool(payload.get("e"))
        token = exchange_code(code, payload["v"])
        try:
            session = jmap_session(token)
            username = session.get("username") or ""
            email, display_name = read_identity(session, token)
            email = email or username
            if not email:
                raise ServiceError("err_no_user")
            login = username if "@" in username else email
            display_name = display_name or email

            device = detect_device(self.headers.get("User-Agent"), lang)
            stamp = datetime.now().astimezone().strftime("%Y-%m-%d %H:%M")
            description = f"{t(lang, 'app_password_label')} {device} {stamp}"
            credential_id, secret = create_app_password(session, token, description)
        finally:
            if REVOKE_TOKEN:
                revoke_token(token)
            del token

        body = build_profile(lang, email, login, display_name, secret, only_email)
        del secret
        log.info(
            "profile issued: user=%s device=%s credential_id=%s only_email=%s ip=%s",
            login,
            device,
            credential_id,
            only_email,
            self.client_ip(),
        )

        filename = safe_filename(email) + ".mobileconfig"
        self.send_response(200)
        self.send_header("Content-Type", "application/x-apple-aspen-config")
        self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
        self.send_header("Content-Length", str(len(body)))
        self.send_common_headers()
        self.send_header(*self.clear_cookie_header())
        self.end_headers()
        self.wfile.write(body)


def main():
    if not PUBLIC_URL.startswith("https://"):
        log.warning("PUBLIC_URL is not HTTPS; the __Host- state cookie requires HTTPS")
    if _random_secret:
        log.warning("SESSION_SECRET not set; using a random key (pending logins break on restart)")
    log.info(
        "starting on %s:%s, stalwart=%s, redirect_uri=%s, client_id=%s, scope=%s, revoke=%s, "
        "mail_host=%s, dav_host=%s, profile_id_prefix=%s, trusted_proxies=%s, "
        "app password disable=%s",
        LISTEN_HOST,
        LISTEN_PORT,
        STALWART_URL,
        REDIRECT_URI,
        CLIENT_ID,
        OAUTH_SCOPE,
        REVOKE_TOKEN,
        MAIL_HOST,
        DAV_HOST,
        PROFILE_ID_PREFIX,
        TRUSTED_PROXIES,
        ",".join(APP_PASSWORD_DISABLE) or "-",
    )
    server = ThreadingHTTPServer((LISTEN_HOST, LISTEN_PORT), Handler)
    server.daemon_threads = True
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
