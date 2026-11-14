#!/usr/bin/env bash
# Show or change Stalwart OAuth clients and OIDC provider settings via JMAP.
# Written for Stalwart >= 1.1 (OAuth client scopes, client metadata documents).
#
# Authentication (one of):
#   STALWART_TOKEN=API_xxx            API key of an admin account (works with MFA)
#   STALWART_ADMIN=admin@example.org  login + password (fails with HTTP 402 if MFA is enabled)
#
# Usage:
#   STALWART_TOKEN=ask ./stalwart-oauth-settings.sh show
#   STALWART_TOKEN=ask ./stalwart-oauth-settings.sh add-client apple-profile \
#       mail,contacts,calendars,full https://profile.example.org/callback
#   STALWART_TOKEN=ask ./stalwart-oauth-settings.sh set-scopes <id> mail,contacts,calendars,full
#   STALWART_TOKEN=ask ./stalwart-oauth-settings.sh del-client <id>
#   STALWART_TOKEN=ask ./stalwart-oauth-settings.sh set-cimd disabled|sameDomain|any
#
# <id> is the registry id printed by `show`, not the clientId.
# Scopes: mail, contacts, calendars, files, security, settings, full
# (only a superuser may allow "full").
#
# STALWART_TOKEN=ask prompts for the API key so it does not end up in the shell history.
# Requires: curl, jq.
set -euo pipefail

usage() {
  cat >&2 <<USAGE
Usage:
  $0 show
  $0 add-client <clientId> <scopes> <redirectUri> [redirectUri ...]
  $0 set-scopes <id> <scopes>
  $0 del-client <id>
  $0 set-cimd <disabled|sameDomain|any>

  <id>      registry id shown by 'show', not the clientId
  <scopes>  comma-separated: mail,contacts,calendars,files,security,settings,full
USAGE
  exit 1
}

case "${1:-show}" in
  show|add-client|set-scopes|del-client|set-cimd) ;;
  *) usage ;;
esac

URL="${STALWART_URL:?Set STALWART_URL, e.g. https://mail.example.org}"
URL="${URL%/}"

if [[ -n "${STALWART_TOKEN:-}" ]]; then
  if [[ "$STALWART_TOKEN" == "ask" ]]; then
    read -rsp "API key: " STALWART_TOKEN
    echo
  fi
  CURL_AUTH=(-H "Authorization: Bearer ${STALWART_TOKEN}")
elif [[ -n "${STALWART_ADMIN:-}" ]]; then
  if [[ -z "${STALWART_PASSWORD:-}" ]]; then
    read -rsp "Password for ${STALWART_ADMIN}: " STALWART_PASSWORD
    echo
  fi
  CURL_AUTH=(-u "${STALWART_ADMIN}:${STALWART_PASSWORD}")
else
  echo "Set STALWART_TOKEN (API key, recommended) or STALWART_ADMIN" >&2
  exit 1
fi

http_get() {
  local out status
  out=$(curl -sS -w '\n%{http_code}' "${CURL_AUTH[@]}" "$1")
  status=${out##*$'\n'}
  out=${out%$'\n'*}
  if [[ "$status" != "200" ]]; then
    case "$status" in
      401) echo "HTTP 401: login failed (wrong credentials or API key)" >&2 ;;
      402) echo "HTTP 402: MFA required - use an API key via STALWART_TOKEN" >&2 ;;
      403) echo "HTTP 403: forbidden" >&2 ;;
      *)   echo "HTTP $status" >&2 ;;
    esac
    [[ -n "$out" ]] && echo "$out" >&2
    exit 1
  fi
  printf '%s' "$out"
}

SESSION=$(http_get "$URL/jmap/session")
API=$(jq -r '.apiUrl' <<<"$SESSION")
ACC=$(jq -r '.primaryAccounts["urn:stalwart:jmap"] // .primaryAccounts["urn:ietf:params:jmap:core"] // empty' <<<"$SESSION")
echo "Authenticated as: $(jq -r '.username' <<<"$SESSION")" >&2
if [[ -z "$ACC" ]]; then
  echo "No account id found in JMAP session" >&2
  exit 1
fi

call() {
  local out status
  out=$(curl -sS -w '\n%{http_code}' "${CURL_AUTH[@]}" -H 'Content-Type: application/json' "$API" --data "$1")
  status=${out##*$'\n'}
  out=${out%$'\n'*}
  if [[ "$status" != "200" ]]; then
    echo "JMAP request failed: HTTP $status" >&2
    echo "$out" >&2
    exit 1
  fi
  printf '%s' "$out"
}

# "mail,contacts" -> {"mail":true,"contacts":true}
scopes_json() {
  local s out='{}'
  local -a list
  IFS=',' read -ra list <<<"$1"
  for s in "${list[@]}"; do
    case "$s" in
      mail|contacts|calendars|files|security|settings|full) ;;
      *) echo "Unknown scope: $s" >&2; exit 1 ;;
    esac
    out=$(jq --arg s "$s" '. + {($s): true}' <<<"$out")
  done
  printf '%s' "$out"
}

CLIENT_PROPS='["clientId", "description", "redirectUris", "scopes", "grantTypes", "expiresAt"]'

case "${1:-show}" in
  show)
    REQ=$(jq -n --arg a "$ACC" --argjson props "$CLIENT_PROPS" '{
      using: ["urn:ietf:params:jmap:core", "urn:stalwart:jmap"],
      methodCalls: [
        ["x:OidcProvider/get", {accountId: $a, ids: ["singleton"],
          properties: ["clientMetadataDocuments", "accessTokenExpiry", "authCodeExpiry"]}, "p"],
        ["x:OAuthClient/get", {accountId: $a, ids: null, properties: $props}, "c"]
      ]}')
    call "$REQ" | jq '
      .methodResponses[] |
      if .[0] == "x:OidcProvider/get" then {OidcProvider: .[1].list}
      elif .[0] == "x:OAuthClient/get" then {OAuthClients: .[1].list}
      else {error: .[1]} end'
    ;;
  set-cimd)
    # Client ID Metadata Documents: disabled (default) | sameDomain | any
    VALUE="${2:?disabled, sameDomain or any}"
    case "$VALUE" in
      disabled|sameDomain|any) ;;
      *) echo "Value must be disabled, sameDomain or any" >&2; exit 1 ;;
    esac
    REQ=$(jq -n --arg a "$ACC" --arg v "$VALUE" '{
      using: ["urn:ietf:params:jmap:core", "urn:stalwart:jmap"],
      methodCalls: [
        ["x:OidcProvider/set", {accountId: $a, update: {singleton: {clientMetadataDocuments: $v}}}, "s"],
        ["x:OidcProvider/get", {accountId: $a, ids: ["singleton"],
          properties: ["clientMetadataDocuments"]}, "g"]
      ]}')
    call "$REQ" | jq '.methodResponses'
    ;;
  add-client)
    # add-client <clientId> <scopes> <redirectUri> [redirectUri ...]
    CID="${2:?client id}"
    SCOPES=$(scopes_json "${3:?scopes, e.g. mail,contacts,calendars,full}")
    shift 3
    if [[ $# -lt 1 ]]; then
      echo "At least one redirect URI is required" >&2
      exit 1
    fi
    URIS='{}'
    for u in "$@"; do
      URIS=$(jq --arg u "$u" '. + {($u): true}' <<<"$URIS")
    done
    # Public client: no secret, PKCE. grantTypes default to authorizationCode + refreshToken.
    REQ=$(jq -n --arg a "$ACC" --arg c "$CID" --argjson uris "$URIS" --argjson sc "$SCOPES" \
      --argjson props "$CLIENT_PROPS" '{
      using: ["urn:ietf:params:jmap:core", "urn:stalwart:jmap"],
      methodCalls: [
        ["x:OAuthClient/set", {accountId: $a, create: {new: {
          clientId: $c, description: $c, redirectUris: $uris, scopes: $sc }}}, "s"],
        ["x:OAuthClient/get", {accountId: $a, ids: null, properties: $props}, "g"]
      ]}')
    call "$REQ" | jq '.methodResponses'
    ;;
  set-scopes)
    # set-scopes <id> <scopes>   replaces the allowed scopes of an existing client
    OID="${2:?object id from show}"
    SCOPES=$(scopes_json "${3:?scopes, e.g. mail,contacts,calendars,full}")
    REQ=$(jq -n --arg a "$ACC" --arg o "$OID" --argjson sc "$SCOPES" --argjson props "$CLIENT_PROPS" '{
      using: ["urn:ietf:params:jmap:core", "urn:stalwart:jmap"],
      methodCalls: [
        ["x:OAuthClient/set", {accountId: $a, update: {($o): {scopes: $sc}}}, "s"],
        ["x:OAuthClient/get", {accountId: $a, ids: [$o], properties: $props}, "g"]
      ]}')
    call "$REQ" | jq '.methodResponses'
    ;;
  del-client)
    # del-client <id>  (the registry id from `show`, not the clientId)
    OID="${2:?object id from show}"
    REQ=$(jq -n --arg a "$ACC" --arg o "$OID" '{
      using: ["urn:ietf:params:jmap:core", "urn:stalwart:jmap"],
      methodCalls: [["x:OAuthClient/set", {accountId: $a, destroy: [$o]}, "d"]]}')
    call "$REQ" | jq '.methodResponses'
    ;;
  *)
    usage
    ;;
esac
