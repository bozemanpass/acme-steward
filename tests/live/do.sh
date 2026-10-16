# shellcheck shell=bash
# DigitalOcean DNS API helpers for the live test (sourced).
#
# Tokens are passed to curl through header files so they never appear on
# a command line or in logs. Call do_auth NAME TOKEN once per account,
# then use NAME as the first argument of the other functions.

DO_API=${DO_API:-https://api.digitalocean.com/v2}
do_hdr_dir=${WORK:?}/harness
mkdir -p "$do_hdr_dir" && chmod 0700 "$do_hdr_dir"

do_auth() { # do_auth NAME TOKEN
  umask 077
  printf 'Authorization: Bearer %s\n' "$2" > "$do_hdr_dir/$1.hdr"
}

do_api() { # do_api NAME METHOD PATH [JSON] -> response body
  local out code
  out=$(curl -sS --retry 3 --retry-delay 2 -X "$2" \
    -H "@$do_hdr_dir/$1.hdr" -H 'Content-Type: application/json' \
    ${4:+--data "$4"} -w '\n%{http_code}' "$DO_API$3") || return 1
  code=${out##*$'\n'}
  out=${out%$'\n'*}
  if [[ $code -ge 300 ]]; then
    echo "DigitalOcean API $2 $3 -> $code: $out" >&2
    return 1
  fi
  printf '%s' "$out"
}

do_add_record() { # do_add_record NAME ZONE JSON -> record id
  do_api "$1" POST "/domains/$2/records" "$3" | jq -r .domain_record.id
}

do_delete_record() { # do_delete_record NAME ZONE ID
  do_api "$1" DELETE "/domains/$2/records/$3" >/dev/null
}

do_list_records() { # do_list_records NAME ZONE -> JSON array of all records
  local page=1 out all='[]'
  while :; do
    out=$(do_api "$1" GET "/domains/$2/records?per_page=200&page=$page") || return 1
    all=$(jq -s '.[0] + .[1].domain_records' <(echo "$all") <(echo "$out"))
    [[ $(jq -r '.links.pages.next // empty' <<<"$out") ]] || break
    page=$((page+1))
  done
  echo "$all"
}

# do_delete_matching NAME ZONE JQ_FILTER: delete records selected by a jq
# filter over the record objects; prints what it deletes.
do_delete_matching() {
  local id
  do_list_records "$1" "$2" | jq -r ".[] | select($3) | \"\(.id) \(.type) \(.name)\"" |
  while read -r id rest; do
    echo "deleting $2: $rest"
    do_delete_record "$1" "$2" "$id" || true
  done
}
