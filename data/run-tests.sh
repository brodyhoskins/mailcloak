#!/bin/sh
# End-to-end tests, run inside the postfix container (`make docker-test`
# does this). Mail goes in through Postfix's ports, through mailcloak, and out to
# Mailpit; results are checked with GnuPG and OpenSSL, not with mailcloak.
set -u

MAILPIT=http://mailpit:8025
T=/test W=$(mktemp -d)
pass=0 fail=0

ok()   { pass=$((pass+1)); echo "  ok    $*"; }
bad()  { fail=$((fail+1)); echo "  FAIL  $*"; }
check() { desc=$1; shift; if "$@" >/dev/null 2>&1; then ok "$desc"; else bad "$desc"; fi; }

# send PORT FROM TO... < message
send() {
  port=$1 from=$2; shift 2
  rcpts=""; for r in "$@"; do rcpts="$rcpts --mail-rcpt $r"; done
  curl -fsS "smtp://127.0.0.1:$port" --mail-from "$from" $rcpts --upload-file - 
}

# fetch RCPT: the newest message delivered to envelope recipient RCPT, raw.
# The To header can't tell the copies of a split message apart (they all
# name every recipient), so match the "for <RCPT>" Mailpit stamps into its
# Received header.
fetch() {
  i=0
  while [ $i -lt 60 ]; do
    for id in $(curl -fsS -G "$MAILPIT/api/v1/search" --data-urlencode "query=to:$1" | jq -r '.messages[].ID'); do
      raw=$(curl -fsS "$MAILPIT/api/v1/message/$id/raw")
      if printf '%s' "$raw" | sed -n '1,4p' | grep -q "for <$1>"; then printf '%s\n' "$raw"; return; fi
    done
    i=$((i+1)); sleep 0.5
  done
  return 1
}

has()    { grep -q -- "$2" "$1"; }
hasnt()  { ! grep -q -- "$2" "$1"; }
armor()  { tr -d '\r' < "$1" | sed -n '/-----BEGIN PGP MESSAGE-----/,/-----END PGP MESSAGE-----/p'; }

for i in $(seq 30); do nc -z 127.0.0.1 25 && nc -z 127.0.0.1 587 && break; sleep 0.5; done
curl -fsS -X DELETE "$MAILPIT/api/v1/messages" >/dev/null

# --- 1. Outbound: one message, three recipients, three treatments ---------
echo "outbound: alice → bob (PGP), carol (S/MIME), dave (no key)"
printf 'From: Alice <alice@corp.test>\r\nTo: bob@pgp.test, carol@smime.test, dave@plain.test\r\nSubject: Quarterly numbers\r\nMessage-ID: <q1@corp.test>\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nThe secret number is 42.\r\n' \
  | send 587 alice@corp.test bob@pgp.test carol@smime.test dave@plain.test

fetch bob@pgp.test > $W/bob.eml
check "bob: PGP/MIME, no plaintext" sh -c "grep -q multipart/encrypted $W/bob.eml && ! grep -q 'secret number' $W/bob.eml"
armor $W/bob.eml | gpg --homedir $T/gnupg/bob --batch --status-fd 3 --decrypt 3>$W/bob.status >$W/bob.txt 2>/dev/null
check "bob: gpg decrypts it" has $W/bob.txt "The secret number is 42."
check "bob: gpg verifies alice's signature" has $W/bob.status GOODSIG
check "bob: no S/MIME signature on PGP mail" hasnt $W/bob.txt pkcs7-signature
check "bob: Autocrypt header for alice" has $W/bob.eml "^Autocrypt: addr=alice@corp.test"

fetch carol@smime.test > $W/carol.eml
check "carol: S/MIME enveloped, no plaintext" sh -c "grep -q application/pkcs7-mime $W/carol.eml && ! grep -q 'secret number' $W/carol.eml"
openssl smime -decrypt -in $W/carol.eml -recip $T/smime/carol.crt -inkey $T/smime/carol.key -out $W/carol.inner 2>/dev/null
check "carol: openssl decrypts it" has $W/carol.inner "The secret number is 42."
check "carol: openssl verifies alice's inner signature" openssl smime -verify -in $W/carol.inner -CAfile $T/smime/alice.crt -out /dev/null

fetch dave@plain.test > $W/dave.eml
check "dave: S/MIME signed, survives Postfix" openssl smime -verify -in $W/dave.eml -CAfile $T/smime/alice.crt -out /dev/null

# --- 2. Inbound PGP/MIME made by GnuPG, with an Autocrypt header ----------
echo "inbound: erin → alice, PGP/MIME from gpg, Autocrypt header"
printf 'Content-Type: text/plain; charset=utf-8\r\n\r\nHello Alice, the PGP secret is 7.\r\n' \
  | gpg --homedir $T/gnupg/erin --batch --trust-model always --armor --sign --encrypt -r alice@corp.test > $W/erin.asc 2>/dev/null
keydata=$(gpg --homedir $T/gnupg/erin --export --export-options export-minimal erin@ext.test | base64 | tr -d '\n' | fold -w 76 | sed 's/^/ /')
{
  printf 'From: Erin <erin@ext.test>\r\nTo: alice@corp.test\r\nSubject: PGP inbound\r\nDate: %s\r\n' "$(date -R)"
  printf 'Autocrypt: addr=erin@ext.test; prefer-encrypt=mutual; keydata=\r\n%s\r\n' "$(printf '%s' "$keydata" | sed 's/$/\r/')"
  printf 'MIME-Version: 1.0\r\nContent-Type: multipart/encrypted; protocol="application/pgp-encrypted"; boundary="b1"\r\n\r\n'
  printf -- '--b1\r\nContent-Type: application/pgp-encrypted\r\n\r\nVersion: 1\r\n\r\n--b1\r\nContent-Type: application/octet-stream\r\n\r\n'
  sed 's/$/\r/' $W/erin.asc
  printf -- '--b1--\r\n'
} | send 25 erin@ext.test alice@corp.test

fetch alice@corp.test > $W/alice-pgp.eml
check "alice: decrypted" has $W/alice-pgp.eml "the PGP secret is 7"
check "alice: X-Mailcloak-Decrypted: pgp" has $W/alice-pgp.eml "X-Mailcloak-Decrypted: pgp"
check "alice: signer unknown to mailcloak" has $W/alice-pgp.eml "status=unknown-key"

echo "outbound: alice → erin, using the harvested Autocrypt key"
printf 'From: Alice <alice@corp.test>\r\nTo: erin@ext.test\r\nSubject: Re: PGP inbound\r\n\r\nReply secret for Erin.\r\n' | send 587 alice@corp.test erin@ext.test
fetch erin@ext.test > $W/erin.eml
armor $W/erin.eml | gpg --homedir $T/gnupg/erin --batch --status-fd 3 --decrypt 3>$W/erin.status >$W/erin.txt 2>/dev/null
check "erin: gpg decrypts the reply" has $W/erin.txt "Reply secret for Erin."
check "erin: gpg verifies alice's signature" has $W/erin.status GOODSIG

# --- 3. Inbound S/MIME made by OpenSSL ------------------------------------
echo "inbound: frank → alice, S/MIME enveloped by openssl"
printf 'Content-Type: text/plain\r\n\r\nHello Alice, the S/MIME secret is 9.\r\n' \
  | openssl smime -encrypt -aes256 -from frank@ext.test -to alice@corp.test -subject "S/MIME inbound" $T/smime/alice.crt \
  | send 25 frank@ext.test alice@corp.test
sleep 1
fetch alice@corp.test > $W/alice-smime.eml
check "alice: decrypted" has $W/alice-smime.eml "the S/MIME secret is 9"
check "alice: X-Mailcloak-Decrypted: smime" has $W/alice-smime.eml "X-Mailcloak-Decrypted: smime"

# --- 4. S/MIME harvesting -------------------------------------------------
echo "inbound: frank → alice, signed by openssl (harvested); then alice → frank"
printf 'Content-Type: text/plain\r\n\r\nHi Alice, here is my certificate.\r\n' \
  | openssl smime -sign -signer $T/smime/frank.crt -inkey $T/smime/frank.key -from frank@ext.test -to alice@corp.test -subject "Signed" \
  | send 25 frank@ext.test alice@corp.test
sleep 2
printf 'From: Alice <alice@corp.test>\r\nTo: frank@ext.test\r\nSubject: Re: Signed\r\n\r\nReply secret for Frank.\r\n' | send 587 alice@corp.test frank@ext.test
fetch frank@ext.test > $W/frank.eml
check "frank: reply is S/MIME encrypted" has $W/frank.eml application/pkcs7-mime
openssl smime -decrypt -in $W/frank.eml -recip $T/smime/frank.crt -inkey $T/smime/frank.key -out $W/frank.inner 2>/dev/null
check "frank: openssl decrypts the reply" has $W/frank.inner "Reply secret for Frank."

echo
echo "$pass passed, $fail failed"
[ $fail -eq 0 ]
