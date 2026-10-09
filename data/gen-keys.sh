#!/bin/sh
# Generate the test identities with GnuPG and OpenSSL.
#
#   alice@corp.test    our user: PGP + S/MIME private keys      (mailcloak)
#   bob@pgp.test       external PGP user, key known to mailcloak
#   carol@smime.test   external S/MIME user, cert known to mailcloak
#   erin@ext.test      external PGP user, learned via Autocrypt
#   frank@ext.test     external S/MIME user, learned via harvesting
#
# mailcloak's keys go to /etc/mailcloak; the external parties' private keys
# go to /test, where run-tests.sh uses them to check mailcloak's output.
set -eu

M=/etc/mailcloak T=/test
install -d -m 0750 $M/pgp $M/smime
install -d -m 0700 $T/gnupg $T/smime

gpg_() { home=$1; shift; gpg --homedir "$home" --batch --pinentry-mode loopback --passphrase '' "$@"; }

pgp_identity() { # name email → $T/gnupg/<local-part>
  home=$T/gnupg/${2%@*}
  install -d -m 0700 "$home"
  gpg_ "$home" --quick-gen-key "$1 <$2>" ed25519 sign,cert never 2>/dev/null
  fpr=$(gpg --homedir "$home" --with-colons --list-keys "$2" | awk -F: '/^fpr/{print $10; exit}')
  gpg_ "$home" --quick-add-key "$fpr" cv25519 encr never 2>/dev/null
}

smime_identity() { # name email → $T/smime/<local-part>.{crt,key}
  openssl req -x509 -newkey rsa:2048 -nodes -days 30 -subj "/CN=$1" \
    -addext "subjectAltName=email:$2" \
    -addext "keyUsage=critical,digitalSignature,keyEncipherment" \
    -addext "extendedKeyUsage=emailProtection" \
    -keyout "$T/smime/${2%@*}.key" -out "$T/smime/${2%@*}.crt" 2>/dev/null
}

pgp_identity Alice alice@corp.test
pgp_identity Bob bob@pgp.test
pgp_identity Erin erin@ext.test
smime_identity Alice alice@corp.test
smime_identity Carol carol@smime.test
smime_identity Frank frank@ext.test

# mailcloak: alice's private keys, bob's and carol's public ones.
gpg_ $T/gnupg/alice --armor --export-secret-keys alice@corp.test > $M/pgp/alice.asc
gpg_ $T/gnupg/bob --armor --export bob@pgp.test > $M/pgp/bob.asc
cp $T/smime/alice.crt $T/smime/alice.key $T/smime/carol.crt $M/smime/
# Roots that S/MIME harvesting trusts: the self-signed test senders.
cat $T/smime/frank.crt > $M/test-roots.pem

# External parties know alice's public key: bob to verify her signatures,
# erin to encrypt to her.
gpg_ $T/gnupg/alice --export alice@corp.test > /tmp/alice.pgp
for who in bob erin; do gpg_ $T/gnupg/$who --import /tmp/alice.pgp 2>/dev/null; done
rm /tmp/alice.pgp

for home in $T/gnupg/*; do gpgconf --homedir "$home" --kill all; done
chown -R root:mailcloak $M
chmod -R g+rX,o= $M
