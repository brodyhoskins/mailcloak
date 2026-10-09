#!/bin/sh
# Configure Alpine's stock Postfix for the test: mailcloak as pipe-mode
# content filters (as in examples/postfix/master.cf), everything relayed to
# Mailpit afterwards.
set -eu

postconf -e \
  'maillog_file = /dev/stdout' \
  'myhostname = mx.corp.test' \
  'mydomain = corp.test' \
  'myorigin = $mydomain' \
  'mydestination =' \
  'relayhost = [mailpit]:1025' \
  'inet_interfaces = all' \
  'inet_protocols = ipv4' \
  'mynetworks = 0.0.0.0/0' \
  'smtpd_relay_restrictions = permit_mynetworks, reject' \
  'smtpd_tls_security_level = none' \
  'smtp_tls_security_level = none' \
  'disable_mime_output_conversion = yes'

# Inbound (port 25) → decrypt; outbound (port 587) → encrypt. content_filter
# is set per service, never in main.cf, or reinjected mail would loop.
postconf -P 'smtp/inet/content_filter=mailcloak-decrypt:dummy'
postconf -M 'submission/inet=submission inet n - n - - smtpd'
postconf -P 'submission/inet/content_filter=mailcloak-encrypt:dummy'

for f in encrypt decrypt; do
  postconf -M "mailcloak-$f/unix=mailcloak-$f unix - n n - 10 pipe flags=Rq user=mailcloak null_sender= argv=/usr/local/bin/mailcloak-$f -f \${sender} -- \${recipient}"
done

newaliases
postfix check
