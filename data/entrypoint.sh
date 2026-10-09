#!/bin/sh
# Run Postfix in the foreground, with mailcloak's log interleaved.
set -e
install -o mailcloak -g mailcloak -m 0640 /dev/null /var/log/mailcloak/mailcloak.log
tail -F /var/log/mailcloak/mailcloak.log 2>/dev/null | sed -u 's/^/mailcloak: /' &
exec postfix start-fg
