#!/bin/sh
set -e

for dir in /etc/mailcloak/pgp /etc/mailcloak/smime; do
	[ -d "$dir" ] || install -d -m 0750 -o root -g mailcloak "$dir"
done
[ -d /var/lib/mailcloak ] || install -d -m 0750 -o mailcloak -g mailcloak /var/lib/mailcloak
