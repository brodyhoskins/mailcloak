#!/bin/sh
set -e

for shell in /usr/sbin/nologin /sbin/nologin /bin/false; do
	[ -x "$shell" ] && break
done

if ! grep -q '^mailcloak:' /etc/group; then
	if command -v groupadd >/dev/null 2>&1; then
		groupadd --system mailcloak
	else
		addgroup -S mailcloak
	fi
fi

if ! id mailcloak >/dev/null 2>&1; then
	if command -v useradd >/dev/null 2>&1; then
		useradd --system --gid mailcloak --home-dir /var/lib/mailcloak --no-create-home --shell "$shell" mailcloak
	else
		adduser -S -D -H -h /var/lib/mailcloak -s "$shell" -G mailcloak mailcloak
	fi
fi
