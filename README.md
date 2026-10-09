# mailcloak

[Postfix](https://www.postfix.org/) [content filters](https://www.postfix.org/FILTER_README.html) for transparent email encryption using [PGP](https://www.openpgp.org/) and [S/MIME](https://en.wikipedia.org/wiki/S/MIME).

```sh
mailcloak-encrypt < outgoing.eml | …   # sign and encrypt (per recipient)
mailcloak-decrypt < incoming.eml | …   # decrypt
```

Each reads a message on `stdin` and writes it to stdout. Postfix runs them on each message and handles queueing, retries and delivery; any [MTA](https://en.wikipedia.org/wiki/Message_transfer_agent) that can pipe mail through a program works too. They can also hand mail back via [sendmail](https://www.postfix.org/sendmail.1.html) or [SMTP](https://en.wikipedia.org/wiki/Simple_Mail_Transfer_Protocol), or run as daemons on a [UNIX® domain socket](https://en.wikipedia.org/wiki/Unix_domain_socket) or TCP port.

## What They Do

`mailcloak-encrypt` encrypts to each recipient with PGP or S/MIME, whichever it has a key for (`prefer` breaks ties). PGP mail is PGP-signed; everything else is S/MIME-signed if the sender has a certificate. Mail to `local_domains`, or mail the client already encrypted, passes through. In `strict` mode, mail to a recipient without a key is bounced instead of sent unencrypted.

`mailcloak-decrypt` decrypts [PGP/MIME](https://www.rfc-editor.org/rfc/rfc3156) and S/MIME mail it holds a key for and records the result in `X-Mailcloak-Decrypted` and `X-Mailcloak-Signature` headers. Incoming `X-Mailcloak-*` headers are stripped.

## Finding Keys

Keys are looked up in this order, first hit wins:

1. Local key directories
2. [Web Key Directory (WKD)](https://wiki.gnupg.org/WKD)
3. [OPENPGPKEY](https://www.rfc-editor.org/rfc/rfc7929) and [SMIMEA](https://www.rfc-editor.org/rfc/rfc8162) DNS records ([DNSSEC](https://en.wikipedia.org/wiki/Domain_Name_System_Security_Extensions)-signed only)
4. S/MIME certificates from [CA](https://en.wikipedia.org/wiki/Certificate_authority)-verified signed incoming mail
5. [Autocrypt](https://autocrypt.org/) headers on incoming mail (off by default)
6. A keyserver, such as [keys.openpgp.org](https://keys.openpgp.org/about) (off by default)

`mailcloak-decrypt` collects certificates and Autocrypt keys into `state_dir`; `mailcloak-encrypt` uses them. Run both as the same user. Lookups are cached in `state_dir` and revalidated with [conditional HTTP requests](https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/Conditional_requests).

DNS lookups need a DNSSEC-validating resolver (e.g. [Unbound](https://nlnetlabs.nl/projects/unbound/about/)) on loopback or in `dns.trusted_networks`. Turn off all network sources and mailcloak makes no DNS queries.

## Usage

```
mailcloak-encrypt [flags] [-f sender] [--] [recipient...] < message
mailcloak-encrypt [flags] -listen addr
	
  -config file   config file
  -pgp dir       PGP keys
  -smime dir     S/MIME certificates and keys
  -state dir     discovered and harvested keys
  -output dest   - (stdout, default) | sendmail | smtp:host:port | smtp:unix:/path
  -listen addr   daemon mode: unix:/path (LMTP) or host:port (SMTP)
  -f sender      envelope sender ('' for the null sender)
  -v             verbose
  -version       print version
```

Without `-f` or recipients, they come from the message headers. Exit codes follow [sysexits](https://man.freebsd.org/cgi/man.cgi?query=sysexits): 0 success, 69 bounce, 75 defer.

If recipients need different methods, the result is more than one message, so use `-output sendmail` or `-output smtp:…` rather than stdout.

## Configuration

Both filters share one YAML file; see [`examples/mailcloak.yaml`](examples/mailcloak.yaml). It's found via `-config`, `$MAILCLOAK_CONFIG`, systemd's `$CONFIGURATION_DIRECTORY`, `~/.config/mailcloak/` (non-root), then `/etc/mailcloak/mailcloak.yaml`.

Key directories hold `*.asc`/`*.gpg` keyrings for PGP and `name.crt` plus optional `name.key` for S/MIME, matched by email address.

## Postfix

See [`examples/postfix/`](examples/postfix/). Set [`content_filter`](https://www.postfix.org/postconf.5.html#content_filter) per service in [`master.cf`](https://www.postfix.org/master.5.html) (not in `main.cf`, or reinjected mail loops), and set [`disable_mime_output_conversion = yes`](https://www.postfix.org/postconf.5.html#disable_mime_output_conversion) so signatures survive. For daemon mode there are service examples for [systemd](https://systemd.io/) ([`examples/systemd/`](examples/systemd/)), [OpenRC](https://github.com/OpenRC/openrc) ([`examples/openrc/`](examples/openrc/)), FreeBSD [rc.d](https://docs.freebsd.org/en/articles/rc-scripting/) ([`examples/freebsd/`](examples/freebsd/)) and macOS [launchd](https://www.launchd.info/) ([`examples/launchd/`](examples/launchd/)).

## Building and Testing

```sh
make build           # or: make build VERSION=1.2.3
make test            # unit tests
make docker-test     # end to end against Postfix, GnuPG and OpenSSL
```

## Known Gaps

- If one recipient group is delivered and a later one fails, the retry duplicates the first.
- Subject and other headers aren't encrypted.
- Inline PGP is passed through, not decrypted.
- Harvesting trusts the `From` header; have the MTA reject mail that fails [DMARC](https://dmarc.org/) first.
- Daemon mode hasn't been tested with Postfix.

## License

MIT; see [LICENSE](LICENSE).

UNIX® is a registered trademark of The Open Group.
