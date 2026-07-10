# socks5shim

`socks5shim` is a small SOCKS5 proxy shim.

It accepts local SOCKS5 client connections, tries an upstream SOCKS5 proxy first, and falls back to a direct TCP connection when the upstream is temporarily unavailable.

## Features

- SOCKS5 `NO AUTH` method (`0x00`) support.
- SOCKS5 `CONNECT` command support.
- IPv4, IPv6, and domain target address support.
- Upstream-first routing with automatic direct fallback.
- Short backoff cache for unavailable upstream endpoints.

## Requirements

- Go

## Build

```
go build -o socks5shim .
```

## Run

```
socks5shim \
  -listen 127.0.0.1:1081 \
  -upstream 127.0.0.1:1080
```

Default values:

- `-listen`: `127.0.0.1:1081`
- `-upstream`: `127.0.0.1:1080`
- `-dial-timeout`: `2s` (TCP connect + SOCKS5 greeting to upstream)
- `-connect-timeout`: `7s` (SOCKS5 CONNECT reply from upstream)
- `-client-handshake-timeout`: `5s` (timeout for reading client greeting/request)

## Behavior Details

- If upstream SOCKS5 is available, traffic is relayed through upstream.
- If upstream is unreachable, or its CONNECT reply times out, the shim falls back to direct TCP dialing and backoff-caches the upstream for a short period (currently 3 seconds).
- If upstream reports its connection attempt to the target failed (CONNECT reply `0x01`/`0x03`/`0x04`/`0x05`/`0x06`), only that connection falls back to direct; no backoff. These failures may depend on the upstream's network vantage point (e.g. a firewall near the upstream, split DNS), so a direct attempt can still succeed.
- Deliberate rejections and capability mismatches (`0x02` ruleset, `0x07`/`0x08`) are returned to the client without bypassing upstream.

## Testing

```
go test ./...
```

Some tests open loopback listeners and may be skipped in restricted environments. Use `-short` to skip them:

## License

MIT License
