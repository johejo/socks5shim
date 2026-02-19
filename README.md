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
- `-dial-timeout`: `2s` (timeout for connecting to upstream)
- `-client-handshake-timeout`: `5s` (timeout for reading client greeting/request)

## Behavior Details

- If upstream SOCKS5 is available, traffic is relayed through upstream.
- If upstream is unreachable (for example connection refused or timeout), the shim falls back to direct TCP dialing.
- If upstream responds with a valid SOCKS5 error reply (policy/auth/protocol-level failure), the shim returns that error to the client and does not bypass upstream.
- Unavailable upstream endpoints are backoff-cached for a short period (currently 3 seconds) to avoid repeated slow failures.

## Testing

```
go test ./...
```

Some tests open loopback listeners and may be skipped in restricted environments. Use `-short` to skip them:

## License

MIT License
