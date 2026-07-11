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

more details

```
socks5shim -h
```

## Testing

```
go test ./...
```

Some tests open loopback listeners and may be skipped in restricted environments. Use `-short` to skip them:

## License

MIT License
