# internal/httpguts

Verbatim copy of `httplex.go` from `golang.org/x/net@v0.55.0/http/httpguts`,
kept in-tree so this module stays dependency-free.

The only changes from upstream: `PunycodeHostPort` and its `isASCII` helper
were removed to drop the `golang.org/x/net/idna` dependency, along with the
then-unused `net` import.

The `LICENSE` file in this directory is the x/net license (BSD-3-Clause),
which the file header refers to.
