# internal/httpguts

Pruned copy of `httplex.go` from `golang.org/x/net@v0.55.0/http/httpguts`,
kept in-tree so this module stays dependency-free.

Only `ValidHeaderFieldName` and `ValidHeaderFieldValue` (and their private
helpers) are kept: they back the post-parse header re-validation in
`handleHTTP`, the same check `net/http.Server` performs after
`http.ReadRequest`. Everything else from upstream was removed, unmodified
code aside.

The `LICENSE` file in this directory is the x/net license (BSD-3-Clause),
which the file header refers to.
