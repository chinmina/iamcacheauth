# Agent Guidelines — iamcacheauth

This document is the authoritative reference for AI agents (and human contributors)
working on this repository. Read it before making any changes.

---

## Repository Purpose

`iamcacheauth` is a minimal Go library that generates AWS SigV4 presigned IAM
authentication tokens for Amazon ElastiCache and MemoryDB (Valkey/Redis) and
integrates with the `valkey-go` client via its `AuthCredentialsFn` callback.

---

## Toolchain Management

The required Go version is managed by [mise](https://mise.jdx.dev/) via
`mise.toml` in the repository root. `mise.toml` also sets environment
variables (e.g. `GODEBUG=netdns=cgo`) needed for reliable operation in
sandboxed environments.

**Never modify the `go` directive or `toolchain` line in `go.mod` to work
around a missing toolchain.** Instead, install mise and then the pinned
toolchain:

```bash
curl https://mise.run | sh   # install mise (skip if already installed)
mise trust                   # trust the repo's mise.toml
mise install                 # install the Go version pinned in mise.toml
```

Activate mise in the current shell before running any Go or make commands:

```bash
eval "$(mise activate bash)"
```

All `make` targets and `go` commands will then use the correct version.
If a dependency requires a newer Go version than what is pinned, update
`mise.toml` (and the `go.mod` `go` directive to match) — do not
downgrade `go.mod` to match an older local toolchain.

---

## How to Run

All common tasks are expressed as `make` targets. Prefer `make` over invoking
tools directly.

```bash
make agent       # format → fix → vet → build → test (full pre-push pipeline)

make format      # gofmt -w .
make fix         # go fix ./...
make vet         # go vet ./...
make build       # go build ./...
make test        # go test -race ./...

make test-integration   # go test -tags=integration -race -v ./...
```

### Integration tests

Integration tests require a live ElastiCache instance and the following
environment variables:

| Variable | Description |
|---|---|
| `ELASTICACHE_ENDPOINT` | DNS endpoint and port, e.g. `my-cache.xxxx.use1.cache.amazonaws.com:6379` |
| `ELASTICACHE_CACHE_NAME` | Replication group ID or serverless cache name |
| `ELASTICACHE_USER_ID` | IAM-enabled ElastiCache user ID |
| `ELASTICACHE_REGION` | AWS region, e.g. `us-east-1` |
| `ELASTICACHE_SERVERLESS` | `true` or `false` |

Do not run integration tests in CI unless the environment is explicitly
configured for it.

---

## Dependency Constraints

**Keep the dependency footprint minimal.** The only permitted non-stdlib
dependencies are:

| Dependency | Purpose |
|---|---|
| `github.com/valkey-io/valkey-go` | Valkey client integration |
| `github.com/aws/aws-sdk-go-v2/config` | AWS credential loading |
| `github.com/aws/smithy-go/aws-http-auth/sigv4` | SigV4 presigning |
| `github.com/aws/smithy-go/aws-http-auth/credentials` | Credentials struct |

Note: `sigv4` and `credentials` are sub-packages of the single Go module
`github.com/aws/smithy-go/aws-http-auth`. The import paths include the
sub-package suffix; the `go get` and `go.mod` entry uses the module path.

Do not add any other third-party dependencies without explicit discussion.
Convenience libraries (ORMs, routers, assertion frameworks, etc.) are not
appropriate for this library.

---

## Test Assertions — Standard Library Only

Tests **must** use only the Go standard library for assertions. Do **not**
introduce `testify`, `gomega`, or any other assertion/matcher library.

Use the `testing.T` methods directly:

```go
// Correct
if got != want {
    t.Errorf("Token() = %q, want %q", got, want)
}

// Correct — fatal stops the test immediately
if err != nil {
    t.Fatalf("unexpected error: %v", err)
}

// Wrong — do not add testify or similar
require.NoError(t, err)
assert.Equal(t, want, got)
```

Helper functions in `_test.go` files are fine; they should call `t.Helper()`
and delegate to `t.Errorf` / `t.Fatalf`.

---

## Development Process — TDD

Follow **Test-Driven Development**:

1. **Write a failing test** that captures the requirement.
2. **Write the minimum production code** to make the test pass.
3. **Refactor** — clean up without changing behaviour. Tests must still pass.
4. Run `make agent` before every commit.

Unit tests live alongside production code in `*_test.go` files with no build
tag. Integration tests must include `//go:build integration` as the first line.

For time-dependent unit tests, use `testing/synctest` instead of
`time.Sleep`. `synctest.Run` provides a fake clock that `time.Now()` reads
automatically — no clock injection into production code is required, and
tests run in microseconds rather than real time.

Do not write code speculatively ahead of a failing test.

---

## Git Usage

### Semantic commits

All commits must follow the [Conventional Commits](https://www.conventionalcommits.org/) format:

```
<type>(<scope>): <subject>

<body>
```

Common types: `feat`, `fix`, `refactor`, `test`, `docs`, `chore`.

### Commit message content

**Never list what changed.** The diff shows that. Commit messages must explain:

- **Why** the change was made — what problem, constraint, or decision drove it
- **Trade-offs** — what alternatives were considered and why this approach was chosen
- **Context** a reviewer needs that is not visible in the diff

Bad (describes the diff):

```
feat(token): add ResourceType query parameter

Added ResourceType=ServerlessCache to the query string when
serverless is true. Updated tests accordingly.
```

Good (explains the why and trade-offs):

```
feat(token): distinguish serverless vs replication group at signing time

ElastiCache rejects tokens for serverless caches that omit ResourceType,
and rejects tokens for replication groups that include it. The flag is
therefore mandatory for correctness, not optional configuration.

Considered deriving the type from the endpoint hostname but the hostname
format is undocumented and subject to change. Explicit configuration at
construction time is more reliable and keeps the signing path simple.
```

### Pull request descriptions

PR descriptions follow the same principle: explain the **why and context**,
not the what. Reviewers can read the diff; they cannot read your mind.

A PR description should answer:
- What problem or requirement prompted this change?
- What decision or design choice was made, and why?
- What did you consider and reject, and why?
- What should a reviewer pay particular attention to?

Do not write a bulleted list that mirrors the commit titles or file changes.
That information is already visible in the PR diff and commit log.

---

## Architectural Constraints

- **No `context.Context` in the credential callback.** The `valkey-go`
  `AuthCredentialsFn` signature does not accept a context. Use
  `context.Background()` internally for AWS credential retrieval. This is a
  known API limitation of valkey-go.
- **TLS is mandatory.** `ClientOption.TLSConfig` must be non-nil when using
  IAM authentication. Document this prominently.
- **Connection lifetime.** ElastiCache disconnects IAM-authenticated
  connections after 12 hours. Recommend `ClientOption.ConnLifetime` < 12 h
  (e.g. 11 h) so valkey-go reconnects proactively with fresh credentials.
- **Fresh token per call.** Never cache generated tokens. Each invocation of
  the credential callback must produce a newly signed token.
- **Concurrency safety.** The token generator must be safe for concurrent
  goroutine use; valkey-go may call `AuthCredentialsFn` from multiple
  goroutines simultaneously.
- **No network calls during signing.** SigV4 presigning is a local
  cryptographic operation. Token generation (after credential retrieval) must
  not make network calls.
