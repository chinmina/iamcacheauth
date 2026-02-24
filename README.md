# iamcacheauth

AWS IAM authentication token generator for Amazon ElastiCache and MemoryDB, usable with any Redis-compatible Go client.

> [!NOTE]
> This library implements the token algorithm as [published by AWS][elasticache-iam-reference], something
> that is currently stable and has a low risk of change. Aside from bugs and
> dependency updates, it is highly unlikely that this library will be updated.
>
> The library is MIT licensed: if there are dependency issues you wish to avoid,
> please feel free to incorporate the `library*.go` and `LICENSE.txt` files into
> your own repository.
>
> All that said, contributions are welcome.

Dependencies have been kept to the minimum practical, and the usage of the dependencies is simple. A `replace` statement in `go.mod` will allow a consuming module to align this library's dependency versions with theirs.

## What it does

ElastiCache and MemoryDB IAM authentication works by using a short-lived SigV4 presigned URL as the Redis `AUTH` password. This library generates those tokens via `Token(ctx)`, returning a plain string you can plug into any client's authentication mechanism.

### Note

1. Generated tokens have a short validity period, enough to establish the connection. They are not checked further once the connection is established, and new connections will use fresh tokens.
1. Each call to `Token(ctx)` generates a fresh SigV4 presigned token. Tokens are never cached — a new one is signed for every connection attempt.
2. The `ctx` parameter to `Token(ctx)` controls the timeout for credential retrieval (e.g. from STS, IMDS, or other credential sources). Signing itself is a local CPU-only operation and completes immediately after credentials are obtained.

## Prerequisites

- **Engine version** — ElastiCache: Valkey 7.2+ or Redis OSS 7.0+. MemoryDB: Valkey or Redis OSS 7.0+.
- **TLS** — In-transit encryption must be enabled on the cache or cluster. Both services reject plaintext connections when IAM auth is active. Set `TLSConfig` to a non-nil value in your client.
- **IAM-enabled user** — Create a user with `authentication-mode Type=iam`. On ElastiCache, the `username` and `user-id` must be set to the same value.
- **User group / ACL** — Assign the IAM user to a user group (ElastiCache) or ACL (MemoryDB) attached to your cache or cluster.

## Limitations

These are AWS-imposed constraints that apply regardless of client library. See the [ElastiCache][elasticache-iam-reference] and [MemoryDB][memorydb-iam-reference] IAM auth documentation.

Both services share these limitations:

- **12-hour connection limit** — the server disconnects after 12 hours. Send `AUTH`/`HELLO` with a fresh token to renew, or set your client's connection lifetime below 12 hours (e.g. `11 * time.Hour`) so it reconnects proactively.
- **15-minute token TTL** — tokens expire 15 minutes after signing. This library generates a fresh token per call, so expiry is not normally a concern.
- **No `MULTI`/`EXEC`** — IAM authentication cannot be used inside transaction blocks.
- **Restricted IAM condition keys** — not all global condition keys are available for `elasticache:Connect` / `memorydb:connect` policies. ElastiCache [documents the supported keys][elasticache-iam-reference] per deployment type (serverless vs replication group); MemoryDB does not specify which keys are supported.

## Supported targets

### Elasticache Valkey/Redis

Provisioned instance support is the most straightforward:

```go
gen, err := iamcacheauth.NewElastiCache("my-iam-user", "my-cache", awsCfg)
```

For ElastiCache serverless caches, pass the `WithServerless` option. This adds the `ResourceType=ServerlessCache` query parameter required by the ElastiCache API.

```go
gen, err := iamcacheauth.NewElastiCache("my-iam-user", "my-cache", awsCfg,
    iamcacheauth.WithServerless(),
)
```

### MemoryDB

Use `NewMemoryDB` instead of `NewElastiCache`. The client integration pattern is the same.

```go
gen, err := iamcacheauth.NewMemoryDB("my-iam-user", "my-cluster", awsCfg)
```
MemoryDB does not support serverless caches; `NewMemoryDB` returns an error if `WithServerless` is passed.

## Client integration examples

The `Token(ctx)` method returns a string, so it works with any Redis client. Below are patterns for three common Go clients.

> [!IMPORTANT]
> The `valkey-go` example has been tested: the others are correct according to their current APIs. Please provide feedback if you find issues.
>
> The token generation is consistent across clients, so the integration is the only point of uncertainty.

### valkey-go

```go
import (
    "context"
    "crypto/tls"
    "time"

    "github.com/aws/aws-sdk-go-v2/config"
    "github.com/chinmina/iamcacheauth"
    "github.com/valkey-io/valkey-go"
)

ctx := context.Background()

awsCfg, err := config.LoadDefaultConfig(ctx, config.WithRegion("us-east-1"))
if err != nil {
    return err
}

gen, err := iamcacheauth.NewElastiCache("my-iam-user", "my-cache", awsCfg)
if err != nil {
    return err
}

client, err := valkey.NewClient(valkey.ClientOption{
    InitAddress:  []string{"my-cache.xxxx.use1.cache.amazonaws.com:6379"},
    TLSConfig:    &tls.Config{},
    ConnLifetime: 11 * time.Hour,
    AuthCredentialsFn: func(_ valkey.AuthCredentialsContext) (valkey.AuthCredentials, error) {
        // valkey-go's `AuthCredentialsFn` does not accept a context,
        // either use the default context or construct one with the 
        // necessary cancellation or timeout criteria.
        token, err := gen.Token(context.Background())
        if err != nil {
            return valkey.AuthCredentials{}, err
        }
        return valkey.AuthCredentials{
            Username: "my-iam-user",
            Password: token,
        }, nil
    },
})
```

### go-redis

```go
import (
    "context"
    "crypto/tls"

    "github.com/redis/go-redis/v9"
)

client := redis.NewClient(&redis.Options{
    Addr:      "my-cache.xxxx.use1.cache.amazonaws.com:6379",
    TLSConfig: &tls.Config{},
    CredentialsProviderContext: func(ctx context.Context) (string, string, error) {
        token, err := gen.Token(ctx)
        return "my-iam-user", token, err
    },
})
```

### redigo

```go
import (
    "context"
    "crypto/tls"
    "time"

    redigo "github.com/gomodule/redigo/redis"
)

endpoint := "my-cache.xxxx.use1.cache.amazonaws.com:6379"

pool := &redigo.Pool{
    DialContext: func(ctx context.Context) (redigo.Conn, error) {
        token, err := gen.Token(ctx)
        if err != nil {
            return nil, err
        }
        c, err := redigo.DialContext(ctx, "tcp", endpoint,
            redigo.DialTLSConfig(&tls.Config{}),
            redigo.DialUseTLS(true),
        )
        if err != nil {
            return nil, err
        }
        if _, err := c.Do("AUTH", "my-iam-user", token); err != nil {
            c.Close()
            return nil, err
        }
        return c, nil
    },
    MaxConnLifetime: 11 * time.Hour,
}
```

## Running tests

```bash
make agent          # format, vet, build, and unit test
make test           # unit tests only (no AWS required)
```

[elasticache-iam-reference]: https://docs.aws.amazon.com/AmazonElastiCache/latest/dg/auth-iam.html
[memorydb-iam-reference]: https://docs.aws.amazon.com/memorydb/latest/devguide/auth-iam.html
