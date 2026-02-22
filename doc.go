// Package iamcacheauth generates AWS SigV4 presigned IAM authentication
// tokens for Amazon ElastiCache and Amazon MemoryDB.
//
// The token is a presigned URL (with the scheme prefix stripped) that is
// passed as the Redis AUTH password. Both ElastiCache and MemoryDB accept
// this format for IAM-authenticated connections.
//
// Create a generator with [NewElastiCache] or [NewMemoryDB], then call
// [TokenGenerator.Token] to produce a fresh token:
//
//	gen, err := iamcacheauth.NewElastiCache(userID, cacheName, awsCfg)
//	token, err := gen.Token(ctx)
//
// Key constraints:
//   - Every call to Token produces a freshly signed token. Never cache tokens.
//   - TLS is mandatory for IAM-authenticated connections.
//   - The server closes IAM-authenticated connections after 12 hours.
//
// The library is client-agnostic: Token returns a plain string usable with
// any Redis-compatible client (valkey-go, go-redis, redigo, etc.).
package iamcacheauth
