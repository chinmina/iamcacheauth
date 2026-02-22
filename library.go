package iamcacheauth

import (
	"context"
	"crypto/sha256"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	smithycreds "github.com/aws/smithy-go/aws-http-auth/credentials"
	"github.com/aws/smithy-go/aws-http-auth/sigv4"
	v4 "github.com/aws/smithy-go/aws-http-auth/v4"
)

// emptyPayloadHash is the SHA-256 hash of the empty string, precomputed.
var emptyPayloadHash = sha256.Sum256(nil)

// tokenConfig holds all configuration for token generation.
type tokenConfig struct {
	userID       string
	resourceName string // cacheName (ElastiCache) or clusterName (MemoryDB)
	region       string
	serverless   bool
	serviceName  string // "elasticache" or "memorydb"
	credProvider aws.CredentialsProvider
}

// Option configures a [TokenGenerator] using the functional options pattern.
// The available options are:
//   - [WithServerless] — marks the target as a serverless cache
type Option func(*tokenConfig) error

// WithServerless marks the target cache as serverless, causing the token to
// include the ResourceType=ServerlessCache query parameter.
func WithServerless() Option {
	return func(cfg *tokenConfig) error {
		cfg.serverless = true
		return nil
	}
}

// TokenGenerator generates IAM authentication tokens for ElastiCache or MemoryDB.
// It is safe for concurrent use after construction.
//
// Use [NewElastiCache] or [NewMemoryDB] to create instances.
type TokenGenerator struct {
	cfg tokenConfig
}

// NewElastiCache creates a [TokenGenerator] for Amazon ElastiCache.
// cacheName is the replication group ID or serverless cache name.
//
// Region is read from awsCfg.Region (set via [config.WithRegion] or resolved
// from the environment/shared config). Credentials are read from
// awsCfg.Credentials (the provider chain configured in [aws.Config]).
// Both are captured at construction time.
//
// Use [WithServerless] to target a serverless cache.
func NewElastiCache(userID, cacheName string, awsCfg aws.Config, opts ...Option) (*TokenGenerator, error) {
	if cacheName == "" {
		return nil, fmt.Errorf("iamcacheauth: cacheName must not be empty")
	}

	return newTokenGenerator(tokenConfig{
		userID:       userID,
		resourceName: cacheName,
		region:       awsCfg.Region,
		serviceName:  "elasticache",
		credProvider: awsCfg.Credentials,
	}, opts)
}

// NewMemoryDB creates a [TokenGenerator] for Amazon MemoryDB.
// clusterName is the MemoryDB cluster name.
//
// Region is read from awsCfg.Region (set via [config.WithRegion] or resolved
// from the environment/shared config). Credentials are read from
// awsCfg.Credentials (the provider chain configured in [aws.Config]).
// Both are captured at construction time.
//
// MemoryDB does not support serverless caches; passing [WithServerless]
// returns an error.
func NewMemoryDB(userID, clusterName string, awsCfg aws.Config, opts ...Option) (*TokenGenerator, error) {
	if clusterName == "" {
		return nil, fmt.Errorf("iamcacheauth: clusterName must not be empty")
	}

	gen, err := newTokenGenerator(tokenConfig{
		userID:       userID,
		resourceName: clusterName,
		region:       awsCfg.Region,
		serviceName:  "memorydb",
		credProvider: awsCfg.Credentials,
	}, opts)
	if err != nil {
		return nil, err
	}

	if gen.cfg.serverless {
		return nil, fmt.Errorf("iamcacheauth: serverless is not supported for MemoryDB")
	}

	return gen, nil
}

// newTokenGenerator is the shared private constructor. It applies options
// and validates common fields.
func newTokenGenerator(cfg tokenConfig, opts []Option) (*TokenGenerator, error) {
	for _, opt := range opts {
		if err := opt(&cfg); err != nil {
			return nil, err
		}
	}

	if cfg.userID == "" {
		return nil, fmt.Errorf("iamcacheauth: userID must not be empty")
	}
	if cfg.region == "" {
		return nil, fmt.Errorf("iamcacheauth: region must not be empty")
	}
	if cfg.credProvider == nil {
		return nil, fmt.Errorf("iamcacheauth: aws.Config must have a Credentials provider")
	}

	return &TokenGenerator{cfg: cfg}, nil
}

// Token generates a fresh IAM authentication token. Each call produces a
// newly signed token using the current wall-clock time.
//
// The ctx parameter controls the timeout and deadline for credential
// retrieval (e.g. from STS, IMDS, or other credential sources). Use
// [context.WithTimeout] to bound credential retrieval time. Signing itself
// is a local CPU-only operation and completes immediately after credentials
// are obtained.
//
// The returned token is valid for 15 minutes but should not be cached;
// generate a fresh token for each connection attempt.
func (g *TokenGenerator) Token(ctx context.Context) (string, error) {
	awsCreds, err := g.cfg.credProvider.Retrieve(ctx)
	if err != nil {
		return "", fmt.Errorf("iamcacheauth: credential retrieval failed: %w", err)
	}

	// The smithy-go signer uses its own credential type, not the SDK v2 type.
	creds := smithycreds.Credentials{
		AccessKeyID:     awsCreds.AccessKeyID,
		SecretAccessKey: awsCreds.SecretAccessKey,
		SessionToken:    awsCreds.SessionToken,
	}

	// X-Amz-Expires must be set before signing so it is included in the
	// signed query string.
	query := url.Values{}
	query.Set("Action", "connect")
	query.Set("User", g.cfg.userID)
	query.Set("X-Amz-Expires", "900")

	// ElastiCache rejects serverless tokens without ResourceType, and
	// rejects replication-group tokens that include it.
	if g.cfg.serverless {
		query.Set("ResourceType", "ServerlessCache")
	}

	reqURL := fmt.Sprintf("http://%s/?%s", g.cfg.resourceName, query.Encode())
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return "", fmt.Errorf("iamcacheauth: failed to build signing request: %w", err)
	}

	signer := sigv4.New()
	if err := signer.SignRequest(&sigv4.SignRequestInput{
		Request:       req,
		PayloadHash:   emptyPayloadHash[:],
		Credentials:   creds,
		Service:       g.cfg.serviceName,
		Region:        g.cfg.region,
		Time:          time.Now(),
		SignatureType: v4.SignatureTypeQueryString,
	}); err != nil {
		return "", fmt.Errorf("iamcacheauth: signing failed: %w", err)
	}

	// The token is the presigned URL without the http:// scheme prefix.
	token := strings.TrimPrefix(req.URL.String(), "http://")
	return token, nil
}
