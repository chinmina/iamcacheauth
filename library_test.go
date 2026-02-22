package iamcacheauth

import (
	"context"
	"errors"
	"net/url"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
)

// staticCredentials is a test helper that returns fixed AWS credentials.
type staticCredentials struct {
	AccessKeyID     string
	SecretAccessKey string
	SessionToken    string
}

func (s staticCredentials) Retrieve(_ context.Context) (aws.Credentials, error) {
	return aws.Credentials{
		AccessKeyID:     s.AccessKeyID,
		SecretAccessKey: s.SecretAccessKey,
		SessionToken:    s.SessionToken,
	}, nil
}

func testAWSConfig(region string) aws.Config {
	return aws.Config{
		Region: region,
		Credentials: staticCredentials{
			AccessKeyID:     "AKIAIOSFODNN7EXAMPLE",
			SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
			SessionToken:    "AQoDYXdzEJr...",
		},
	}
}

// parseToken splits a token on "?" and returns the parsed query parameters.
func parseToken(t *testing.T, token string) url.Values {
	t.Helper()
	parts := strings.SplitN(token, "?", 2)
	if len(parts) != 2 {
		t.Fatalf("token has no query string: %q", token)
	}
	vals, err := url.ParseQuery(parts[1])
	if err != nil {
		t.Fatalf("failed to parse token query string: %v", err)
	}
	return vals
}

// newElastiCacheGenerator creates an ElastiCache TokenGenerator with standard test values.
func newElastiCacheGenerator(t *testing.T, opts ...Option) *TokenGenerator {
	t.Helper()
	gen, err := NewElastiCache("my-user", "my-cache", testAWSConfig("us-east-1"), opts...)
	if err != nil {
		t.Fatalf("NewElastiCache() unexpected error: %v", err)
	}
	return gen
}

// newMemoryDBGenerator creates a MemoryDB TokenGenerator with standard test values.
func newMemoryDBGenerator(t *testing.T, opts ...Option) *TokenGenerator {
	t.Helper()
	gen, err := NewMemoryDB("my-user", "my-cluster", testAWSConfig("us-east-1"), opts...)
	if err != nil {
		t.Fatalf("NewMemoryDB() unexpected error: %v", err)
	}
	return gen
}

// --- ElastiCache construction validation tests ---

func TestNewElastiCache_EmptyUserID(t *testing.T) {
	_, err := NewElastiCache("", "my-cache", testAWSConfig("us-east-1"))
	if err == nil {
		t.Fatal("NewElastiCache() with empty userID should return error")
	}
}

func TestNewElastiCache_EmptyCacheName(t *testing.T) {
	_, err := NewElastiCache("my-user", "", testAWSConfig("us-east-1"))
	if err == nil {
		t.Fatal("NewElastiCache() with empty cacheName should return error")
	}
}

func TestNewElastiCache_EmptyRegion(t *testing.T) {
	_, err := NewElastiCache("my-user", "my-cache", testAWSConfig(""))
	if err == nil {
		t.Fatal("NewElastiCache() with empty region should return error")
	}
}

// --- Token structure validation tests ---

func TestToken_StartsWithCacheName(t *testing.T) {
	gen := newElastiCacheGenerator(t)
	token, err := gen.Token(context.Background())
	if err != nil {
		t.Fatalf("Token() unexpected error: %v", err)
	}
	if !strings.HasPrefix(token, "my-cache/?") {
		t.Errorf("token should start with %q, got %q", "my-cache/?", token[:min(len(token), 30)])
	}
}

func TestToken_NoProtocolPrefix(t *testing.T) {
	gen := newElastiCacheGenerator(t)
	token, err := gen.Token(context.Background())
	if err != nil {
		t.Fatalf("Token() unexpected error: %v", err)
	}
	if strings.HasPrefix(token, "http://") {
		t.Error("token should not start with http://")
	}
	if strings.HasPrefix(token, "https://") {
		t.Error("token should not start with https://")
	}
}

func TestToken_ContainsSigV4Parameters(t *testing.T) {
	gen := newElastiCacheGenerator(t)
	token, err := gen.Token(context.Background())
	if err != nil {
		t.Fatalf("Token() unexpected error: %v", err)
	}
	vals := parseToken(t, token)
	required := []string{
		"X-Amz-Algorithm",
		"X-Amz-Credential",
		"X-Amz-Date",
		"X-Amz-Expires",
		"X-Amz-SignedHeaders",
		"X-Amz-Signature",
	}
	for _, param := range required {
		if vals.Get(param) == "" {
			t.Errorf("token missing required parameter %q", param)
		}
	}
}

func TestToken_ExpiryIs900(t *testing.T) {
	gen := newElastiCacheGenerator(t)
	token, err := gen.Token(context.Background())
	if err != nil {
		t.Fatalf("Token() unexpected error: %v", err)
	}
	vals := parseToken(t, token)
	if got := vals.Get("X-Amz-Expires"); got != "900" {
		t.Errorf("X-Amz-Expires = %q, want %q", got, "900")
	}
}

func TestToken_SignedHeadersContainHost(t *testing.T) {
	gen := newElastiCacheGenerator(t)
	token, err := gen.Token(context.Background())
	if err != nil {
		t.Fatalf("Token() unexpected error: %v", err)
	}
	vals := parseToken(t, token)
	if got := vals.Get("X-Amz-SignedHeaders"); got != "host" {
		t.Errorf("X-Amz-SignedHeaders = %q, want %q", got, "host")
	}
}

func TestElastiCacheToken_CredentialScopeContainsElasticache(t *testing.T) {
	gen := newElastiCacheGenerator(t)
	token, err := gen.Token(context.Background())
	if err != nil {
		t.Fatalf("Token() unexpected error: %v", err)
	}
	vals := parseToken(t, token)
	cred := vals.Get("X-Amz-Credential")
	parts := strings.Split(cred, "/")
	if len(parts) < 5 {
		t.Fatalf("X-Amz-Credential has unexpected format: %q", cred)
	}
	if parts[3] != "elasticache" {
		t.Errorf("credential scope service = %q, want %q", parts[3], "elasticache")
	}
}

func TestToken_ActionConnect(t *testing.T) {
	gen := newElastiCacheGenerator(t)
	token, err := gen.Token(context.Background())
	if err != nil {
		t.Fatalf("Token() unexpected error: %v", err)
	}
	vals := parseToken(t, token)
	if got := vals.Get("Action"); got != "connect" {
		t.Errorf("Action = %q, want %q", got, "connect")
	}
}

func TestToken_UserParameter(t *testing.T) {
	gen := newElastiCacheGenerator(t)
	token, err := gen.Token(context.Background())
	if err != nil {
		t.Fatalf("Token() unexpected error: %v", err)
	}
	vals := parseToken(t, token)
	if got := vals.Get("User"); got != "my-user" {
		t.Errorf("User = %q, want %q", got, "my-user")
	}
}

func TestToken_ServerlessResourceType(t *testing.T) {
	gen, err := NewElastiCache("my-user", "my-cache", testAWSConfig("us-east-1"),
		WithServerless(),
	)
	if err != nil {
		t.Fatalf("NewElastiCache() unexpected error: %v", err)
	}
	token, err := gen.Token(context.Background())
	if err != nil {
		t.Fatalf("Token() unexpected error: %v", err)
	}
	vals := parseToken(t, token)
	if got := vals.Get("ResourceType"); got != "ServerlessCache" {
		t.Errorf("ResourceType = %q, want %q", got, "ServerlessCache")
	}
}

func TestToken_NonServerlessOmitsResourceType(t *testing.T) {
	gen := newElastiCacheGenerator(t)
	token, err := gen.Token(context.Background())
	if err != nil {
		t.Fatalf("Token() unexpected error: %v", err)
	}
	vals := parseToken(t, token)
	if vals.Has("ResourceType") {
		t.Errorf("non-serverless token should not contain ResourceType, got %q", vals.Get("ResourceType"))
	}
}

func TestToken_CredentialRegion(t *testing.T) {
	gen, err := NewElastiCache("my-user", "my-cache", testAWSConfig("ap-southeast-2"))
	if err != nil {
		t.Fatalf("NewElastiCache() unexpected error: %v", err)
	}
	token, err := gen.Token(context.Background())
	if err != nil {
		t.Fatalf("Token() unexpected error: %v", err)
	}
	vals := parseToken(t, token)
	cred := vals.Get("X-Amz-Credential")
	parts := strings.Split(cred, "/")
	if len(parts) < 5 {
		t.Fatalf("X-Amz-Credential has unexpected format: %q", cred)
	}
	if parts[2] != "ap-southeast-2" {
		t.Errorf("credential scope region = %q, want %q", parts[2], "ap-southeast-2")
	}
}

func TestToken_ConsecutiveTokensDiffer(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		gen, err := NewElastiCache("my-user", "my-cache", testAWSConfig("us-east-1"))
		if err != nil {
			t.Fatalf("NewElastiCache() unexpected error: %v", err)
		}
		tok1, err := gen.Token(context.Background())
		if err != nil {
			t.Fatalf("Token() #1 unexpected error: %v", err)
		}
		time.Sleep(time.Second)
		tok2, err := gen.Token(context.Background())
		if err != nil {
			t.Fatalf("Token() #2 unexpected error: %v", err)
		}
		vals1 := parseToken(t, tok1)
		vals2 := parseToken(t, tok2)
		sig1 := vals1.Get("X-Amz-Signature")
		sig2 := vals2.Get("X-Amz-Signature")
		if sig1 == sig2 {
			t.Errorf("consecutive tokens should have different signatures, both = %q", sig1)
		}
	})
}

// --- Error path tests ---

// failingCredentials is a test helper that always returns an error.
type failingCredentials struct {
	err error
}

func (f failingCredentials) Retrieve(_ context.Context) (aws.Credentials, error) {
	return aws.Credentials{}, f.err
}

func TestToken_CredentialError(t *testing.T) {
	sentinel := errors.New("cred boom")
	gen, err := NewElastiCache("my-user", "my-cache", aws.Config{
		Region:      "us-east-1",
		Credentials: failingCredentials{err: sentinel},
	})
	if err != nil {
		t.Fatalf("NewElastiCache() unexpected error: %v", err)
	}
	_, err = gen.Token(context.Background())
	if err == nil {
		t.Fatal("Token() should return error when credentials fail")
	}
	if !errors.Is(err, sentinel) {
		t.Errorf("Token() error should wrap sentinel, got: %v", err)
	}
}

// --- Concurrency test ---

func TestToken_ConcurrentSafety(t *testing.T) {
	gen := newElastiCacheGenerator(t)
	var wg sync.WaitGroup
	for range 100 {
		wg.Go(func() {
			token, err := gen.Token(context.Background())
			if err != nil {
				t.Errorf("Token() unexpected error: %v", err)
			}
			if token == "" {
				t.Error("Token() returned empty string")
			}
		})
	}
	wg.Wait()
}

// --- MemoryDB tests ---

func TestMemoryDBToken_StartsWithClusterName(t *testing.T) {
	gen := newMemoryDBGenerator(t)
	token, err := gen.Token(context.Background())
	if err != nil {
		t.Fatalf("Token() unexpected error: %v", err)
	}
	if !strings.HasPrefix(token, "my-cluster/?") {
		t.Errorf("token should start with %q, got %q", "my-cluster/?", token[:min(len(token), 30)])
	}
}

func TestMemoryDBToken_CredentialScopeContainsMemoryDB(t *testing.T) {
	gen := newMemoryDBGenerator(t)
	token, err := gen.Token(context.Background())
	if err != nil {
		t.Fatalf("Token() unexpected error: %v", err)
	}
	vals := parseToken(t, token)
	cred := vals.Get("X-Amz-Credential")
	parts := strings.Split(cred, "/")
	if len(parts) < 5 {
		t.Fatalf("X-Amz-Credential has unexpected format: %q", cred)
	}
	if parts[3] != "memorydb" {
		t.Errorf("credential scope service = %q, want %q", parts[3], "memorydb")
	}
}

func TestMemoryDBToken_OmitsResourceType(t *testing.T) {
	gen := newMemoryDBGenerator(t)
	token, err := gen.Token(context.Background())
	if err != nil {
		t.Fatalf("Token() unexpected error: %v", err)
	}
	vals := parseToken(t, token)
	if vals.Has("ResourceType") {
		t.Errorf("MemoryDB token should not contain ResourceType, got %q", vals.Get("ResourceType"))
	}
}

func TestNewMemoryDB_RejectsServerless(t *testing.T) {
	_, err := NewMemoryDB("my-user", "my-cluster", testAWSConfig("us-east-1"),
		WithServerless(),
	)
	if err == nil {
		t.Fatal("NewMemoryDB() with WithServerless() should return error")
	}
	if !strings.Contains(err.Error(), "serverless is not supported for MemoryDB") {
		t.Errorf("error message should mention serverless not supported, got: %v", err)
	}
}

func TestNewMemoryDB_EmptyClusterName(t *testing.T) {
	_, err := NewMemoryDB("my-user", "", testAWSConfig("us-east-1"))
	if err == nil {
		t.Fatal("NewMemoryDB() with empty clusterName should return error")
	}
}

func TestNewMemoryDB_EmptyUserID(t *testing.T) {
	_, err := NewMemoryDB("", "my-cluster", testAWSConfig("us-east-1"))
	if err == nil {
		t.Fatal("NewMemoryDB() with empty userID should return error")
	}
}

func TestNewMemoryDB_EmptyRegion(t *testing.T) {
	_, err := NewMemoryDB("my-user", "my-cluster", testAWSConfig(""))
	if err == nil {
		t.Fatal("NewMemoryDB() with empty region should return error")
	}
}
