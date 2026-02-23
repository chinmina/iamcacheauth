package iamcacheauth

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4sdk "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
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

// --- Differential tests against aws-sdk-go-v2/aws/signer/v4 ---
//
// These tests verify that iamcacheauth produces tokens equivalent to the
// reference signing approach used by build-on-aws/aws-redis-iam-auth-golang
// (and other community implementations) which use v4.NewSigner().PresignHTTP.
//
// synctest controls time.Now() inside the bubble so both signers see the
// same timestamp. Both signers produce identical signatures; the only
// permitted difference is query parameter ordering (which is not
// semantically significant in URLs).

const hexEncodedSHA256EmptyString = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

// referenceToken generates a token using the aws-sdk-go-v2 v4.PresignHTTP
// approach, mirroring the build-on-aws/aws-redis-iam-auth-golang implementation.
func referenceToken(t *testing.T, serviceName, resourceName, userID, region string, serverless bool, creds aws.Credentials) string {
	t.Helper()

	queryParams := url.Values{
		"Action":        {"connect"},
		"User":          {userID},
		"X-Amz-Expires": {"900"},
	}
	if serverless {
		queryParams.Set("ResourceType", "ServerlessCache")
	}

	authURL := url.URL{
		Host:     resourceName,
		Scheme:   "http",
		Path:     "/",
		RawQuery: queryParams.Encode(),
	}

	req, err := http.NewRequest(http.MethodGet, authURL.String(), nil)
	if err != nil {
		t.Fatalf("reference: failed to build request: %v", err)
	}

	signer := v4sdk.NewSigner()
	signedURL, _, err := signer.PresignHTTP(
		context.Background(),
		creds,
		req,
		hexEncodedSHA256EmptyString,
		serviceName,
		region,
		time.Now().UTC(),
	)
	if err != nil {
		t.Fatalf("reference: signing failed: %v", err)
	}

	return strings.Replace(signedURL, "http://", "", 1)
}

// assertTokensEqual compares two tokens by parsing their host/path and query
// parameters independently. Query parameter order varies between signing
// libraries and is not semantically significant. The comparison verifies that
// both tokens have the same host/path prefix and identical key-value pairs,
// including the cryptographic signature.
func assertTokensEqual(t *testing.T, got, want string) {
	t.Helper()

	gotParts := strings.SplitN(got, "?", 2)
	wantParts := strings.SplitN(want, "?", 2)

	if len(gotParts) != 2 || len(wantParts) != 2 {
		t.Fatalf("malformed tokens:\n  got:  %s\n  want: %s", got, want)
	}

	if gotParts[0] != wantParts[0] {
		t.Errorf("host/path mismatch:\n  got:  %s\n  want: %s", gotParts[0], wantParts[0])
	}

	gotVals, err := url.ParseQuery(gotParts[1])
	if err != nil {
		t.Fatalf("failed to parse got query: %v", err)
	}
	wantVals, err := url.ParseQuery(wantParts[1])
	if err != nil {
		t.Fatalf("failed to parse want query: %v", err)
	}

	// Check every key in want exists in got with the same value.
	for key, wantV := range wantVals {
		gotV, ok := gotVals[key]
		if !ok {
			t.Errorf("missing query parameter %q (want %q)", key, wantV)
			continue
		}
		if len(gotV) != len(wantV) {
			t.Errorf("parameter %q: got %d values, want %d", key, len(gotV), len(wantV))
			continue
		}
		for i := range wantV {
			if gotV[i] != wantV[i] {
				t.Errorf("parameter %q[%d]: got %q, want %q", key, i, gotV[i], wantV[i])
			}
		}
	}

	// Check got has no extra keys.
	for key := range gotVals {
		if _, ok := wantVals[key]; !ok {
			t.Errorf("unexpected query parameter %q = %q", key, gotVals[key])
		}
	}
}

func TestDifferential_ElastiCache(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		cfg := testAWSConfig("us-east-1")
		gen, err := NewElastiCache("my-user", "my-cache", cfg)
		if err != nil {
			t.Fatalf("NewElastiCache() unexpected error: %v", err)
		}

		got, err := gen.Token(context.Background())
		if err != nil {
			t.Fatalf("Token() unexpected error: %v", err)
		}

		creds, _ := cfg.Credentials.Retrieve(context.Background())
		want := referenceToken(t, "elasticache", "my-cache", "my-user", "us-east-1", false, creds)

		assertTokensEqual(t, got, want)
	})
}

func TestDifferential_ElastiCacheServerless(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		cfg := testAWSConfig("us-east-1")
		gen, err := NewElastiCache("my-user", "my-cache", cfg, WithServerless())
		if err != nil {
			t.Fatalf("NewElastiCache() unexpected error: %v", err)
		}

		got, err := gen.Token(context.Background())
		if err != nil {
			t.Fatalf("Token() unexpected error: %v", err)
		}

		creds, _ := cfg.Credentials.Retrieve(context.Background())
		want := referenceToken(t, "elasticache", "my-cache", "my-user", "us-east-1", true, creds)

		assertTokensEqual(t, got, want)
	})
}

func TestDifferential_MemoryDB(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		cfg := testAWSConfig("us-east-1")
		gen, err := NewMemoryDB("my-user", "my-cluster", cfg)
		if err != nil {
			t.Fatalf("NewMemoryDB() unexpected error: %v", err)
		}

		got, err := gen.Token(context.Background())
		if err != nil {
			t.Fatalf("Token() unexpected error: %v", err)
		}

		creds, _ := cfg.Credentials.Retrieve(context.Background())
		want := referenceToken(t, "memorydb", "my-cluster", "my-user", "us-east-1", false, creds)

		assertTokensEqual(t, got, want)
	})
}

func TestDifferential_DifferentRegion(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		cfg := testAWSConfig("ap-southeast-2")
		gen, err := NewElastiCache("my-user", "my-cache", cfg)
		if err != nil {
			t.Fatalf("NewElastiCache() unexpected error: %v", err)
		}

		got, err := gen.Token(context.Background())
		if err != nil {
			t.Fatalf("Token() unexpected error: %v", err)
		}

		creds, _ := cfg.Credentials.Retrieve(context.Background())
		want := referenceToken(t, "elasticache", "my-cache", "my-user", "ap-southeast-2", false, creds)

		assertTokensEqual(t, got, want)
	})
}

func TestDifferential_VariedInputs(t *testing.T) {
	cases := []struct {
		name         string
		serviceName  string
		resourceName string
		userID       string
		region       string
		serverless   bool
	}{
		{"long-cache-name", "elasticache", "my-very-long-cache-name-prod-us-east-1", "admin", "us-east-1", false},
		{"special-user-chars", "elasticache", "my-cache", "user@domain.com", "eu-west-1", false},
		{"memorydb-eu", "memorydb", "prod-cluster", "service-account", "eu-central-1", false},
		{"serverless-west", "elasticache", "serverless-cache", "app-user", "us-west-2", true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				cfg := testAWSConfig(tc.region)

				var gen *TokenGenerator
				var err error
				if tc.serviceName == "elasticache" {
					opts := []Option{}
					if tc.serverless {
						opts = append(opts, WithServerless())
					}
					gen, err = NewElastiCache(tc.userID, tc.resourceName, cfg, opts...)
				} else {
					gen, err = NewMemoryDB(tc.userID, tc.resourceName, cfg)
				}
				if err != nil {
					t.Fatalf("constructor unexpected error: %v", err)
				}

				got, err := gen.Token(context.Background())
				if err != nil {
					t.Fatalf("Token() unexpected error: %v", err)
				}

				creds, _ := cfg.Credentials.Retrieve(context.Background())
				want := referenceToken(t, tc.serviceName, tc.resourceName, tc.userID, tc.region, tc.serverless, creds)

				assertTokensEqual(t, got, want)
			})
		})
	}
}

func TestDifferential_WithoutSessionToken(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		cfg := aws.Config{
			Region: "us-east-1",
			Credentials: staticCredentials{
				AccessKeyID:     "AKIAIOSFODNN7EXAMPLE",
				SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
				SessionToken:    "",
			},
		}
		gen, err := NewElastiCache("my-user", "my-cache", cfg)
		if err != nil {
			t.Fatalf("NewElastiCache() unexpected error: %v", err)
		}

		got, err := gen.Token(context.Background())
		if err != nil {
			t.Fatalf("Token() unexpected error: %v", err)
		}

		creds, _ := cfg.Credentials.Retrieve(context.Background())
		want := referenceToken(t, "elasticache", "my-cache", "my-user", "us-east-1", false, creds)

		assertTokensEqual(t, got, want)
	})
}

func TestDifferential_TimeSensitivity(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		cfg := testAWSConfig("us-east-1")
		gen, err := NewElastiCache("my-user", "my-cache", cfg)
		if err != nil {
			t.Fatalf("NewElastiCache() unexpected error: %v", err)
		}
		creds, _ := cfg.Credentials.Retrieve(context.Background())

		// Generate at t=0
		got1, err := gen.Token(context.Background())
		if err != nil {
			t.Fatalf("Token() #1 unexpected error: %v", err)
		}
		want1 := referenceToken(t, "elasticache", "my-cache", "my-user", "us-east-1", false, creds)
		assertTokensEqual(t, got1, want1)

		// Advance fake clock by 5 minutes
		time.Sleep(5 * time.Minute)

		// Generate at t=5m — both should agree on the new timestamp
		got2, err := gen.Token(context.Background())
		if err != nil {
			t.Fatalf("Token() #2 unexpected error: %v", err)
		}
		want2 := referenceToken(t, "elasticache", "my-cache", "my-user", "us-east-1", false, creds)
		assertTokensEqual(t, got2, want2)

		// The two tokens must differ (different timestamps)
		vals1 := parseToken(t, got1)
		vals2 := parseToken(t, got2)
		if vals1.Get("X-Amz-Signature") == vals2.Get("X-Amz-Signature") {
			t.Error("tokens at different times should have different signatures")
		}
		if vals1.Get("X-Amz-Date") == vals2.Get("X-Amz-Date") {
			t.Error("tokens at different times should have different X-Amz-Date values")
		}
	})
}
