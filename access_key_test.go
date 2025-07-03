package authcontrol_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/0xsequence/authcontrol"
	"github.com/stretchr/testify/require"
)

func TestAccessKeyEncoding(t *testing.T) {
	t.Run("v0", func(t *testing.T) {
		ctx := authcontrol.WithVersion(context.Background(), 0)
		projectID := uint64(12345)
		accessKey := authcontrol.NewAccessKey(ctx, projectID)
		t.Log("=> k", accessKey)

		outID, err := accessKey.GetProjectID()
		require.NoError(t, err)
		require.Equal(t, projectID, outID)
	})

	t.Run("v1", func(t *testing.T) {
		ctx := authcontrol.WithVersion(context.Background(), 1)
		projectID := uint64(12345)
		accessKey := authcontrol.NewAccessKey(ctx, projectID)
		t.Log("=> k", accessKey)
		outID, err := accessKey.GetProjectID()
		require.NoError(t, err)
		require.Equal(t, projectID, outID)
	})
	t.Run("v2", func(t *testing.T) {
		ctx := authcontrol.WithVersion(context.Background(), 2)
		projectID := uint64(12345)
		accessKey := authcontrol.NewAccessKey(ctx, projectID)
		t.Log("=> k", accessKey, "| prefix =>", accessKey.GetPrefix())
		outID, err := accessKey.GetProjectID()
		require.NoError(t, err)
		require.Equal(t, projectID, outID)

		ctx = authcontrol.WithPrefix(ctx, "newprefix:dev")

		accessKey2 := authcontrol.NewAccessKey(ctx, projectID)
		t.Log("=> k", accessKey2, "| prefix =>", accessKey2.GetPrefix())
		outID, err = accessKey2.GetProjectID()
		require.NoError(t, err)
		require.Equal(t, projectID, outID)
		// retrocompatibility with the older prefix
		outID, err = accessKey.GetProjectID()
		require.NoError(t, err)
		require.Equal(t, projectID, outID)
	})
}

func TestDecode(t *testing.T) {
	ctx := authcontrol.WithVersion(context.Background(), 2)
	accessKey := authcontrol.NewAccessKey(ctx, 237)
	t.Log("=> k", accessKey, "| prefix =>", accessKey.GetPrefix())
}

func TestForwardAccessKeyTransport(t *testing.T) {
	// Create a test server that captures the request headers
	var capturedHeaders http.Header
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedHeaders = r.Header.Clone()
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	// Create context with access key
	accessKey := "test-access-key-123"
	ctx := authcontrol.WithAccessKey(context.Background(), accessKey)

	// Create HTTP client with ForwardAccessKeyTransport
	client := &http.Client{
		Transport: authcontrol.ForwardAccessKeyTransport(http.DefaultTransport),
	}

	// Create request with the context
	req, err := http.NewRequestWithContext(ctx, "GET", server.URL, nil)
	require.NoError(t, err)

	// Make the request
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	// Verify the access key header was set
	require.Equal(t, accessKey, capturedHeaders.Get(authcontrol.HeaderAccessKey))
}
