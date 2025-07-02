package authcontrol_test

import (
	"context"
	"testing"

	"github.com/0xsequence/authcontrol"
	"github.com/stretchr/testify/require"
)

func TestAccessKeyEncoding(t *testing.T) {
	t.Run("v0", func(t *testing.T) {
		ctx := authcontrol.WithVersion(context.Background(), 0)
		projectID := uint64(12345)
		accessKey := authcontrol.GenerateAccessKey(ctx, projectID)
		t.Log("=> k", accessKey)

		outID, err := authcontrol.GetProjectIDFromAccessKey(accessKey)
		require.NoError(t, err)
		require.Equal(t, projectID, outID)
	})

	t.Run("v1", func(t *testing.T) {
		ctx := authcontrol.WithVersion(context.Background(), 1)
		projectID := uint64(12345)
		accessKey := authcontrol.GenerateAccessKey(ctx, projectID)
		t.Log("=> k", accessKey)
		outID, err := authcontrol.GetProjectIDFromAccessKey(accessKey)
		require.NoError(t, err)
		require.Equal(t, projectID, outID)
	})
	t.Run("v2", func(t *testing.T) {
		ctx := authcontrol.WithVersion(context.Background(), 2)
		projectID := uint64(12345)
		accessKey := authcontrol.GenerateAccessKey(ctx, projectID)
		t.Log("=> k", accessKey, "| prefix =>", authcontrol.GetAccessKeyPrefix(accessKey))
		outID, err := authcontrol.GetProjectIDFromAccessKey(accessKey)
		require.NoError(t, err)
		require.Equal(t, projectID, outID)

		ctx = authcontrol.WithPrefix(ctx, "newprefix:dev")

		accessKey2 := authcontrol.GenerateAccessKey(ctx, projectID)
		t.Log("=> k", accessKey2, "| prefix =>", authcontrol.GetAccessKeyPrefix(accessKey2))
		outID, err = authcontrol.GetProjectIDFromAccessKey(accessKey2)
		require.NoError(t, err)
		require.Equal(t, projectID, outID)
		// retrocompatibility with the older prefix
		outID, err = authcontrol.GetProjectIDFromAccessKey(accessKey)
		require.NoError(t, err)
		require.Equal(t, projectID, outID)
	})
}

func TestDecode(t *testing.T) {
	ctx := authcontrol.WithVersion(context.Background(), 2)
	accessKey := authcontrol.GenerateAccessKey(ctx, 237)
	t.Log("=> k", accessKey, "| prefix =>", authcontrol.GetAccessKeyPrefix(accessKey))
}
