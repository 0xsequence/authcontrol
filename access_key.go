package authcontrol

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"crypto/rand"
	"encoding/binary"

	"github.com/go-chi/transport"
	"github.com/goware/base64"
	"github.com/jxskiss/base62"
)

var (
	// SupportedEncodings is a list of supported encodings. If more versions of the same version are added, the first one will be used.
	SupportedEncodings = []Encoding{V2{}, V1{}, V0{}}

	DefaultEncoding Encoding = V1{}

	ErrInvalidKeyLength = errors.New("invalid access key length")
)

func GetProjectIDFromAccessKey(accessKey string) (projectID uint64, err error) {
	var errs []error
	for _, e := range SupportedEncodings {
		projectID, err := e.Decode(accessKey)
		if err != nil {
			errs = append(errs, fmt.Errorf("decode v%d: %w", e.Version(), err))
			continue
		}
		return projectID, nil
	}
	return 0, errors.Join(errs...)
}

func GenerateAccessKey(ctx context.Context, projectID uint64) string {
	version, ok := GetVersion(ctx)
	if !ok {
		return DefaultEncoding.Encode(ctx, projectID)
	}

	for _, e := range SupportedEncodings {
		if e.Version() == version {
			return e.Encode(ctx, projectID)
		}
	}
	return ""
}

func GetAccessKeyPrefix(accessKey string) string {
	parts := strings.Split(accessKey, Separator)
	if len(parts) < 2 {
		return ""
	}
	return strings.Join(parts[:len(parts)-1], Separator)
}

func ForwardAccessKeyTransport(next http.RoundTripper) http.RoundTripper {
	return transport.RoundTripFunc(func(req *http.Request) (resp *http.Response, err error) {
		r := transport.CloneRequest(req)

		if accessKey, ok := GetAccessKey(req.Context()); ok {
			r.Header.Set(HeaderAccessKey, accessKey)
		}

		return next.RoundTrip(r)
	})
}

type Encoding interface {
	Version() byte
	Encode(ctx context.Context, projectID uint64) string
	Decode(accessKey string) (projectID uint64, err error)
}

const (
	sizeV0 = 24
	sizeV1 = 26
	sizeV2 = 32
)

// V0: base62 encoded, 24-byte fixed length. 8 bytes for project ID, rest random.
// Uses custom base62, limiting cross-language compatibility.
type V0 struct{}

func (V0) Version() byte { return 0 }

func (V0) Encode(_ context.Context, projectID uint64) string {
	buf := make([]byte, sizeV0)
	binary.BigEndian.PutUint64(buf, projectID)
	_, _ = rand.Read(buf[8:])
	return base62.EncodeToString(buf)
}

func (V0) Decode(accessKey string) (projectID uint64, err error) {
	buf, err := base62.DecodeString(accessKey)
	if err != nil {
		return 0, fmt.Errorf("base62 decode: %w", err)
	}
	if len(buf) != sizeV0 {
		return 0, ErrInvalidKeyLength
	}
	return binary.BigEndian.Uint64(buf[:8]), nil
}

// V1: base64 encoded, 26-byte fixed length. 1 byte for version, 8 bytes for project ID, rest random.
// Uses standard base64url  Compatible with other systems.
type V1 struct{}

func (V1) Version() byte { return 1 }

func (v V1) Encode(_ context.Context, projectID uint64) string {
	buf := make([]byte, sizeV1)
	buf[0] = v.Version()
	binary.BigEndian.PutUint64(buf[1:], projectID)
	_, _ = rand.Read(buf[9:])
	return base64.Base64UrlEncode(buf)
}

func (V1) Decode(accessKey string) (projectID uint64, err error) {
	buf, err := base64.Base64UrlDecode(accessKey)
	if err != nil {
		return 0, fmt.Errorf("base64 decode: %w", err)
	}
	if len(buf) != sizeV1 {
		return 0, ErrInvalidKeyLength
	}
	return binary.BigEndian.Uint64(buf[1:9]), nil
}

// V2: base64 encoded, 32-byte fixed length. 1 byte for version, 8 bytes for project ID, rest random.
// Uses ":" as separator between prefix and base64 encoded data.
type V2 struct{}

const (
	Separator     = ":"
	DefaultPrefix = "seq"
)

func (V2) Version() byte { return 2 }

func (v V2) Encode(ctx context.Context, projectID uint64) string {
	buf := make([]byte, sizeV2)
	buf[0] = v.Version()
	binary.BigEndian.PutUint64(buf[1:], projectID)
	_, _ = rand.Read(buf[9:])
	return getPrefix(ctx) + Separator + base64.Base64UrlEncode(buf)
}

func (V2) Decode(accessKey string) (projectID uint64, err error) {
	parts := strings.Split(accessKey, Separator)
	accessKey = parts[len(parts)-1]

	buf, err := base64.Base64UrlDecode(accessKey)
	if err != nil {
		return 0, fmt.Errorf("base64 decode: %w", err)
	}
	if len(buf) != sizeV2 {
		return 0, ErrInvalidKeyLength
	}
	return binary.BigEndian.Uint64(buf[1:9]), nil
}
