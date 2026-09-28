package weaveauth

import (
	"context"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// callWith runs the interceptor with whatever metadata the caller presented,
// reporting whether the call reached the handler.
func callWith(t *testing.T, md metadata.MD) (served bool, code codes.Code) {
	t.Helper()

	ctx := context.Background()
	if md != nil {
		ctx = metadata.NewIncomingContext(ctx, md)
	}
	handler := func(context.Context, any) (any, error) {
		served = true
		return nil, nil
	}

	_, err := authenticate("the-real-token")(ctx, nil, &grpc.UnaryServerInfo{}, handler)
	return served, status.Code(err)
}

// The positive control: without it every test below would pass against an
// interceptor that refuses everyone, including WeaveAuth.
func TestServesACallerPresentingTheToken(t *testing.T) {
	served, _ := callWith(t, metadata.Pairs(TokenMetadataKey, "the-real-token"))

	if !served {
		t.Fatal("a caller presenting the right token was refused")
	}
}

func TestRefusesACallerPresentingTheWrongToken(t *testing.T) {
	served, code := callWith(t, metadata.Pairs(TokenMetadataKey, "not-the-token"))

	if served {
		t.Fatal("a caller with a bad token reached the handler")
	}
	if code != codes.Unauthenticated {
		t.Fatalf("got %v, want Unauthenticated", code)
	}
}

func TestRefusesACallerPresentingNoToken(t *testing.T) {
	served, code := callWith(t, metadata.MD{})

	if served {
		t.Fatal("a caller with no token reached the handler")
	}
	if code != codes.Unauthenticated {
		t.Fatalf("got %v, want Unauthenticated", code)
	}
}

func TestRefusesACallerWithNoMetadataAtAll(t *testing.T) {
	served, code := callWith(t, nil)

	if served {
		t.Fatal("a caller with no metadata reached the handler")
	}
	if code != codes.Unauthenticated {
		t.Fatalf("got %v, want Unauthenticated", code)
	}
}

// A repeated key would otherwise let a caller smuggle a good value alongside
// a bad one.
func TestRefusesACallerPresentingTheTokenTwice(t *testing.T) {
	md := metadata.Pairs(TokenMetadataKey, "not-the-token")
	md.Append(TokenMetadataKey, "the-real-token")

	served, _ := callWith(t, md)

	if served {
		t.Fatal("a caller reached the handler by presenting two tokens")
	}
}
