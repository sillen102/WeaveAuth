package weaveauth

import (
	"context"
	"io"
	"net"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
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

// startServing runs serve on one end of a socket pair with the health
// service registered, since its Watch is a streaming rpc a plugin might add,
// and returns a client on the other end -- WeaveAuth's.
func startServing(t *testing.T) *grpc.ClientConn {
	t.Helper()

	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	ours, theirs := fileConn(t, fds[0]), fileConn(t, fds[1])
	go func() {
		_ = serve(theirs, "the-real-token", func(server *grpc.Server) {
			healthpb.RegisterHealthServer(server, health.NewServer())
		})
	}()

	client, err := grpc.NewClient("passthrough:///plugin",
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return ours, nil }),
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return client
}

func fileConn(t *testing.T, fd int) net.Conn {
	t.Helper()

	file := os.NewFile(uintptr(fd), "socketpair")
	defer func() { _ = file.Close() }()
	conn, err := net.FileConn(file)
	if err != nil {
		t.Fatal(err)
	}
	return conn
}

func watch(t *testing.T, client *grpc.ClientConn, md metadata.MD) codes.Code {
	t.Helper()

	ctx, cancel := context.WithTimeout(metadata.NewOutgoingContext(context.Background(), md), 5*time.Second)
	defer cancel()
	stream, err := healthpb.NewHealthClient(client).Watch(ctx, &healthpb.HealthCheckRequest{})
	if err != nil {
		return status.Code(err)
	}
	_, err = stream.Recv()
	return status.Code(err)
}

// The positive control for the streaming check below.
func TestServesAStreamingCallPresentingTheToken(t *testing.T) {
	client := startServing(t)

	if code := watch(t, client, metadata.Pairs(TokenMetadataKey, "the-real-token")); code != codes.OK {
		t.Fatalf("got %v, want OK", code)
	}
}

func TestRefusesAStreamingCallPresentingNoToken(t *testing.T) {
	client := startServing(t)

	if code := watch(t, client, metadata.MD{}); code != codes.Unauthenticated {
		t.Fatalf("got %v, want Unauthenticated", code)
	}
}

// Whatever follows the newline is the client's HTTP/2 preface; reading one
// byte too many would corrupt the connection.
func TestReadsTheTokenLineAndNotAByteFurther(t *testing.T) {
	stream := strings.NewReader("s3cret\nPRI * HTTP/2.0")

	token, err := readToken(stream)

	if err != nil || token != "s3cret" {
		t.Fatalf("got %q, %v", token, err)
	}
	if rest, _ := io.ReadAll(stream); string(rest) != "PRI * HTTP/2.0" {
		t.Fatalf("read past the newline, leaving %q", rest)
	}
}

func TestReadsNoTokenFromAnEndlessLine(t *testing.T) {
	token, err := readToken(strings.NewReader(strings.Repeat("a", maxTokenLine+1)))

	if err != nil || token != "" {
		t.Fatalf("got %q, %v", token, err)
	}
}
