// Package weaveauth serves the WeaveAuth plugin contract from a Go plugin.
//
// A plugin is an ordinary binary. WeaveAuth spawns it with one end of a
// connected unix socket as its stdin, writes a secret token as the first line
// on it, and then calls the Plugin service over it with gRPC. Because it is
// an ordinary process it keeps its own goroutines, its own *sql.DB pool and
// whatever libraries it likes.
//
// This package deliberately ships no generated code. Generate the stubs from
// plugin-sdk/proto in your own project the way you would for any other gRPC
// service, then hand Serve a function that registers them:
//
//	func main() {
//		err := weaveauth.Serve(func(server *grpc.Server) {
//			weaveauthv1.RegisterPluginServer(server, &plugin{db: db})
//		})
//		if err != nil {
//			log.Fatal(err)
//		}
//	}
//
// Serve owns the connection and the token check; your callback owns the
// service.
package weaveauth

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// TokenMetadataKey is the metadata key WeaveAuth presents its token in on
// every call. The token itself is the first line WeaveAuth writes on the
// connection, before any gRPC traffic: a secret generated at startup and
// handed to every restart of the plugin.
const TokenMetadataKey = "x-weaveauth-token"

// maxTokenLine is the longest token line read before giving up. WeaveAuth's
// is 43 characters; the cap only stops a stray stream from being read forever.
const maxTokenLine = 256

// Serve serves whatever register adds to the server on the connection
// WeaveAuth handed over as stdin, until the process is killed.
//
// There is no address: stdin is one end of a socket pair WeaveAuth created,
// so WeaveAuth is the only process that can call the plugin. On top of that,
// every call is checked against the token before it reaches a service, so an
// implementation cannot forget to do it.
func Serve(register func(*grpc.Server), opts ...grpc.ServerOption) error {
	conn, err := net.FileConn(os.Stdin)
	if err != nil {
		return fmt.Errorf("stdin is not a unix socket -- a plugin is spawned by WeaveAuth, which connects it there: %w", err)
	}
	// Unbuffered: anything past the token's newline is already gRPC, and has
	// to be left on the socket for the server.
	token, err := readToken(conn)
	if err != nil {
		return fmt.Errorf("could not read the token from stdin: %w", err)
	}
	// A missing or empty token is a refusal to start, not a call that skips
	// the check: an empty one would authenticate every caller that sends an
	// empty header.
	if token == "" {
		return errors.New("no token on the connection -- WeaveAuth writes one before its first call")
	}
	return serve(conn, token, register, opts...)
}

// serve takes the connection rather than reading stdin so a test can hand
// it one end of its own socket pair.
func serve(conn net.Conn, token string, register func(*grpc.Server), opts ...grpc.ServerOption) error {
	// Chained rather than set, so a caller's own interceptors still apply.
	// Streams too: a plugin may register its own streaming services
	// (health's Watch, reflection), and those must not skip the check.
	opts = append(opts,
		grpc.ChainUnaryInterceptor(authenticate(token)),
		grpc.ChainStreamInterceptor(authenticateStream(token)),
	)
	server := grpc.NewServer(opts...)
	register(server)
	return server.Serve(newSingleConnListener(conn))
}

// readToken reads the first line one byte at a time.
func readToken(r io.Reader) (string, error) {
	line := make([]byte, 0, maxTokenLine)
	b := make([]byte, 1)
	for len(line) < maxTokenLine {
		n, err := r.Read(b)
		if n == 1 && b[0] == '\n' {
			return string(line), nil
		}
		if n == 1 {
			line = append(line, b[0])
		}
		if errors.Is(err, io.EOF) {
			return string(line), nil
		}
		if err != nil {
			return "", err
		}
	}
	return "", nil
}

// singleConnListener hands the server its one connection, then blocks until
// closed: the server would otherwise stop for want of another.
type singleConnListener struct {
	conns  chan net.Conn
	addr   net.Addr
	closed chan struct{}
	once   sync.Once
}

func newSingleConnListener(conn net.Conn) *singleConnListener {
	conns := make(chan net.Conn, 1)
	conns <- conn
	return &singleConnListener{conns: conns, addr: conn.LocalAddr(), closed: make(chan struct{})}
}

func (l *singleConnListener) Accept() (net.Conn, error) {
	select {
	case conn := <-l.conns:
		return conn, nil
	case <-l.closed:
		return nil, net.ErrClosed
	}
}

func (l *singleConnListener) Close() error {
	l.once.Do(func() { close(l.closed) })
	return nil
}

func (l *singleConnListener) Addr() net.Addr { return l.addr }

// authenticate rejects any unary call that does not present WeaveAuth's token.
func authenticate(token string) grpc.UnaryServerInterceptor {
	expected := []byte(token)

	return func(
		ctx context.Context,
		req any,
		_ *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (any, error) {
		if err := checkToken(ctx, expected); err != nil {
			return nil, err
		}
		return handler(ctx, req)
	}
}

// authenticateStream is authenticate for streaming calls.
func authenticateStream(token string) grpc.StreamServerInterceptor {
	expected := []byte(token)

	return func(srv any, stream grpc.ServerStream, _ *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		if err := checkToken(stream.Context(), expected); err != nil {
			return err
		}
		return handler(srv, stream)
	}
}

func checkToken(ctx context.Context, expected []byte) error {
	// Deliberately one answer for every failure: a caller learns whether it
	// holds the secret, not how close it got.
	denied := status.Error(codes.Unauthenticated, "caller did not present WeaveAuth's plugin token")

	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return denied
	}
	presented := md.Get(TokenMetadataKey)
	if len(presented) != 1 || subtle.ConstantTimeCompare([]byte(presented[0]), expected) != 1 {
		return denied
	}
	return nil
}
