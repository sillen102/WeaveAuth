// Package weaveauth serves the WeaveAuth plugin contract from a Go plugin.
//
// A plugin is an ordinary binary. WeaveAuth spawns it, hands it a unix socket
// path in WA_PLUGIN_SOCKET and a secret in WA_PLUGIN_TOKEN, and calls the
// Plugin service over gRPC. Because it is an ordinary process it keeps its
// own goroutines, its own *sql.DB pool and whatever libraries it likes.
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
// Serve owns the socket and the token check; your callback owns the service.
package weaveauth

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"net"
	"os"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// SocketEnv is where WeaveAuth tells a plugin to listen. WeaveAuth owns the
// directory it points into and removes it when the plugin is torn down.
const SocketEnv = "WA_PLUGIN_SOCKET"

// TokenEnv holds the shared secret WeaveAuth generates at startup and
// presents on every call. It is regenerated whenever WeaveAuth restarts, and
// the same value is handed to a plugin that gets restarted under it.
const TokenEnv = "WA_PLUGIN_TOKEN"

// TokenMetadataKey is the metadata key TokenEnv's value travels in.
const TokenMetadataKey = "x-weaveauth-token"

// Serve listens on the socket WeaveAuth assigned and serves whatever register
// adds to the server, until the process is killed.
//
// A plugin does not choose its own address: WeaveAuth creates a private
// directory per plugin process and passes the path in. Every call is checked
// against the secret in TokenEnv before it reaches a service, so an
// implementation cannot forget to do it.
func Serve(register func(*grpc.Server), opts ...grpc.ServerOption) error {
	path := os.Getenv(SocketEnv)
	if path == "" {
		return errors.New(SocketEnv + " is not set -- a plugin is spawned by WeaveAuth, which sets it")
	}
	// A missing or empty token is a refusal to start, not a call that skips
	// the check: an empty one would authenticate every caller that sends an
	// empty header.
	token := os.Getenv(TokenEnv)
	if token == "" {
		return errors.New(TokenEnv + " is unset or empty -- a plugin is spawned by WeaveAuth, which sets it")
	}

	// A restarted plugin inherits the path of the one that died, and Listen
	// fails on a leftover file rather than replacing it.
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("could not clear %s: %w", path, err)
	}
	listener, err := net.Listen("unix", path)
	if err != nil {
		return fmt.Errorf("could not listen on %s: %w", path, err)
	}

	// Chained rather than set, so a caller's own interceptors still apply.
	opts = append(opts, grpc.ChainUnaryInterceptor(authenticate(token)))
	server := grpc.NewServer(opts...)
	register(server)
	return server.Serve(listener)
}

// authenticate rejects any call that does not present WeaveAuth's token.
func authenticate(token string) grpc.UnaryServerInterceptor {
	expected := []byte(token)

	return func(
		ctx context.Context,
		req any,
		_ *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (any, error) {
		// Deliberately one answer for every failure: a caller learns whether
		// it holds the secret, not how close it got.
		denied := status.Error(codes.Unauthenticated, "caller did not present WeaveAuth's plugin token")

		md, ok := metadata.FromIncomingContext(ctx)
		if !ok {
			return nil, denied
		}
		presented := md.Get(TokenMetadataKey)
		if len(presented) != 1 || subtle.ConstantTimeCompare([]byte(presented[0]), expected) != 1 {
			return nil, denied
		}
		return handler(ctx, req)
	}
}
