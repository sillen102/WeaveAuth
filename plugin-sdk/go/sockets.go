// Package weaveauth wraps the socket capability a WeaveAuth plugin is granted.
//
// Import it as github.com/sillen102/WeaveAuth/plugin-sdk/go. It turns the
// four JSON/base64 imports into ordinary functions, so your plugin only
// writes protocol.
//
// Requires github.com/extism/go-pdk, and TinyGo to build.
package weaveauth

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/extism/go-pdk"
)

//go:wasmimport extism:host/user sock_open
func _sockOpen(offset uint64) uint64

//go:wasmimport extism:host/user sock_write
func _sockWrite(offset uint64) uint64

//go:wasmimport extism:host/user sock_read
func _sockRead(offset uint64) uint64

//go:wasmimport extism:host/user sock_release
func _sockRelease(offset uint64) uint64

// SocketError is a refusal from the host. Match on Code, not Message: the
// codes are stable, the messages are for logs.
type SocketError struct {
	Code    string
	Message string
}

func (e *SocketError) Error() string { return fmt.Sprintf("%s (%s)", e.Message, e.Code) }

// IsTimeout reports whether the call's time budget is spent. Retrying inside
// the same call will not help.
func IsTimeout(err error) bool {
	var socketError *SocketError
	return errors.As(err, &socketError) && socketError.Code == "timeout"
}

type response struct {
	Status  string `json:"status"`
	Code    string `json:"code"`
	Message string `json:"message"`
	Handle  uint64 `json:"handle"`
	Fresh   bool   `json:"fresh"`
	Written int    `json:"written"`
	Data    string `json:"data"`
	EOF     bool   `json:"eof"`
}

func call(hostFn func(uint64) uint64, request any) (response, error) {
	var resp response

	body, err := json.Marshal(request)
	if err != nil {
		return resp, err
	}
	mem := pdk.AllocateBytes(body)
	defer mem.Free()

	out := pdk.FindMemory(hostFn(mem.Offset()))
	defer out.Free()

	if err := json.Unmarshal(out.ReadBytes(), &resp); err != nil {
		return resp, err
	}
	if resp.Status != "ok" {
		return resp, &SocketError{Code: resp.Code, Message: resp.Message}
	}
	return resp, nil
}

// Socket is a connection the host owns. Not releasing it leaves the host to
// close it -- correct, just not reusable by the next call.
type Socket struct {
	handle uint64

	// Fresh is false when the host handed back a pooled connection, which
	// means your protocol handshake has already been done on it.
	Fresh bool
}

func Open(host string, port int, tls bool) (*Socket, error) {
	resp, err := call(_sockOpen, map[string]any{"host": host, "port": port, "tls": tls})
	if err != nil {
		return nil, err
	}
	return &Socket{handle: resp.Handle, Fresh: resp.Fresh}, nil
}

func (s *Socket) Write(data []byte) (int, error) {
	resp, err := call(_sockWrite, map[string]any{
		"handle": s.handle,
		"data":   base64.StdEncoding.EncodeToString(data),
	})
	if err != nil {
		return 0, err
	}
	return resp.Written, nil
}

// Read returns what was available, up to max (the host caps a single read at
// 1MB). A nil slice means the peer closed the connection.
func (s *Socket) Read(max int) ([]byte, error) {
	resp, err := call(_sockRead, map[string]any{"handle": s.handle, "max": max})
	if err != nil {
		return nil, err
	}
	if resp.EOF {
		return nil, nil
	}
	return base64.StdEncoding.DecodeString(resp.Data)
}

// ReadExact reads until n bytes have arrived, the way a framed protocol needs.
func (s *Socket) ReadExact(n int) ([]byte, error) {
	buffer := make([]byte, 0, n)
	for len(buffer) < n {
		chunk, err := s.Read(n - len(buffer))
		if err != nil {
			return nil, err
		}
		if len(chunk) == 0 {
			return nil, errors.New("the peer closed the connection mid-message")
		}
		buffer = append(buffer, chunk...)
	}
	return buffer, nil
}

// Release hands the connection back. Pass reuse=true only when the connection
// is back in a clean, reusable protocol state -- mid-protocol it must be
// false. The host refuses to pool a connection an operation already failed on,
// whatever you pass.
func (s *Socket) Release(reuse bool) error {
	_, err := call(_sockRelease, map[string]any{"handle": s.handle, "reuse": reuse})
	return err
}
