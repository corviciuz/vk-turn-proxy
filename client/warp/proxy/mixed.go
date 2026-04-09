// Package proxy implements a mixed SOCKS5/HTTP proxy server that listens on a single
// port and automatically detects the protocol from the first byte of each connection.
package proxy

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync/atomic"
	"time"

	"github.com/cacggghp/vk-turn-proxy/client/warp/internal"
	"github.com/things-go/go-socks5"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

// netResolverAdapter wraps a *net.Resolver so it satisfies socks5.NameResolver.
// Using *net.Resolver (via NewNetstackResolver) instead of TunnelDNSResolver gives us
// Go's built-in UDP retry / exponential-backoff logic, which is far more resilient to
// the packet loss inherent in a UDP-over-MASQUE-over-VK-TURN chain.
type netResolverAdapter struct {
	r *net.Resolver
}

func (a netResolverAdapter) Resolve(ctx context.Context, name string) (context.Context, net.IP, error) {
	dnsCtx, dnsCancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer dnsCancel()
	ips, err := a.r.LookupIP(dnsCtx, "ip", name)
	if err != nil || len(ips) == 0 {
		log.Printf("[Warp] SOCKS5: DNS failed for %s: %v", name, err)
		return ctx, nil, fmt.Errorf("DNS lookup %s: %w", name, err)
	}
	return ctx, ips[0], nil
}

// MixedProxy listens on a single address and routes incoming connections to either
// a SOCKS5 handler or an HTTP/CONNECT handler based on the first byte received.
// Both protocols resolve DNS through the MASQUE tunnel via *net.Resolver,
// which has built-in retry logic suitable for high-latency/lossy relay paths.
type MixedProxy struct {
	addr     string
	tunNet   *netstack.Net
	resolver *net.Resolver      // tunnel-aware resolver (used by both HTTP and SOCKS5)
	socks    netResolverAdapter // socks5.NameResolver adapter around the same resolver
	ready    atomic.Bool        // whether the tunnel is fully connected
}

// NewMixedProxy creates a new MixedProxy.
//
// Parameters:
//   - addr: The address to listen on (e.g. "127.0.0.1:4080").
//   - tunNet: The netstack network (from the MASQUE tunnel).
//   - dnsAddrs: DNS servers to use inside the tunnel (e.g. 162.159.36.1).
//   - localDNS: if true, use the system resolver instead of routing DNS through the tunnel.
func NewMixedProxy(addr string, tunNet *netstack.Net, dnsAddrs []netip.Addr, localDNS bool) *MixedProxy {
	var resolver *net.Resolver
	if localDNS {
		resolver = &net.Resolver{PreferGo: false}
		log.Printf("[Warp] Using local (system) DNS resolver")
	} else {
		// Tunnel resolver — DNS goes through MASQUE to 162.159.36.1.
		resolver = internal.NewNetstackResolver(tunNet, dnsAddrs)
	}
	return &MixedProxy{
		addr:     addr,
		tunNet:   tunNet,
		resolver: resolver,
		socks:    netResolverAdapter{r: resolver},
	}
}

// SetReady updates the tunnel connection state.
// When false, the proxy quickly rejects pending connections.
func (m *MixedProxy) SetReady(ready bool) {
	m.ready.Store(ready)
}

// ListenAndServe starts the mixed proxy server and blocks until the context is cancelled.
func (m *MixedProxy) ListenAndServe(ctx context.Context) error {
	listener, err := net.Listen("tcp", m.addr)
	if err != nil {
		return fmt.Errorf("mixed proxy: listen on %s: %w", m.addr, err)
	}
	defer listener.Close()

	context.AfterFunc(ctx, func() { _ = listener.Close() })

	log.Printf("[Warp] Mixed proxy (SOCKS5+HTTP) listening on %s", m.addr)

	socksServer := socks5.NewServer(
		socks5.WithLogger(socks5.NewLogger(log.New(io.Discard, "", 0))),
		socks5.WithDial(func(sCtx context.Context, network, addr string) (net.Conn, error) {
			return m.tunNet.DialContext(sCtx, network, addr)
		}),
		socks5.WithResolver(m.socks),
	)

	for {
		conn, err := listener.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
				log.Printf("[Warp] Mixed proxy accept error: %v", err)
				continue
			}
		}
		go m.handleConn(ctx, conn, socksServer)
	}
}

// handleConn peeks at the first byte to detect protocol: 0x05 = SOCKS5, else HTTP.
func (m *MixedProxy) handleConn(ctx context.Context, conn net.Conn, socksServer *socks5.Server) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[Warp] Mixed proxy panic: %v", r)
			conn.Close()
		}
	}()

	buf := make([]byte, 1)
	if _, err := io.ReadFull(conn, buf); err != nil {
		conn.Close()
		return
	}

	peeked := &peekedConn{Conn: conn, buf: buf}

	if buf[0] == 0x05 {
		if !m.ready.Load() {
			log.Printf("[Warp] Rejecting SOCKS5 from %s (tunnel not ready)", conn.RemoteAddr())
			conn.Close()
			return
		}
		if err := socksServer.ServeConn(peeked); err != nil {
			log.Printf("[Warp] SOCKS5 error: %v", err)
		}
		return
	}

	if !m.ready.Load() {
		conn.Close()
		return
	}

	m.handleHTTP(ctx, peeked)
}

// handleHTTP serves a single HTTP/CONNECT connection.
func (m *MixedProxy) handleHTTP(ctx context.Context, conn net.Conn) {
	defer conn.Close()

	server := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodConnect {
				m.handleHTTPConnect(w, r)
			} else {
				m.handleHTTPPlain(w, r)
			}
		}),
	}
	_ = server.Serve(&oneConnListener{conn: conn})
}

func (m *MixedProxy) handleHTTPConnect(w http.ResponseWriter, r *http.Request) {
	host, port, err := net.SplitHostPort(r.Host)
	if err != nil {
		http.Error(w, "invalid host", http.StatusBadRequest)
		return
	}

	dnsCtx, dnsCancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer dnsCancel()
	ips, err := m.resolver.LookupIP(dnsCtx, "ip", host)
	if err != nil || len(ips) == 0 {
		log.Printf("[Warp] HTTP CONNECT: DNS failed for %s: %v", host, err)
		http.Error(w, fmt.Sprintf("DNS failed for %s: %v", host, err), http.StatusServiceUnavailable)
		return
	}
	destAddr := net.JoinHostPort(ips[0].String(), port)

	destConn, err := m.tunNet.DialContext(r.Context(), "tcp", destAddr)
	if err != nil {
		log.Printf("[Warp] HTTP CONNECT: tunnel dial failed for %s: %v", destAddr, err)
		http.Error(w, fmt.Sprintf("tunnel dial failed: %v", err), http.StatusServiceUnavailable)
		return
	}

	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijacking not supported", http.StatusInternalServerError)
		destConn.Close()
		return
	}
	clientConn, _, err := hj.Hijack()
	if err != nil {
		destConn.Close()
		return
	}

	_, _ = clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
	go func() {
		defer destConn.Close()
		defer clientConn.Close()
		_, _ = io.Copy(destConn, clientConn)
	}()
	_, _ = io.Copy(clientConn, destConn)
}

// handleHTTPPlain handles plain HTTP proxy requests (GET, POST, etc.).
// Mirrors the working implementation from the old http-proxy.
func (m *MixedProxy) handleHTTPPlain(w http.ResponseWriter, r *http.Request) {
	if !strings.HasPrefix(r.RequestURI, "http") {
		http.Error(w, "only absolute URIs supported", http.StatusBadRequest)
		return
	}

	client := &http.Client{
		Transport: &http.Transport{
			DialContext: func(dialCtx context.Context, network, addr string) (net.Conn, error) {
				h, p, err := net.SplitHostPort(addr)
				if err != nil {
					return nil, fmt.Errorf("invalid address: %w", err)
				}
				dnsCtx, dnsCancel := context.WithTimeout(context.Background(), 45*time.Second)
				defer dnsCancel()
				ips, err := m.resolver.LookupIP(dnsCtx, "ip", h)
				if err != nil || len(ips) == 0 {
					log.Printf("[Warp] HTTP plain: DNS failed for %s: %v", h, err)
					return nil, fmt.Errorf("DNS failed for %s: %w", h, err)
				}
				return m.tunNet.DialContext(dialCtx, network, net.JoinHostPort(ips[0].String(), p))
			},
		},
	}

	req, err := http.NewRequestWithContext(r.Context(), r.Method, r.URL.String(), r.Body)
	if err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	req.Header = r.Header.Clone()

	resp, err := client.Do(req)
	if err != nil {
		log.Printf("[Warp] HTTP plain: upstream error for %s: %v", r.URL.Host, err)
		http.Error(w, fmt.Sprintf("upstream error: %v", err), http.StatusServiceUnavailable)
		return
	}
	defer resp.Body.Close()

	for k, vv := range resp.Header {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

// peekedConn wraps a net.Conn and re-injects already-read bytes into the stream.
type peekedConn struct {
	net.Conn
	buf    []byte
	offset int
}

func (p *peekedConn) Read(b []byte) (int, error) {
	if p.offset < len(p.buf) {
		n := copy(b, p.buf[p.offset:])
		p.offset += n
		return n, nil
	}
	return p.Conn.Read(b)
}

// oneConnListener serves a single pre-accepted connection to http.Server.Serve.
type oneConnListener struct {
	conn net.Conn
	done chan struct{}
}

func (l *oneConnListener) Accept() (net.Conn, error) {
	if l.done == nil {
		l.done = make(chan struct{})
		return l.conn, nil
	}
	<-l.done
	return nil, fmt.Errorf("oneConnListener: done")
}

func (l *oneConnListener) Close() error {
	if l.done != nil {
		close(l.done)
	}
	return nil
}

func (l *oneConnListener) Addr() net.Addr { return l.conn.LocalAddr() }
