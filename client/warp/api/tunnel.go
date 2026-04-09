package api

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"math/big"
	"net"
	"sync"
	"sync/atomic"
	"time"

	connectip "github.com/Diniboy1123/connect-ip-go"
	"github.com/cacggghp/vk-turn-proxy/client/warp/internal"
	"github.com/songgao/water"
	"golang.zx2c4.com/wireguard/tun"
)

// Verbose controls whether diagnostic logs like tunnel stats are printed.
var Verbose bool

// NetBuffer is a pool of byte slices with a fixed capacity.
// Helps to reduce memory allocations and improve performance.
// It uses a sync.Pool to manage the byte slices.
// The capacity of the byte slices is set when the pool is created.
type NetBuffer struct {
	capacity int
	buf      sync.Pool
}

// Get returns a byte slice from the pool.
func (n *NetBuffer) Get() []byte {
	return *(n.buf.Get().(*[]byte))
}

// Put places a byte slice back into the pool.
// It checks if the capacity of the byte slice matches the pool's capacity.
// If it doesn't match, the byte slice is not returned to the pool.
func (n *NetBuffer) Put(buf []byte) {
	if cap(buf) != n.capacity {
		return
	}
	n.buf.Put(&buf)
}

// NewNetBuffer creates a new NetBuffer with the specified capacity.
// The capacity must be greater than 0.
func NewNetBuffer(capacity int) *NetBuffer {
	if capacity <= 0 {
		panic("capacity must be greater than 0")
	}
	return &NetBuffer{
		capacity: capacity,
		buf: sync.Pool{
			New: func() interface{} {
				b := make([]byte, capacity)
				return &b
			},
		},
	}
}

// TunnelDevice abstracts a TUN device so that we can use the same tunnel-maintenance code
// regardless of the underlying implementation.
type TunnelDevice interface {
	// ReadPacket reads a packet from the device (using the given mtu) and returns its contents.
	ReadPacket(buf []byte) (int, error)
	// WritePacket writes a packet to the device.
	WritePacket(pkt []byte) error
}

// NetstackAdapter wraps a tun.Device (e.g. from netstack) to satisfy TunnelDevice.
type NetstackAdapter struct {
	dev             tun.Device
	tunnelBufPool   sync.Pool
	tunnelSizesPool sync.Pool
}

func (n *NetstackAdapter) ReadPacket(buf []byte) (int, error) {
	packetBufsPtr := n.tunnelBufPool.Get().(*[][]byte)
	sizesPtr := n.tunnelSizesPool.Get().(*[]int)

	defer func() {
		(*packetBufsPtr)[0] = nil
		n.tunnelBufPool.Put(packetBufsPtr)
		n.tunnelSizesPool.Put(sizesPtr)
	}()

	(*packetBufsPtr)[0] = buf
	(*sizesPtr)[0] = 0

	_, err := n.dev.Read(*packetBufsPtr, *sizesPtr, 0)
	if err != nil {
		return 0, err
	}

	return (*sizesPtr)[0], nil
}

func (n *NetstackAdapter) WritePacket(pkt []byte) error {
	// Write expects a slice of packet buffers.
	_, err := n.dev.Write([][]byte{pkt}, 0)
	return err
}

// NewNetstackAdapter creates a new NetstackAdapter.
func NewNetstackAdapter(dev tun.Device) TunnelDevice {
	return &NetstackAdapter{
		dev: dev,
		tunnelBufPool: sync.Pool{
			New: func() interface{} {
				buf := make([][]byte, 1)
				return &buf
			},
		},
		tunnelSizesPool: sync.Pool{
			New: func() interface{} {
				sizes := make([]int, 1)
				return &sizes
			},
		},
	}
}

// WaterAdapter wraps a *water.Interface so it satisfies TunnelDevice.
type WaterAdapter struct {
	iface *water.Interface
}

func (w *WaterAdapter) ReadPacket(buf []byte) (int, error) {
	n, err := w.iface.Read(buf)
	if err != nil {
		return 0, err
	}

	return n, nil
}

func (w *WaterAdapter) WritePacket(pkt []byte) error {
	_, err := w.iface.Write(pkt)
	return err
}

// NewWaterAdapter creates a new WaterAdapter.
func NewWaterAdapter(iface *water.Interface) TunnelDevice {
	return &WaterAdapter{iface: iface}
}

// GetRelayConnFunc is a function type that returns a pre-allocated packet connection
// for use as a TURN relay (e.g. from VK TURN). If nil is provided, a direct UDP
// connection to the MASQUE endpoint will be created.
type GetRelayConnFunc func(ctx context.Context) (net.PacketConn, error)

// MaintainTunnel continuously connects to the MASQUE server, then starts two
// forwarding goroutines: one forwarding from the device to the IP connection (and handling
// any ICMP reply), and the other forwarding from the IP connection to the device.
// If an error occurs in either loop, the connection is closed and a reconnect is attempted.
//
// Parameters:
//   - ctx: context.Context - The context for the connection.
//   - tlsConfig: *tls.Config - The TLS configuration for secure communication.
//   - keepalivePeriod: time.Duration - The keepalive period for the QUIC connection.
//   - initialPacketSize: uint16 - The initial packet size for the QUIC connection.
//   - endpoint: *net.UDPAddr - The UDP address of the MASQUE server.
//   - device: TunnelDevice - The TUN device to forward packets to and from.
//   - mtu: int - The MTU of the TUN device.
//   - reconnectDelay: time.Duration - The delay between reconnect attempts.
//   - getRelayConn: GetRelayConnFunc - Optional function to obtain a TURN relay connection.
//     If nil, a direct UDP connection to the endpoint is used.
//   - onReady: func(bool) - Optional callback fired with true when connected, and false when disconnected.
func MaintainTunnel(ctx context.Context, tlsConfig *tls.Config, keepalivePeriod time.Duration, initialPacketSize uint16, endpoint *net.UDPAddr, device TunnelDevice, mtu int, reconnectDelay time.Duration, getRelayConn GetRelayConnFunc, onReady func(bool)) {
	packetBufferPool := NewNetBuffer(mtu)
	for {
		// Check if context is done before attempting connection
		select {
		case <-ctx.Done():
			return
		default:
		}

		log.Printf("Establishing MASQUE connection to %s:%d", endpoint.IP, endpoint.Port)

		// Optionally obtain a TURN relay packet connection
		var baseConn net.PacketConn
		if getRelayConn != nil {
			var err error
			baseConn, err = getRelayConn(ctx)
			if err != nil {
				log.Printf("Failed to obtain TURN relay connection: %v", err)
				select {
				case <-ctx.Done():
					return
				case <-time.After(reconnectDelay):
				}
				continue
			}
		}

		udpConn, tr, ipConn, rsp, err := ConnectTunnel(
			ctx,
			tlsConfig,
			internal.DefaultQuicConfig(keepalivePeriod, initialPacketSize),
			internal.ConnectURI,
			endpoint,
			baseConn,
		)
		if err != nil {
			log.Printf("Failed to connect tunnel: %v", err)
			if udpConn != nil {
				udpConn.Close()
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(reconnectDelay):
			}
			continue
		}
		if rsp.StatusCode != 200 {
			log.Printf("Tunnel connection failed: %s", rsp.Status)
			ipConn.Close()
			if udpConn != nil {
				udpConn.Close()
			}
			if tr != nil {
				tr.Close()
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(reconnectDelay):
			}
			continue
		}

		log.Println("Connected to MASQUE server")
		if onReady != nil {
			onReady(true)
		}
		errChan := make(chan error, 2)

		// Packet counters for diagnostics
		var txPkts, rxPkts atomic.Int64
		go func() {
			ticker := time.NewTicker(10 * time.Second)
			defer ticker.Stop()
			for {
				select {
				case <-ticker.C:
					if Verbose {
						log.Printf("[Warp] Tunnel stats: TX=%d pkts, RX=%d pkts", txPkts.Load(), rxPkts.Load())
					}
				case <-ctx.Done():
					return
				}
			}
		}()

		go func() {
			for {
				buf := packetBufferPool.Get()
				n, err := device.ReadPacket(buf)
				if err != nil {
					packetBufferPool.Put(buf)
					errChan <- fmt.Errorf("failed to read from TUN device: %v", err)
					return
				}
				txPkts.Add(1)

				paddedSize := n
				if n < mtu-100 {
					randOffset, _ := rand.Int(rand.Reader, big.NewInt(64))
					paddedSize = n + int(randOffset.Int64())
					if paddedSize > mtu {
						paddedSize = mtu
					}
					if paddedSize > n {
						_, _ = rand.Read(buf[n:paddedSize])
					}
				}

				icmp, err := ipConn.WritePacket(buf[:paddedSize])
				if err != nil {
					packetBufferPool.Put(buf)
					if errors.As(err, new(*connectip.CloseError)) {
						errChan <- fmt.Errorf("connection closed while writing to IP connection: %v", err)
						return
					}
					log.Printf("Error writing to IP connection: %v, continuing...", err)
					continue
				}
				packetBufferPool.Put(buf)

				if len(icmp) > 0 {
					if err := device.WritePacket(icmp); err != nil {
						if errors.As(err, new(*connectip.CloseError)) {
							errChan <- fmt.Errorf("connection closed while writing ICMP to TUN device: %v", err)
							return
						}
						log.Printf("Error writing ICMP to TUN device: %v, continuing...", err)
					}
				}
			}
		}()

		go func() {
			buf := packetBufferPool.Get()
			defer packetBufferPool.Put(buf)
			for {
				n, err := ipConn.ReadPacket(buf, true)
				if err != nil {
					if errors.As(err, new(*connectip.CloseError)) {
						errChan <- fmt.Errorf("connection closed while reading from IP connection: %v", err)
						return
					}
					log.Printf("Error reading from IP connection: %v, continuing...", err)
					continue
				}
				rxPkts.Add(1)
				if err := device.WritePacket(buf[:n]); err != nil {
					errChan <- fmt.Errorf("failed to write to TUN device: %v", err)
					return
				}
			}
		}()

		err = <-errChan
		if onReady != nil {
			onReady(false)
		}
		log.Printf("Tunnel connection lost: %v. Reconnecting...", err)
		ipConn.Close()
		if udpConn != nil {
			udpConn.Close()
		}
		if tr != nil {
			tr.Close()
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(reconnectDelay):
		}
	}
}
