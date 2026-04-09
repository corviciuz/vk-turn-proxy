package api

import (
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"

	connectip "github.com/Diniboy1123/connect-ip-go"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/yosida95/uritemplate/v3"
)

// fixedPeerConn wraps a net.PacketConn and makes it behave like a point-to-point
// connection to a fixed peer (e.g. the Cloudflare MASQUE endpoint).
// This is critical when using a TURN relay as the QUIC transport: the relay
// conn knows how to send/receive via TURN indications, but quic-go needs
// the connection to look like a direct pipe to the remote.
// Matches the fixedPeerConn from the working vk-turn-usque-old implementation.
type fixedPeerConn struct {
	net.PacketConn
	peer net.Addr
}

func (c *fixedPeerConn) Write(p []byte) (n int, err error) {
	return c.PacketConn.WriteTo(p, c.peer)
}

func (c *fixedPeerConn) Read(p []byte) (n int, err error) {
	n, _, err = c.PacketConn.ReadFrom(p)
	return n, err
}

func (c *fixedPeerConn) RemoteAddr() net.Addr {
	return c.peer
}

// PrepareTlsConfig creates a TLS configuration using the provided certificate and SNI (Server Name Indication).
// It also verifies the peer's public key against the provided public key.
//
// Parameters:
//   - privKey: *ecdsa.PrivateKey - The private key to use for TLS authentication.
//   - peerPubKey: *ecdsa.PublicKey - The endpoint's public key to pin to.
//   - cert: [][]byte - The certificate chain to use for TLS authentication.
//   - sni: string - The Server Name Indication (SNI) to use.
//
// Returns:
//   - *tls.Config: A TLS configuration for secure communication.
//   - error: An error if TLS setup fails.
func PrepareTlsConfig(privKey *ecdsa.PrivateKey, peerPubKey *ecdsa.PublicKey, cert [][]byte, sni string) (*tls.Config, error) {
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{
			{
				Certificate: cert,
				PrivateKey:  privKey,
			},
		},
		ServerName: sni,
		NextProtos: []string{http3.NextProtoH3},
		MinVersion: tls.VersionTLS12,
		MaxVersion: tls.VersionTLS13,
		CurvePreferences: []tls.CurveID{
			tls.X25519,
			tls.CurveP256,
		},
		CipherSuites: []uint16{
			tls.TLS_AES_128_GCM_SHA256,
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
		},
		// WARN: SNI is usually not for the endpoint, so we must skip verification
		InsecureSkipVerify: true,
		// we pin to the endpoint public key
		VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return nil
			}

			cert, err := x509.ParseCertificate(rawCerts[0])
			if err != nil {
				return err
			}

			if _, ok := cert.PublicKey.(*ecdsa.PublicKey); !ok {
				// we only support ECDSA
				// TODO: don't hardcode cert type in the future
				// as backend can start using different cert types
				return x509.ErrUnsupportedAlgorithm
			}

			if !cert.PublicKey.(*ecdsa.PublicKey).Equal(peerPubKey) {
				// reason is incorrect, but the best I could figure
				// detail explains the actual reason

				//10 is NoValidChains, but we support go1.22 where it's not defined
				return x509.CertificateInvalidError{Cert: cert, Reason: 10, Detail: "remote endpoint has a different public key than what we trust in config.json"}
			}

			return nil
		},
	}

	return tlsConfig, nil
}

// ConnectTunnel establishes a QUIC connection and sets up a Connect-IP tunnel with the provided endpoint.
// Endpoint address is used to check whether the authentication/connection is successful or not.
// Requires modified connect-ip-go for now to support Cloudflare's non RFC compliant implementation.
//
// Parameters:
//   - ctx: context.Context - The QUIC TLS context.
//   - tlsConfig: *tls.Config - The TLS configuration for secure communication.
//   - quicConfig: *quic.Config - The QUIC configuration settings.
//   - connectUri: string - The URI template for the Connect-IP request.
//   - endpoint: *net.UDPAddr - The UDP address of the QUIC server.
//   - baseConn: net.PacketConn - Optional pre-allocated connection (e.g. from VK TURN relay). If nil, a new UDP socket is created.
//
// Returns:
//   - net.PacketConn: The packet connection used for the QUIC session.
//   - *http3.Transport: The HTTP/3 transport used for initial request.
//   - *connectip.Conn: The Connect-IP connection instance.
//   - *http.Response: The response from the Connect-IP handshake.
//   - error: An error if the connection setup fails.
func ConnectTunnel(ctx context.Context, tlsConfig *tls.Config, quicConfig *quic.Config, connectUri string, endpoint *net.UDPAddr, baseConn net.PacketConn) (net.PacketConn, *http3.Transport, *connectip.Conn, *http.Response, error) {
	var conn net.PacketConn
	var err error

	if baseConn != nil {
		// Wrap the TURN relay conn in fixedPeerConn so quic-go sees it as a
		// point-to-point connection to the Cloudflare endpoint.
		// Without this wrapping, some QUIC packet flows don't survive the
		// TURN relay hop (e.g. keepalives and connect-ip IP packets time out).
		conn = &fixedPeerConn{PacketConn: baseConn, peer: endpoint}
	} else {
		// Create a new UDP socket for direct connection to the Cloudflare MASQUE endpoint
		var udpConn *net.UDPConn
		if endpoint.IP.To4() == nil {
			udpConn, err = net.ListenUDP("udp", &net.UDPAddr{
				IP:   net.IPv6zero,
				Port: 0,
			})
		} else {
			udpConn, err = net.ListenUDP("udp", &net.UDPAddr{
				IP:   net.IPv4zero,
				Port: 0,
			})
		}
		if err != nil {
			return nil, nil, nil, nil, err
		}
		conn = udpConn
	}

	qconn, err := quic.Dial(
		ctx,
		conn,
		endpoint,
		tlsConfig,
		quicConfig,
	)
	if err != nil {
		return conn, nil, nil, nil, err
	}

	tr := &http3.Transport{
		EnableDatagrams: true,
		AdditionalSettings: map[uint64]uint64{
			// SETTINGS_H3_DATAGRAM (current IETF RFC 9297) - required by Cloudflare
			0x33: 1,
			// SETTINGS_H3_DATAGRAM_00 (deprecated draft, but official client still sends it)
			0x276: 1,
		},
		DisableCompression: true,
	}

	hconn := tr.NewClientConn(qconn)

	additionalHeaders := http.Header{
		"User-Agent": []string{""},
	}

	template := uritemplate.MustNew(connectUri)
	ipConn, rsp, err := connectip.Dial(ctx, hconn, template, "cf-connect-ip", additionalHeaders, true)
	if err != nil {
		if err.Error() == "CRYPTO_ERROR 0x131 (remote): tls: access denied" {
			return conn, nil, nil, nil, errors.New("login failed! Please double-check if your tls key and cert is enrolled in the Cloudflare Access service")
		}
		return conn, nil, nil, nil, fmt.Errorf("failed to dial connect-ip: %v", err)
	}

	return conn, tr, ipConn, rsp, nil
}
