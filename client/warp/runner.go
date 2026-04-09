// Package warp provides the Warp (MASQUE/Cloudflare) mode runner for the vk-turn-proxy client.
// It is activated by the -warp flag in the main binary and reuses existing vk-turn flags
// for VK TURN relay integration (-vk-link, -listen, etc.).
package warp

import (
	"context"
	"encoding/base64"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/cacggghp/vk-turn-proxy/client/warp/api"
	"github.com/cacggghp/vk-turn-proxy/client/warp/config"
	"github.com/cacggghp/vk-turn-proxy/client/warp/internal"
	"github.com/cacggghp/vk-turn-proxy/client/warp/proxy"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

// RunnerConfig holds all parameters needed to start the Warp mode.
type RunnerConfig struct {
	// ConfigPath is the path to the Warp config.json.
	// If empty and the file is not found at the default path, registration is triggered.
	ConfigPath string
	// ProxyAddr is the address for the mixed SOCKS5/HTTP proxy (e.g. "127.0.0.1:4080").
	ProxyAddr string
	// GetRelayConn is an optional function that provides a pre-allocated TURN relay connection.
	// If nil, Warp connects directly to Cloudflare's MASQUE endpoint.
	GetRelayConn api.GetRelayConnFunc
	// ConnectPort is the port for the MASQUE QUIC connection (default 443).
	ConnectPort int
	// UseIPv6 selects the IPv6 endpoint instead of IPv4 for the MASQUE connection.
	UseIPv6 bool
	// KeepalivePeriod is the QUIC keepalive interval.
	KeepalivePeriod time.Duration
	// InitialPacketSize is the initial QUIC packet size.
	InitialPacketSize uint16
	// ReconnectDelay is the delay between tunnel reconnect attempts.
	ReconnectDelay time.Duration
	// MTU is the MTU for the virtual TUN device.
	MTU int
	// LocalDNS skips tunnel DNS and uses the system resolver.
	// Useful when 162.159.36.1 is unreachable over the TURN relay.
	LocalDNS bool
	// Debug enables verbose logging in the warp/api package.
	Debug bool
}

// DefaultRunnerConfig returns a RunnerConfig with sensible defaults.
func DefaultRunnerConfig() RunnerConfig {
	return RunnerConfig{
		ConfigPath:        "config.json",
		ProxyAddr:         "127.0.0.1:4080",
		ConnectPort:       443,
		UseIPv6:           false,
		KeepalivePeriod:   30 * time.Second,
		InitialPacketSize: 1242,
		ReconnectDelay:    1 * time.Second,
		MTU:               1200, // Lowered to avoid fragmentation over TURN relay
	}
}

// Run starts the Warp-in-VK-TURN mode.
// It handles config loading/registration, then starts the MASQUE tunnel and mixed proxy.
func Run(ctx context.Context, cfg RunnerConfig) error {
	// 1. Resolve config path to absolute
	cfgPath, err := resolveConfigPath(cfg.ConfigPath)
	if err != nil {
		return fmt.Errorf("warp: resolve config path: %w", err)
	}

	// 2. Try to load config
	if err := config.LoadConfig(cfgPath); err != nil {
		if cfg.ConfigPath != "" && cfg.ConfigPath != "config.json" {
			// User explicitly specified a config path — error out
			return fmt.Errorf("warp: config file not found at %s: %w", cfgPath, err)
		}
		// Default path not found — start interactive registration
		log.Printf("[Warp] Config not found at %s. Starting registration...", cfgPath)
		if err := runInteractiveRegistration(cfgPath); err != nil {
			return fmt.Errorf("warp: registration failed: %w", err)
		}
	}

	// 3. Prepare TLS keys from config
	privKey, err := config.AppConfig.GetEcPrivateKey()
	if err != nil {
		return fmt.Errorf("warp: get private key: %w", err)
	}
	peerPubKey, err := config.AppConfig.GetEcEndpointPublicKey()
	if err != nil {
		return fmt.Errorf("warp: get peer public key: %w", err)
	}
	cert, err := internal.GenerateCert(privKey, &privKey.PublicKey)
	if err != nil {
		return fmt.Errorf("warp: generate cert: %w", err)
	}

	tlsConfig, err := api.PrepareTlsConfig(privKey, peerPubKey, cert, internal.ConnectSNI)
	if err != nil {
		return fmt.Errorf("warp: prepare TLS config: %w", err)
	}

	// 4. Determine MASQUE endpoint
	connectPort := cfg.ConnectPort
	if connectPort <= 0 {
		connectPort = 443
	}
	var endpoint *net.UDPAddr
	if cfg.UseIPv6 {
		addr := net.JoinHostPort(config.AppConfig.EndpointV6, fmt.Sprint(connectPort))
		endpoint, err = net.ResolveUDPAddr("udp", addr)
		if err != nil {
			return fmt.Errorf("warp: resolve IPv6 endpoint: %w", err)
		}
	} else {
		addr := net.JoinHostPort(config.AppConfig.EndpointV4, fmt.Sprint(connectPort))
		endpoint, err = net.ResolveUDPAddr("udp", addr)
		if err != nil {
			return fmt.Errorf("warp: resolve IPv4 endpoint: %w", err)
		}
		if ip4 := endpoint.IP.To4(); ip4 != nil {
			endpoint.IP = ip4
		}
	}

	// DNS addresses: Cloudflare WARP intentionally blocks/drops most regular UDP port 53 traffic 
	// over MASQUE tunnels to public servers (like 9.9.9.9 or 1.1.1.1) to enforce their DoH proxy.
	// You MUST use their internal designated DNS forwarder: 162.159.36.1
	dnsAddrs := []netip.Addr{
		netip.MustParseAddr("162.159.36.1"),
		netip.MustParseAddr("1.1.1.1"),
		netip.MustParseAddr("1.0.0.1"),
	}
	var localAddresses []netip.Addr
	parseInternalIP := func(s string) (netip.Addr, error) {
		// Strip mask if present (e.g. 172.16.0.2/32)
		if i := strings.Index(s, "/"); i != -1 {
			s = s[:i]
		}
		return netip.ParseAddr(s)
	}
	if v4, err := parseInternalIP(config.AppConfig.IPv4); err == nil {
		localAddresses = append(localAddresses, v4)
	}
	if v6, err := parseInternalIP(config.AppConfig.IPv6); err == nil {
		localAddresses = append(localAddresses, v6)
	}

	api.Verbose = cfg.Debug
	tunDev, tunNet, err := netstack.CreateNetTUN(localAddresses, dnsAddrs, cfg.MTU)
	if err != nil {
		return fmt.Errorf("warp: create virtual TUN: %w", err)
	}
	defer tunDev.Close()

	// 6. Init mixed proxy so we can pass its SetReady callback
	mp := proxy.NewMixedProxy(cfg.ProxyAddr, tunNet, dnsAddrs, cfg.LocalDNS)

	// 7. Start tunnel maintenance in background
	log.Printf("[Warp] Starting MASQUE tunnel to %s (via TURN: %v)", endpoint, cfg.GetRelayConn != nil)
	go api.MaintainTunnel(
		ctx,
		tlsConfig,
		cfg.KeepalivePeriod,
		cfg.InitialPacketSize,
		endpoint,
		api.NewNetstackAdapter(tunDev),
		cfg.MTU,
		cfg.ReconnectDelay,
		cfg.GetRelayConn,
		mp.SetReady,
	)

	// 8. Start mixed proxy listener (blocks until cancelled)
	// Both SOCKS5 and HTTP resolve DNS through the MASQUE tunnel via TunnelDNSResolver,
	// then dial tunNet with the resolved IP — matching the working httpproxy.go pattern.
	return mp.ListenAndServe(ctx)
}

// resolveConfigPath returns the absolute path for the config file.
// If the path is relative, it is resolved relative to the executable's directory.
func resolveConfigPath(cfgPath string) (string, error) {
	if filepath.IsAbs(cfgPath) {
		return cfgPath, nil
	}
	// Try CWD first
	if _, err := os.Stat(cfgPath); err == nil {
		abs, err := filepath.Abs(cfgPath)
		if err != nil {
			return "", err
		}
		return abs, nil
	}
	// Fall back to executable directory (useful on Android/embedded)
	exePath, err := os.Executable()
	if err != nil {
		return cfgPath, nil //nolint:nilerr — best effort
	}
	return filepath.Join(filepath.Dir(exePath), cfgPath), nil
}

// runInteractiveRegistration runs the interactive Cloudflare WARP registration flow.
// It asks the user to accept TOS and choose a device name, then saves the config.
func runInteractiveRegistration(cfgPath string) error {
	log.Printf("[Warp] === Cloudflare WARP Registration ===")

	// Register (will prompt for TOS internally inside api.Register)
	accountData, err := api.Register(internal.DefaultModel, internal.DefaultLocale, "", false /* acceptTos — prompt inside */)
	if err != nil {
		return fmt.Errorf("register: %w", err)
	}

	fmt.Print("[Warp] Enter device name (leave empty for default): ")
	var deviceName string
	_, _ = fmt.Scanln(&deviceName)

	privKey, pubKey, err := internal.GenerateEcKeyPair()
	if err != nil {
		return fmt.Errorf("generate key pair: %w", err)
	}

	log.Printf("[Warp] Enrolling device key...")
	updatedAccountData, apiErr, err := api.EnrollKey(accountData, pubKey, deviceName)
	if err != nil {
		if apiErr != nil {
			return fmt.Errorf("enroll key: %v (API errors: %s)", err, apiErr.ErrorsAsString("; "))
		}
		return fmt.Errorf("enroll key: %w", err)
	}

	log.Printf("[Warp] Registration successful. Saving config to %s...", cfgPath)
	config.AppConfig = config.Config{
		PrivateKey:     base64.StdEncoding.EncodeToString(privKey),
		EndpointV4:     updatedAccountData.Config.Peers[0].Endpoint.V4[:len(updatedAccountData.Config.Peers[0].Endpoint.V4)-2],
		EndpointV6:     updatedAccountData.Config.Peers[0].Endpoint.V6[1 : len(updatedAccountData.Config.Peers[0].Endpoint.V6)-3],
		EndpointPubKey: updatedAccountData.Config.Peers[0].PublicKey,
		License:        updatedAccountData.Account.License,
		ID:             updatedAccountData.ID,
		AccessToken:    accountData.Token,
		IPv4:           updatedAccountData.Config.Interface.Addresses.V4,
		IPv6:           updatedAccountData.Config.Interface.Addresses.V6,
	}

	if err := config.AppConfig.SaveConfig(cfgPath); err != nil {
		return fmt.Errorf("save config: %w", err)
	}
	config.ConfigLoaded = true
	log.Printf("[Warp] Config saved successfully.")
	return nil
}
