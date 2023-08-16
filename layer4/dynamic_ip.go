package layer4

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"time"

	"github.com/caddyserver/caddy/v2"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(DynamicIP{})
}

type Poller interface {
	Poll(ctx context.Context) ([]netip.Prefix, error)
}

// MatchIP matches requests by remote IP (or CIDR range).
type DynamicIP struct {
	APIEndpoint  string `json:"api_endpoint"`
	APIKey       string `json:"api_key"`
	PollInterval string `json:"poll_interval"`

	poller Poller
	mu     *sync.RWMutex
	cidrs  []netip.Prefix
}

// CaddyModule returns the Caddy module information.
func (DynamicIP) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "layer4.matchers.dynamic_ip",
		New: func() caddy.Module { return new(DynamicIP) },
	}
}

func (d *DynamicIP) Provision(c caddy.Context) (err error) {
	d.poller = NewClient(d.APIEndpoint, d.APIKey)
	d.mu = &sync.RWMutex{}

	pollInterval, err := time.ParseDuration(d.PollInterval)
	if err != nil {
		return fmt.Errorf("Unable to parse poll interval %s: %w", d.PollInterval, err)
	}

	cidrs, err := d.poller.Poll(c)
	if err != nil {
		return fmt.Errorf("Unable to pull initial IP list: %w", err)
	}
	d.cidrs = cidrs

	go d.poll(c, pollInterval)

	return nil
}

// Match returns true if the connection is from one of the designated IP ranges.
func (d DynamicIP) Match(cx *Connection) (bool, error) {
	clientIP, err := d.getClientIP(cx)
	if err != nil {
		return false, fmt.Errorf("getting client IP: %v", err)
	}

	cx.Logger.Info("Handling conn", zap.String("ip", clientIP.String()))

	d.mu.RLock()
	defer d.mu.RUnlock()
	for _, ipRange := range d.cidrs {
		if ipRange.Contains(clientIP) {
			cx.Logger.Info("Match", zap.String("ip", clientIP.String()))
			return true, nil
		}
	}
	cx.Logger.Info("No match", zap.String("ip", clientIP.String()))
	return false, nil
}

func (d DynamicIP) getClientIP(cx *Connection) (netip.Addr, error) {
	remote := cx.Conn.RemoteAddr().String()

	ipStr, _, err := net.SplitHostPort(remote)
	if err != nil {
		ipStr = remote // OK; probably didn't have a port
	}

	return netip.ParseAddr(ipStr)
}

func (d *DynamicIP) poll(ctx caddy.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	logger := ctx.Logger()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			cidrs, err := d.poller.Poll(ctx)
			if err != nil {
				logger.Error("Unable to poll IP", zap.Error(err))
				continue
			}
			logger.Info("Polled successfully", zap.Int("cidrs", len(cidrs)))
			d.mu.Lock()
			d.cidrs = cidrs
			d.mu.Unlock()
		}
	}
}

func NewClient(apiEndpoint, apiKey string) Poller {
	return &client{
		apiEndpoint: apiEndpoint,
		apiKey:      apiKey,
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

type client struct {
	client      *http.Client
	apiEndpoint string
	apiKey      string
}

func (c *client) Poll(ctx context.Context) ([]netip.Prefix, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.apiEndpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Api-Key", c.apiKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Received non-200 status code: %d", resp.StatusCode)
	}

	type ips struct {
		CIDRs []netip.Prefix `json:"cidrs"`
	}

	allowed := &ips{}
	if err := json.NewDecoder(resp.Body).Decode(allowed); err != nil {
		return nil, err
	}
	return allowed.CIDRs, nil
}

var (
	_ ConnMatcher       = (*DynamicIP)(nil)
	_ caddy.Provisioner = (*DynamicIP)(nil)
)
