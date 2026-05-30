package main

import (
	"fmt"
	"maps"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/fatih/color"
	probing "github.com/prometheus-community/pro-bing"
	utls "github.com/refraction-networking/utls"
)

type ResultRow struct {
	Addr     string
	Port     int
	Domain   string
	MinRTT   time.Duration
	Latency  int64
	Jitter   float64
	Download float64
	Err      error
}

type IPChecker struct {
	config *Conf
}

func NewIPChecker(conf *Conf) *IPChecker {
	return &IPChecker{
		config: conf,
	}
}

// CheckIP performs ping validation on an IP address
// Returns minimum RTT if ping passes, -1 on failure
func (ic *IPChecker) CheckIP(ip string) (time.Duration, error) {
	if !ic.config.Ping.Enable {
		return time.Millisecond, nil
	}

	pinger := probing.New(ip)
	if ic.config.Interface != "" {
		pinger.InterfaceName = ic.config.Interface
	}
	pinger.SetPrivileged(ic.config.Ping.Privileged)
	pinger.Size = randomRange(ic.config.Ping.Size)
	pinger.Timeout = time.Duration(ic.config.Ping.MaxPing) * time.Millisecond
	pinger.Count = 1

	if err := pinger.Run(); err != nil {
		if ic.config.LogErr {
			color.Red("PING: %s", err)
		}
		return -1, err
	}

	stats := pinger.Statistics()
	if stats.PacketLoss > 0 || stats.MinRtt > time.Duration(ic.config.Ping.MaxPing)*time.Millisecond {
		if ic.config.LogErr {
			color.Red("PING: %s\t%s\n", ip, stats.MinRtt)
		}
		return -1, fmt.Errorf("ping failed: loss=%v, rtt=%v", stats.PacketLoss, stats.MinRtt)
	}

	return stats.AvgRtt, nil
}

type HTTPScanner struct {
	config      *Conf
	fingerprint utls.ClientHelloID
	ifaceIP     net.IP
	ipChecker   *IPChecker
}

func NewHTTPScanner(conf *Conf, fingerprint utls.ClientHelloID, ifaceIP net.IP, checker *IPChecker) *HTTPScanner {
	return &HTTPScanner{
		config:      conf,
		fingerprint: fingerprint,
		ifaceIP:     ifaceIP,
		ipChecker:   checker,
	}
}

// getHTTPClient initializes the appropriate HTTP client based on config
func (hs *HTTPScanner) getHTTPClient(sni *string) (*http.Client, error) {
	if !hs.config.TLS.Enable {
		return http.DefaultClient, nil
	}

	if hs.config.HTTP3 {
		return h3transporter(hs.config, sni, nil), nil
	}

	if !hs.config.TLS.Utls.Enable {
		return tlsTransporter(hs.config, sni), nil
	}

	return http.DefaultClient, nil
}

// getUTLSClient initializes uTLS client if needed
func (hs *HTTPScanner) getUTLSClient(sni, addr string, port int) (*http.Client, error) {
	if !hs.config.TLS.Utls.Enable || !hs.config.TLS.Enable || hs.config.HTTP3 {
		return nil, nil
	}

	return utlsTransporter(hs.config, hs.fingerprint, sni, addr+":"+strconv.Itoa(port), hs.ifaceIP)
}

// buildRequest constructs an HTTP request for the target
func (hs *HTTPScanner) buildRequest(addr string, port int, hostname, scheme string) *http.Request {
	host := hostname
	if strings.Contains(hs.config.Hostname, "{ip}") {
		host = addr
	}

	req := &http.Request{
		Method: "GET",
		URL:    &url.URL{Scheme: scheme, Host: addr + ":" + strconv.Itoa(port), Path: hs.config.Path},
		Host:   host,
	}
	req.Header = maps.Clone(hs.config.Headers)
	req.Header.Set("Host", host)

	if hs.config.Padding {
		req.Header.Set("Cookie", RandomString(hs.config.PaddingSize))
	}

	return req
}

// isResponseValid checks if response matches expected status and headers
func (hs *HTTPScanner) isResponseValid(resp *http.Response) bool {
	return slices.Contains(hs.config.ResponseStatusCode, resp.StatusCode) &&
		match(resp.Header, hs.config.ResponseHeader)
}

// scanJitter measures latency variance
func (hs *HTTPScanner) scanJitter(client *http.Client, req *http.Request) (float64, error) {
	if !hs.config.Jitter.Enable {
		return -1, nil
	}

	latencies := make([]float64, 0, hs.config.Jitter.Samples)

	for range hs.config.Jitter.Samples {
		start := time.Now()
		_, err := client.Do(req)
		elapsed := time.Since(start).Milliseconds()

		if err != nil {
			return -1, fmt.Errorf("jitter scan failed: %w", err)
		}

		latencies = append(latencies, float64(elapsed))

		if hs.config.Jitter.Interval > 0 {
			time.Sleep(time.Millisecond * time.Duration(hs.config.Jitter.Interval))
		}
	}

	return Calc_jitter(latencies), nil
}

// scanTarget performs a complete scan on a single IP:port pair
func (hs *HTTPScanner) scanTarget(
	addr string, port int,
	domain, hostname string,
	sni *string,
	scheme string,
) ResultRow {
	// Check IP connectivity
	minRTT, pingErr := hs.ipChecker.CheckIP(addr)
	if pingErr != nil {
		return ResultRow{
			Addr:     addr,
			Port:     port,
			Domain:   domain,
			MinRTT:   minRTT,
			Latency:  -1,
			Jitter:   -1,
			Download: -1,
			Err:      pingErr,
		}
	}

	// Get HTTP client
	client, err := hs.getHTTPClient(sni)
	if err != nil {
		return ResultRow{
			Addr:     addr,
			Port:     port,
			Domain:   domain,
			MinRTT:   minRTT,
			Latency:  -1,
			Jitter:   -1,
			Download: -1,
			Err:      err,
		}
	}

	// Try uTLS if configured
	if utlsClient, utlsErr := hs.getUTLSClient(*sni, addr, port); utlsErr != nil {
		return ResultRow{
			Addr:     addr,
			Port:     port,
			Domain:   domain,
			MinRTT:   minRTT,
			Latency:  -1,
			Jitter:   -1,
			Download: -1,
			Err:      utlsErr,
		}
	} else if utlsClient != nil {
		client = utlsClient
	}

	client.Timeout = time.Millisecond * time.Duration(hs.config.Maxlatency)

	// Send HTTP request
	req := hs.buildRequest(addr, port, hostname, scheme)
	start := time.Now()
	resp, httpErr := client.Do(req)
	latency := time.Since(start).Milliseconds()

	if httpErr != nil {
		return ResultRow{
			Addr:     addr,
			Port:     port,
			Domain:   domain,
			MinRTT:   minRTT,
			Latency:  latency,
			Jitter:   -1,
			Download: -1,
			Err:      httpErr,
		}
	}
	defer resp.Body.Close()

	// Check response validity
	if !hs.isResponseValid(resp) {
		return ResultRow{
			Addr:     addr,
			Port:     port,
			Domain:   domain,
			MinRTT:   minRTT,
			Latency:  latency,
			Jitter:   -1,
			Download: -1,
			Err:      fmt.Errorf("HTTP.StatusCode=%d", resp.StatusCode),
		}
	}

	// Scan jitter
	jitter, jitterErr := hs.scanJitter(client, req)
	if jitterErr != nil {
		return ResultRow{
			Addr:     addr,
			Port:     port,
			Domain:   domain,
			MinRTT:   minRTT,
			Latency:  latency,
			Jitter:   jitter,
			Download: -1,
			Err:      jitterErr,
		}
	}

	// Download test
	var downloadTestResult float64
	var downloadErr error
	if hs.config.DownloadTest.Enable {
		downloadTestResult, downloadErr = downloadTest(client, hs.config, addr+":"+strconv.Itoa(port), hs.ifaceIP, hs.fingerprint)
	}

	return ResultRow{
		Addr:     addr,
		Port:     port,
		Domain:   domain,
		MinRTT:   minRTT,
		Latency:  latency,
		Jitter:   jitter,
		Download: downloadTestResult,
		Err:      downloadErr,
	}
}
