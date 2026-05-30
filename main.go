package main

import (
	"encoding/json"
	"fmt"
	"log"
	"math/rand"
	"net"
	"os"
	"slices"
	"strings"
	"sync"

	"github.com/fatih/color"

	utls "github.com/refraction-networking/utls"
)

type DS struct {
	Enable         bool   `json:"Enable"`
	DomainAsSNI    bool   `json:"DomainAsSNI"`
	DomainAsHost   bool   `json:"DomainAsHost"`
	SkipIPV6       bool   `json:"SkipIPV6"`
	Shuffle        bool   `json:"Shuffle"`
	DomainListPath string `json:"DomainListPath"`
}

type NoisePacket struct {
	Type    string `json:"Type"`
	Payload string `json:"Payload"`
	Sleep   string `json:"Sleep"`
}

type NoiseConfig struct {
	Enable  bool          `json:"Enable"`
	Packets []NoisePacket `json:"Packets"`
}

type DownloadConfig struct {
	Enable             bool   `json:"Enable"`
	SeparateConnection bool   `json:"SeparateConnection"`
	Url                string `json:"Url"`
	SNI                string `json:"SNI"`
	TargetBytes        int    `json:"TargetBytes"`
	Timeout            int    `json:"Timeout"`
}

type UtlsConfig struct {
	Enable      bool   `json:"Enable"`
	Fingerprint string `json:"Fingerprint"`
	TcpTimeout  int64  `json:"TcpTimeout"`
	TcpRetry    int    `json:"TcpRetry"`
}

type TLSConfig struct {
	Enable   bool       `json:"Enable"`
	SNI      string     `json:"SNI"`
	Insecure bool       `json:"Insecure"`
	Alpn     []string   `json:"Alpn"`
	Utls     UtlsConfig `json:"Utls"`
}

type JitterConfig struct {
	Enable    bool    `json:"Enable"`
	MaxJitter float64 `json:"MaxJitter"`
	Samples   int     `json:"Samples"`
	Interval  int64   `json:"Interval"`
}

type PingConfig struct {
	Enable     bool    `json:"Enable"`
	MaxPing    float64 `json:"MaxPing"`
	Privileged bool    `json:"Privileged"`
	Size       string  `json:"Size"`
}

type Conf struct {
	LogErr             bool                `json:"LogErr"`
	CSV                bool                `json:"CSV"`
	RandomScan         bool                `json:"RandomScan"`
	Interface          string              `json:"Interface"`
	Hostname           string              `json:"Hostname"`
	Ports              []int               `json:"Ports"`
	Path               string              `json:"Path"`
	Headers            map[string][]string `json:"Headers"`
	ResponseHeader     map[string]string   `json:"ResponseHeader"`
	ResponseStatusCode []int               `json:"ResponseStatusCode"`
	Padding            bool                `json:"Padding"`
	PaddingSize        string              `json:"PaddingSize"`
	Ping               PingConfig          `json:"Ping"`
	Goroutines         int                 `json:"Goroutines"`
	Scans              int                 `json:"Scans"`
	Maxlatency         int64               `json:"Maxlatency"`
	Jitter             JitterConfig        `json:"Jitter"`
	IpVersion          int                 `json:"IpVersion"`
	IplistPath         string              `json:"IplistPath"`
	IgnoreRange        []string            `json:"IgnoreRange"`
	AllowRange         []string            `json:"AllowRange"`
	TLS                TLSConfig           `json:"TLS"`
	HTTP3              bool                `json:"HTTP/3"`
	Noises             NoiseConfig         `json:"Noises"`
	DomainScan         DS                  `json:"DomainScan"`
	DownloadTest       DownloadConfig      `json:"DownloadTest"`
}

func main() {
	// load config file
	cfile, cfile_err := os.ReadFile("conf.json")
	if cfile_err != nil {
		log.Fatalln(cfile_err.Error())
	}
	conf := Conf{}
	conf_err := json.Unmarshal(cfile, &conf)
	if conf_err != nil {
		log.Fatalln(conf_err.Error())
	}

	// Download ipv4.txt if not exist
	_, exist := os.Stat("ipv4.txt")
	if exist != nil {
		e := GithubAPI("https://api.github.com/repos/compassvpn/cf-tools/releases/latest", "all_cf_v4.txt", "ipv4.txt")
		if e != nil {
			log.Println("Failed to download ipv4.txt: ", e, "\nFallback to ipv4_old.txt")
			conf.IplistPath = "ipv4_old.txt"
		}
	}

	var ifaceIP net.IP

	ips := make([]string, 0, 256)
	switch conf.IpVersion {
	case 4:
		ifaceIP = net.ParseIP("0.0.0.0")
		// Generate IPs from CIDRs
		color.Yellow("Generating IPs\n")
		GenIPs(&ips, conf.IplistPath, conf.IgnoreRange, conf.AllowRange)
	case 6:
		ifaceIP = net.ParseIP("[::]")
		// Load CIDRs into list and generate random IPv6 during scan
		file, ipListFileErr := os.ReadFile(conf.IplistPath)
		if ipListFileErr != nil {
			log.Fatalln(ipListFileErr)
		}
		ips = strings.Split(string(file), "\n")
	default:
		log.Fatalln("Invalid IP version")
	}

	if conf.Interface != "" {
		iface, getIfaceErr := net.InterfaceByName(conf.Interface)
		if getIfaceErr != nil {
			log.Println(getIfaceErr)
		}

		addrs, getAddrsErr := iface.Addrs()
		if getAddrsErr != nil {
			log.Println(getAddrsErr)
		}

		for _, ip := range addrs {
			ip, _, e := net.ParseCIDR(ip.String())
			if e != nil {
				continue
			}
			switch conf.IpVersion {
			case 4:
				if ip.To4() != nil {
					ifaceIP = ip
				}
			case 6:
				if ip.To4() == nil {
					ifaceIP = ip
				}
			}
		}
	}

	color.Yellow("Interface IP: %s", ifaceIP.String())

	fingerprint := utls.HelloChrome_Auto
	if conf.TLS.Utls.Enable {
		fingerprint = fgen(conf.TLS.Utls.Fingerprint)
	}

	scheme := "http"
	if conf.TLS.Enable {
		scheme = "https"
		if len(conf.Ports) == 0 {
			conf.Ports = append(conf.Ports, 443)
		}
	} else {
		if len(conf.Ports) == 0 {
			conf.Ports = append(conf.Ports, 80)
		}
	}

	LOG := conf.LogErr
	result := make(chan ResultRow, conf.Goroutines)
	color.Green("【ＨＴＴＰ Ｓｃａｎ】\n")

	ipChecker := NewIPChecker(&conf)
	scanner := NewHTTPScanner(&conf, fingerprint, ifaceIP, ipChecker)

	if !conf.DomainScan.Enable {
		// IP-based scanning
		ipCh := make(chan string, conf.Goroutines)

		// Worker goroutines
		for range conf.Goroutines {
			go func() {
				for ip := range ipCh {
					for _, port := range conf.Ports {
						result <- scanner.scanTarget(ip, port, "", conf.Hostname, &conf.TLS.SNI, scheme)
					}
				}
			}()
		}

		// IP producer goroutine
		go func() {
			defer close(ipCh)

			if conf.RandomScan {
				switch conf.IpVersion {
				case 4:
					rand.Shuffle(len(ips), func(i, j int) {
						ips[i], ips[j] = ips[j], ips[i]
					})
					for _, ip := range ips {
						ipCh <- ip
					}
				case 6:
					for {
						ipv6, err := randomIPv6FromCIDR(strings.TrimSpace(ips[rand.Intn(len(ips))]))
						if err != nil {
							continue
						}
						ipCh <- fmt.Sprintf("[%s]", ipv6.String())
					}
				}
			} else {
				if conf.IpVersion != 4 {
					log.Fatalln("linear method is only available for ipv4")
				}
				for _, ip := range ips {
					ipCh <- ip
				}
			}
		}()

	} else {
		// Domain-based scanning
		var wg sync.WaitGroup

		domainListFile, err := os.ReadFile(conf.DomainScan.DomainListPath)
		if err != nil {
			log.Fatalln(err)
		}

		domains := strings.Split(string(domainListFile), "\n")
		if conf.DomainScan.Shuffle {
			rand.Shuffle(len(domains), func(i, j int) {
				domains[i], domains[j] = domains[j], domains[i]
			})
		}

		for domainsChunk := range slices.Chunk(domains, len(domains)/conf.Goroutines) {
			wg.Add(1)
			go func(chunk []string) {
				defer wg.Done()

				for _, domain := range chunk {
					domain = strings.TrimSpace(domain)
					resolvedIPs, resolveErr := net.LookupIP(domain)
					if resolveErr != nil {
						log.Println(resolveErr)
						continue
					}

					for _, ip := range resolvedIPs {
						// Skip IPv6 if configured
						if conf.DomainScan.SkipIPV6 && ip.To4() == nil && ip.To16() != nil {
							continue
						}

						for _, port := range conf.Ports {
							host := conf.Hostname
							if conf.DomainScan.DomainAsHost {
								host = domain
							}

							sni := conf.TLS.SNI
							if conf.DomainScan.DomainAsSNI {
								sni = domain
							}

							result <- scanner.scanTarget(ip.String(), port, domain, host, &sni, scheme)
						}
					}
				}
			}(domainsChunk)
		}

		go func() {
			wg.Wait()
			close(result)
		}()
	}

	file := resultFile(conf.CSV)
	defer file.Close()

	for row := range result {
		if row.Err == nil {
			downloadSpeed := "0"
			if row.Download > 0 {
				downloadSpeed = fmt.Sprintf("%fMB/s", row.Download/1024/1024)
			}

			rep := fmt.Sprintf("%s:%d\t%s\t%s\t%d\t%f\t%s\n", row.Addr, row.Port, row.Domain, row.MinRTT, row.Latency, row.Jitter, downloadSpeed)

			if row.Jitter > conf.Jitter.MaxJitter {
				if LOG {
					color.Yellow("%s", rep)
				}
			} else {
				color.Green("%s", rep)

				if conf.CSV {
					fmt.Fprintf(file, "%s:%d,%s,%s,%d,%f,%s\n", row.Addr, row.Port, row.Domain, row.MinRTT, row.Latency, row.Jitter, downloadSpeed)
				} else {
					file.Write([]byte(rep))
				}
			}

		} else {
			addr := row.Addr
			if row.Domain != "" {
				addr = fmt.Sprintf("%s(%s:%d)", row.Domain, row.Addr, row.Port)
			}

			color.Red("%s\t%s", addr, row.Err.Error())
		}

	}
}
