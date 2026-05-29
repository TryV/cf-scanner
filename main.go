package main

import (
	"context"
	crand "crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"maps"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/fatih/color"
	probing "github.com/prometheus-community/pro-bing"
	"golang.org/x/net/http2"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"

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
	color.Green("【ＨＴＴＰ Ｓｃａｎ】\n")
	if !conf.DomainScan.Enable {
		res_ch := make(chan string, conf.Goroutines)
		ip_ch := make(chan string, conf.Goroutines)

		// scanners
		for range conf.Goroutines {
			go func() {
				var client *http.Client
				if conf.TLS.Enable {
					if conf.HTTP3 {
						client = h3transporter(&conf, nil, nil)
					} else if !conf.TLS.Utls.Enable {
						client = tlsTransporter(&conf, nil)
					}
				} else {
					client = http.DefaultClient
				}

				for {
					ip, e := <-ip_ch
					if !e {
						break
					}
					minrtt := time.Millisecond
					if conf.Ping.Enable {
						// ping ip
						pinger := probing.New(ip)
						if conf.Interface != "" {
							pinger.InterfaceName = conf.Interface
						}
						pinger.SetPrivileged(conf.Ping.Privileged)
						pinger.Size = randomRange(conf.Ping.Size)
						pinger.Timeout = time.Duration(conf.Ping.MaxPing) * time.Millisecond
						pinger.Count = 1
						pinging_err := pinger.Run()
						if pinging_err != nil {
							if LOG {
								color.Red("PING: %s", pinging_err)
							}
							continue
						}

						if pinger.Statistics().PacketLoss > 0 || pinger.Statistics().MinRtt > (time.Duration(conf.Ping.MaxPing)*time.Millisecond) {
							if LOG {
								color.Red("PING: %s\t%s\n", ip, pinger.Statistics().MinRtt)
							}
							continue
						}

						minrtt = pinger.Statistics().AvgRtt
					}

					for _, port := range conf.Ports {
						addr := fmt.Sprintf("%s:%d", ip, port)

						// generate http req
						var hostname string
						if strings.Contains(conf.Hostname, "{ip}") {
							hostname = ip
						} else {
							hostname = conf.Hostname
						}
						req := http.Request{Method: "GET", URL: &url.URL{Scheme: scheme, Host: addr, Path: conf.Path}, Host: hostname}
						req.Header = maps.Clone(conf.Headers)
						req.Header.Set("Host", hostname)
						if conf.Padding {
							req.Header.Set("Cookie", RandomString(conf.PaddingSize))
						}

						s := time.Now()
						if conf.TLS.Utls.Enable && conf.TLS.Enable && !conf.HTTP3 {
							uclient, utlsE := utlsTransporter(&conf, fingerprint, conf.TLS.SNI, addr, ifaceIP)
							if utlsE != nil {
								if LOG {
									color.Red("%s", utlsE.Error())
								}
								continue
							}
							client = uclient
						}
						client.Timeout = time.Millisecond * time.Duration(conf.Maxlatency)
						// send request
						respone, http_err := client.Do(&req)
						e := time.Now()
						latency := e.UnixMilli() - s.UnixMilli()
						if http_err != nil {
							if LOG {
								color.Red("%s", http_err.Error())
							}
							continue
						}

						if slices.Contains(conf.ResponseStatusCode, respone.StatusCode) && match(respone.Header, conf.ResponseHeader) {
							// Calc jiiter
							jitter_str := "Null"
							download_test := "Null"
							if conf.Jitter.Enable {
								latencies := []float64{}
								jammed := false
								for range conf.Jitter.Samples {
									s := time.Now()
									// send request
									_, http_err := client.Do(&req)
									e := time.Now()
									latency := e.UnixMilli() - s.UnixMilli()
									if http_err != nil {
										jammed = true
										break
									}
									latencies = append(latencies, float64(latency))
									if conf.Jitter.Interval > 0 {
										time.Sleep(time.Millisecond * time.Duration(conf.Jitter.Interval))
									}
								}
								if jammed {
									if LOG {
										color.Red("%s\t%s\t%d\tJAMMED\n", addr, minrtt, latency)
									}
									continue
								}
								jitter := Calc_jitter(latencies)
								if jitter > conf.Jitter.MaxJitter {
									color.Yellow("%s\t%s\t%d\t%f\n", addr, minrtt, latency, jitter)
									continue
								}
								jitter_str = fmt.Sprintf("%f", jitter)
							}
							if conf.DownloadTest.Enable {
								download_test = downloadTest(client, &conf, addr, ifaceIP, fingerprint)
							}
							rep := fmt.Sprintf("%s\t%s\t%d\t%s\t%s\n", addr, minrtt, latency, jitter_str, download_test)
							color.Green("%s", rep)
							if conf.CSV {
								res_ch <- fmt.Sprintf("%s,%s,%d,%s,%s\n", addr, minrtt, latency, jitter_str, download_test)
							} else {
								res_ch <- rep
							}
						} else {
							if LOG {
								color.Red("%s\t%s\tHTTP.StatusCode=%d\n", addr, minrtt, respone.StatusCode)
							}
						}
					}
				}
			}()
		}

		go func() {
			file := resultFile(conf.CSV)
			defer file.Close()

			for {
				v, ok := <-res_ch
				if !ok {
					break
				}
				file.Write([]byte(v))
			}
		}()

		if conf.RandomScan {
			switch conf.IpVersion {
			case 4:
				rand.Shuffle(len(ips), func(i, j int) {
					ips[i], ips[j] = ips[j], ips[i]
				})
				for _, ip := range ips {
					ip_ch <- ip
				}
			case 6:
				for {
					ipv6, e := randomIPv6FromCIDR(strings.TrimSpace(ips[rand.Intn(len(ips))]))
					if e != nil {
						continue
					}
					ip_ch <- fmt.Sprintf("[%s]", ipv6.String())
				}
			}
		} else {
			if conf.IpVersion != 4 {
				log.Fatalln("linear method is only available for ipv4")
			}
			for _, ip := range ips {
				ip_ch <- ip
			}
		}

		time.Sleep(time.Duration(conf.Maxlatency*int64(len(conf.Ports))) * time.Millisecond)
	} else {
		// Domain Scan
		domainListFile, domainListFileErr := os.ReadFile(conf.DomainScan.DomainListPath)
		if domainListFileErr != nil {
			log.Fatalln(domainListFileErr)
		}

		domains := strings.Split(string(domainListFile), "\n")
		if conf.DomainScan.Shuffle {
			rand.Shuffle(len(domains), func(i, j int) {
				domains[i], domains[j] = domains[j], domains[i]
			})
		}

		ch := make(chan string, conf.Goroutines)
		for domainsChunk := range slices.Chunk(domains, len(domains)/conf.Goroutines) {
			go func() {
				for _, domain := range domainsChunk {
					domain := strings.TrimSpace(domain)
					ips, resolve_err := net.LookupIP(domain)
					if resolve_err != nil {
						log.Println(resolve_err)
						continue
					}

					for _, ip := range ips {
						if conf.DomainScan.SkipIPV6 {
							if ip.To4() == nil && ip.To16() != nil {
								continue
							}
						}

						minrtt := time.Millisecond
						if conf.Ping.Enable {
							// ping ip
							pinger := probing.New(ip.String())
							if conf.Interface != "" {
								pinger.InterfaceName = conf.Interface
							}
							pinger.SetPrivileged(true)
							pinger.Size = randomRange(conf.Ping.Size)
							pinger.Timeout = time.Duration(conf.Ping.MaxPing) * time.Millisecond

							pinger.Count = 1
							pinging_err := pinger.Run()
							if pinging_err != nil {
								if LOG {
									color.Red("PING: %s", pinging_err)
								}
								continue
							}

							if pinger.Statistics().PacketLoss > 0 || pinger.Statistics().MinRtt > (time.Duration(conf.Ping.MaxPing)*time.Millisecond) {
								if LOG {
									color.Red("PING: %s(%s)\t%s\n", domain, ip, pinger.Statistics().MinRtt)
								}
								continue
							}

							minrtt = pinger.Statistics().AvgRtt
						}
						for _, port := range conf.Ports {
							ip := fmt.Sprintf("%s:%d", ip, port)
							// generate http req
							host := conf.Hostname
							if conf.DomainScan.DomainAsHost {
								host = domain
							}
							req := http.Request{Method: "GET", URL: &url.URL{Scheme: scheme, Host: ip, Path: conf.Path}, Host: host}
							req.Header = maps.Clone(conf.Headers)
							req.Header.Set("Host", host)
							if conf.Padding {
								req.Header.Set("Cookie", RandomString(conf.PaddingSize))
							}

							sni := conf.TLS.SNI
							if conf.DomainScan.DomainAsSNI {
								sni = domain
							}
							var client *http.Client
							if conf.TLS.Enable {
								if conf.HTTP3 {
									client = h3transporter(&conf, &sni, nil)
								} else if !conf.TLS.Utls.Enable {
									client = tlsTransporter(&conf, &sni)
								}
							} else {
								client = http.DefaultClient
							}

							s := time.Now()
							if conf.TLS.Utls.Enable && conf.TLS.Enable && !conf.HTTP3 {
								uclient, utlsE := utlsTransporter(&conf, fingerprint, sni, ip, ifaceIP)
								if utlsE != nil {
									if LOG {
										color.Red("%s", utlsE.Error())
									}
									continue
								}
								client = uclient
							}
							client.Timeout = time.Millisecond * time.Duration(conf.Maxlatency)
							// send request
							respone, http_err := client.Do(&req)
							e := time.Now()
							latency := e.UnixMilli() - s.UnixMilli()
							if http_err != nil {
								if LOG {
									color.Red("%s", http_err.Error())
								}
								continue
							}

							if slices.Contains(conf.ResponseStatusCode, respone.StatusCode) && match(respone.Header, conf.ResponseHeader) {
								// Calc jiiter
								jitter_str := "Null"
								download_test := "Null"
								if conf.Jitter.Enable {
									latencies := []float64{}
									jammed := false
									for range 5 {
										s := time.Now()
										// send request
										_, http_err := client.Do(&req)
										e := time.Now()
										latency := e.UnixMilli() - s.UnixMilli()
										if http_err != nil {
											jammed = true
											break
										}
										latencies = append(latencies, float64(latency))
										if conf.Jitter.Interval > 0 {
											time.Sleep(time.Millisecond * time.Duration(conf.Jitter.Interval))
										}
									}
									if jammed {
										if LOG {
											color.Red("%s(%s)\t%s\t%d\tJAMMED\n", domain, ip, minrtt, latency)
										}
										continue
									}
									jitter := Calc_jitter(latencies)
									if jitter > conf.Jitter.MaxJitter {
										color.Yellow("%s(%s)\t%s\t%d\t%f\n", domain, ip, minrtt, latency, jitter)
										continue
									}
									jitter_str = fmt.Sprintf("%f", jitter)
								}
								if conf.DownloadTest.Enable {
									download_test = downloadTest(client, &conf, ip, ifaceIP, fingerprint)
								}
								rep := fmt.Sprintf("%s:\t%s\t%s\t%d\t%s\t%s\n", domain, ip, minrtt, latency, jitter_str, download_test)
								color.Green("%s", rep)
								if conf.CSV {
									ch <- fmt.Sprintf("%s:%s,%s,%d,%s,%s\n", domain, ip, minrtt, latency, jitter_str, download_test)
								} else {
									ch <- rep
								}
							} else {
								if LOG {
									color.Red("%s(%s)\t%s\tHTTP.StatusCode=%d\n", domain, ip, minrtt, respone.StatusCode)
								}
							}
						}
					}
				}
			}()
		}

		file := resultFile(conf.CSV)
		defer file.Close()

		deadgoroutines := 0
		for {
			if deadgoroutines == conf.Goroutines {
				break
			}
			v, ok := <-ch
			if !ok {
				break
			}
			if v == "end" {
				deadgoroutines += 1
				color.Green("end of goroutine")
				continue
			}
			file.Write([]byte(v))
		}
	}
}
