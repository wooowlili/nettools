// Command lidar probes a set of target IPs using TCP SYN packets over
// raw sockets and reports per-target availability (SYN-ACK = alive,
// RST = closed, timeout = unreachable).
//
// Usage:
//
//	lidar -t 10.0.0.1,10.0.0.2 -p 80
//	lidar -c lidar.json
//	lidar -c lidar.json -p 443   # CLI overrides config file
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"golang.org/x/time/rate"

	"github.com/baidu/nettools/lidar"
	"github.com/spf13/pflag"
)

// lidarFileConfig maps the JSON config file fields.
type lidarFileConfig struct {
	TargetAddrs    string `json:"target_addrs"`
	ServerPort     int    `json:"server_port"`
	LocalAddr      string `json:"local_addr"`
	LocalPort      int    `json:"local_port"`
	LocalPortCount int    `json:"local_port_count"`
	Rate           int    `json:"rate"`
	Span           string `json:"span"`
	Delay          string `json:"delay"`
	Count          int    `json:"count"`
	SendDuration   string `json:"send_duration"`
	Interface      string `json:"interface"`
	Verbose        bool   `json:"verbose"`
}

func main() {
	var (
		configFile     string
		targets        string
		port           int
		localAddr      string
		localPort      int
		localPortCount int
		verbose        bool
		rateValue      int
		span           time.Duration
		delay          time.Duration
		count          int
		duration       time.Duration
		iface          string
	)

	pflag.StringVarP(&configFile, "config", "c", "", "Path to JSON config file")
	pflag.StringVarP(&targets, "targets", "t", "", "Comma-separated target IP addresses")
	pflag.IntVarP(&port, "port", "p", 0, "Target TCP port (default: 22)")
	pflag.StringVarP(&localAddr, "local-addr", "l", "", "Source IP address (auto-detected if empty)")
	pflag.IntVar(&localPort, "local-port", 0, "Base source port (default: 54321)")
	pflag.IntVar(&localPortCount, "local-port-count", 0, "Number of consecutive source ports (default: 100)")
	pflag.IntVar(&rateValue, "rate", 0, "Packets per second (default: 10)")
	pflag.DurationVarP(&span, "span", "s", 0, "Statistics reporting interval (default: 1s)")
	pflag.DurationVar(&delay, "delay", 0, "Delay before first stats report (default: 3s)")
	pflag.IntVarP(&count, "count", "n", 0, "Max packets to send (0 = unlimited)")
	pflag.DurationVarP(&duration, "duration", "d", 0, "Max send duration (0 = unlimited)")
	pflag.StringVarP(&iface, "interface", "i", "", "Outgoing interface name (auto-detected if empty)")
	pflag.BoolVarP(&verbose, "verbose", "v", false, "Print per-port loss details")

	pflag.Parse()
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)

	// Load config file if specified.
	var fileCfg lidarFileConfig
	if configFile != "" {
		data, err := os.ReadFile(configFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "read config %s: %v\n", configFile, err)
			os.Exit(1)
		}
		if err := json.Unmarshal(data, &fileCfg); err != nil {
			fmt.Fprintf(os.Stderr, "parse config %s: %v\n", configFile, err)
			os.Exit(1)
		}
	}

	// Build Config from file values first.
	cfg := &lidar.Config{
		TargetAddrs:    splitNonEmpty(fileCfg.TargetAddrs),
		ServerPort:     fileCfg.ServerPort,
		LocalAddr:      fileCfg.LocalAddr,
		LocalPort:      fileCfg.LocalPort,
		LocalPortCount: fileCfg.LocalPortCount,
		Rate:           fileCfg.Rate,
		Span:           parseDuration(fileCfg.Span),
		Delay:          parseDuration(fileCfg.Delay),
		Count:          fileCfg.Count,
		SendDuration:   parseDuration(fileCfg.SendDuration),
		Interface:      fileCfg.Interface,
		Verbose:        fileCfg.Verbose,
	}

	// Override with explicitly set CLI flags.
	pflag.Visit(func(f *pflag.Flag) {
		switch f.Name {
		case "targets":
			cfg.TargetAddrs = splitNonEmpty(targets)
		case "port":
			cfg.ServerPort = port
		case "local-addr":
			cfg.LocalAddr = localAddr
		case "local-port":
			cfg.LocalPort = localPort
		case "local-port-count":
			cfg.LocalPortCount = localPortCount
		case "rate":
			cfg.Rate = rateValue
		case "span":
			cfg.Span = span
		case "delay":
			cfg.Delay = delay
		case "count":
			cfg.Count = count
		case "duration":
			cfg.SendDuration = duration
		case "interface":
			cfg.Interface = iface
		case "verbose":
			cfg.Verbose = verbose
		}
	})

	// Fill defaults for zero-valued fields.
	if cfg.ServerPort == 0 {
		cfg.ServerPort = 22
	}
	if cfg.LocalPort == 0 {
		cfg.LocalPort = 54321
	}
	if cfg.LocalPortCount == 0 {
		cfg.LocalPortCount = 100
	}
	if cfg.Rate == 0 {
		cfg.Rate = 10
	}
	if cfg.Span == 0 {
		cfg.Span = time.Second
	}
	if cfg.Delay == 0 {
		cfg.Delay = 3 * time.Second
	}

	if len(cfg.TargetAddrs) == 0 {
		fmt.Fprintln(os.Stderr, "error: --targets/-t or config file target_addrs is required")
		pflag.Usage()
		os.Exit(1)
	}

	if err := cfg.Validate(); err != nil {
		fmt.Fprintf(os.Stderr, "config error: %v\n", err)
		os.Exit(1)
	}

	logger := log.Default()

	ctx, cancel := context.WithCancel(context.Background())

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		logger.Printf("[INFO] received signal, shutting down...")
		cancel()
	}()

	limiter := rate.NewLimiter(rate.Limit(cfg.Rate), 1)
	scanner := lidar.NewScanner(cfg, limiter, logger)

	logger.Printf("[INFO] probing %d target(s) on port %d from %s (rate: %d pps)",
		len(cfg.TargetAddrs), cfg.ServerPort, cfg.LocalAddr, cfg.Rate)

	if err := scanner.Run(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "scanner error: %v\n", err)
		os.Exit(1)
	}
}

func parseDuration(s string) time.Duration {
	if s == "" {
		return 0
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid duration %q: %v\n", s, err)
		os.Exit(1)
	}
	return d
}

func splitNonEmpty(s string) []string {
	var result []string
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part != "" {
			result = append(result, part)
		}
	}
	return result
}
