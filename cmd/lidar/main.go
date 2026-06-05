// Command lidar probes a set of target IPs using TCP SYN packets over
// raw sockets and reports per-target availability (SYN-ACK = alive,
// RST = closed, timeout = unreachable).
//
// Usage:
//
//	lidar -t 10.0.0.1,10.0.0.2 -p 80
//	lidar -t 192.168.1.0/24 -n 1000 -d 10s
package main

import (
	"context"
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

func main() {
	var (
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

	pflag.StringVarP(&targets, "targets", "t", "", "Comma-separated target IP addresses")
	pflag.IntVarP(&port, "port", "p", 22, "Target TCP port")
	pflag.StringVarP(&localAddr, "local-addr", "l", "", "Source IP address (auto-detected if empty)")
	pflag.IntVar(&localPort, "local-port", 54321, "Base source port")
	pflag.IntVar(&localPortCount, "local-port-count", 100, "Number of consecutive source ports")
	pflag.IntVar(&rateValue, "rate", 10, "Packets per second")
	pflag.DurationVarP(&span, "span", "s", time.Second, "Statistics reporting interval")
	pflag.DurationVar(&delay, "delay", 3*time.Second, "Delay before first stats report")
	pflag.IntVarP(&count, "count", "n", 0, "Max packets to send (0 = unlimited)")
	pflag.DurationVarP(&duration, "duration", "d", 0, "Max send duration (0 = unlimited)")
	pflag.StringVarP(&iface, "interface", "i", "", "Outgoing interface name (auto-detected if empty)")
	pflag.BoolVarP(&verbose, "verbose", "v", false, "Print per-port loss details")

	pflag.Parse()
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)

	if targets == "" {
		fmt.Fprintln(os.Stderr, "error: --targets/-t is required")
		pflag.Usage()
		os.Exit(1)
	}

	cfg := &lidar.Config{
		TargetAddrs:    splitNonEmpty(targets),
		ServerPort:     port,
		LocalAddr:      localAddr,
		LocalPort:      localPort,
		LocalPortCount: localPortCount,
		Verbose:        verbose,
		Rate:           rateValue,
		Span:           span,
		Delay:          delay,
		Count:          count,
		SendDuration:   duration,
		Interface:      iface,
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
