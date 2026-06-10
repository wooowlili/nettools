package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	_ "net/http/pprof"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/baidu/nettools/kuiniu/client"
	"github.com/baidu/nettools/kuiniu/config"
	"github.com/baidu/nettools/kuiniu/server"
	"github.com/baidu/nettools/stat"
	"github.com/baidu/nettools/version"
	"go.uber.org/ratelimit"
)

var configFile = flag.String("c", "kuiniu.json", "path to config file")

func main() {
	showVersion := flag.Bool("version", false, "Print version and exit")
	flag.Parse()
	if *showVersion {
		fmt.Println(version.String())
		return
	}

	defer func() {
		if err := recover(); err != nil {
			log.Printf("[FATAL] recovered: %v", err)
			buf := make([]byte, 8192)
			n := runtime.Stack(buf, true)
			log.Printf("[FATAL] stack:\n%s", buf[:n])
			os.Exit(1)
		}
	}()

	log.SetFlags(log.LstdFlags | log.Lmicroseconds)

	data, err := os.ReadFile(*configFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "read config %s: %v\n", *configFile, err)
		os.Exit(1)
	}

	var cfg config.Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		fmt.Fprintf(os.Stderr, "parse config: %v\n", err)
		os.Exit(1)
	}

	if err := cfg.Validate(); err != nil {
		fmt.Fprintf(os.Stderr, "config error: %v\n", err)
		os.Exit(1)
	}

	var logWriter *rotateWriter
	if cfg.LogDir != "" {
		logWriter = setupLog(cfg.LogDir, cfg.LogMaxAgeDays)
		defer logWriter.Close()
	}

	if cfg.PprofAddr != "" {
		go func() {
			log.Printf("[INFO] pprof on %s", cfg.PprofAddr)
			if err := http.ListenAndServe(cfg.PprofAddr, nil); err != nil {
				log.Printf("[WARN] pprof: %v", err)
			}
		}()
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigCh
		log.Printf("[INFO] signal %v, shutting down", sig)
		cancel()
	}()

	logger := log.Default()
	proc := stat.NewProcessor(cfg.Span, cfg.Delay)
	go proc.Run(ctx)

	if cfg.Role == config.RoleClient {
		runClient(ctx, cancel, &cfg, proc, logger)
	} else {
		runServer(ctx, cancel, &cfg, proc, logger)
	}
}

func runClient(ctx context.Context, cancel context.CancelFunc, cfg *config.Config, proc *stat.Processor, logger *log.Logger) {
	limiter := ratelimit.New(int(cfg.RateInSpan), ratelimit.Per(cfg.Span))
	c, err := client.NewClient(cfg, limiter, proc, nil, logger)
	if err != nil {
		log.Printf("[ERRO] client init: %v", err)
		cancel()
		return
	}

	go func() {
		if err := c.Run(ctx); err != nil {
			log.Printf("[ERRO] client: %v", err)
		}
	}()

	log.Printf("[INFO] kuiniu client started, %d GPU pairs", cfg.GPUPairCount())
	<-ctx.Done()
	time.Sleep(1 * time.Second)
}

func runServer(ctx context.Context, cancel context.CancelFunc, cfg *config.Config, proc *stat.Processor, logger *log.Logger) {
	s := server.New(cfg, proc, nil, logger)

	go func() {
		if err := s.Run(ctx); err != nil {
			log.Printf("[ERRO] server: %v", err)
		}
	}()

	log.Printf("[INFO] kuiniu server started, %d GPU IPs", cfg.GPUPairCount())
	<-ctx.Done()
	time.Sleep(1 * time.Second)
}

type rotateWriter struct {
	dir    string
	maxAge int
	mu     sync.Mutex
	file   *os.File
	date   string
}

func (w *rotateWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	today := time.Now().Format("20060102")
	if today != w.date {
		if w.file != nil {
			_ = w.file.Close()
			w.file = nil
		}
		name := "kuiniu.log." + today
		f, err := os.OpenFile(filepath.Join(w.dir, name), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			w.date = ""
			return 0, fmt.Errorf("open log file: %w", err)
		}
		w.file = f
		w.date = today
		link := filepath.Join(w.dir, "kuiniu.log")
		_ = os.Remove(link)
		_ = os.Symlink(name, link)
		w.clean()
	}
	if w.file == nil {
		return 0, fmt.Errorf("log file not open")
	}
	return w.file.Write(p)
}

func (w *rotateWriter) Close() {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.file != nil {
		_ = w.file.Close()
	}
}

func (w *rotateWriter) clean() {
	if w.maxAge <= 0 {
		return
	}
	cutoff := time.Now().AddDate(0, 0, -w.maxAge)
	entries, _ := os.ReadDir(w.dir)
	for _, e := range entries {
		if !strings.HasPrefix(e.Name(), "kuiniu.log.") {
			continue
		}
		info, err := e.Info()
		if err != nil || info.ModTime().After(cutoff) {
			continue
		}
		_ = os.Remove(filepath.Join(w.dir, e.Name()))
	}
}

func setupLog(dir string, maxAgeDays int) *rotateWriter {
	if err := os.MkdirAll(dir, 0755); err != nil {
		log.Fatalf("[FATAL] mkdir %s: %v", dir, err)
	}
	if maxAgeDays <= 0 {
		maxAgeDays = 7
	}
	w := &rotateWriter{dir: dir, maxAge: maxAgeDays}
	log.SetOutput(w)
	return w
}
