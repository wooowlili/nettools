package server

import (
	"bytes"
	"context"
	"log"
	"net"
	"sync"

	"github.com/baidu/nettools/kuiniu/codec"
	"github.com/baidu/nettools/kuiniu/config"
	"github.com/baidu/nettools/kuiniu/transport"
	"github.com/baidu/nettools/stat"
	"github.com/baidu/nettools/util"

	"github.com/smallnest/goscapy/pkg/packet"
)

// Server listens for probe packets on GPU NICs and echoes them back via CPU NIC.
type Server struct {
	conf          *config.Config
	statProcessor *stat.Processor
	logger        *log.Logger
	sender        stat.Sender
	salts         *util.Salts

	mu    sync.RWMutex
	stats map[string]stat.Stat // keyed by client GPU IP
}

// New creates a Server with the given configuration.
func New(conf *config.Config, statProcessor *stat.Processor, sender stat.Sender, logger *log.Logger) *Server {
	if conf.MsgLen < codec.MsgHeaderLen {
		conf.MsgLen = codec.MsgHeaderLen
	}
	if sender == nil {
		sender = stat.NewLogSender(logger, conf.Verbose)
	}

	s := &Server{
		conf:          conf,
		statProcessor: statProcessor,
		logger:        logger,
		sender:        sender,
		salts:         util.NewSalts(conf.MsgLen - codec.MsgHeaderLen),
		stats:         make(map[string]stat.Stat),
	}

	// Pre-register client GPU IPs from config
	for _, addr := range conf.RemoteGPUAddrs {
		st := stat.NewServerStat(addr, conf.LocalCPUAddr,
			conf.ClientPortRange, conf.ServerPortRange,
			conf.RateInSpan, conf.Span, conf.Delay, s.sender)
		statProcessor.AddStat(st)
		s.stats[addr] = st
		s.logger.Printf("[INFO] prepare client GPU: %s", addr)
	}

	return s
}

// Run starts GPU receivers and CPU sender. It blocks until ctx is cancelled.
func (s *Server) Run(ctx context.Context) error {
	s.logger.Printf("[INFO] [server] creating CPU sender on %s...", s.conf.LocalCPUAddr)

	localCPUIP := net.ParseIP(s.conf.LocalCPUAddr)
	cpuSender, err := transport.NewUDPSender(localCPUIP, s.conf.TOS, 64, s.logger)
	if err != nil {
		s.logger.Printf("[ERRO] [server] failed to create CPU sender on %s: %v", localCPUIP, err)
		return err
	}
	defer cpuSender.Close()
	s.logger.Printf("[INFO] [server] CPU sender bound to %s", localCPUIP)

	// Create GPU receivers — one per GPU IP
	s.logger.Printf("[INFO] [server] creating GPU receivers...")
	for i, gpuAddr := range s.conf.LocalGPUAddrs {
		gpuIP := net.ParseIP(gpuAddr)
		r, err := transport.NewUDPReceiver(gpuIP, s.conf.TOS, s.conf.ServerPortRange, s.logger)
		if err != nil {
			s.logger.Printf("[ERRO] [GPU-%d] failed to create receiver on %s: %v", i, gpuAddr, err)
			continue
		}
		defer r.Close()
		s.logger.Printf("[INFO] [GPU-%d] listening on %s, ports %d-%d", i, gpuAddr, s.conf.ServerPortRange.Min, s.conf.ServerPortRange.Max)
		go s.readLoop(ctx, r, cpuSender, i)
	}

	s.logger.Printf("[INFO] [server] all GPU receivers started, %d listening", len(s.conf.LocalGPUAddrs))
	<-ctx.Done()
	return nil
}

func (s *Server) readLoop(ctx context.Context, r transport.Receiver, cpuSender transport.Sender, gpuIndex int) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		data, remote, err := r.Receive(ctx)
		if err != nil {
			continue
		}
		s.handlePacket(data, remote, cpuSender, gpuIndex)
	}
}

func (s *Server) handlePacket(rawPkt []byte, remote net.Addr, cpuSender transport.Sender, gpuIndex int) {
	parsed, err := packet.DissectByProto(rawPkt, "UDP")
	if err != nil {
		return
	}
	rawLayer := parsed.GetLayer("Raw")
	if rawLayer == nil {
		return
	}
	loadVal, _ := rawLayer.Get("load")
	payload, _ := loadVal.([]byte)
	if len(payload) == 0 {
		return
	}

	if !codec.IsValid(payload) {
		return
	}

	r := codec.Decode(payload)

	// Detect server-side bitflip
	hasBitflip := false
	if len(payload) == s.conf.MsgLen {
		salt := s.salts.Get(r.Seq)
		if !bytes.Equal(salt, payload[codec.MsgHeaderLen:]) {
			hasBitflip = true
			for i, v := range payload[codec.MsgHeaderLen:] {
				if v != salt[i] {
					s.logger.Printf("[ERRO] [GPU-%d] [server bitflip] %s -> local, %02x->%02x, idx: %d, seq: %d, ts: %d",
						gpuIndex, remote.String(), salt[i], v, i+codec.MsgHeaderLen, r.Seq, r.Ts)
				}
			}
		}
	}

	// Record server-side stats
	clientGPUIP := net.IP(r.SrcIP).String()
	st := s.getOrCreateStat(clientGPUIP)
	if st != nil {
		st.ReceivedAndFix(r.Seq, r.Ts, 0, r.LastSentCount, r.LastStartSrcPort, r.LastStartDstPort, hasBitflip)
	}

	// Echo back via CPU network to the client's CPU address
	targetCPUIP := net.ParseIP(s.conf.RemoteCPUAddr)
	if targetCPUIP == nil {
		return
	}

	// Echo the payload back via CPU NIC
	_ = cpuSender.Send(context.Background(), net.ParseIP(s.conf.LocalCPUAddr), targetCPUIP, r.DstPort, r.SrcPort, payload)
}

func (s *Server) getOrCreateStat(clientGPUIP string) stat.Stat {
	s.mu.RLock()
	st := s.stats[clientGPUIP]
	s.mu.RUnlock()
	if st != nil {
		return st
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	st = s.stats[clientGPUIP]
	if st != nil {
		return st
	}

	s.logger.Printf("[INFO] [server] auto-register client GPU: %s", clientGPUIP)
	st = stat.NewServerStat(clientGPUIP, s.conf.LocalCPUAddr,
		s.conf.ClientPortRange, s.conf.ServerPortRange,
		s.conf.RateInSpan, s.conf.Span, s.conf.Delay, s.sender)
	s.statProcessor.AddStat(st)
	s.stats[clientGPUIP] = st
	return st
}
