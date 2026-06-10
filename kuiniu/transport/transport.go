package transport

import (
	"context"
	"net"
)

// Sender sends probe packets from a specified local IP to a remote IP.
type Sender interface {
	Send(ctx context.Context, localIP, remoteIP net.IP, localPort, remotePort uint16, payload []byte) error
	Close() error
}

// Receiver receives probe packets on a specified local IP.
type Receiver interface {
	Receive(ctx context.Context) ([]byte, net.Addr, error)
	Close() error
}
