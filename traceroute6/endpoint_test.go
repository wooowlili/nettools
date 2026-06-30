package traceroute6

import (
	"net"
	"testing"
)

func TestLocalEndpointRejectsNonV6(t *testing.T) {
	conf := &Config{LocalAddr: "10.0.0.1"}
	if _, _, err := localEndpoint(conf, net.ParseIP("2001:4860:4860::8888")); err == nil {
		t.Errorf("expected error for IPv4 local addr")
	}
	conf = &Config{LocalAddr: "garbage"}
	if _, _, err := localEndpoint(conf, net.ParseIP("2001:4860:4860::8888")); err == nil {
		t.Errorf("expected error for garbage local addr")
	}
}

// TestInterfaceForIP exercises the IP-to-interface mapping using whatever IPv6
// address the loopback interface owns (::1 on most systems).
func TestInterfaceForIP(t *testing.T) {
	ifaces, err := net.Interfaces()
	if err != nil {
		t.Skip("cannot enumerate interfaces")
	}
	var v6 net.IP
	var wantIface string
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, _ := iface.Addrs()
		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok && ipnet.IP.To4() == nil && ipnet.IP.To16() != nil {
				v6 = ipnet.IP
				wantIface = iface.Name
				break
			}
		}
		if v6 != nil {
			break
		}
	}
	if v6 == nil {
		t.Skip("no IPv6 address on any interface")
	}
	if got := interfaceForIP(v6); got != wantIface {
		t.Errorf("interfaceForIP(%s) = %q, want %q", v6, got, wantIface)
	}

	// An address owned by no interface yields "".
	if got := interfaceForIP(net.ParseIP("2001:db8::dead:beef")); got != "" {
		t.Errorf("interfaceForIP of unowned addr = %q, want empty", got)
	}
}

func TestLocalEndpointExplicitInterface(t *testing.T) {
	conf := &Config{LocalAddr: "2001:db8::1", Interface: "eth-test"}
	src, iface, err := localEndpoint(conf, net.ParseIP("2001:4860:4860::8888"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !src.Equal(net.ParseIP("2001:db8::1")) {
		t.Errorf("src = %v, want 2001:db8::1", src)
	}
	if iface != "eth-test" {
		t.Errorf("iface = %q, want eth-test", iface)
	}
}
