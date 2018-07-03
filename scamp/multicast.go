package scamp

import "fmt"
import "net"

import "golang.org/x/net/ipv4"

func loopbackInterface() (lo *net.Interface, err error) {
	lo, err = net.InterfaceByName("lo0")
	if err != nil {
		lo, err = net.InterfaceByName("lo")
		if err != nil {
			Error.Printf("could not find `lo0` or `lo`: `%s`", err)
			return
		}
	}

	return
}

func multicastPacketConn(config *Config) (conn *ipv4.PacketConn, err error) {
	addr := config.DiscoveryMulticastIP()
	port := config.DiscoveryMulticastPort()
	multicastSpec := fmt.Sprintf("%s:%d", addr, port)

	udpConn, err := net.ListenPacket("udp", multicastSpec)
	if err != nil {
		Error.Printf("could not listen to `%s`", multicastSpec)
		return
	}

	conn = ipv4.NewPacketConn(udpConn)
	return
}

func getIPForAnnouncePacket() (ip net.IP, err error) {
	infs, err := net.Interfaces()
	if err != nil {
		Error.Printf("err: `%s`", err)
		return
	}

	for _, inf := range infs {
		if inf.Flags&net.FlagLoopback != 0 {
			continue
		}

		addrs, err := inf.Addrs()
		if err != nil {
			return nil, err
		}

		for _, addr := range addrs {
			ip, _, err = net.ParseCIDR(addr.String())
			if err != nil {
				Error.Printf("ParseCIDR err: `%s`\n", err)
				continue
			} else if ip.To4() == nil {
				// Trace.Printf("IP is not IPv4: `%s`\n", ip)
				continue
			}
			break
		}
		if ip != nil {
			break
		}
	}

	if ip == nil {
		err = fmt.Errorf("no suitables IPs found")
		return
	}

	return
}
