package scamp

import (
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"golang.org/x/net/ipv4"
)

// DiscoveryAnnouncer ... TODO: godoc
type DiscoveryAnnouncer struct {
	services      []*Service
	multicastConn *ipv4.PacketConn
	multicastDest *net.UDPAddr
	stopSig       (chan bool)
	termSig       (chan os.Signal)
}

// NewDiscoveryAnnouncer creates a DiscoveryAnnouncer
func NewDiscoveryAnnouncer() (announcer *DiscoveryAnnouncer, err error) {
	announcer = new(DiscoveryAnnouncer)
	announcer.services = make([]*Service, 0, 0)
	announcer.stopSig = make(chan bool)
	announcer.termSig = make(chan os.Signal, 1)
	signal.Notify(announcer.termSig, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)

	config := DefaultConfig()
	announcer.multicastDest = &net.UDPAddr{IP: config.DiscoveryMulticastIP(), Port: config.DiscoveryMulticastPort()}
	// announcer.multicastDest = &net.UDPAddr{IP: 127.0.0.1, Port: config.DiscoveryMulticastPort()}
	announcer.multicastConn, err = localMulticastPacketConn(config)
	if err != nil {
		return
	}

	return
}

// Stop notifies stopSig channel to stop announcer
func (announcer *DiscoveryAnnouncer) Stop() {
	announcer.stopSig <- true
}

// Track indicates that announcer should track and announce service
func (announcer *DiscoveryAnnouncer) Track(serv *Service) {
	announcer.services = append(announcer.services, serv)
}

// AnnounceLoop runs service announceloop and runs announcer.doAnnounce() at time
// interval configured in defaultAnnounceInterval
// TODO: make defaultAnnounceInterval configurable in the service (rather than hardcoded in scamp)
func (announcer *DiscoveryAnnouncer) AnnounceLoop() {
	// Trace.Printf("starting announcer loop")

	for {
		select {
		case <-announcer.stopSig:
			return
		case <-announcer.termSig:
			return
		default:
			announcer.doAnnounce()
		}

		time.Sleep(time.Duration(defaultAnnounceInterval) * time.Second)
	}
}

func (announcer *DiscoveryAnnouncer) doAnnounce() (err error) {
	for _, serv := range announcer.services {
		serviceDesc, err := serv.MarshalText()
		if err != nil {
			Error.Printf("failed to marshal service as text: `%s`. skipping.", err)
		}

		_, err = announcer.multicastConn.WriteTo(serviceDesc, nil, announcer.multicastDest)
		if err != nil {
			return err
		}
	}

	return
}
