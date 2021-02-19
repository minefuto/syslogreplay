package main

import (
	"bytes"
	"errors"
	"net"
	"syscall"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/vishvananda/netlink"
)

type SyslogConn struct {
	handle  *pcap.Handle
	srcMAC  net.HardwareAddr
	dstMAC  net.HardwareAddr
	srcIP   net.IP
	dstIP   net.IP
	srcPort layers.UDPPort
	dstPort layers.UDPPort
}

func Open(srcIP, dstIP net.IP, srcPort, dstPort layers.UDPPort) (*SyslogConn, error) {
	r, err := netlink.RouteGet(dstIP)
	if err != nil {
		return nil, err
	}
	route := r[0]

	if srcIP == nil {
		srcIP = route.Src
	}

	var targetIP net.IP
	if route.Gw != nil {
		targetIP = route.Gw
	} else {
		targetIP = dstIP
	}

	iface, err := net.InterfaceByIndex(route.LinkIndex)
	if err != nil {
		return nil, err
	}

	if iface.Name == "lo" {
		return nil, errors.New("Sending packet to the loopback is not supported")
	}

	neighList, err := netlink.NeighList(iface.Index, syscall.AF_INET)
	if err != nil {
		return nil, err
	}

	for _, neigh := range neighList {
		if targetIP.Equal(neigh.IP) {
			h, err := pcap.OpenLive(iface.Name, int32(iface.MTU), true, pcap.BlockForever)
			if err != nil {
				return nil, err
			}

			return &SyslogConn{
				handle:  h,
				srcMAC:  iface.HardwareAddr,
				dstMAC:  neigh.HardwareAddr,
				srcIP:   srcIP,
				dstIP:   dstIP,
				srcPort: srcPort,
				dstPort: dstPort,
			}, nil
		}
	}

	macLayer := &layers.Ethernet{
		SrcMAC:       iface.HardwareAddr,
		DstMAC:       net.HardwareAddr{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF},
		EthernetType: layers.EthernetTypeARP,
	}

	arpLayer := &layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPRequest,
		SourceHwAddress:   iface.HardwareAddr,
		SourceProtAddress: srcIP,
		DstHwAddress:      net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		DstProtAddress:    targetIP,
	}

	buf := gopacket.NewSerializeBuffer()
	gopacket.SerializeLayers(
		buf,
		gopacket.SerializeOptions{
			ComputeChecksums: true,
			FixLengths:       true,
		},
		macLayer,
		arpLayer,
	)

	h, err := pcap.OpenLive(iface.Name, int32(iface.MTU), true, pcap.BlockForever)
	if err != nil {
		return nil, err
	}

	ch := make(chan net.HardwareAddr, 1)
	go func() {
		h.WritePacketData(buf.Bytes())

		packetSource := gopacket.NewPacketSource(h, h.LinkType())
		for packet := range packetSource.Packets() {
			arpLayer := packet.Layer(layers.LayerTypeARP)
			if arpLayer == nil {
				continue
			}
			arp := arpLayer.(*layers.ARP)
			if arp.Operation == layers.ARPReply && bytes.Equal(arp.SourceProtAddress, targetIP) {
				ch <- arp.SourceHwAddress
				return
			}
		}
	}()

	select {
	case res := <-ch:
		return &SyslogConn{
			handle:  h,
			srcMAC:  iface.HardwareAddr,
			dstMAC:  res,
			srcIP:   srcIP,
			dstIP:   dstIP,
			srcPort: srcPort,
			dstPort: dstPort,
		}, nil
	case <-time.After(3 * time.Second):
		h.Close()
		return nil, errors.New("Failed to resolve arp")
	}
}

func (s *SyslogConn) Close() {
	s.handle.Close()
}

func (s *SyslogConn) Write(p []byte) (n int, err error) {
	buf := s.createPacket(p)
	s.handle.WritePacketData(buf.Bytes())
	return len(p), nil
}

func (s *SyslogConn) createPacket(p []byte) gopacket.SerializeBuffer {
	ipLayer := &layers.IPv4{
		Version:    uint8(4),
		TOS:        uint8(0),
		Id:         uint16(0),
		Flags:      layers.IPv4DontFragment,
		FragOffset: uint16(0),
		TTL:        uint8(64),
		SrcIP:      s.srcIP,
		DstIP:      s.dstIP,
		Protocol:   layers.IPProtocolUDP,
	}

	udpLayer := &layers.UDP{
		SrcPort: s.srcPort,
		DstPort: s.dstPort,
	}
	udpLayer.SetNetworkLayerForChecksum(ipLayer)

	payload := gopacket.Payload(p)

	buf := gopacket.NewSerializeBuffer()

	macLayer := &layers.Ethernet{
		SrcMAC:       s.srcMAC,
		DstMAC:       s.dstMAC,
		EthernetType: layers.EthernetTypeIPv4,
	}
	gopacket.SerializeLayers(
		buf,
		gopacket.SerializeOptions{
			ComputeChecksums: true,
			FixLengths:       true,
		},
		macLayer,
		ipLayer,
		udpLayer,
		payload,
	)
	return buf
}
