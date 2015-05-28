package main

import (
	"errors"
	"flag"
	"fmt"
	"golang.org/x/net/icmp"
	"golang.org/x/net/internal/iana"
	"golang.org/x/net/ipv6"
	"net"
	"time"
)

type NeighborSolicitation struct {
	TargetAddress net.IP
}

func (m *NeighborSolicitation) Len(proto int) int {
	return 4 + len(m.TargetAddress)
}

func (m *NeighborSolicitation) Marshal(proto int) ([]byte, error) {
	buf := make([]byte, m.Len(proto))
	copy(buf[4:], m.TargetAddress)
	return buf, nil
}

type ResultType int

const (
	REACHABLE ResultType = iota
	UNREACHABLE
	ERROR
)

type Result struct {
	Type  ResultType
	Peer  net.IP
	Error error
}

func ping(inputTargetIps []net.IP) (<-chan Result, error) {
	targetIps := make([]net.IP, len(inputTargetIps))
	copy(targetIps, inputTargetIps)

	c, err := icmp.ListenPacket("ip6:ipv6-icmp", "::")
	if err != nil {
		return nil, err
	}

	for _, targetIp := range targetIps {

		wm := icmp.Message{
			Type: ipv6.ICMPTypeNeighborSolicitation,
			Code: 0,
			Body: &NeighborSolicitation{
				TargetAddress: targetIp,
			},
		}

		wb, err := wm.Marshal(nil)
		if err != nil {
			return nil, err
		}

		addr := &net.IPAddr{IP: targetIp}

		_, err = c.WriteTo(wb, addr)
		if err != nil {
			return nil, err
		}
	}

	responseChannel := make(chan Result)
	go func() {
		defer c.Close()

		rb := make([]byte, 1500)

		timeout := time.Duration(5 * time.Second)
		c.SetReadDeadline(time.Now().Add(timeout))

		for {
			n, peer, err := c.ReadFrom(rb)
			if err != nil {
				if neterr, ok := err.(net.Error); ok && neterr.Timeout() {
					for _, targetIp := range targetIps {
						responseChannel <- Result{
							Type: UNREACHABLE,
							Peer: targetIp,
						}
					}
				} else {
					responseChannel <- Result{
						Type:  ERROR,
						Error: err,
					}
				}
				close(responseChannel)
				return
			}

			rm, err := icmp.ParseMessage(iana.ProtocolIPv6ICMP, rb[:n])
			if err != nil {
				responseChannel <- Result{
					Type:  ERROR,
					Error: err,
				}
				close(responseChannel)
				return
			}
			switch rm.Type {
			case ipv6.ICMPTypeNeighborAdvertisement:
				for i, candidateIp := range targetIps {
					if candidateIp.Equal(peer.(*net.IPAddr).IP) {
						responseChannel <- Result{
							Type: REACHABLE,
							Peer: candidateIp,
						}

						targetIps = append(targetIps[:i], targetIps[i+1:]...)
						if len(targetIps) == 0 {
							close(responseChannel)
							return
						}
						break
					}
				}
			case ipv6.ICMPTypeDestinationUnreachable:
				msg := rm.Body.(*icmp.DstUnreach)
				destination := make(net.IP, net.IPv6len)
				copy(destination, msg.Data[24:40])

				for i, candidateIp := range targetIps {
					if candidateIp.Equal(destination) {
						responseChannel <- Result{
							Type: UNREACHABLE,
							Peer: candidateIp,
						}

						targetIps = append(targetIps[:i], targetIps[i+1:]...)
						if len(targetIps) == 0 {
							close(responseChannel)
							return
						}
						break
					}
				}
			}
		}
	}()

	return responseChannel, nil
}

type ipList []net.IP

func (i *ipList) String() string {
	return fmt.Sprint(*i)
}

func (i *ipList) Set(value string) error {
	ip := net.ParseIP(value)
	if ip == nil {
		return errors.New(fmt.Sprintf("%s is not a valid IP", value))
	}
	*i = append(*i, ip)
	return nil
}

func main() {
	var targetIPs ipList
	var targetScript string
	var callInterval int

	flag.Var(&targetIPs, "ip", "What IPv6 addresses to check")
	flag.StringVar(&targetScript, "script", "", "What script to call with results")
	flag.IntVar(&callInterval, "interval", 60, "How often to try fetching new results")
	flag.Parse()

	for {
		responseChannel, err := ping(targetIPs)
		if err != nil {
			fmt.Println(err)
		}

		for r := range responseChannel {
			fmt.Println(r)
		}

		time.Sleep(time.Duration(callInterval) * time.Second)
	}
}
