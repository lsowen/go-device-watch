package main

import (
	"errors"
	"flag"
	"fmt"
	"golang.org/x/net/icmp"
	"golang.org/x/net/internal/iana"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	"net"
	"sync"
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

func ping(targetIps []net.IP) (<-chan Result, error) {
	responseChannel := make(chan Result, len(targetIps))
	wg := &sync.WaitGroup{}

	processor := func(targetIp net.IP) {
		wg.Add(1)
		defer wg.Done()

		isIPv6 := targetIp.To4() == nil

		network := "ip6:ipv6-icmp"
		if isIPv6 == false {
			network = "ip4:icmp"
		}

		c, err := icmp.ListenPacket(network, "")
		if err != nil {
			responseChannel <- Result{
				Type:  ERROR,
				Error: err,
				Peer:  targetIp,
			}

			return
		}
		defer c.Close()

		var wm icmp.Message
		if isIPv6 == false {
			wm.Type = ipv4.ICMPTypeEcho
			wm.Code = 0
			wm.Body = &icmp.Echo{
				ID:   1,
				Seq:  1,
				Data: []byte("ping"),
			}

		} else {
			wm.Type = ipv6.ICMPTypeNeighborSolicitation
			wm.Code = 0
			wm.Body = &NeighborSolicitation{
				TargetAddress: targetIp,
			}
		}

		wb, err := wm.Marshal(nil)
		if err != nil {
			responseChannel <- Result{
				Type:  ERROR,
				Error: err,
				Peer:  targetIp,
			}

			return
		}

		addr := &net.IPAddr{IP: targetIp}

		_, err = c.WriteTo(wb, addr)
		if err != nil {
			responseChannel <- Result{
				Type:  ERROR,
				Error: err,
				Peer:  targetIp,
			}

			return
		}

		rb := make([]byte, 1500)

		timeout := time.Duration(5 * time.Second)
		c.SetReadDeadline(time.Now().Add(timeout))

		for {
			n, peer, err := c.ReadFrom(rb)
			if err != nil {
				if neterr, ok := err.(net.Error); ok && neterr.Timeout() {
					responseChannel <- Result{
						Type: UNREACHABLE,
						Peer: targetIp,
					}
				} else {
					responseChannel <- Result{
						Type:  ERROR,
						Error: err,
						Peer:  targetIp,
					}
				}

				return
			}

			proto := iana.ProtocolIPv6ICMP
			if isIPv6 == false {
				proto = iana.ProtocolICMP
			}

			rm, err := icmp.ParseMessage(proto, rb[:n])
			if err != nil {
				responseChannel <- Result{
					Type:  ERROR,
					Error: err,
					Peer:  targetIp,
				}

				return
			}
			switch rm.Type {
			case ipv6.ICMPTypeNeighborAdvertisement:
				if targetIp.Equal(peer.(*net.IPAddr).IP) {
					responseChannel <- Result{
						Type: REACHABLE,
						Peer: targetIp,
					}

					return
				}
			case ipv6.ICMPTypeDestinationUnreachable:
				msg := rm.Body.(*icmp.DstUnreach)
				destination := make(net.IP, net.IPv6len)
				copy(destination, msg.Data[24:24+net.IPv6len])

				if targetIp.Equal(destination) {
					responseChannel <- Result{
						Type: UNREACHABLE,
						Peer: targetIp,
					}

					return
				}
			case ipv4.ICMPTypeEchoReply:
				if targetIp.Equal(peer.(*net.IPAddr).IP) {
					responseChannel <- Result{
						Type: REACHABLE,
						Peer: targetIp,
					}

					return
				}
			case ipv4.ICMPTypeDestinationUnreachable:
				msg := rm.Body.(*icmp.DstUnreach)
				destination := make(net.IP, net.IPv4len)
				copy(destination, msg.Data[16:16+net.IPv4len])
				if targetIp.Equal(destination) {
					responseChannel <- Result{
						Type: UNREACHABLE,
						Peer: targetIp,
					}

					return
				}
			default:
				fmt.Printf("Other packet %+v\n", rm)
			}
		}
	}

	for _, targetIp := range targetIps {
		go processor(targetIp)
	}

	go func() {
		wg.Wait()
		close(responseChannel)
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

		fmt.Println("before")
		for r := range responseChannel {
			fmt.Printf("Response Message: %+v\n", r)
		}
		fmt.Println("after")

		time.Sleep(time.Duration(callInterval) * time.Second)
	}
}
