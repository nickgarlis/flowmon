package types

import (
	"fmt"
	"strings"

	"golang.org/x/sys/unix"
)

type Protocol uint8

const (
	ProtocolTCP    Protocol = unix.IPPROTO_TCP
	ProtocolUDP    Protocol = unix.IPPROTO_UDP
	ProtocolICMP   Protocol = unix.IPPROTO_ICMP
	ProtocolICMPv6 Protocol = unix.IPPROTO_ICMPV6
)

func (p Protocol) String() string {
	switch p {
	case ProtocolTCP:
		return "tcp"
	case ProtocolUDP:
		return "udp"
	case ProtocolICMP:
		return "icmp"
	case ProtocolICMPv6:
		return "icmpv6"
	default:
		return "unknown"
	}
}

func (p *Protocol) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var s string
	if err := unmarshal(&s); err != nil {
		return err
	}
	*p = ProtocolFromString(s)
	return nil
}

func (p Protocol) AsSlice() []byte {
	return []byte{byte(p)}
}

func ProtocolFromString(s string) Protocol {
	switch s {
	case "tcp":
		return ProtocolTCP
	case "udp":
		return ProtocolUDP
	case "icmp":
		return ProtocolICMP
	case "icmpv6":
		return ProtocolICMPv6
	default:
		return 0
	}
}

type TcpFlag uint8

const (
	TcpFlagFIN TcpFlag = 0x01
	TcpFlagSYN TcpFlag = 0x02
	TcpFlagRST TcpFlag = 0x04
	TcpFlagPSH TcpFlag = 0x08
	TcpFlagACK TcpFlag = 0x10
	TcpFlagURG TcpFlag = 0x20
	TcpFlagECE TcpFlag = 0x40
	TcpFlagCWR TcpFlag = 0x80
)

func TcpFlagFromString(s string) TcpFlag {
	switch strings.ToLower(s) {
	case "fin":
		return TcpFlagFIN
	case "syn":
		return TcpFlagSYN
	case "rst":
		return TcpFlagRST
	case "psh":
		return TcpFlagPSH
	case "ack":
		return TcpFlagACK
	case "urg":
		return TcpFlagURG
	case "ece":
		return TcpFlagECE
	case "cwr":
		return TcpFlagCWR
	default:
		return 0
	}
}

func (f *TcpFlag) UnmarshalText(text []byte) error {
	*f = TcpFlagFromString(string(text))
	if *f == 0 {
		return fmt.Errorf("invalid TCP flag: %s", string(text))
	}
	return nil
}

func (f TcpFlag) String() string {
	switch f {
	case TcpFlagFIN:
		return "fin"
	case TcpFlagSYN:
		return "syn"
	case TcpFlagRST:
		return "rst"
	case TcpFlagPSH:
		return "psh"
	case TcpFlagACK:
		return "ack"
	case TcpFlagURG:
		return "urg"
	case TcpFlagECE:
		return "ece"
	case TcpFlagCWR:
		return "cwr"
	default:
		return "unknown"
	}
}

func TcpFlagsFromByte(b byte) []TcpFlag {
	flags := []TcpFlag{}
	for _, flag := range []TcpFlag{TcpFlagFIN, TcpFlagSYN, TcpFlagRST, TcpFlagPSH, TcpFlagACK, TcpFlagURG, TcpFlagECE, TcpFlagCWR} {
		if b&byte(flag) != 0 {
			flags = append(flags, flag)
		}
	}
	return flags
}

func TcpFlagsToByte(flags ...TcpFlag) byte {
	var b byte = 0
	for _, flag := range flags {
		b |= byte(flag)
	}
	return b
}

type TableFamily uint8

const (
	TableFamilyIPv4 TableFamily = unix.NFPROTO_IPV4
	TableFamilyIPv6 TableFamily = unix.NFPROTO_IPV6
	// Not yet supported
	TableFamilyInet TableFamily = unix.NFPROTO_INET
)

func TableFamilyFromString(s string) TableFamily {
	switch s {
	case "ip":
		return TableFamilyIPv4
	case "ip6":
		return TableFamilyIPv6
	case "inet":
		return TableFamilyInet
	default:
		return 0
	}
}

func (f *TableFamily) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var s string
	if err := unmarshal(&s); err != nil {
		return err
	}
	*f = TableFamilyFromString(s)
	return nil
}

func (f TableFamily) String() string {
	switch f {
	case TableFamilyIPv4:
		return "ip"
	case TableFamilyIPv6:
		return "ip6"
	case TableFamilyInet:
		return "inet"
	default:
		return "unknown"
	}
}

type OTLPProtocol string

const (
	OTLPProtocolGRPC   OTLPProtocol = "grpc"
	OTLPProtocolHTTP   OTLPProtocol = "http"
	OTLPProtocolStdout OTLPProtocol = "stdout"
)

func (p *OTLPProtocol) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var s string
	if err := unmarshal(&s); err != nil {
		return err
	}
	switch strings.ToLower(s) {
	case "grpc":
		*p = OTLPProtocolGRPC
	case "http":
		*p = OTLPProtocolHTTP
	case "stdout":
		*p = OTLPProtocolStdout
	default:
		*p = OTLPProtocolGRPC
	}
	return nil
}
