package nft

import (
	"fmt"
	"net/netip"

	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	"github.com/google/nftables/userdata"
	"github.com/nickgarlis/flowmon/types"
	"golang.org/x/sys/unix"
)

func marshalRule(table *nftables.Table, chain *nftables.Chain, counter *types.Counter) (*nftables.Rule, error) {
	exprs := []expr.Any{}

	if counter.SrcAddr.IsValid() {
		len := uint32(4)
		offset := uint32(12) // IPv4 source address offset
		if counter.SrcAddr.Is6() {
			len = 16
			offset = 8 // IPv6 source address offset
		}
		exprs = append(exprs,
			&expr.Payload{
				DestRegister: 1,
				Base:         expr.PayloadBaseNetworkHeader,
				Offset:       offset,
				Len:          len,
			},
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     counter.SrcAddr.AsSlice(),
			},
		)
	}

	if counter.DstAddr.IsValid() {
		len := uint32(4)
		offset := uint32(16) // IPv4 destination address offset
		if counter.DstAddr.Is6() {
			len = 16
			offset = 24
		}
		exprs = append(exprs,
			&expr.Payload{
				DestRegister: 1,
				Base:         expr.PayloadBaseNetworkHeader,
				Offset:       offset,
				Len:          len,
			},
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     counter.DstAddr.AsSlice(),
			},
		)
	}

	if counter.Protocol > 0 {
		exprs = append(exprs,
			&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
			&expr.Cmp{Register: 1, Op: expr.CmpOpEq, Data: counter.Protocol.AsSlice()},
		)
	}

	if counter.SrcPort != 0 && (counter.Protocol == unix.IPPROTO_TCP || counter.Protocol == unix.IPPROTO_UDP) {
		exprs = append(exprs,
			&expr.Payload{
				DestRegister: 1,
				Base:         expr.PayloadBaseTransportHeader,
				Offset:       0,
				Len:          2,
			},
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     binaryutil.BigEndian.PutUint16(counter.SrcPort),
			},
		)
	}

	if counter.DstPort != 0 && (counter.Protocol == unix.IPPROTO_TCP || counter.Protocol == unix.IPPROTO_UDP) {
		exprs = append(exprs,
			&expr.Payload{
				DestRegister: 1,
				Base:         expr.PayloadBaseTransportHeader,
				Offset:       2,
				Len:          2,
			},
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     binaryutil.BigEndian.PutUint16(counter.DstPort),
			},
		)
	}

	if len(counter.TcpFlags) > 0 && counter.Protocol == types.ProtocolTCP {
		match := types.TcpFlagsToByte(counter.TcpFlags...)
		mask := types.TcpFlagsToByte(types.TcpFlagFIN, types.TcpFlagSYN, types.TcpFlagRST, types.TcpFlagACK)
		exprs = append(exprs,
			&expr.Payload{
				DestRegister: 1,
				Base:         expr.PayloadBaseTransportHeader,
				Offset:       13, // TCP flags offset
				Len:          1,
			},
			&expr.Bitwise{
				DestRegister:   1,
				SourceRegister: 1,
				Len:            1,
				Mask:           []byte{byte(mask)},
				Xor:            []byte{0x00},
			},
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     []byte{byte(match)},
			},
		)
	}

	exprs = append(exprs,
		&expr.Counter{},
	)

	userData := userdata.AppendString([]byte{}, userdata.TypeComment, counter.Label)

	return &nftables.Rule{
		Table:    table,
		Chain:    chain,
		Exprs:    exprs,
		UserData: userData,
	}, nil
}

func unmarshalRule(rule *nftables.Rule) (*types.Counter, error) {
	rulespec := &types.Counter{}
	parser := &ruleUnmarshaler{
		counter: rulespec,
		regs:    make(map[uint32]registerType),
	}

	for _, e := range rule.Exprs {
		if err := parser.unmarshalExpr(e); err != nil {
			return nil, err
		}
	}

	if !parser.hasCounterExpr {
		return nil, fmt.Errorf("rule has no counter")
	}

	name, ok := userdata.GetString(rule.UserData, userdata.TypeComment)
	if !ok {
		return nil, fmt.Errorf("rule has no comment")
	}
	rulespec.Label = name

	return rulespec, nil
}

type registerType string

const (
	regProtocol registerType = "protocol"
	regSrcPort  registerType = "src_port"
	regDstPort  registerType = "dst_port"
	regTcpFlag  registerType = "tcp_flag"
	regSrcAddr  registerType = "src_addr"
	regDstAddr  registerType = "dst_addr"
)

type ruleUnmarshaler struct {
	counter        *types.Counter
	regs           map[uint32]registerType
	hasCounterExpr bool
}

func (r *ruleUnmarshaler) unmarshalExpr(e expr.Any) error {
	switch ex := e.(type) {
	case *expr.Meta:
		return r.unmarshalMeta(ex)
	case *expr.Payload:
		return r.unmarshalPayload(ex)
	case *expr.Cmp:
		return r.unmarshalCmp(ex)
	case *expr.Counter:
		return r.unmarshalCounter(ex)
	case *expr.Bitwise:
		// TCP flags bitwise masking - we can ignore this
		return nil
	default:
		return fmt.Errorf("unknown expression type")
	}
}

func (r *ruleUnmarshaler) unmarshalMeta(e *expr.Meta) error {
	if e.Key == expr.MetaKeyL4PROTO {
		r.regs[e.Register] = regProtocol
		return nil
	}
	return fmt.Errorf("unsupported meta key")
}

func (r *ruleUnmarshaler) unmarshalPayload(e *expr.Payload) error {
	switch {
	// Transport layer (ports, TCP flags)
	case e.Base == expr.PayloadBaseTransportHeader && e.Offset == 0 && e.Len == 2:
		r.regs[e.DestRegister] = regSrcPort
	case e.Base == expr.PayloadBaseTransportHeader && e.Offset == 2 && e.Len == 2:
		r.regs[e.DestRegister] = regDstPort
	case e.Base == expr.PayloadBaseTransportHeader && e.Offset == 13 && e.Len == 1:
		r.regs[e.DestRegister] = regTcpFlag

	// Network layer - IPv4
	case e.Base == expr.PayloadBaseNetworkHeader && e.Offset == 12 && e.Len == 4:
		r.regs[e.DestRegister] = regSrcAddr
	case e.Base == expr.PayloadBaseNetworkHeader && e.Offset == 16 && e.Len == 4:
		r.regs[e.DestRegister] = regDstAddr

	// Network layer - IPv6
	case e.Base == expr.PayloadBaseNetworkHeader && e.Offset == 8 && e.Len == 16:
		r.regs[e.DestRegister] = regSrcAddr
	case e.Base == expr.PayloadBaseNetworkHeader && e.Offset == 24 && e.Len == 16:
		r.regs[e.DestRegister] = regDstAddr

	default:
		return fmt.Errorf("unsupported payload")
	}

	return nil
}

func (r *ruleUnmarshaler) unmarshalCmp(e *expr.Cmp) error {
	regType, ok := r.regs[e.Register]
	if !ok {
		return fmt.Errorf("unknown register")
	}

	switch regType {
	case regProtocol:
		if len(e.Data) != 1 {
			return fmt.Errorf("invalid protocol length")
		}
		r.counter.Protocol = types.Protocol(e.Data[0])

	case regSrcPort:
		if len(e.Data) != 2 {
			return fmt.Errorf("invalid port length")
		}
		r.counter.SrcPort = binaryutil.BigEndian.Uint16(e.Data)

	case regDstPort:
		if len(e.Data) != 2 {
			return fmt.Errorf("invalid port length")
		}
		r.counter.DstPort = binaryutil.BigEndian.Uint16(e.Data)

	case regSrcAddr, regDstAddr:
		if len(e.Data) != 4 && len(e.Data) != 16 {
			return fmt.Errorf("invalid address length")
		}
		addr, ok := netip.AddrFromSlice(e.Data)
		if !ok {
			return fmt.Errorf("invalid address")
		}
		if regType == regSrcAddr {
			r.counter.SrcAddr = addr
		} else {
			r.counter.DstAddr = addr
		}

	case regTcpFlag:
		if len(e.Data) != 1 {
			return fmt.Errorf("invalid flag length")
		}
		r.counter.TcpFlags = types.TcpFlagsFromByte(e.Data[0])

	default:
		return fmt.Errorf("unknown register type")
	}

	return nil
}

func (r *ruleUnmarshaler) unmarshalCounter(e *expr.Counter) error {
	r.hasCounterExpr = true
	r.counter.Packets = e.Packets
	r.counter.Bytes = e.Bytes
	return nil
}
