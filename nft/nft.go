package nft

import (
	"errors"
	"fmt"
	"net/netip"
	"sync"

	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	"github.com/google/nftables/userdata"
	"github.com/nickgarlis/flowmon/types"
	"golang.org/x/sys/unix"
)

type Config struct {
	TableFamily   uint8
	TableName     string
	InputChain    string
	OutputChain   string
	ChainPriority int32
}

type Conn struct {
	mu            sync.Mutex
	conn          *nftables.Conn
	tableFamily   nftables.TableFamily
	tableName     string
	inputChain    string
	outputChain   string
	chainPriority int32
}

func New(c *Config) (*Conn, error) {
	if c == nil {
		c = &Config{}
	}
	if c.TableFamily == 0 {
		c.TableFamily = uint8(nftables.TableFamilyIPv4)
	}
	if c.TableName == "" {
		c.TableName = "traffic_monitoring"
	}
	if c.InputChain == "" {
		c.InputChain = "input"
	}
	if c.OutputChain == "" {
		c.OutputChain = "output"
	}
	if c.ChainPriority == 0 {
		// Default to raw priority -300
		c.ChainPriority = -300
	}

	conn, err := nftables.New()
	if err != nil {
		return nil, err
	}

	return &Conn{
		conn:          conn,
		tableFamily:   nftables.TableFamily(c.TableFamily),
		tableName:     c.TableName,
		inputChain:    c.InputChain,
		outputChain:   c.OutputChain,
		chainPriority: c.ChainPriority,
	}, nil
}

func (n *Conn) Setup(input, output []types.Rule) error {
	n.mu.Lock()
	defer n.mu.Unlock()

	table, err := getOrCreateTable(n.conn, n.tableName, n.tableFamily)
	if err != nil {
		return err
	}

	if err := n.setupChain(n.conn, table, true, input); err != nil {
		return err
	}
	if err := n.setupChain(n.conn, table, false, output); err != nil {
		return err
	}

	if err := n.conn.Flush(); err != nil {
		return fmt.Errorf("failed to flush nftables changes: %v", err)
	}

	return nil
}

func (n *Conn) ListRules() ([]types.Rule, []types.Rule, error) {
	n.mu.Lock()
	defer n.mu.Unlock()

	table, err := n.conn.ListTableOfFamily(n.tableName, n.tableFamily)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get nftables table %s: %v", n.tableName, err)
	}

	inputRules, err := n.listRules(n.conn, table, true)
	if err != nil {
		return nil, nil, err
	}

	outputRules, err := n.listRules(n.conn, table, false)
	if err != nil {
		return nil, nil, err
	}

	return inputRules, outputRules, nil
}

func (n *Conn) listRules(conn *nftables.Conn, table *nftables.Table, input bool) ([]types.Rule, error) {
	chainName := n.inputChain
	if !input {
		chainName = n.outputChain
	}

	chain, err := conn.ListChain(table, chainName)
	if err != nil {
		return nil, fmt.Errorf("failed to get %s chain: %v", chainName, err)
	}

	rules, err := conn.ResetRules(table, chain)
	if err != nil {
		return nil, fmt.Errorf("failed to reset rules in %s chain: %v", chainName, err)
	}

	var specs []types.Rule
	for _, rule := range rules {
		rulespec := parseRule(rule)
		if rulespec != nil {
			rulespec.Dir = chainName
			specs = append(specs, *rulespec)
		}
	}

	return specs, nil
}

func (n *Conn) Cleanup() error {
	n.mu.Lock()
	defer n.mu.Unlock()

	table, err := n.conn.ListTableOfFamily(n.tableName, n.tableFamily)
	if err != nil && !errors.Is(err, unix.ENOENT) {
		return fmt.Errorf("failed to get nftables table %s: %v", n.tableName, err)
	}

	if table == nil || errors.Is(err, unix.ENOENT) {
		return nil
	}

	n.conn.FlushTable(table)
	n.conn.DelTable(table)

	if err := n.conn.Flush(); err != nil {
		return fmt.Errorf("failed to flush nftables changes: %v", err)
	}

	return nil
}

func (n *Conn) setupChain(conn *nftables.Conn, table *nftables.Table, input bool, rules []types.Rule) error {
	name := n.inputChain
	hook := nftables.ChainHookInput
	if !input {
		name = n.outputChain
		hook = nftables.ChainHookOutput
	}
	priority := nftables.ChainPriority(n.chainPriority)
	chain, err := getOrCreateChain(conn, table, &nftables.Chain{
		Name:     name,
		Table:    table,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  hook,
		Priority: &priority,
	})
	if err != nil {
		return fmt.Errorf("failed to get or create input chain: %w", err)
	}

	for _, spec := range rules {
		rule := buildRule(table, chain, spec)
		conn.AddRule(rule)
	}

	return nil
}

func parseRule(rule *nftables.Rule) *types.Rule {
	rulespec := &types.Rule{}
	hasCounterExpr := false

	type data string
	const (
		dataProtocol data = "protocol"
		dataSrcPort  data = "src_port"
		dataDstPort  data = "dst_port"
		dataTcpFlag  data = "tcp_flag"
		dataSrcAddr  data = "src_addr"
		dataDstAddr  data = "dst_addr"
	)

	regs := make(map[uint32]data)

	for _, ee := range rule.Exprs {
		switch e := ee.(type) {
		case *expr.Meta:
			if e.Key == expr.MetaKeyL4PROTO {
				regs[e.Register] = dataProtocol
			} else {
				return nil // We don't use other meta keys.
			}
		case *expr.Payload:
			if e.Len == 2 && (e.Base == expr.PayloadBaseTransportHeader && e.Offset == 0) {
				regs[e.DestRegister] = dataSrcPort
			} else if e.Len == 2 && (e.Base == expr.PayloadBaseTransportHeader && e.Offset == 2) {
				regs[e.DestRegister] = dataSrcPort
			} else if (e.Len == 4 || e.Len == 16) && (e.Base == expr.PayloadBaseNetworkHeader && (e.Offset == 12 || e.Offset == 8)) {
				regs[e.DestRegister] = dataSrcAddr
			} else if (e.Len == 4 || e.Len == 16) && (e.Base == expr.PayloadBaseNetworkHeader && (e.Offset == 16 || e.Offset == 24)) {
				regs[e.DestRegister] = dataDstAddr
			} else if e.Len == 1 && e.Base == expr.PayloadBaseTransportHeader {
				regs[e.DestRegister] = dataTcpFlag
			} else {
				return nil // We don't use other payload types.
			}
		case *expr.Bitwise:
			// We only expect bitwise on TCP flags where the mask is hardcoded.
			// Ignore.
		case *expr.Cmp:
			if dtype, ok := regs[e.Register]; ok {
				switch dtype {
				case dataProtocol:
					if len(e.Data) != 1 {
						return nil
					}
					rulespec.Protocol = types.Protocol(e.Data[0])
				case dataSrcPort:
					if len(e.Data) != 2 {
						return nil
					}
					port := binaryutil.BigEndian.Uint16(e.Data)
					rulespec.SrcPort = port
				case dataDstPort:
					if len(e.Data) != 2 {
						return nil
					}
					port := binaryutil.BigEndian.Uint16(e.Data)
					rulespec.DstPort = port
				case dataSrcAddr:
					if len(e.Data) != 4 && len(e.Data) != 16 {
						return nil
					}
					addr, ok := netip.AddrFromSlice(e.Data)
					if !ok {
						return nil
					}
					rulespec.SrcAddr = addr
				case dataDstAddr:
					if len(e.Data) != 4 && len(e.Data) != 16 {
						return nil
					}
					addr, ok := netip.AddrFromSlice(e.Data)
					if !ok {
						return nil
					}
					rulespec.DstAddr = addr
				case dataTcpFlag:
					if len(e.Data) != 1 {
						return nil
					}
					rulespec.Flags = types.TcpFlagsFromByte(e.Data[0])
				}
			} else {
				return nil // Unknown register usage
			}
			// parse comparison
		case *expr.Counter:
			hasCounterExpr = true
			rulespec.Packets = e.Packets
			rulespec.Bytes = e.Bytes
		default:
			// We don't use other expression types.
			// Disregard rule.
			return nil
		}
	}

	// Only return rules that have a counter expression
	if !hasCounterExpr {
		return nil
	}

	name, ok := userdata.GetString(rule.UserData, userdata.TypeComment)
	if !ok {
		return nil
	}
	rulespec.Name = name

	return rulespec
}

func buildRule(table *nftables.Table, chain *nftables.Chain, spec types.Rule) *nftables.Rule {
	exprs := []expr.Any{}

	if spec.SrcAddr.IsValid() {
		len := uint32(4)
		offset := uint32(12) // IPv4 source address offset
		if spec.SrcAddr.Is6() {
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
				Data:     spec.SrcAddr.AsSlice(),
			},
		)
	}

	if spec.DstAddr.IsValid() {
		len := uint32(4)
		offset := uint32(16) // IPv4 destination address offset
		if spec.DstAddr.Is6() {
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
				Data:     spec.DstAddr.AsSlice(),
			},
		)
	}

	if spec.Protocol > 0 {
		exprs = append(exprs,
			&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
			&expr.Cmp{Register: 1, Op: expr.CmpOpEq, Data: spec.Protocol.AsSlice()},
		)
	}

	if spec.SrcPort != 0 && (spec.Protocol == unix.IPPROTO_TCP || spec.Protocol == unix.IPPROTO_UDP) {
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
				Data:     binaryutil.BigEndian.PutUint16(spec.SrcPort),
			},
		)
	}

	if spec.DstPort != 0 && (spec.Protocol == unix.IPPROTO_TCP || spec.Protocol == unix.IPPROTO_UDP) {
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
				Data:     binaryutil.BigEndian.PutUint16(spec.DstPort),
			},
		)
	}

	if len(spec.Flags) > 0 && spec.Protocol == types.ProtocolTCP {
		match := types.TcpFlagsToByte(spec.Flags...)
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

	userData := userdata.AppendString([]byte{}, userdata.TypeComment, spec.Name)

	rule := &nftables.Rule{
		Table:    table,
		Chain:    chain,
		Exprs:    exprs,
		UserData: userData,
	}

	return rule
}
