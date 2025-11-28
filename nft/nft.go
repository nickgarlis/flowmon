package nft

import (
	"errors"
	"fmt"
	"sync"

	"github.com/google/nftables"
	"github.com/nickgarlis/flowmon/types"
	"golang.org/x/sys/unix"
)

type Config struct {
	TableFamily   types.TableFamily
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
		c.TableFamily = types.TableFamilyIPv4
	}
	if c.TableName == "" {
		c.TableName = "flowmon"
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
		return fmt.Errorf("flush: %v", err)
	}

	return nil
}

func (n *Conn) ListRules() ([]types.Rule, []types.Rule, error) {
	n.mu.Lock()
	defer n.mu.Unlock()

	table, err := n.conn.ListTableOfFamily(n.tableName, n.tableFamily)
	if err != nil {
		return nil, nil, fmt.Errorf("get table %s: %v", n.tableName, err)
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
		return nil, fmt.Errorf("get chain %s: %v", chainName, err)
	}

	rules, err := conn.ResetRules(table, chain)
	if err != nil {
		return nil, fmt.Errorf("reset %s rules: %v", chainName, err)
	}

	var specs []types.Rule
	for _, rule := range rules {
		rulespec, err := unmarshalRule(rule)
		if err != nil {
			return nil, fmt.Errorf("unmarshalRule: %v", err)
		}
		rulespec.Dir = chainName
		specs = append(specs, *rulespec)
	}

	return specs, nil
}

func (n *Conn) Cleanup() error {
	n.mu.Lock()
	defer n.mu.Unlock()

	table, err := n.conn.ListTableOfFamily(n.tableName, n.tableFamily)
	if err != nil && !errors.Is(err, unix.ENOENT) {
		return fmt.Errorf("get table %s: %v", n.tableName, err)
	}

	if table == nil || errors.Is(err, unix.ENOENT) {
		return nil
	}

	n.conn.FlushTable(table)
	n.conn.DelTable(table)

	if err := n.conn.Flush(); err != nil {
		return fmt.Errorf("flush: %v", err)
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
		return fmt.Errorf("getOrCreateChain: %v", err)
	}

	for _, rr := range rules {
		rule, err := marshalRule(table, chain, &rr)
		if err != nil {
			return fmt.Errorf("marshalRule: %v", err)
		}
		conn.AddRule(rule)
	}

	return nil
}
