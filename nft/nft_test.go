package nft

import (
	"net/netip"
	"testing"

	"github.com/nickgarlis/flowmon/types"
)

func TestIPv4(t *testing.T) {
	nft, err := New(&Config{
		TableFamily:   uint8(types.TableFamilyIPv4),
		TableName:     "test_table",
		InputChain:    "input",
		OutputChain:   "output",
		ChainPriority: -300,
	})
	if err != nil {
		t.Fatalf("Failed to create Nft instance: %v", err)
	}

	inputRules := []types.Rule{
		{Name: "test_input_rule", Port: 8080, Protocol: types.ProtocolTCP, Flags: []types.TcpFlag{types.TcpFlagSYN}},
		{Name: "test_input_rule", Port: 8080, Protocol: types.ProtocolTCP, Flags: []types.TcpFlag{types.TcpFlagSYN}},
	}
	outputRules := []types.Rule{
		{Name: "test_output_rule", Port: 8080, Protocol: types.ProtocolTCP, Flags: []types.TcpFlag{types.TcpFlagSYN, types.TcpFlagACK}, Addr: netip.MustParseAddr("1.2.3.4")},
		{Name: "test_output_rule", Port: 9090, Protocol: types.ProtocolUDP},
	}

	if err := nft.Setup(inputRules, outputRules); err != nil {
		t.Fatalf("Setup failed: %v", err)
	}

	input, output, err := nft.ListRules()
	if err != nil {
		t.Fatalf("Failed to list rules: %v", err)
	}

	if len(input) != len(inputRules) {
		t.Errorf("Expected %d input rules, got %d", len(inputRules), len(input))
	}
	if len(output) != len(outputRules) {
		t.Errorf("Expected %d output rules, got %d", len(outputRules), len(output))
	}

	t.Logf("Input Rules:")
	for _, rule := range input {
		t.Logf("%+v", rule)
	}
	t.Logf("Output Rules:")
	for _, rule := range output {
		t.Logf("%+v", rule)
	}

	if err := nft.Cleanup(); err != nil {
		t.Fatalf("Cleanup failed: %v", err)
	}
}

func TestIPv6(t *testing.T) {
	nft, err := New(&Config{
		TableFamily:   uint8(types.TableFamilyIPv6),
		TableName:     "test_table_v6",
		InputChain:    "input",
		OutputChain:   "output",
		ChainPriority: -300,
	})
	if err != nil {
		t.Fatalf("Failed to create Nft instance: %v", err)
	}

	inputRules := []types.Rule{
		{Name: "test_input_rule_v6", Port: 8080, Protocol: types.ProtocolTCP, Flags: []types.TcpFlag{types.TcpFlagSYN}},
	}
	outputRules := []types.Rule{
		{Name: "test_output_rule_v6", Port: 8080, Protocol: types.ProtocolTCP, Flags: []types.TcpFlag{types.TcpFlagSYN, types.TcpFlagACK}, Addr: netip.MustParseAddr("2001:db8::1")},
	}

	if err := nft.Setup(inputRules, outputRules); err != nil {
		t.Fatalf("Setup failed: %v", err)
	}

	input, output, err := nft.ListRules()
	if err != nil {
		t.Fatalf("Failed to list rules: %v", err)
	}

	if len(input) != len(inputRules) {
		t.Errorf("Expected %d input rules, got %d", len(inputRules), len(input))
	}
	if len(output) != len(outputRules) {
		t.Errorf("Expected %d output rules, got %d", len(outputRules), len(output))
	}

	t.Logf("Input Rules:")
	for _, rule := range input {
		t.Logf("%+v", rule)
	}
	t.Logf("Output Rules:")
	for _, rule := range output {
		t.Logf("%+v", rule)
	}

	if err := nft.Cleanup(); err != nil {
		t.Fatalf("Cleanup failed: %v", err)
	}
}
