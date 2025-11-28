package nft

import (
	"net/netip"
	"reflect"
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
		{Name: "test_input_rule", DstPort: 8080, Protocol: types.ProtocolTCP, SrcAddr: netip.MustParseAddr("1.2.3.4"), Flags: []types.TcpFlag{types.TcpFlagSYN}},
	}
	outputRules := []types.Rule{
		{Name: "test_output_rule", SrcPort: 8080, Protocol: types.ProtocolTCP, Flags: []types.TcpFlag{types.TcpFlagSYN, types.TcpFlagACK}, DstAddr: netip.MustParseAddr("1.2.3.4")},
		{Name: "test_output_rule", DstPort: 9090, Protocol: types.ProtocolUDP, DstAddr: netip.MustParseAddr("2.3.4.5")},
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

	for i := range input {
		input[i].Bytes = 0
		input[i].Packets = 0
		input[i].Dir = ""
	}

	if reflect.DeepEqual(inputRules, input) == false {
		t.Errorf("Input rules do not match expected rules.\nExpected: %+v\nGot: %+v", inputRules, input)
	}

	for i := range output {
		output[i].Bytes = 0
		output[i].Packets = 0
		output[i].Dir = ""
	}

	if reflect.DeepEqual(outputRules, output) == false {
		t.Errorf("Output rules do not match expected rules.\nExpected: %+v\nGot: %+v", outputRules, output)
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
		{Name: "test_input_rule", DstPort: 8080, Protocol: types.ProtocolTCP, SrcAddr: netip.MustParseAddr("2001:db8::1"), Flags: []types.TcpFlag{types.TcpFlagSYN}},
	}
	outputRules := []types.Rule{
		{Name: "test_output_rule", SrcPort: 8080, Protocol: types.ProtocolTCP, Flags: []types.TcpFlag{types.TcpFlagSYN, types.TcpFlagACK}, DstAddr: netip.MustParseAddr("2001:db8::1")},
		{Name: "test_output_rule", DstPort: 9090, Protocol: types.ProtocolUDP, DstAddr: netip.MustParseAddr("2001:db8::2")},
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

	for i := range input {
		input[i].Bytes = 0
		input[i].Packets = 0
		input[i].Dir = ""
	}

	if reflect.DeepEqual(inputRules, input) == false {
		t.Errorf("Input rules do not match expected rules.\nExpected: %+v\nGot: %+v", inputRules, input)
	}

	for i := range output {
		output[i].Bytes = 0
		output[i].Packets = 0
		output[i].Dir = ""
	}

	if reflect.DeepEqual(outputRules, output) == false {
		t.Errorf("Output rules do not match expected rules.\nExpected: %+v\nGot: %+v", outputRules, output)
	}

	if err := nft.Cleanup(); err != nil {
		t.Fatalf("Cleanup failed: %v", err)
	}
}
