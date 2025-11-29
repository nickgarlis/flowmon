package nft

import (
	"net/netip"
	"os"
	"reflect"
	"testing"

	"github.com/nickgarlis/flowmon/types"
)

func TestIPv4(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("Skipping test that requires root privileges")
	}

	nft, err := New(&Config{
		TableFamily:   types.TableFamilyIPv4,
		TableName:     "test_table",
		InputChain:    "input",
		OutputChain:   "output",
		ChainPriority: -300,
	})
	if err != nil {
		t.Fatalf("Failed to create Nft instance: %v", err)
	}

	wantCounters := &types.Counters{
		Input: []types.Counter{
			{Label: "rest_syn", DstPort: 8080, Protocol: types.ProtocolTCP, SrcAddr: netip.MustParseAddr("1.2.3.4"), TcpFlags: []types.TcpFlag{types.TcpFlagSYN}},
		},
		Output: []types.Counter{
			{Label: "rest_syn_ack", SrcPort: 8080, Protocol: types.ProtocolTCP, TcpFlags: []types.TcpFlag{types.TcpFlagSYN, types.TcpFlagACK}, DstAddr: netip.MustParseAddr("1.2.3.4")},
			{DstPort: 9090, Protocol: types.ProtocolUDP, DstAddr: netip.MustParseAddr("2.3.4.5")},
		},
	}

	if err := nft.Setup(wantCounters); err != nil {
		t.Fatalf("Setup failed: %v", err)
	}

	gotCounters, err := nft.ListCounters()
	if err != nil {
		t.Fatalf("Failed to list counters: %v", err)
	}

	if len(wantCounters.Input) != len(gotCounters.Input) {
		t.Errorf("Expected %d input counters, got %d", len(wantCounters.Input), len(gotCounters.Input))
	}
	if len(wantCounters.Output) != len(gotCounters.Output) {
		t.Errorf("Expected %d output counters, got %d", len(wantCounters.Output), len(gotCounters.Output))
	}

	for i := range wantCounters.Input {
		wantCounters.Input[i].Bytes = 0
		wantCounters.Input[i].Packets = 0
		wantCounters.Input[i].Dir = ""
	}

	for i := range wantCounters.Output {
		wantCounters.Output[i].Bytes = 0
		wantCounters.Output[i].Packets = 0
		wantCounters.Output[i].Dir = ""
	}

	if reflect.DeepEqual(wantCounters, gotCounters) == false {
		t.Errorf("Counters do not match expected counters.\nExpected: %+v\nGot: %+v", wantCounters, gotCounters)
	}

	if err := nft.Cleanup(); err != nil {
		t.Fatalf("Cleanup failed: %v", err)
	}
}

func TestIPv6(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("Skipping test that requires root privileges")
	}

	nft, err := New(&Config{
		TableFamily:   types.TableFamilyIPv6,
		TableName:     "test_table_v6",
		InputChain:    "input",
		OutputChain:   "output",
		ChainPriority: -300,
	})
	if err != nil {
		t.Fatalf("Failed to create Nft instance: %v", err)
	}

	wantCounters := &types.Counters{
		Input: []types.Counter{
			{Label: "rest_syn", DstPort: 8080, Protocol: types.ProtocolTCP, SrcAddr: netip.MustParseAddr("2001:db8::1"), TcpFlags: []types.TcpFlag{types.TcpFlagSYN}},
		},
		Output: []types.Counter{
			{Label: "rest_syn_ack", SrcPort: 8080, Protocol: types.ProtocolTCP, TcpFlags: []types.TcpFlag{types.TcpFlagSYN, types.TcpFlagACK}, DstAddr: netip.MustParseAddr("2001:db8::1")},
			{DstPort: 9090, Protocol: types.ProtocolUDP, DstAddr: netip.MustParseAddr("2001:db8::2")},
		},
	}

	if err := nft.Setup(wantCounters); err != nil {
		t.Fatalf("Setup failed: %v", err)
	}

	gotCounters, err := nft.ListCounters()
	if err != nil {
		t.Fatalf("Failed to list counters: %v", err)
	}

	if len(wantCounters.Input) != len(gotCounters.Input) {
		t.Errorf("Expected %d input counters, got %d", len(wantCounters.Input), len(gotCounters.Input))
	}
	if len(wantCounters.Output) != len(gotCounters.Output) {
		t.Errorf("Expected %d output counters, got %d", len(wantCounters.Output), len(gotCounters.Output))
	}

	for i := range wantCounters.Input {
		wantCounters.Input[i].Bytes = 0
		wantCounters.Input[i].Packets = 0
		wantCounters.Input[i].Dir = ""
	}

	for i := range wantCounters.Output {
		wantCounters.Output[i].Bytes = 0
		wantCounters.Output[i].Packets = 0
		wantCounters.Output[i].Dir = ""
	}

	if reflect.DeepEqual(wantCounters, gotCounters) == false {
		t.Errorf("Counters do not match expected counters.\nExpected: %+v\nGot: %+v", wantCounters, gotCounters)
	}

	if err := nft.Cleanup(); err != nil {
		t.Fatalf("Cleanup failed: %v", err)
	}
}
