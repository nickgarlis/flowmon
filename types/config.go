package types

import (
	"net/netip"
	"time"
)

type NftSetup struct {
	ProtocolFamily TableFamily `yaml:"protocol_family"`
	TableName      string      `yaml:"table_name"`
	ChainPriority  int32       `yaml:"chain_priority"`
}

type Exporter struct {
	CollectionInterval time.Duration `yaml:"collection_interval"`
	OTLPEndpoint       string        `yaml:"otlp_endpoint"`
	Debug              bool          `yaml:"debug"`
}

type Config struct {
	Exporter    Exporter `yaml:"exporter"`
	NftSetup    NftSetup `yaml:"nft_setup"`
	InputRules  []Rule   `yaml:"input_rules"`
	OutputRules []Rule   `yaml:"output_rules"`
}

type Rule struct {
	Name     string     `yaml:"name"`
	SrcPort  uint16     `yaml:"src_port"`
	DstPort  uint16     `yaml:"dst_port"`
	Flags    []TcpFlag  `yaml:"flags"`
	Protocol Protocol   `yaml:"protocol"`
	SrcAddr  netip.Addr `yaml:"src_addr"`
	DstAddr  netip.Addr `yaml:"dst_addr"`
	Dir      string     // internal field to denote "input" or "output"
	Packets  uint64     // internal field to hold counter value
	Bytes    uint64     // internal field to hold byte count
}
