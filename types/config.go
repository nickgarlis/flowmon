package types

import (
	"net/netip"
	"time"
)

type NFTables struct {
	Family        TableFamily `yaml:"family"`
	TableName     string      `yaml:"table_name"`
	ChainPriority int32       `yaml:"chain_priority"`
}

type Exporter struct {
	Interval time.Duration `yaml:"interval"`
	OLTP     OLTP          `yaml:"otlp"`
}

type OLTP struct {
	Endpoint string `yaml:"endpoint"`
	Debug    bool   `yaml:"debug"`
}

type Config struct {
	Version  string   // internal field of the application version
	Exporter Exporter `yaml:"exporter"`
	NFTables NFTables `yaml:"nftables"`
	Counters Counters `yaml:"counters"`
}

type Counters struct {
	Input  []Counter `yaml:"input"`
	Output []Counter `yaml:"output"`
}

type Counter struct {
	Label    string     `yaml:"label"`
	SrcPort  uint16     `yaml:"src_port"`
	DstPort  uint16     `yaml:"dst_port"`
	TcpFlags []TcpFlag  `yaml:"tcp_flags"`
	Protocol Protocol   `yaml:"protocol"`
	SrcAddr  netip.Addr `yaml:"src_addr"`
	DstAddr  netip.Addr `yaml:"dst_addr"`
	Dir      string     // internal field to denote "input" or "output"
	Packets  uint64     // internal field to hold counter value
	Bytes    uint64     // internal field to hold byte count
}
