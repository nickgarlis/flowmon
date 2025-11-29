package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"time"

	"github.com/nickgarlis/flowmon/nft"
	"github.com/nickgarlis/flowmon/types"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc"
	"go.opentelemetry.io/otel/exporters/stdout/stdoutmetric"
	"go.opentelemetry.io/otel/metric"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	semconv "go.opentelemetry.io/otel/semconv/v1.37.0"
	"go.yaml.in/yaml/v3"
	"golang.org/x/sys/unix"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

var (
	version = "dev"
)

type Flowmon struct {
	nftClient     *nft.Conn
	meter         metric.Meter
	meterProvider *sdkmetric.MeterProvider
}

func getExporter(ctx context.Context, cfg *types.Config) (sdkmetric.Exporter, error) {
	if cfg.Exporter.Debug {
		return stdoutmetric.New(stdoutmetric.WithPrettyPrint())
	}

	conn, err := grpc.NewClient(
		cfg.Exporter.OTLPEndpoint,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create gRPC connection: %v", err)
	}

	return otlpmetricgrpc.New(ctx, otlpmetricgrpc.WithGRPCConn(conn))
}

func NewFlowmon(ctx context.Context, cfg *types.Config) (*Flowmon, error) {
	nftClient, err := nft.New(&nft.Config{
		TableFamily:   cfg.NftSetup.ProtocolFamily,
		TableName:     cfg.NftSetup.TableName,
		ChainPriority: cfg.NftSetup.ChainPriority,
	})
	if err != nil {
		return nil, fmt.Errorf("nft.New(): %v", err)
	}

	if err := nftClient.Setup(cfg.InputRules, cfg.OutputRules); err != nil {
		return nil, fmt.Errorf("nftClient.Setup(): %v", err)
	}

	exporter, err := getExporter(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("getExporter(): %v", err)
	}

	// Create resource with service information
	res, err := resource.Merge(
		resource.Default(),
		resource.NewWithAttributes(
			semconv.SchemaURL,
			semconv.ServiceName("flowmon"),
			semconv.ServiceVersion("0.0.1"),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create resource: %v", err)
	}

	// Create meter provider
	meterProvider := sdkmetric.NewMeterProvider(
		sdkmetric.WithResource(res),
		sdkmetric.WithReader(sdkmetric.NewPeriodicReader(
			exporter,
			sdkmetric.WithInterval(cfg.Exporter.CollectionInterval),
		)),
	)
	otel.SetMeterProvider(meterProvider)

	meter := meterProvider.Meter("flowmon")

	packetsGauge, err := meter.Int64ObservableGauge(
		"flow.packets",
		metric.WithDescription("Number of packets matched"),
		metric.WithUnit("{packets}"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create packets gauge: %v", err)
	}

	bytesGauge, err := meter.Int64ObservableGauge(
		"flow.bytes",
		metric.WithDescription("Number of bytes processed by NFT rule"),
		metric.WithUnit("By"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create bytes gauge: %v", err)
	}

	_, err = meter.RegisterCallback(func(ctx context.Context, o metric.Observer) error {
		input, output, err := nftClient.ListRules()
		if err != nil {
			return fmt.Errorf("failed to list rules: %w", err)
		}

		rules := append(input, output...)
		for _, rule := range rules {
			ruleAttrs := buildAttributes(rule)

			o.ObserveInt64(packetsGauge, int64(rule.Packets), metric.WithAttributes(ruleAttrs...))
			o.ObserveInt64(bytesGauge, int64(rule.Bytes), metric.WithAttributes(ruleAttrs...))
		}

		return nil
	}, packetsGauge, bytesGauge)
	if err != nil {
		return nil, fmt.Errorf("failed to register callback: %v", err)
	}

	return &Flowmon{
		nftClient:     nftClient,
		meter:         meter,
		meterProvider: meterProvider,
	}, nil
}

func buildAttributes(rule types.Rule) []attribute.KeyValue {
	attrs := []attribute.KeyValue{
		attribute.String("direction", rule.Dir),
	}

	if rule.SrcAddr.IsValid() {
		attrs = append(attrs, attribute.String("src_addr", rule.SrcAddr.String()))
	}

	if rule.DstAddr.IsValid() {
		attrs = append(attrs, attribute.String("dst_addr", rule.DstAddr.String()))
	}

	if rule.Protocol > 0 {
		attrs = append(attrs, attribute.String("protocol", rule.Protocol.String()))
	}

	if rule.SrcPort > 0 && (rule.Protocol == types.ProtocolTCP || rule.Protocol == types.ProtocolUDP) {
		attrs = append(attrs, attribute.Int("src_port", int(rule.SrcPort)))
	}

	if rule.DstPort > 0 && (rule.Protocol == types.ProtocolTCP || rule.Protocol == types.ProtocolUDP) {
		attrs = append(attrs, attribute.Int("dst_port", int(rule.DstPort)))
	}

	if len(rule.Flags) > 0 {
		flags := make([]string, len(rule.Flags))
		for i, flag := range rule.Flags {
			flags[i] = flag.String()
		}
		attrs = append(attrs, attribute.StringSlice("flags", flags))
	}

	return attrs
}

func (f *Flowmon) Shutdown(ctx context.Context) error {
	shutdownCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	if err := f.meterProvider.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("failed to shutdown meter provider: %v", err)
	}

	if err := f.nftClient.Cleanup(); err != nil {
		return fmt.Errorf("failed to cleanup nft client: %v", err)
	}

	return nil
}

func loadConfig(path string) (*types.Config, error) {
	yamlFile, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	cfg := &types.Config{
		Exporter: types.Exporter{
			CollectionInterval: 10,
			OTLPEndpoint:       "localhost:4317",
			Debug:              false,
		},
		NftSetup: types.NftSetup{
			ProtocolFamily: types.TableFamilyIPv4,
			TableName:      "flowmon",
			ChainPriority:  -300,
		},
		InputRules:  []types.Rule{},
		OutputRules: []types.Rule{},
	}

	if err := yaml.Unmarshal(yamlFile, &cfg); err != nil {
		return nil, err
	}

	return cfg, nil
}

func start(configPath string) {

	ctx, cancel := signal.NotifyContext(context.Background(), unix.SIGINT, unix.SIGTERM)
	defer cancel()

	cfg, err := loadConfig(configPath)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	log.Println("Flowmon starting...")
	exporter, err := NewFlowmon(ctx, cfg)
	if err != nil {
		log.Fatalf("Failed to create flowmon: %v", err)
	}

	<-ctx.Done()

	log.Println("Flowmon stopping...")
	if err := exporter.Shutdown(context.Background()); err != nil {
		log.Fatalf("Failed to shutdown flowmon: %v", err)
	}

}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "Usage: %s <command> [options]\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "\nCommands:\n")
		fmt.Fprintf(os.Stderr, "  start    Start the flowmon daemon\n")
		fmt.Fprintf(os.Stderr, "  version  Show version information\n")
		os.Exit(1)
	}

	switch os.Args[1] {
	case "start":
		startCmd := flag.NewFlagSet("start", flag.ExitOnError)
		configPath := startCmd.String("config", "/etc/flowmon/config.yaml", "path to config file")
		startCmd.Parse(os.Args[2:])
		start(*configPath)
	case "version":
		fmt.Printf("flowmon version %s\n", version)
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n", os.Args[1])
		os.Exit(1)
	}
}
