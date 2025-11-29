package exporter

import (
	"context"
	"fmt"
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
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

type Exporter struct {
	cfg           *types.Config
	nftClient     *nft.Conn
	meter         metric.Meter
	meterProvider *sdkmetric.MeterProvider
}

func New(cfg *types.Config) (*Exporter, error) {
	nftClient, err := nft.New(&nft.Config{
		TableFamily:   cfg.NftSetup.ProtocolFamily,
		TableName:     cfg.NftSetup.TableName,
		ChainPriority: cfg.NftSetup.ChainPriority,
	})
	if err != nil {
		return nil, fmt.Errorf("nft.New(): %w", err)
	}

	if err := nftClient.Setup(cfg.InputRules, cfg.OutputRules); err != nil {
		return nil, fmt.Errorf("nftClient.Setup(): %w", err)
	}

	return &Exporter{
		cfg:       cfg,
		nftClient: nftClient,
	}, nil
}

func (e *Exporter) Start(ctx context.Context) error {
	exporter, err := getExporter(ctx, e.cfg)
	if err != nil {
		return fmt.Errorf("getExporter(): %w", err)
	}

	res, err := resource.Merge(
		resource.Default(),
		resource.NewWithAttributes(
			semconv.SchemaURL,
			semconv.ServiceName("flowmon"),
			semconv.ServiceVersion(e.cfg.Version),
		),
	)
	if err != nil {
		return fmt.Errorf("failed to create resource: %w", err)
	}

	e.meterProvider = sdkmetric.NewMeterProvider(
		sdkmetric.WithResource(res),
		sdkmetric.WithReader(sdkmetric.NewPeriodicReader(
			exporter,
			sdkmetric.WithInterval(e.cfg.Exporter.CollectionInterval),
		)),
	)
	otel.SetMeterProvider(e.meterProvider)

	e.meter = e.meterProvider.Meter("flowmon")

	if err := e.registerMetrics(); err != nil {
		return fmt.Errorf("failed to register metrics: %w", err)
	}

	return nil
}

func (e *Exporter) registerMetrics() error {
	packetsGauge, err := e.meter.Int64ObservableGauge(
		"flow.packets",
		metric.WithDescription("Number of packets matched"),
		metric.WithUnit("{packets}"),
	)
	if err != nil {
		return fmt.Errorf("failed to create packets gauge: %w", err)
	}

	bytesGauge, err := e.meter.Int64ObservableGauge(
		"flow.bytes",
		metric.WithDescription("Number of bytes processed by NFT rule"),
		metric.WithUnit("By"),
	)
	if err != nil {
		return fmt.Errorf("failed to create bytes gauge: %w", err)
	}

	_, err = e.meter.RegisterCallback(func(ctx context.Context, o metric.Observer) error {
		input, output, err := e.nftClient.ListRules()
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
		return fmt.Errorf("failed to register callback: %w", err)
	}

	return nil
}

func (e *Exporter) Shutdown(ctx context.Context) error {
	shutdownCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	if e.meterProvider != nil {
		if err := e.meterProvider.Shutdown(shutdownCtx); err != nil {
			return fmt.Errorf("failed to shutdown meter provider: %w", err)
		}
	}

	if err := e.nftClient.Cleanup(); err != nil {
		return fmt.Errorf("failed to cleanup nft client: %w", err)
	}

	return nil
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
		return nil, fmt.Errorf("failed to create gRPC connection: %w", err)
	}

	return otlpmetricgrpc.New(ctx, otlpmetricgrpc.WithGRPCConn(conn))
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
