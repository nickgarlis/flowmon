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
		TableFamily:   cfg.NFTables.Family,
		TableName:     cfg.NFTables.TableName,
		ChainPriority: cfg.NFTables.ChainPriority,
	})
	if err != nil {
		return nil, fmt.Errorf("nft.New(): %w", err)
	}

	if err := nftClient.Setup(&cfg.Counters); err != nil {
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
			sdkmetric.WithInterval(e.cfg.Exporter.Interval),
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
		metric.WithDescription("Number of bytes processed by counter"),
		metric.WithUnit("By"),
	)
	if err != nil {
		return fmt.Errorf("failed to create bytes gauge: %w", err)
	}

	_, err = e.meter.RegisterCallback(func(ctx context.Context, o metric.Observer) error {
		counters, err := e.nftClient.ListCounters()
		if err != nil {
			return fmt.Errorf("failed to list counters: %v", err)
		}

		all := append(counters.Input, counters.Output...)
		for _, counter := range all {
			counterAttrs := buildAttributes(counter)

			o.ObserveInt64(packetsGauge, int64(counter.Packets), metric.WithAttributes(counterAttrs...))
			o.ObserveInt64(bytesGauge, int64(counter.Bytes), metric.WithAttributes(counterAttrs...))
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
	if cfg.Exporter.OLTP.Debug {
		return stdoutmetric.New(stdoutmetric.WithPrettyPrint())
	}

	conn, err := grpc.NewClient(
		cfg.Exporter.OLTP.Endpoint,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create gRPC connection: %w", err)
	}

	return otlpmetricgrpc.New(ctx, otlpmetricgrpc.WithGRPCConn(conn))
}

func buildAttributes(counter types.Counter) []attribute.KeyValue {
	attrs := []attribute.KeyValue{
		attribute.String("direction", counter.Dir),
	}

	if counter.Label != "" {
		attrs = append(attrs, attribute.String("label", counter.Label))
	}

	if counter.SrcAddr.IsValid() {
		attrs = append(attrs, attribute.String("src_addr", counter.SrcAddr.String()))
	}

	if counter.DstAddr.IsValid() {
		attrs = append(attrs, attribute.String("dst_addr", counter.DstAddr.String()))
	}

	if counter.Protocol > 0 {
		attrs = append(attrs, attribute.String("protocol", counter.Protocol.String()))
	}

	if counter.SrcPort > 0 && (counter.Protocol == types.ProtocolTCP || counter.Protocol == types.ProtocolUDP) {
		attrs = append(attrs, attribute.Int("src_port", int(counter.SrcPort)))
	}

	if counter.DstPort > 0 && (counter.Protocol == types.ProtocolTCP || counter.Protocol == types.ProtocolUDP) {
		attrs = append(attrs, attribute.Int("dst_port", int(counter.DstPort)))
	}

	if len(counter.TcpFlags) > 0 {
		flags := make([]string, len(counter.TcpFlags))
		for i, flag := range counter.TcpFlags {
			flags[i] = flag.String()
		}
		attrs = append(attrs, attribute.StringSlice("flags", flags))
	}

	return attrs
}
