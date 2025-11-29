package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"

	"github.com/nickgarlis/flowmon/exporter"
	"github.com/nickgarlis/flowmon/types"
	"go.yaml.in/yaml/v3"
	"golang.org/x/sys/unix"
)

var (
	version = "dev"
)

func loadConfig(path string) (*types.Config, error) {
	yamlFile, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	cfg := &types.Config{
		Version: version,
		Exporter: types.Exporter{
			Interval: 10,
			OTLP: types.OTLP{
				Endpoint: "localhost:4317",
				Protocol: types.OTLPProtocolGRPC,
			},
		},
		NFTables: types.NFTables{
			Family:        types.TableFamilyIPv4,
			TableName:     "flowmon",
			ChainPriority: -300,
		},
		Counters: types.Counters{
			Input:  []types.Counter{},
			Output: []types.Counter{},
		},
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

	exp, err := exporter.New(cfg)
	if err != nil {
		log.Fatalf("Failed to create exporter: %v", err)
	}

	log.Println("Flowmon starting...")
	if err := exp.Start(ctx); err != nil {
		log.Fatalf("Failed to start exporter: %v", err)
	}

	<-ctx.Done()

	log.Println("Flowmon stopping...")
	if err := exp.Shutdown(context.Background()); err != nil {
		log.Fatalf("Failed to shutdown exporter: %v", err)
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
