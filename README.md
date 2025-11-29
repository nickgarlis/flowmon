## Flowmon
Flowmon is an OpenTelemetry exporter for Linux that collects network packet
metrics using [nftables](https://wiki.nftables.org/wiki-nftables/index.php/Quick_reference-nftables_in_10_minutes).
You define which traffic to monitor, and Flowmon exports packet and byte counts
for each counter to an OTLP-compatible backend.

## Features
- Define nftables-based counters for the traffic you want to observe.
- Collect metrics such as packet and byte counts for each counter.
- Export metrics to OpenTelemetry endpoints (gRPC, HTTP, or stdout).
- Simple YAML configuration.
- Lightweight and easy to run as a daemon.

## Installation
Download the latest release from the [releases](https://github.com/nickgarlis/flowmon/releases) page.

## Usage
Run Flowmon with a configuration file:
```yaml
exporter:
  interval: "30s"
  otlp:
    endpoint: "localhost:4317"
    protocol: "grpc"
counters:
  input:
    - label: "rest_syn_requests"
      protocol: "tcp"
      dst_port: 8080
      tcp_flags: [sync]
  output:
    - label: "rest_syn_ack_responses"
      protocol: "tcp"
      src_port: 8080
      tcp_flags: [syn, ack]
```
This example monitors TCP SYN requests to port 8080 and TCP SYN-ACK responses
from port 8080, exporting metrics every 30 seconds to an OpenTelemetry endpoint
at localhost:4317.

You can run Flowmon as a systemd service:
```bash
sudo systemctl start flowmon
```

Or manually:
```bash
sudo ./flowmon --config /path/to/config.yaml
```