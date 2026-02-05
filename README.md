# Arris S33 Prometheus Exporter

A Prometheus exporter for the Arris S33 DOCSIS 3.1 cable modem. Collects downstream/upstream channel statistics, signal levels, error counts, and device information.

## Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `arris_modem_info` | Info | firmware, model, mac_address, serial_number | Modem information |
| `arris_modem_uptime_seconds` | Gauge | | Modem uptime in seconds |
| `arris_downstream_power_dbmv` | Gauge | channel_id, frequency_hz, modulation | Downstream power level |
| `arris_downstream_snr_db` | Gauge | channel_id, frequency_hz, modulation | Downstream SNR/MER |
| `arris_downstream_corrected_total` | Gauge | channel_id, frequency_hz, modulation | Corrected codewords |
| `arris_downstream_uncorrected_total` | Gauge | channel_id, frequency_hz, modulation | Uncorrected codewords |
| `arris_upstream_power_dbmv` | Gauge | channel_id, frequency_hz, channel_type | Upstream power level |
| `arris_upstream_width_hz` | Gauge | channel_id, frequency_hz, channel_type | Upstream channel width |

## Quick Start

### Docker (Recommended)

```bash
docker run -d \
  --name arris-exporter \
  -p 9393:9393 \
  -e MODEM_PASSWORD=your_password \
  ghcr.io/shakataganai/arris-exporter:latest
```

### Docker Compose

```yaml
services:
  arris-exporter:
    image: ghcr.io/shakataganai/arris-exporter:latest
    ports:
      - "9393:9393"
    environment:
      - MODEM_URL=https://192.168.100.1
      - MODEM_USERNAME=admin
      - MODEM_PASSWORD=your_password
      - SCRAPE_INTERVAL=0
    restart: unless-stopped
```

### Run Locally with uv

```bash
# Clone the repository
git clone https://github.com/ShakataGaNai/arris-exporter.git
cd arris-exporter

# Create .env file
cat > .env << EOF
MODEM_URL=https://192.168.100.1
MODEM_USERNAME=admin
MODEM_PASSWORD=your_password
SCRAPE_INTERVAL=0
EOF

# Run with uv
export $(cat .env | xargs) && uv run arris_exporter.py
```

## Configuration

| Environment Variable | Default | Description |
|---------------------|---------|-------------|
| `MODEM_URL` | `https://192.168.100.1` | Modem web interface URL |
| `MODEM_USERNAME` | `admin` | Login username |
| `MODEM_PASSWORD` | (required) | Login password |
| `EXPORTER_PORT` | `9393` | Prometheus metrics port |
| `SCRAPE_INTERVAL` | `0` | Polling interval in seconds. `0` = on-demand (fetch on each `/metrics` request) |

### Scrape Modes

- **On-demand mode** (`SCRAPE_INTERVAL=0`): Fetches fresh data from the modem each time Prometheus scrapes `/metrics`. Recommended when Prometheus is the only consumer.

- **Interval mode** (`SCRAPE_INTERVAL=30`): Polls the modem at fixed intervals and caches the data. Useful if you have multiple consumers or want to reduce load on the modem.

## Prometheus Configuration

Add to your `prometheus.yml`:

```yaml
scrape_configs:
  - job_name: 'arris'
    static_configs:
      - targets: ['localhost:9393']
    scrape_interval: 30s
```

## Grafana Dashboard

Example panels to create:

- Downstream/Upstream power levels over time
- SNR trends per channel
- Corrected vs uncorrected error rates
- Channel frequency distribution

## Building

### Local Docker Build

```bash
docker build -t arris-exporter .
```

### Multi-architecture Build

```bash
docker buildx build --platform linux/amd64,linux/arm64,linux/arm/v7 -t arris-exporter .
```

## How It Works

The exporter authenticates to the Arris S33's HNAP1 API using a challenge-response mechanism:

1. Requests a challenge from the modem
2. Computes HMAC-MD5 credentials from the challenge and password
3. Authenticates and receives a session token
4. Fetches metrics using the session token
5. Re-authenticates automatically when the session expires (HTTP 404)

## Supported Devices

- Arris S33

## License

MIT License - see [LICENSE](LICENSE) file.
