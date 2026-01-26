# WiFi Guardian System - Installation Guide

## Prerequisites

- Python 3.12+
- WiFi adapter (for live capture) OR PCAP files for testing
- Mistral AI API key ([Get one here](https://console.mistral.ai/))

## Quick Start

### 1. Install Dependencies

```bash
# Install Python dependencies
pip install -r requirements.txt

# Install Pydantic AI (if not in requirements.txt)
pip install pydantic-ai
```

### 2. Configure Environment

```bash
# Copy environment template
cp .env.example .env

# Edit .env and add your Mistral API key
nano .env  # or use your preferred editor
```

**Important**: Set `MISTRAL_API_KEY` in `.env`:
```
MISTRAL_API_KEY=your-actual-api-key-here
```

### 3. Run the System

```bash
# Start WiFi Guardian System
python main.py
```

The system will start and be available at:
- API: http://localhost:8000
- Dashboard: http://localhost:8000/dashboard
- Health Check: http://localhost:8000/api/health

## Configuration Options

Edit `.env` to customize:

### Network Settings
```
NETWORK_INTERFACE=wlan0          # Your WiFi interface
ENABLE_LIVE_CAPTURE=true         # Set to false to use PCAP files
PROMISCUOUS_MODE=true            # Monitor mode for WiFi
```

### ML Settings
```
ML_CONFIDENCE_THRESHOLD=0.85     # Minimum confidence for escalation
ML_MODELS_PATH=data/models       # Path to ML models
```

### API Settings
```
API_HOST=0.0.0.0                 # API host
API_PORT=8000                    # API port
```

### Caching Settings
```
ENABLE_RESPONSE_CACHE=true       # Cache Mistral responses
MISTRAL_CACHE_TTL=3600           # Cache TTL in seconds
```

## Testing with PCAP Files

If you don't have a WiFi adapter or want to test with pre-recorded traffic:

1. Set `ENABLE_LIVE_CAPTURE=false` in `.env`
2. Place PCAP files in `data/pcaps/` directory
3. Run the system

The system will replay packets from the PCAP files.

## Permissions for Live Capture

Live packet capture requires elevated privileges:

```bash
# Option 1: Run with sudo
sudo python main.py

# Option 2: Set capabilities (Linux only)
sudo setcap cap_net_raw,cap_net_admin=eip $(which python3.12)
python main.py
```

## Troubleshooting

### "No module named 'pydantic_ai'"

```bash
pip install pydantic-ai
```

### "Permission denied" for packet capture

Run with sudo or set capabilities (see above).

### "Mistral API key not found"

Make sure `MISTRAL_API_KEY` is set in `.env` file.

### Import errors

```bash
# Reinstall all dependencies
pip install --force-reinstall -r requirements.txt
```

## Development Mode

For development with automatic reload:

```bash
# Install development dependencies
pip install -r requirements.txt

# Run with uvicorn hot reload
uvicorn src.api.app:app --reload --host 0.0.0.0 --port 8000
```

## Next Steps

1. Open dashboard at http://localhost:8000/dashboard
2. Monitor system status and threats
3. Check API docs at http://localhost:8000/docs
4. View logs in console for detailed information

## Support

For issues or questions:
- Check logs in console output
- Review configuration in `.env`
- Ensure all dependencies are installed
- Verify Mistral API key is valid

Happy threat hunting! 🛡️
