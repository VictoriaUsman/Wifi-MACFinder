# WiFi Active Users

A local web dashboard that scans your network and shows every active device — IP, MAC address, vendor, device type, and OS.

![Python](https://img.shields.io/badge/python-3.10%2B-blue) ![Flask](https://img.shields.io/badge/flask-3.0-lightgrey)

## Features

- Discovers all active devices on your subnet via nmap + Windows ARP cache
- Classifies devices as Mobile / Computer / Router / Printer / etc.
- Detects OS (Android, iOS, Windows, macOS, Linux) via vendor heuristics
- Auto-refreshes every 30 seconds; manual scan button
- Filter table by IP, MAC, vendor, hostname, type, or OS
- Shows active device count, mobile device count, and unique vendor count

## Requirements

- Python 3.10+
- [nmap](https://nmap.org/download.html) installed and on `PATH`

## Setup

```bash
pip install -r requirements.txt
python app.py
```

Open `http://localhost:5000` in your browser.

> **Note:** For OS detection beyond vendor heuristics, run as Administrator:
> `Right-click → Run as administrator` (or `sudo python app.py` on Linux/macOS).
> Without elevated privileges all devices are still discovered — only OS identification is limited.

## How it works

1. **nmap `-sn`** ping-scans the local `/24` subnet to find live hosts and their MAC/vendor info
2. **Windows ARP cache** (`arp -a`) supplements nmap with any devices nmap may have missed
3. The local machine is added automatically via `ipconfig /all`
4. Vendor strings and nmap device-type lines are matched against known mobile manufacturers and OS keyword rules to classify each device
5. Results are served via a Flask API (`/api/status`) and rendered in the browser

## Project structure

```
WifiActiveUserREADER/
├── app.py               # Flask backend + scan logic
├── requirements.txt
└── templates/
    └── index.html       # Single-page frontend
```

## API

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Main dashboard |
| `/api/status` | GET | Returns current device list + scan state as JSON |
| `/api/scan` | POST | Triggers an immediate background scan |
