# Network Scanner

## Overview

This Python-based network scanner identifies active devices on a local network, displaying their IP addresses, MAC addresses, and vendor details. The scanner supports two modes:

1. **Fast Scan** - Uses a local dataset to determine vendor details.
2. **Advanced Scan** - Uses an API to fetch vendor details online.

## Features

- Detects devices connected to the same network.
- Retrieves IP and MAC addresses.
- Finds vendor information using a local dataset or an online API.
- Displays results in an easy-to-read format.

## Requirements

Before running the script, ensure you have the following dependencies installed:

```sh
pip install psutil socket ipaddress pyfiglet requests time csv scapy
```

## Installation

1. Clone or download the repository.
2. Ensure the `mac-vendors-export.csv` file is in the same directory as the script.
3. Install the required Python libraries using the command above.

## Usage

Run the script using:

```sh
python net_scn.py
```

Follow the on-screen prompts:

- Enter `1` for a **Fast Scan** (local lookup).
- Enter `2` for an **Advanced Scan** (API lookup, may take longer).
- Enter `3` to exit.

## How It Works

1. The script determines the local network IP and subnet mask.
2. It sends ARP requests to detect active devices.
3. For vendor lookup:
   - **Fast Scan**: Checks the local dataset (`mac-vendors-export.csv`).
   - **Advanced Scan**: Queries an online MAC address lookup API.
4. Results are displayed in a table format.

## Notes

- The API allows one request per second in the free tier.
- Ensure `mac-vendors-export.csv` is in the same directory for fast scanning.

## License

Open-source | free to use

## Author

**Janidu Dilshan**
