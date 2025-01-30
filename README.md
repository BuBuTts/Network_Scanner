# Net_Scanner

## Overview
**Net_Scanner** is a Python-based network scanning tool that automatically discovers and lists all connected devices in a network along with their respective IP and MAC addresses. The tool works without any user input and is designed for ease of use.

## Features
- Fully automated, requires no user input.
- Detects the device's own IP address and subnet mask.
- Sends ARP packets combined with Ether broadcast packets.
- Captures responses to extract IP and MAC addresses of all connected devices.
- Displays the results in a structured format on the console.

## Installation
Ensure you have Python installed on your system, along with the required dependencies:
```sh
pip install scapy 