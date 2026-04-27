# DNS Deceptor - Active DNS Security & Simulation Tool

**DNS Deceptor** is an active defense tool that listens for DNS queries and replies with spoofed responses for specific domains. It helps in deceptive security, honeypot redirection, and testing network defenses.

## Features
- Intercepts DNS requests in real-time
- Replies with custom fake IP addresses for target domains
- Configurable domain-to-IP mapping
- Works on Kali Linux and any Linux with Scapy

## Requirements
- Python 3
- Scapy

Install Scapy:
```bash
sudo apt install python3-scapy -y
