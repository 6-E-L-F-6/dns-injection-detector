# DNS Injection Detector

A Python-based Textual application to detect potential DNS injection by resolving domains across multiple DNS servers and analyzing traceroute hops. The tool checks for suspicious IP addresses and provides a visual interface to display results.

## Features
- Resolves domain names using multiple DNS servers (e.g., Cloudflare, Google, etc.).
- Identifies suspicious IP addresses (private, loopback, reserved).
- Performs traceroute on a valid IP to analyze network hops.
- Interactive TUI (Textual User Interface) with domain selection and DNS server options.
- Displays results in tables with suspicion levels and response times.

## Prerequisites
To run this project, ensure you have the following installed:
- **Python**: Version 3.7 or higher.
- **dig**: Command-line tool for DNS queries (usually part of `dnsutils` or `bind-utils`).
  - On Debian/Ubuntu: `sudo apt-get install dnsutils`
  - On Red Hat/CentOS: `sudo yum install bind-utils`
  - On macOS: `brew install bind`
- **traceroute**: Command-line tool for network diagnostics.
  - On Debian/Ubuntu: `sudo apt-get install traceroute`
  - On Red Hat/CentOS: `sudo yum install traceroute`
  - On macOS: `brew install traceroute`

## Installation
1. Clone the repository:
   ```bash
   git clone https://github.com/your-username/dns-injection-detector.git
   cd dns-injection-detector
   ```
2. Install Python dependencies:
   ```bash
   pip install textual
   ```
3. Ensure `dig` and `traceroute` are installed (see Prerequisites).

## Usage
1. Run the application:
   ```bash
   python main.py
   ```
2. In the TUI:
   - Select a domain from the dropdown (e.g., `bbc.com`, `facebook.com`).
   - Choose DNS servers to query by checking/unchecking boxes.
   - Click "Start Analysis" to resolve the domain and perform a traceroute.
3. View results in the tables:
   - **DNS Results**: Shows resolved IPs, suspicion levels, and response times.
   - **Traceroute Hops**: Displays hop details for a valid IP.

## Example
```bash
$ python main.py
```
- Select `bbc.com` and DNS servers (e.g., Cloudflare, Google).
- Click "Start Analysis" to see resolved IPs and traceroute data.

## Notes
- Ensure your system has internet access for DNS queries and traceroute.
- The tool assumes `dig` and `traceroute` are in your system PATH.
- Custom domain input is not implemented in this version.

## License
MIT License
