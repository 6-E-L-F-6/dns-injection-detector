import subprocess
import asyncio
import re
import ipaddress
import time
from dataclasses import dataclass
from typing import Dict, List, Tuple

from textual.app import App, ComposeResult
from textual.widgets import Static, Button, Select, DataTable, Checkbox, Header, Footer
from textual.containers import Vertical, Horizontal
from textual.reactive import reactive

def sanitize_id(name: str) -> str:
    return re.sub(r'[^a-zA-Z0-9_-]', '_', name)

@dataclass
class DNSResult:
    dns_name: str
    dns_ip: str
    is_suspicious: bool = False
    ip_scope: str = "Unknown"
    response_time_ms: float = -1.0
    suspicion_level: str = "Unknown"

@dataclass
class TracerouteHop:
    hop_number: int
    ip: str
    ip_scope: str
    rtt_ms: float

class DNSInjectionDetector:
    def __init__(self, dns_servers: Dict[str, str]):
        self.dns_servers = dns_servers

    def is_suspicious_ip(self, ip: str) -> Tuple[bool, str]:
        try:
            parsed_ip = ipaddress.ip_address(ip)
            if (
                parsed_ip.is_loopback or
                parsed_ip.is_private or
                parsed_ip.is_reserved or
                parsed_ip.is_unspecified
            ):
                return True, "Injection Likely"
            elif parsed_ip.is_global:
                return False, "Secure"
            else:
                return True, "Possibly Injected"
        except ValueError:
            return False, "Invalid"

    def ip_scope(self, ip: str) -> str:
        try:
            parsed_ip = ipaddress.ip_address(ip)
            if parsed_ip.is_private or parsed_ip.is_loopback:
                return "Private Network"
            elif parsed_ip.is_global:
                return "Public Internet"
            else:
                return "Other/Reserved"
        except ValueError:
            return "Invalid IP"

    async def resolve(self, domain: str, dns_server: str) -> Tuple[str, float]:
        try:
            start = time.monotonic()
            proc = await asyncio.create_subprocess_exec(
                "dig", "+short", domain, f"@{dns_server}",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=5)
            end = time.monotonic()
            output = stdout.decode().strip()
            return (output if output else "# No response", (end - start) * 1000)
        except asyncio.TimeoutError:
            return ("# Timeout", -1.0)
        except Exception:
            return ("# Error", -1.0)

    async def traceroute(self, target_ip: str) -> List[TracerouteHop]:
        hops = []
        try:
            proc = await asyncio.create_subprocess_exec(
                "traceroute", "-n", "-w", "2", "-q", "1", "-m", "30", target_ip,
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL
            )
            while True:
                line = await proc.stdout.readline()
                if not line:
                    break
                line = line.decode().strip()
                if not line or line.startswith("traceroute to"):
                    continue
                parts = line.split()
                if len(parts) < 2:
                    continue
                try:
                    hop_num = int(parts[0])
                    ip = parts[1]
                    rtt_ms = float(parts[2]) if len(parts) >= 3 and parts[2] != "*" else -1.0
                    ip_scope = self.ip_scope(ip)
                    hops.append(TracerouteHop(hop_num, ip, ip_scope, rtt_ms))
                except (ValueError, IndexError):
                    continue
            await proc.wait()
        except Exception:
            pass
        return hops

class DNSInjectionApp(App):
    CSS = """
    Screen {
        background: black;
        color: green;
    }

    Static, DataTable, Select, Button, Checkbox, Header, Footer {
        color: green;
        background: transparent;
    }

    DataTable > .table-row {
        color: green;
    }

    Select > .option--selected {
        background: darkgreen;
        color: green;
    }

    Button {
        border: solid green;
        background: transparent;
        color: green;
    }

    Button:focus, Button:hover {
        background: darkgreen;
    }

    Checkbox {
        color: green;
    }

    Header, Footer {
        background: black;
        color: green;
        border-bottom: solid green;
    }

    #status_line {
        color: green;
        background: transparent;
        padding: 1;
    }

    DataTable {
        border: solid green;
    }

    .title {
        color: green;
        background: transparent;
        padding: 1 0;
       
    }
    """

    dns_options = {
        "Cloudflare (1.1.1.1)": "1.1.1.1",
        "Google (8.8.8.8)": "8.8.8.8",
        "Iran DNS (Shatel)": "178.22.122.100",
    }

    domain_presets = [
        ("bbc.com", "bbc.com"),
        ("facebook.com", "facebook.com"),
        ("youtube.com", "youtube.com"),
        ("telegram.org", "telegram.org"),
        ("wikipedia.org", "wikipedia.org"),
        ("digikala.com", "digikala.com"),
        ("cafebazaar.ir", "cafebazaar.ir"),
        ("aparat.com", "aparat.com"),
        ("namnak.com", "namnak.com"),
        ("zoomit.ir", "zoomit.ir"),
        ("paypal.com","paypal.com") 
    ]

    selected_domain = reactive("bbc.com")

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        yield Select(self.domain_presets, prompt="Choose domain", id="domain_selector", value="bbc.com")
        with Horizontal():
            for name in self.dns_options:
                yield Checkbox(name, id=f"dns_{sanitize_id(name)}", value=True)
        yield Static("DNS Results:", classes="title")
        yield DataTable(id="result_table")
        yield Static("Traceroute hops:", classes="title")
        yield DataTable(id="traceroute_table")
        yield Button("Start Analysis", id="start_btn")
        yield Static("", id="status_line")
        yield Footer()

    def on_mount(self):
        self.query_one("#result_table", DataTable).add_columns("Domain", "DNS", "IP", "Scope", "Suspicion", "Time (ms)")
        self.query_one("#traceroute_table", DataTable).add_columns("Hop", "IP", "Scope", "RTT (ms)")

    def on_select_changed(self, event: Select.Changed) -> None:
        if event.select.id == "domain_selector":
            self.selected_domain = event.value

    async def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "start_btn":
            event.button.disabled = True
            self.update_status("Running analysis...")
            self.clear_tables()
            await self.run_analysis()
            event.button.disabled = False

    def clear_tables(self):
        self.query_one("#result_table", DataTable).clear()
        self.query_one("#traceroute_table", DataTable).clear()

    def add_dns_result(self, domain: str, result: DNSResult):
        table = self.query_one("#result_table", DataTable)
        suspicion = f"{result.suspicion_level}" if result.is_suspicious else f"[OK]  {result.suspicion_level}"
        table.add_row(domain, result.dns_name, result.dns_ip, result.ip_scope, suspicion, f"{result.response_time_ms:.1f}")

    def add_dns_summary(self, status_text: str, message: str):
        self.query_one("#result_table", DataTable).add_row("", status_text, message, "", "", "")

    def add_traceroute_hop(self, hop: TracerouteHop):
        rtt_display = f"{hop.rtt_ms:.2f}" if hop.rtt_ms >= 0 else None
        self.query_one("#traceroute_table", DataTable).add_row(str(hop.hop_number), hop.ip, hop.ip_scope, rtt_display)

    def update_status(self, message: str):
        self.query_one("#status_line", Static).update(message)

    async def run_analysis(self):
        selected_dns = {
            name: ip for name, ip in self.dns_options.items()
            if self.query_one(f"#dns_{sanitize_id(name)}", Checkbox).value
        }
        domain = self.selected_domain
        if domain == "Custom":
            self.update_status("Custom domain input not implemented.")
            return

        if not selected_dns:
            self.update_status("Please select at least one DNS server.")
            return

        detector = DNSInjectionDetector(selected_dns)
        suspicious_found = False
        good_dns_ip = None

        for dns_name, dns_ip in selected_dns.items():
            ip, response_time = await detector.resolve(domain, dns_ip)
            ip_addr = ip.split()[0] if ip and not ip.startswith("#") else ip
            is_suspicious, suspicion_level = detector.is_suspicious_ip(ip_addr) if not ip.startswith("⛔") else (False, "Error")
            scope = detector.ip_scope(ip_addr) if not ip.startswith("#") else "Unknown"
            result = DNSResult(dns_name, ip_addr, is_suspicious, scope, response_time, suspicion_level)
            self.add_dns_result(domain, result)
            await asyncio.sleep(0.1)

            if not is_suspicious and not ip.startswith("#") and not good_dns_ip:
                good_dns_ip = ip_addr
            if is_suspicious:
                suspicious_found = True

        if suspicious_found:
            self.add_dns_summary("ALERT", "Suspicious DNS response(s) detected!")
        else:
            self.add_dns_summary("OK", "All DNS responses look safe.")

        if good_dns_ip:
            self.update_status("Running traceroute...")
            hops = await detector.traceroute(good_dns_ip)
            for hop in hops:
                self.add_traceroute_hop(hop)
                await asyncio.sleep(0.05)
            self.update_status("Analysis complete!")
        else:
            self.update_status("No valid IP to traceroute.")

if __name__ == "__main__":
    DNSInjectionApp().run()

