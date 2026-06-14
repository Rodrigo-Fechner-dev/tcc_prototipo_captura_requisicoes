"""
PhishGuard — DNS Packet Capture Module

Captures DNS traffic on the local network using Scapy with Npcap (Windows).
Runs in a background thread to keep the GUI responsive.

Architecture:
    DNSCapture (thread) → parses DNS packets → puts DNSEvent in Queue → GUI polls Queue

Privacy: Only metadata is captured (domain, IPs, ports, timestamps).
         No payload/content is stored, per TCC ethical requirements.
"""

import threading
import queue
import logging
from datetime import datetime

from scapy.all import sniff, DNS, DNSQR, DNSRR, IP, UDP, TCP, Raw, conf, get_if_list

from models import DNSEvent, TrafficType

logger = logging.getLogger(__name__)

# Capture all traffic on port 53 (UDP and TCP).
# We handle the TCP 2-byte length prefix manually to avoid dropping packets.
DNS_FILTER = "port 53"

# DNS query type mapping
QUERY_TYPES = {
    1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR",
    15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV", 255: "ANY",
}


class DNSCapture:
    """
    Threaded DNS packet sniffer using Scapy.

    Usage:
        q = queue.Queue()
        capture = DNSCapture(event_queue=q)
        capture.start()
        # ... poll q for DNSEvent objects ...
        capture.stop()
    """

    def __init__(self, event_queue: queue.Queue, interface: str | None = None):
        self.event_queue = event_queue
        self.interface = interface
        self._running = False
        self._thread: threading.Thread | None = None
        self._packet_count = 0
        self._dropped_count = 0  # packets seen but not DNS
        self._active_iface: str = ""  # resolved interface name

    def start(self):
        """Start capturing DNS packets in a background thread."""
        if self._running:
            logger.warning("Capture already running")
            return

        self._running = True
        self._packet_count = 0
        self._dropped_count = 0

        # Log all available interfaces to aid debugging
        try:
            ifaces = get_if_list()
            logger.info("Available interfaces: %s", ifaces)
        except Exception:
            pass

        self._thread = threading.Thread(target=self._capture_loop, daemon=True)
        self._thread.start()
        logger.info("DNS capture started — interface: %s | filter: %s",
                    self.interface or "default", DNS_FILTER)

    def stop(self):
        """Signal the capture thread to stop."""
        self._running = False
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=5)
        logger.info("DNS capture stopped. Total packets: %d", self._packet_count)

    @property
    def is_running(self) -> bool:
        return self._running

    @property
    def packet_count(self) -> int:
        return self._packet_count

    def _capture_loop(self):
        """
        Main capture loop. Uses short 1-second timeout cycles so the
        _running flag is checked frequently for a clean stop on Windows.

        Uses prn= callback (store=False) so packets are processed
        immediately as they arrive — no buffering delay.
        """
        logger.info("Capture thread started")
        cycle = 0
        try:
            while self._running:
                sniff(
                    filter=DNS_FILTER,
                    prn=self._process_packet,
                    timeout=1,
                    store=False,
                    iface=self.interface,
                )
                cycle += 1
                # Log a heartbeat every 10 cycles (10s) so we know it's alive
                if cycle % 10 == 0:
                    logger.info(
                        "[heartbeat] Capture running — %d DNS events enqueued, "
                        "%d pkts dropped",
                        self._packet_count, self._dropped_count,
                    )
        except PermissionError:
            logger.error(
                "Permission denied. Run as Administrator for packet capture."
            )
            self._running = False
        except OSError as e:
            if "Npcap" in str(e) or "winpcap" in str(e).lower():
                logger.error("Npcap not found. Install from https://npcap.com/")
            else:
                logger.error("OS error during capture: %s", e)
            self._running = False
        except Exception as e:
            logger.error("Unexpected capture error: %s", e, exc_info=True)
            self._running = False

        logger.info(
            "Capture thread exiting. Total DNS events: %d | Non-DNS dropped: %d",
            self._packet_count, self._dropped_count,
        )

    def _process_packet(self, packet):
        """Parse a single DNS packet and enqueue a DNSEvent."""
        protocol = "UDP"
        dns_layer = None
        
        # Scapy handles UDP DNS automatically.
        if packet.haslayer(UDP) and packet.haslayer(DNS):
            dns_layer = packet[DNS]
            
        # TCP DNS has a 2-byte length prefix. Scapy might not parse it automatically.
        elif packet.haslayer(TCP):
            protocol = "TCP"
            if packet.haslayer(DNS):
                dns_layer = packet[DNS]
            elif packet.haslayer(Raw):
                payload = packet[Raw].load
                if len(payload) > 2:
                    try:
                        dns_layer = DNS(payload[2:])
                    except Exception:
                        return
                else:
                    return
            else:
                return
        else:
            # Packet matched the BPF filter (port 53) but is neither parseable UDP nor TCP
            self._dropped_count += 1
            return

        if not dns_layer:
            self._dropped_count += 1
            return

        try:
            src_ip = packet[IP].src if packet.haslayer(IP) else "N/A"
            dst_ip = packet[IP].dst if packet.haslayer(IP) else "N/A"

            # DNS Query (qr=0)
            if dns_layer.qr == 0 and dns_layer.qd:
                domain = self._decode_domain(dns_layer.qd.qname)
                traffic_type = self._classify_traffic_type(domain)
                qtype = QUERY_TYPES.get(dns_layer.qd.qtype, str(dns_layer.qd.qtype))

                event = DNSEvent(
                    timestamp=datetime.now(),
                    domain=domain,
                    query_type=qtype,
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    protocol=protocol,
                    event_type="query",
                    traffic_type=traffic_type,
                )
                self._enqueue(event)
                logger.debug("Enqueued DNS query: %s (%s) from %s [%s]", domain, qtype, src_ip, traffic_type.name)

            # DNS Response (qr=1)
            elif dns_layer.qr == 1 and dns_layer.an:
                domain = self._decode_domain(dns_layer.qd.qname) if dns_layer.qd else "N/A"
                qtype = QUERY_TYPES.get(dns_layer.qd.qtype, "?") if dns_layer.qd else "?"
                answers = self._extract_answers(dns_layer)

                event = DNSEvent(
                    timestamp=datetime.now(),
                    domain=domain,
                    query_type=qtype,
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    protocol=protocol,
                    event_type="response",
                    traffic_type=TrafficType.CACHE,
                    answers=answers,
                )
                self._enqueue(event)

            else:
                # DNS packet with no parseable query or response
                self._dropped_count += 1

        except Exception as e:
            self._dropped_count += 1
            logger.debug("Packet parse error: %s", e)

    def _classify_traffic_type(self, domain: str) -> TrafficType:
        """Categorize traffic to help user distinguish active browsing from noise."""
        d = domain.lower()
        
        # 1. Local Network / MDNS / Service Discovery
        if d.endswith(('.local', '.lan', '.arpa')) or d == 'localhost':
            return TrafficType.BACKGROUND
            
        # 2. Microsoft Windows Telemetry & Background Sync
        if any(kw in d for kw in ('microsoft.com', 'windowsupdate', 'msftncsi', 'msedge.net', 'live.com', 'live.net', 'azure')):
            return TrafficType.BACKGROUND
            
        # 3. Google Background Services (Android/Chrome sync)
        if any(kw in d for kw in ('googleapis.com', 'googleusercontent.com', 'gstatic.com', 'googlevideo.com', '1e100.net', '.goog', 'gvt2.com', 'gvt1.com')):
            return TrafficType.BACKGROUND
            
        # 4. Apple Background Services (iCloud, telemetry)
        if any(kw in d for kw in ('apple.com', 'icloud.com', 'apple-dns.net')):
            return TrafficType.BACKGROUND
            
        # 5. Background Apps & Games (Roblox, Spotify, Steam etc)
        if any(kw in d for kw in ('roblox.com', 'spotify.com', 'steamcommunity.com', 'steampowered.com', 'discord.gg', 'discord.com', 'whatsapp.net', 'whatsapp.com')):
            return TrafficType.BACKGROUND

        # 6. CDNs, Ad Networks, and Trackers
        if any(kw in d for kw in ('cdn', 'akamai', 'cloudfront', 'fastly', 'doubleclick', 'ads', 'tracker', 'analytics', 'cloudflare')):
            return TrafficType.CDN
            
        return TrafficType.ACTIVE

    def _enqueue(self, event: DNSEvent):
        """Thread-safe enqueue with overflow protection."""
        self._packet_count += 1
        try:
            self.event_queue.put_nowait(event)
        except queue.Full:
            logger.warning(
                "Event queue full (%d events). Dropping oldest to make room.",
                self.event_queue.maxsize,
            )
            try:
                self.event_queue.get_nowait()
                self.event_queue.put_nowait(event)
            except queue.Empty:
                pass

    @staticmethod
    def _decode_domain(qname) -> str:
        """Decode DNS domain name bytes to string."""
        if isinstance(qname, bytes):
            return qname.decode("utf-8", errors="ignore").rstrip(".")
        return str(qname).rstrip(".")

    @staticmethod
    def _extract_answers(dns_layer) -> list[str]:
        """Extract answer records from DNS response."""
        answers = []
        try:
            for i in range(dns_layer.ancount):
                rr = dns_layer.an[i]
                if hasattr(rr, "rdata"):
                    rdata = rr.rdata
                    if isinstance(rdata, bytes):
                        rdata = rdata.decode("utf-8", errors="ignore").rstrip(".")
                    answers.append(str(rdata))
        except Exception:
            pass
        return answers
