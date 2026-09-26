"""
SentinelShield Network Collector.

Captures IP packets using Scapy and converts them into normalized
SentinelShield Event objects.

IMPORTANT:
Only capture traffic on systems/networks you own or are explicitly
authorized to monitor. Use this collector in an isolated lab environment.
"""

from typing import Callable, Optional

from scapy.all import sniff, IP, TCP, UDP, ICMP

from app.core.models import Event, EngineSource


# ---------------------------------------------------------------------------
# Packet → Event
# ---------------------------------------------------------------------------

def packet_to_event(packet) -> Optional[Event]:
    """
    Convert a Scapy packet into a SentinelShield Event.

    The collector only normalizes network traffic.
    Attack classification is handled by detector modules.
    """

    # We only process IPv4 packets.
    if not packet.haslayer(IP):
        return None

    ip_layer = packet[IP]

    source_ip = ip_layer.src
    destination_ip = ip_layer.dst

    source_port = None
    destination_port = None
    protocol = "IP"
    event_type = "IP_PACKET"

    # ---------------------------------------------------------
    # TCP
    # ---------------------------------------------------------

    if packet.haslayer(TCP):

        tcp_layer = packet[TCP]

        source_port = tcp_layer.sport
        destination_port = tcp_layer.dport

        protocol = "TCP"
        event_type = "TCP_CONNECTION"

    # ---------------------------------------------------------
    # UDP
    # ---------------------------------------------------------

    elif packet.haslayer(UDP):

        udp_layer = packet[UDP]

        source_port = udp_layer.sport
        destination_port = udp_layer.dport

        protocol = "UDP"
        event_type = "UDP_CONNECTION"

    # ---------------------------------------------------------
    # ICMP
    # ---------------------------------------------------------

    elif packet.haslayer(ICMP):

        protocol = "ICMP"
        event_type = "ICMP_PACKET"

    # ---------------------------------------------------------
    # Build normalized Event
    # ---------------------------------------------------------

    event = Event(
        source_ip=source_ip,
        destination_ip=destination_ip,
        source_port=source_port,
        destination_port=destination_port,
        protocol=protocol,
        event_type=event_type,
        description=(
            f"{protocol} traffic from "
            f"{source_ip} to {destination_ip}"
        ),
        raw_data=None,
        engine=EngineSource.SENTINELSHIELD,
    )

    return event


# ---------------------------------------------------------------------------
# Packet handler
# ---------------------------------------------------------------------------

def _handle_packet(
    packet,
    on_event: Callable[[Event], None],
) -> None:
    """
    Convert a packet into an Event and send it to the callback.
    """

    try:

        event = packet_to_event(packet)

        if event is not None:
            on_event(event)

    except Exception as exc:

        print(
            f"[SentinelShield] Packet processing error: {exc}"
        )


# ---------------------------------------------------------------------------
# Start packet capture
# ---------------------------------------------------------------------------

def start_capture(
    interface: str,
    on_event: Callable[[Event], None],
) -> None:
    """
    Start live packet capture on the specified interface.

    Args:
        interface:
            Network interface name, e.g. eth0.

        on_event:
            Callback receiving each normalized Event.
    """

    print(
        f"[SentinelShield] Starting network capture on: {interface}"
    )

    print(
        "[SentinelShield] Press CTRL+C to stop."
    )

    try:

        sniff(
            iface=interface,
            prn=lambda packet: _handle_packet(
                packet,
                on_event,
            ),
            store=False,
            promisc=False,
        )

    except PermissionError:

        print(
            "[SentinelShield] Permission denied. "
            "Run packet capture with the required privileges "
            "in your authorized lab environment."
        )

    except Exception as exc:

        print(
            f"[SentinelShield] Capture error: {exc}"
        )


# ---------------------------------------------------------------------------
# Manual smoke test
# ---------------------------------------------------------------------------

if __name__ == "__main__":

    def print_event(event: Event) -> None:
        print(
            "\n--- Network Event ---"
        )

        print(
            f"Time:        {event.timestamp}"
        )

        print(
            f"Source:      {event.source_ip}:{event.source_port}"
        )

        print(
            f"Destination: {event.destination_ip}:{event.destination_port}"
        )

        print(
            f"Protocol:    {event.protocol}"
        )

        print(
            f"Event Type:  {event.event_type}"
        )

    # Change this to your authorized lab interface.
    start_capture(
        interface="eth0",
        on_event=print_event,
    )