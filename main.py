import json
import os
from datetime import datetime

import pydivert

RULES_FILE = "rules.json"
LOG_FILE   = "fw_log.txt"


def load_rules():
    """
    Load JSON rules from rules.json:
      - action:   "allow" or "block"
      - direction:"inbound" or "outbound"
      - protocol: "TCP", "UDP", or "ANY"
      - src_ip, src_port, dst_ip, dst_port: strings, "ANY" or specific
    """
    if not os.path.exists(RULES_FILE):
        return []
    with open(RULES_FILE, "r", encoding="utf-8") as f:
        try:
            return json.load(f)
        except json.JSONDecodeError:
            print(f"[!] Error parsing {RULES_FILE}; using empty rule set.")
            return []


def get_protocol(pkt):
    """
    Return "TCP" if this packet has a TCP header,
           "UDP" if it has a UDP header,
           otherwise "OTHER".
    """
    if pkt.tcp is not None:
        return "TCP"
    if pkt.udp is not None:
        return "UDP"
    return "OTHER"


def packet_matches_rule(pkt, rule):
    """
    Return True if this packet matches all non-ANY fields in the given rule.
    We compare:
      - direction: "inbound" or "outbound"
      - protocol:  "TCP", "UDP", or "ANY"
      - src_ip, src_port, dst_ip, dst_port (each "ANY" or exact match)
    """
    # 1) Direction check
    pkt_dir = "outbound" if pkt.is_outbound else "inbound"
    if rule["direction"].lower() != pkt_dir:
        return False

    # 2) Protocol check
    proto = get_protocol(pkt)  # "TCP", "UDP", or "OTHER"
    if rule["protocol"] != "ANY" and rule["protocol"] != proto:
        return False

    # 3) IP / port checks
    if rule["src_ip"] != "ANY" and rule["src_ip"] != str(pkt.src_addr):
        return False

    if rule["dst_ip"] != "ANY" and rule["dst_ip"] != str(pkt.dst_addr):
        return False

    if proto == "TCP":
        if rule["src_port"] != "ANY" and rule["src_port"] != str(pkt.tcp.src_port):
            return False
        if rule["dst_port"] != "ANY" and rule["dst_port"] != str(pkt.tcp.dst_port):
            return False
    elif proto == "UDP":
        if rule["src_port"] != "ANY" and rule["src_port"] != str(pkt.udp.src_port):
            return False
        if rule["dst_port"] != "ANY" and rule["dst_port"] != str(pkt.udp.dst_port):
            return False

    return True


def should_block(pkt, rules):
    """
    Return True if any matching rule’s action is "block".
    First-match wins: if a rule matches and action=="allow", return False immediately.
    """
    for rule in rules:
        if packet_matches_rule(pkt, rule):
            return (rule["action"].lower() == "block")
    return False  # default: allow if no rule matches


def log_blocked(pkt):
    """
    Append a line to fw_log.txt with timestamp, src->dst, proto, ports.
    Use ASCII '->' instead of a Unicode arrow.
    """
    proto = get_protocol(pkt)
    if proto == "TCP":
        src_port = pkt.tcp.src_port
        dst_port = pkt.tcp.dst_port
    elif proto == "UDP":
        src_port = pkt.udp.src_port
        dst_port = pkt.udp.dst_port
    else:
        # For non-TCP/UDP packets, use 0 as placeholder
        src_port = 0
        dst_port = 0

    line = (
        f"{datetime.now():%Y-%m-%d %H:%M:%S} "
        f"BLOCKED {proto} {pkt.src_addr}:{src_port} -> {pkt.dst_addr}:{dst_port}\n"
    )

    # Open with UTF-8 and ignore errors
    with open(LOG_FILE, "a", encoding="utf-8", errors="ignore") as logf:
        logf.write(line)


def firewall_loop():
    """
    Main loop: open a WinDivert handle on filter "ip", capture packets,
    decide block/allow, and either drop or reinject. Dropped packets are logged.
    """
    filter_expr = "ip"
    with pydivert.WinDivert(filter_expr) as w:
        print("[*] Firewall started. Capturing all IP packets...")
        while True:
            try:
                pkt = w.recv()
            except Exception:
                continue

            rules = load_rules()
            if should_block(pkt, rules):
                log_blocked(pkt)
                # Drop packet
                continue
            else:
                # Reinject packet so it proceeds normally
                w.send(pkt)


if __name__ == "__main__":
    # Ensure the log file exists (UTF-8)
    if not os.path.exists(LOG_FILE):
        open(LOG_FILE, "w", encoding="utf-8").close()

    firewall_loop()
