import json
import os
import sys
import subprocess
import threading
import time
import hashlib
import getpass
import argparse
import base64
import hmac
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from datetime import datetime

import pydivert

RULES_FILE = "rules.json"
LOG_FILE = "fw_log.txt"
PASSWORD_FILE = "password.json"
DISABLE_LOG = "disable_log.txt"
INTEGRITY_FILE = "log_hashes.json"
TAMPER_LOG = "tamper_log.txt"


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

    now = datetime.now().astimezone()
    line = (
        f"{now:%Y-%m-%d %H:%M:%S %z} "
        f"BLOCKED {proto} {pkt.src_addr}:{src_port} -> {pkt.dst_addr}:{dst_port}\n"
    )

    # Open with UTF-8 and ignore errors
    with open(LOG_FILE, "a", encoding="utf-8", errors="ignore") as logf:
        logf.write(line)
    update_integrity(LOG_FILE)


def log_disabled(username: str) -> None:
    """Append a timestamped entry to disable_log.txt with the given username."""
    now = datetime.now().astimezone()
    entry = f"{now:%Y-%m-%d %H:%M:%S %z} DISABLED_BY {username}\n"
    with open(DISABLE_LOG, "a", encoding="utf-8", errors="ignore") as f:
        f.write(entry)
    update_integrity(DISABLE_LOG)


def file_sha256(path: str) -> str:
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                h.update(chunk)
    except OSError:
        return ""
    return h.hexdigest()


def update_integrity(path: str) -> None:
    hashes = {}
    if os.path.exists(INTEGRITY_FILE):
        try:
            with open(INTEGRITY_FILE, "r", encoding="utf-8") as f:
                hashes = json.load(f)
        except Exception:
            hashes = {}
    hashes[path] = file_sha256(path)
    with open(INTEGRITY_FILE, "w", encoding="utf-8") as f:
        json.dump(hashes, f)


def check_integrity() -> None:
    if not os.path.exists(INTEGRITY_FILE):
        return
    try:
        with open(INTEGRITY_FILE, "r", encoding="utf-8") as f:
            hashes = json.load(f)
    except Exception:
        hashes = {}
    for p, old in hashes.items():
        if os.path.exists(p):
            new = file_sha256(p)
            if old and new != old:
                now = datetime.now().astimezone()
                entry = f"{now:%Y-%m-%d %H:%M:%S %z} TAMPER_DETECTED {p}\n"
                with open(TAMPER_LOG, "a", encoding="utf-8", errors="ignore") as tf:
                    tf.write(entry)
    for p in [LOG_FILE, DISABLE_LOG]:
        if os.path.exists(p):
            update_integrity(p)


def setup_autostart():
    """Create a Windows scheduled task to launch this script on startup."""
    task_name = "WinFirewall"
    script_path = os.path.abspath(__file__)
    pythonw = os.path.join(os.path.dirname(sys.executable), "pythonw.exe")

    # Check if the task already exists
    try:
        result = subprocess.run([
            "schtasks",
            "/query",
            "/TN",
            task_name,
        ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if result.returncode == 0:
            return  # task already exists
    except FileNotFoundError:
        print("[!] 'schtasks' not found; cannot set autostart.")
        return

    subprocess.run([
        "schtasks",
        "/create",
        "/SC",
        "ONSTART",
        "/RL",
        "HIGHEST",
        "/TN",
        task_name,
        "/TR",
        f'"{pythonw}" "{script_path}"',
    ])


def monitor_autostart(interval=60):
    """Background thread to ensure the scheduled task remains present."""
    task_name = "WinFirewall"
    while True:
        try:
            result = subprocess.run([
                "schtasks",
                "/query",
                "/TN",
                task_name,
            ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if result.returncode != 0:
                setup_autostart()
        except FileNotFoundError:
            pass
        time.sleep(interval)


def password_complexity(pw: str) -> bool:
    """Return True if pw meets length and character mix requirements."""
    if len(pw) < 16:
        return False
    if sum(ch.isdigit() for ch in pw) < 2:
        return False
    if sum(ch.isupper() for ch in pw) < 2:
        return False
    specials = "!@#$%^&*()-_=+[]{}|;:'\",.<>/?`~"
    if sum(ch in specials for ch in pw) < 2:
        return False
    return True


def load_password_data():
    if not os.path.exists(PASSWORD_FILE):
        return None
    try:
        with open(PASSWORD_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return None


def save_credentials(username: str, pw: str, level: int, pub_key_path: str) -> None:
    """Hash credentials and encrypt them with the RSA public key."""
    u_salt = os.urandom(16)
    u_hash = hashlib.pbkdf2_hmac("sha256", username.encode(), u_salt, 200000)
    p_salt = os.urandom(16)
    p_hash = hashlib.pbkdf2_hmac("sha256", pw.encode(), p_salt, 200000)

    with open(pub_key_path, "rb") as f:
        public_key = serialization.load_pem_public_key(f.read())

    enc_u = public_key.encrypt(
        u_hash,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    enc_p = public_key.encrypt(
        p_hash,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    enc_level = public_key.encrypt(
        str(level).encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    data = {
        "u_salt": base64.b64encode(u_salt).decode(),
        "pw_salt": base64.b64encode(p_salt).decode(),
        "enc_u_hash": base64.b64encode(enc_u).decode(),
        "enc_pw_hash": base64.b64encode(enc_p).decode(),
        "enc_level": base64.b64encode(enc_level).decode(),
    }

    with open(PASSWORD_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f)


def ensure_password_setup():
    if os.path.exists(PASSWORD_FILE):
        return
    print("[*] Initial setup: create credentials for the --stop option.")
    while True:
        user = input("Create username: ").strip()
        if not user:
            print("[!] Username cannot be empty.")
            continue
        pw1 = getpass.getpass("Create password: ")
        if not password_complexity(pw1):
            print("[!] Password does not meet complexity requirements.")
            continue
        pw2 = getpass.getpass("Confirm password: ")
        if pw1 != pw2:
            print("[!] Passwords do not match.")
            continue
        while True:
            try:
                level = int(input("Permission level (1=owner,2=block-only,3=monitor): ").strip())
            except ValueError:
                print("[!] Invalid level.")
                continue
            if level not in (1, 2, 3):
                print("[!] Level must be 1, 2, or 3.")
                continue
            break
        pub_path = input("Path to your RSA public key (PEM): ").strip()
        if not os.path.isfile(pub_path):
            print("[!] Public key file not found.")
            continue
        try:
            with open(pub_path, "rb") as f:
                serialization.load_pem_public_key(f.read())
        except Exception:
            print("[!] Invalid public key file.")
            continue
        save_credentials(user, pw1, level, pub_path)
        print("[*] Credentials saved.")
        break


def prompt_credentials() -> tuple[str, int] | None:
    data = load_password_data()
    if not data:
        print("[!] No credentials set; cannot disable firewall.")
        return None
    key_path = input("Path to your RSA private key (PEM): ").strip()
    if not os.path.isfile(key_path):
        print("[!] Private key file not found.")
        return None
    try:
        with open(key_path, "rb") as f:
            private_key = serialization.load_pem_private_key(f.read(), password=None)
    except Exception:
        print("[!] Invalid private key file.")
        return None
    user = input("Enter username: ").strip()
    if not user:
        print("[!] Username cannot be empty.")
        return None
    pwd = getpass.getpass("Enter password: ")
    if not password_complexity(pwd):
        print("[!] Password does not meet complexity requirements.")
        return None
    u_salt = base64.b64decode(data["u_salt"])
    p_salt = base64.b64decode(data["pw_salt"])
    enc_u = base64.b64decode(data["enc_u_hash"])
    enc_p = base64.b64decode(data["enc_pw_hash"])
    enc_lvl = base64.b64decode(data.get("enc_level", ""))
    try:
        stored_u = private_key.decrypt(
            enc_u,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        stored_p = private_key.decrypt(
            enc_p,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        stored_level_b = private_key.decrypt(
            enc_lvl,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        ) if enc_lvl else b"1"
    except Exception:
        print("[!] Failed to decrypt stored password.")
        return None
    digest_u = hashlib.pbkdf2_hmac("sha256", user.encode(), u_salt, 200000)
    digest_p = hashlib.pbkdf2_hmac("sha256", pwd.encode(), p_salt, 200000)
    if hmac.compare_digest(digest_u, stored_u) and hmac.compare_digest(digest_p, stored_p):
        level = int(stored_level_b.decode()) if stored_level_b else 1
        return user, level
    return None


def remove_autostart():
    task_name = "WinFirewall"
    subprocess.run([
        "schtasks", "/delete", "/TN", task_name, "/f"
    ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def firewall_loop():
    """
    Main loop: open a WinDivert handle on filter "ip", capture packets,
    decide block/allow, and either drop or reinject. Dropped packets are logged.
    """
    filter_expr = "ip"
    while True:
        try:
            with pydivert.WinDivert(filter_expr) as w:
                print("[*] Firewall started. Capturing all IP packets...")
                while True:
                    try:
                        pkt = w.recv()
                    except Exception:
                        break

                    rules = load_rules()
                    if should_block(pkt, rules):
                        log_blocked(pkt)
                        continue
                    else:
                        w.send(pkt)
        except Exception as e:
            print(f"[!] Firewall error: {e}; restarting...")
            time.sleep(1)

def main():
    parser = argparse.ArgumentParser(description="Win-Firewall")
    parser.add_argument(
        "--stop",
        action="store_true",
        help="Disable firewall and remove autostart (requires password)",
    )
    args = parser.parse_args()

    ensure_password_setup()
    check_integrity()

    if args.stop:
        res = prompt_credentials()
        if res:
            user, level = res
            if level != 1:
                print("[!] Insufficient permission to disable firewall.")
            else:
                remove_autostart()
                log_disabled(user)
                print("[*] Firewall autostart removed.")
        else:
            print("[!] Invalid credentials; firewall remains active.")
        return

    if not os.path.exists(LOG_FILE):
        open(LOG_FILE, "w", encoding="utf-8").close()
    update_integrity(LOG_FILE)
    update_integrity(DISABLE_LOG)

    setup_autostart()
    threading.Thread(target=monitor_autostart, daemon=True).start()
    firewall_loop()


if __name__ == "__main__":
    main()
