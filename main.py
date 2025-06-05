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
import uuid
import shutil
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from datetime import datetime

BASE_DIR = os.path.dirname(os.path.abspath(__file__))


def local_path(name: str) -> str:
    return os.path.join(BASE_DIR, name)

import pydivert

CONFIG_FILE = "config.json.enc"
MACHINE_ID_FILE = "machine_id.txt"
USERS_FILE = "users.db.enc"
RULES_ALLOW_FILE = "rules_allow.json.enc"
RULES_BLOCK_FILE = "rules_block.json.enc"
LOG_FILE = "fw_log.txt.enc"
TRAFFIC_LOG = "traffic_log.txt.enc"
DISABLE_LOG = "disable_log.txt"
INTEGRITY_FILE = "log_hashes.json"
TAMPER_LOG = "tamper_log.txt"
WRONG_PW_LOG = "wrong_pw_log.txt"
TEST_DIR = "test_files"


def data_path(filename: str, cfg: dict | None = None) -> str:
    """Return the absolute path for a data file respecting organization mode."""
    if cfg is None and os.path.exists(local_path(CONFIG_FILE)):
        try:
            cfg = load_config()
        except Exception:
            cfg = {}
    cfg = cfg or {}
    if cfg.get("mode") == 2:
        shared = cfg.get("shared_path")
        if shared:
            return os.path.join(shared, filename)
    return local_path(filename)


def derive_key(machine_id: str) -> bytes:
    """Derive a 256-bit key from the machine id."""
    return hashlib.sha256(machine_id.encode()).digest()


def encrypt_json(data: dict, path: str, key: bytes) -> None:
    aes = AESGCM(key)
    nonce = os.urandom(12)
    ct = aes.encrypt(nonce, json.dumps(data).encode(), None)
    with open(path, "wb") as f:
        f.write(nonce + ct)


def decrypt_json(path: str, key: bytes) -> dict:
    if not os.path.exists(path):
        return {}
    with open(path, "rb") as f:
        blob = f.read()
    nonce, ct = blob[:12], blob[12:]
    aes = AESGCM(key)
    data = aes.decrypt(nonce, ct, None)
    return json.loads(data.decode())


def generate_machine_id() -> str:
    """Generate and persist a unique machine identifier."""
    path = local_path(MACHINE_ID_FILE)
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            return f.read().strip()
    hw = str(uuid.getnode()).encode()
    salt = os.urandom(16)
    mid = hashlib.sha256(hw + salt).hexdigest()
    with open(path, "w", encoding="utf-8") as f:
        f.write(mid)
    return mid


def initial_setup() -> dict:
    """Interactive first-run setup to create config and owner credentials."""
    if os.path.exists(local_path(CONFIG_FILE)):
        key = derive_key(generate_machine_id())
        return decrypt_json(local_path(CONFIG_FILE), key)

    print("[*] First launch: setting up ChrisFW")
    while True:
        mode = input("Install mode (1=single PC, 2=organization): ").strip()
        if mode not in ("1", "2"):
            print("[!] Enter 1 or 2")
            continue
        mode = int(mode)
        break

    shared_path = ""
    is_owner = True
    if mode == 2:
        ans = input("Is this the OWNER machine? (y/n): ").strip().lower()
        is_owner = ans != "n"
        shared_path = input("Path to shared organization folder: ").strip()
        if not shared_path:
            print("[!] Shared folder required for organization mode.")
            sys.exit(1)
        if is_owner:
            os.makedirs(shared_path, exist_ok=True)

    disable_pw = getpass.getpass("Create Disable-Firewall Password: ")
    if not password_complexity(disable_pw):
        print("[!] Password does not meet complexity requirements.")
        sys.exit(1)
    disable_salt = os.urandom(16)
    disable_hash = hashlib.pbkdf2_hmac(
        "sha256", disable_pw.encode(), disable_salt, 200000
    )

    recovery_pw = getpass.getpass("Create Recovery Password: ")
    if not password_complexity(recovery_pw):
        print("[!] Password does not meet complexity requirements.")
        sys.exit(1)
    recovery_salt = os.urandom(16)
    recovery_hash = hashlib.pbkdf2_hmac(
        "sha256", recovery_pw.encode(), recovery_salt, 200000
    )

    owner_user = None
    owner_pass = None
    if is_owner:
        owner_user = input("Owner username: ").strip()
        owner_pass = getpass.getpass("Owner password: ")
        if not password_complexity(owner_pass):
            print("[!] Password does not meet complexity requirements.")
            sys.exit(1)
        owner_salt = os.urandom(16)
        owner_hash = hashlib.pbkdf2_hmac(
            "sha256", owner_pass.encode(), owner_salt, 200000
        )
    
    machine_id = generate_machine_id()
    key = derive_key(machine_id)

    owner_id = machine_id if is_owner else input("Enter Owner machine ID: ").strip()
    owner_key = derive_key(owner_id)

    cfg = {
        "mode": mode,
        "owner_id": owner_id,
        "shared_path": shared_path,
        "disable_salt": base64.b64encode(disable_salt).decode(),
        "disable_hash": base64.b64encode(disable_hash).decode(),
        "recovery_salt": base64.b64encode(recovery_salt).decode(),
        "recovery_hash": base64.b64encode(recovery_hash).decode(),
    }
    encrypt_json(cfg, local_path(CONFIG_FILE), key)

    users = []
    if is_owner:
        users.append(
            {
                "username": owner_user,
                "salt": base64.b64encode(owner_salt).decode(),
                "hash": base64.b64encode(owner_hash).decode(),
                "role": 1,
            }
        )
        encrypt_json({"users": users}, os.path.join(shared_path, USERS_FILE) if mode == 2 else local_path(USERS_FILE), owner_key)
    else:
        path = os.path.join(shared_path, USERS_FILE) if mode == 2 else local_path(USERS_FILE)
        if not os.path.exists(path):
            encrypt_json({"users": users}, path, owner_key)

    allow_path = os.path.join(shared_path, RULES_ALLOW_FILE) if mode == 2 else local_path(RULES_ALLOW_FILE)
    block_path = os.path.join(shared_path, RULES_BLOCK_FILE) if mode == 2 else local_path(RULES_BLOCK_FILE)
    if is_owner:
        encrypt_json([], allow_path, owner_key)
        encrypt_json([], block_path, owner_key)
    else:
        for p in (allow_path, block_path):
            if not os.path.exists(p):
                encrypt_json([], p, owner_key)

    encrypt_json([], local_path(LOG_FILE), key)
    encrypt_json([], local_path(TRAFFIC_LOG), key)

    test_path = local_path(TEST_DIR)
    if not os.path.exists(test_path):
        os.makedirs(test_path, exist_ok=True)
        try:
            os.chmod(test_path, 0o700)
        except Exception:
            pass

    return cfg


def load_config() -> dict:
    key = derive_key(generate_machine_id())
    return decrypt_json(local_path(CONFIG_FILE), key)


def save_config(cfg: dict) -> None:
    key = derive_key(generate_machine_id())
    encrypt_json(cfg, local_path(CONFIG_FILE), key)


def load_users() -> list:
    cfg = load_config()
    key = derive_key(cfg.get("owner_id", generate_machine_id()))
    path = data_path(USERS_FILE, cfg)
    data = decrypt_json(path, key)
    return data.get("users", [])


def save_users(users: list) -> None:
    cfg = load_config()
    key = derive_key(cfg.get("owner_id", generate_machine_id()))
    path = data_path(USERS_FILE, cfg)
    encrypt_json({"users": users}, path, key)


def add_user(current_machine: str, username: str, password: str, role: int) -> bool:
    """Add a user if this machine is the owner PC."""
    cfg = load_config()
    if cfg.get("owner_id") != current_machine:
        print("[!] Only the Owner PC can add users.")
        return False
    users = load_users()
    if any(u["username"] == username for u in users):
        print("[!] User already exists.")
        return False
    salt = os.urandom(16)
    pw_hash = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 200000)
    users.append({
        "username": username,
        "salt": base64.b64encode(salt).decode(),
        "hash": base64.b64encode(pw_hash).decode(),
        "role": role,
    })
    save_users(users)
    return True


def remove_user(current_machine: str, username: str) -> bool:
    """Remove a user if this machine is the owner PC."""
    cfg = load_config()
    if cfg.get("owner_id") != current_machine:
        print("[!] Only the Owner PC can remove users.")
        return False
    users = load_users()
    for u in users:
        if u["username"] == username:
            users.remove(u)
            save_users(users)
            return True
    print("[!] User not found.")
    return False


def set_user_role(current_machine: str, username: str, role: int) -> bool:
    """Change a user's role if this machine is the owner PC."""
    cfg = load_config()
    if cfg.get("owner_id") != current_machine:
        print("[!] Only the Owner PC can change roles.")
        return False
    if role not in (1, 2, 3, 4):
        print("[!] Invalid role.")
        return False
    users = load_users()
    for u in users:
        if u["username"] == username:
            u["role"] = role
            save_users(users)
            return True
    print("[!] User not found.")
    return False


def verify_user(username: str, password: str) -> tuple[int, bool]:
    users = load_users()
    for u in users:
        if u["username"] == username:
            salt = base64.b64decode(u["salt"])
            pw_hash = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 200000)
            if hmac.compare_digest(pw_hash, base64.b64decode(u["hash"])):
                return u.get("role", 4), True
            else:
                break
    log_wrong_password(username)
    return 0, False


def load_rules() -> list:
    """Return merged allow and block rules from encrypted rule files."""
    cfg = load_config()
    key = derive_key(cfg.get("owner_id", generate_machine_id()))
    allow_rules = decrypt_json(data_path(RULES_ALLOW_FILE, cfg), key)
    block_rules = decrypt_json(data_path(RULES_BLOCK_FILE, cfg), key)
    now = time.time()
    changed = False
    for r in allow_rules[:]:
        if r.get("expires") and now > r["expires"]:
            allow_rules.remove(r)
            changed = True
    for r in block_rules[:]:
        if r.get("expires") and now > r["expires"]:
            block_rules.remove(r)
            changed = True
    if changed:
        encrypt_json(allow_rules, data_path(RULES_ALLOW_FILE, cfg), key)
        encrypt_json(block_rules, data_path(RULES_BLOCK_FILE, cfg), key)
    return allow_rules + block_rules


def save_rules(allow_rules: list, block_rules: list) -> None:
    cfg = load_config()
    key = derive_key(cfg.get("owner_id", generate_machine_id()))
    encrypt_json(allow_rules, data_path(RULES_ALLOW_FILE, cfg), key)
    encrypt_json(block_rules, data_path(RULES_BLOCK_FILE, cfg), key)


def add_timed_block(ip: str, duration: int = 3600) -> None:
    """Add a temporary block rule for the given destination IP."""
    cfg = load_config()
    key = derive_key(cfg.get("owner_id", generate_machine_id()))
    allow_rules = decrypt_json(data_path(RULES_ALLOW_FILE, cfg), key)
    block_rules = decrypt_json(data_path(RULES_BLOCK_FILE, cfg), key)
    rule = {
        "action": "block",
        "direction": "outbound",
        "protocol": "ANY",
        "src_ip": "ANY",
        "src_port": "ANY",
        "dst_ip": ip,
        "dst_port": "ANY",
        "expires": time.time() + duration,
    }
    block_rules.append(rule)
    save_rules(allow_rules, block_rules)


def add_timed_allow(ip: str, duration: int = 3600) -> None:
    """Add a temporary allow rule for the given destination IP."""
    cfg = load_config()
    key = derive_key(cfg.get("owner_id", generate_machine_id()))
    allow_rules = decrypt_json(data_path(RULES_ALLOW_FILE, cfg), key)
    block_rules = decrypt_json(data_path(RULES_BLOCK_FILE, cfg), key)
    rule = {
        "action": "allow",
        "direction": "outbound",
        "protocol": "ANY",
        "src_ip": "ANY",
        "src_port": "ANY",
        "dst_ip": ip,
        "dst_port": "ANY",
        "expires": time.time() + duration,
    }
    allow_rules.append(rule)
    save_rules(allow_rules, block_rules)


def add_quarantine(ip: str, duration: int = 3600) -> None:
    """Add a quarantine block rule (marked) for the IP."""
    cfg = load_config()
    key = derive_key(cfg.get("owner_id", generate_machine_id()))
    allow_rules = decrypt_json(data_path(RULES_ALLOW_FILE, cfg), key)
    block_rules = decrypt_json(data_path(RULES_BLOCK_FILE, cfg), key)
    rule = {
        "action": "block",
        "direction": "outbound",
        "protocol": "ANY",
        "src_ip": "ANY",
        "src_port": "ANY",
        "dst_ip": ip,
        "dst_port": "ANY",
        "expires": time.time() + duration,
        "quarantine": True,
    }
    block_rules.append(rule)
    save_rules(allow_rules, block_rules)


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


def detect_layer(pkt) -> int:
    """Rudimentary layer detection based on ports and payload."""
    if pkt.tcp:
        port = pkt.tcp.dst_port if pkt.is_outbound else pkt.tcp.src_port
        if port in (80, 8080, 8000, 8888):
            return 7
        if port == 443:
            return 6
    if pkt.udp:
        port = pkt.udp.dst_port if pkt.is_outbound else pkt.udp.src_port
        if port == 53:
            return 7
    return 4


def extract_domain(pkt) -> str | None:
    """Attempt to pull domain from HTTP Host header."""
    if pkt.tcp and pkt.payload:
        port = pkt.tcp.dst_port if pkt.is_outbound else pkt.tcp.src_port
        if port in (80, 8080, 8000, 8888):
            try:
                data = bytes(pkt.payload).decode(errors="ignore")
                for line in data.splitlines():
                    if line.lower().startswith("host:"):
                        return line.split(":", 1)[1].strip()
            except Exception:
                pass
    return None


MALICIOUS_INDICATORS = {"malware", "phishing", "badexample.com"}


def ai_analyze(target: str) -> tuple[bool, float]:
    """Very basic heuristic 'AI' check."""
    if not target:
        return False, 0.0
    lower = target.lower()
    for word in MALICIOUS_INDICATORS:
        if word in lower:
            return True, 0.95
    return False, 0.05


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

    cfg = load_config()
    key = derive_key(cfg.get("owner_id", generate_machine_id()))
    logs = decrypt_json(local_path(LOG_FILE), key)
    if not isinstance(logs, list):
        logs = []
    logs.append(line.strip())
    encrypt_json(logs, local_path(LOG_FILE), key)
    update_integrity(local_path(LOG_FILE))
    layer = detect_layer(pkt)
    domain = extract_domain(pkt)
    log_traffic(pkt, "BLOCKED", layer, domain)


def log_traffic(pkt, action: str, layer: int = 4, dest: str | None = None, username: str | None = None) -> None:
    """Log every packet with ALLOWED/BLOCKED/AI-FLAGGED status."""
    proto = get_protocol(pkt)
    if proto == "TCP":
        src_port = pkt.tcp.src_port
        dst_port = pkt.tcp.dst_port
    elif proto == "UDP":
        src_port = pkt.udp.src_port
        dst_port = pkt.udp.dst_port
    else:
        src_port = 0
        dst_port = 0

    now = datetime.now().astimezone()
    user = username or os.getenv("USERNAME", "unknown")
    dest = dest or str(pkt.dst_addr)
    line = (
        f"{now:%Y-%m-%d %H:%M:%S.%f %z} "
        f"{user} {action} L{layer} {proto} {pkt.src_addr}:{src_port} -> {dest}:{dst_port}"
    )

    cfg = load_config()
    key = derive_key(cfg.get("owner_id", generate_machine_id()))
    logs = decrypt_json(local_path(TRAFFIC_LOG), key)
    if not isinstance(logs, list):
        logs = []
    logs.append(line)
    encrypt_json(logs, local_path(TRAFFIC_LOG), key)
    update_integrity(local_path(TRAFFIC_LOG))


def log_disabled(username: str) -> None:
    """Append a timestamped entry to disable_log.txt with the given username."""
    now = datetime.now().astimezone()
    entry = f"{now:%Y-%m-%d %H:%M:%S %z} DISABLED_BY {username}\n"
    with open(local_path(DISABLE_LOG), "a", encoding="utf-8", errors="ignore") as f:
        f.write(entry)
    update_integrity(local_path(DISABLE_LOG))


def get_local_ip() -> str:
    """Return the local machine's IP address for logging."""
    try:
        import socket
        hostname = socket.gethostname()
        return socket.gethostbyname(hostname)
    except Exception:
        return "unknown"


def log_wrong_password(username: str) -> None:
    """Record a failed authentication attempt with IP and timestamp."""
    now = datetime.now().astimezone()
    ip = get_local_ip()
    entry = f"{now:%Y-%m-%d %H:%M:%S %z} WRONG_PW {username} {ip}\n"
    with open(local_path(WRONG_PW_LOG), "a", encoding="utf-8", errors="ignore") as f:
        f.write(entry)
    update_integrity(local_path(WRONG_PW_LOG))


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
    integ_path = local_path(INTEGRITY_FILE)
    if os.path.exists(integ_path):
        try:
            with open(integ_path, "r", encoding="utf-8") as f:
                hashes = json.load(f)
        except Exception:
            hashes = {}
    hashes[path] = file_sha256(path)
    with open(integ_path, "w", encoding="utf-8") as f:
        json.dump(hashes, f)


def check_integrity() -> None:
    integ_path = local_path(INTEGRITY_FILE)
    if not os.path.exists(integ_path):
        return
    try:
        with open(integ_path, "r", encoding="utf-8") as f:
            hashes = json.load(f)
    except Exception:
        hashes = {}
    for p, old in hashes.items():
        if os.path.exists(p):
            new = file_sha256(p)
            if old and new != old:
                now = datetime.now().astimezone()
                entry = f"{now:%Y-%m-%d %H:%M:%S %z} TAMPER_DETECTED {p}\n"
                with open(local_path(TAMPER_LOG), "a", encoding="utf-8", errors="ignore") as tf:
                    tf.write(entry)
    for p in [local_path(LOG_FILE), local_path(TRAFFIC_LOG), local_path(DISABLE_LOG), local_path(WRONG_PW_LOG)]:
        if os.path.exists(p):
            update_integrity(p)


def setup_autostart():
    """Create a Windows scheduled task to launch this script on startup."""
    task_name = "WinFirewall"
    script_path = local_path(os.path.basename(__file__))
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
        "/F",
        "/TN",
        task_name,
        "/TR",
        f'"{pythonw}" "{script_path}"',
    ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


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



def prompt_user() -> tuple[str, int] | None:
    """Prompt for username and password and return (username, role) on success."""
    user = input("Username: ").strip()
    pwd = getpass.getpass("Password: ")
    role, ok = verify_user(user, pwd)
    if ok:
        return user, role
    return None


def prompt_disable() -> str | None:
    cfg = load_config()
    user_data = prompt_user()
    if not user_data:
        print("[!] Invalid credentials.")
        return None
    user, role = user_data
    if role != 1:
        print("[!] Only level 1 users may disable the firewall.")
        return None
    pw = getpass.getpass("Disable-Firewall Password: ")
    salt = base64.b64decode(cfg["disable_salt"])
    stored = base64.b64decode(cfg["disable_hash"])
    digest = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt, 200000)
    if hmac.compare_digest(digest, stored):
        return user
    print("[!] Wrong disable password.")
    log_wrong_password(user)
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

                    domain = extract_domain(pkt)
                    layer = detect_layer(pkt)
                    malicious, score = ai_analyze(domain or str(pkt.dst_addr))

                    rules = load_rules()
                    if malicious:
                        log_traffic(pkt, f"AI-FLAGGED({score:.2f})", layer, domain)
                        add_quarantine(str(pkt.dst_addr), 3600)
                        print(f"WARNING: {os.getenv('USERNAME','user')} to {domain or pkt.dst_addr} L{layer} flagged malicious {score:.0%}")
                        continue

                    if should_block(pkt, rules):
                        log_blocked(pkt)
                        continue
                    else:
                        w.send(pkt)
                        log_traffic(pkt, "ALLOWED", layer, domain)
                        print(f"ALLOWED {pkt.src_addr}->{pkt.dst_addr}")
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
    parser.add_argument(
        "--add-user",
        action="store_true",
        help="Add a user (Owner PC only)",
    )
    parser.add_argument(
        "--remove-user",
        metavar="USERNAME",
        help="Remove a user (Owner PC only)",
    )
    parser.add_argument(
        "--set-role",
        nargs=2,
        metavar=("USERNAME", "LEVEL"),
        help="Change user's role (Owner PC only)",
    )
    args = parser.parse_args()

    cfg = initial_setup()
    check_integrity()

    current_machine = generate_machine_id()

    if args.add_user or args.remove_user or args.set_role:
        cred = prompt_user()
        if not cred:
            print("[!] Invalid credentials.")
            return
        user, role = cred
        if role != 1 or current_machine != cfg.get("owner_id"):
            print("[!] Only an Owner on the Owner PC may manage users.")
            return
        if args.add_user:
            new_user = input("New username: ").strip()
            pw = getpass.getpass("New password: ")
            if not password_complexity(pw):
                print("[!] Password does not meet complexity requirements.")
                return
            try:
                lvl = int(input("Role (1=Owner,2=Admin,3=Block,4=Monitor): "))
            except ValueError:
                print("[!] Invalid role.")
                return
            if add_user(current_machine, new_user, pw, lvl):
                print("[*] User added.")
            return
        if args.remove_user:
            if remove_user(current_machine, args.remove_user):
                print("[*] User removed.")
            return
        if args.set_role:
            uname, lvl_str = args.set_role
            try:
                lvl = int(lvl_str)
            except ValueError:
                print("[!] Invalid role.")
                return
            if set_user_role(current_machine, uname, lvl):
                print("[*] Role updated.")
            return

    if args.stop:
        user = prompt_disable()
        if user:
            remove_autostart()
            log_disabled(user)
            print("[*] Firewall autostart removed.")
        else:
            print("[!] Invalid credentials; firewall remains active.")
        return

    log_path = local_path(LOG_FILE)
    if not os.path.exists(log_path):
        encrypt_json([], log_path, derive_key(generate_machine_id()))
    tlog_path = local_path(TRAFFIC_LOG)
    if not os.path.exists(tlog_path):
        encrypt_json([], tlog_path, derive_key(generate_machine_id()))
    update_integrity(log_path)
    update_integrity(tlog_path)
    update_integrity(local_path(DISABLE_LOG))
    update_integrity(local_path(WRONG_PW_LOG))

    setup_autostart()
    threading.Thread(target=monitor_autostart, daemon=True).start()
    firewall_loop()


if __name__ == "__main__":
    main()
