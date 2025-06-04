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

import pydivert

CONFIG_FILE = "config.json.enc"
MACHINE_ID_FILE = "machine_id.txt"
USERS_FILE = "users.db.enc"
RULES_ALLOW_FILE = "rules_allow.json.enc"
RULES_BLOCK_FILE = "rules_block.json.enc"
LOG_FILE = "fw_log.txt.enc"
DISABLE_LOG = "disable_log.txt"
INTEGRITY_FILE = "log_hashes.json"
TAMPER_LOG = "tamper_log.txt"
WRONG_PW_LOG = "wrong_pw_log.txt"
TEST_DIR = "test_files"


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
    if os.path.exists(MACHINE_ID_FILE):
        with open(MACHINE_ID_FILE, "r", encoding="utf-8") as f:
            return f.read().strip()
    hw = str(uuid.getnode()).encode()
    salt = os.urandom(16)
    mid = hashlib.sha256(hw + salt).hexdigest()
    with open(MACHINE_ID_FILE, "w", encoding="utf-8") as f:
        f.write(mid)
    return mid


def initial_setup() -> dict:
    """Interactive first-run setup to create config and owner credentials."""
    if os.path.exists(CONFIG_FILE):
        key = derive_key(generate_machine_id())
        return decrypt_json(CONFIG_FILE, key)

    print("[*] First launch: setting up ChrisFW")
    while True:
        mode = input("Install mode (1=single PC, 2=organization): ").strip()
        if mode not in ("1", "2"):
            print("[!] Enter 1 or 2")
            continue
        mode = int(mode)
        break

    is_owner = True
    if mode == 2:
        ans = input("Is this the OWNER machine? (y/n): ").strip().lower()
        is_owner = ans != "n"

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

    cfg = {
        "mode": mode,
        "owner_id": owner_id,
        "disable_salt": base64.b64encode(disable_salt).decode(),
        "disable_hash": base64.b64encode(disable_hash).decode(),
        "recovery_salt": base64.b64encode(recovery_salt).decode(),
        "recovery_hash": base64.b64encode(recovery_hash).decode(),
    }
    encrypt_json(cfg, CONFIG_FILE, key)

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
        encrypt_json({"users": users}, USERS_FILE, key)
    else:
        src = input(
            "Path to owner-provided users.db.enc (leave blank for none): "
        ).strip()
        if src and os.path.exists(src):
            shutil.copy(src, USERS_FILE)
        else:
            encrypt_json({"users": users}, USERS_FILE, key)

    if is_owner:
        encrypt_json([], RULES_ALLOW_FILE, key)
        encrypt_json([], RULES_BLOCK_FILE, key)
    else:
        src_allow = input(
            "Path to owner-provided rules_allow.json.enc (blank for none): "
        ).strip()
        if src_allow and os.path.exists(src_allow):
            shutil.copy(src_allow, RULES_ALLOW_FILE)
        else:
            encrypt_json([], RULES_ALLOW_FILE, key)

        src_block = input(
            "Path to owner-provided rules_block.json.enc (blank for none): "
        ).strip()
        if src_block and os.path.exists(src_block):
            shutil.copy(src_block, RULES_BLOCK_FILE)
        else:
            encrypt_json([], RULES_BLOCK_FILE, key)

    encrypt_json([], LOG_FILE, key)

    if not os.path.exists(TEST_DIR):
        os.makedirs(TEST_DIR, exist_ok=True)
        try:
            os.chmod(TEST_DIR, 0o700)
        except Exception:
            pass

    return cfg


def load_config() -> dict:
    key = derive_key(generate_machine_id())
    return decrypt_json(CONFIG_FILE, key)


def save_config(cfg: dict) -> None:
    key = derive_key(generate_machine_id())
    encrypt_json(cfg, CONFIG_FILE, key)


def load_users() -> list:
    key = derive_key(generate_machine_id())
    data = decrypt_json(USERS_FILE, key)
    return data.get("users", [])


def save_users(users: list) -> None:
    key = derive_key(generate_machine_id())
    encrypt_json({"users": users}, USERS_FILE, key)


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
    key = derive_key(generate_machine_id())
    allow_rules = decrypt_json(RULES_ALLOW_FILE, key)
    block_rules = decrypt_json(RULES_BLOCK_FILE, key)
    return allow_rules + block_rules


def save_rules(allow_rules: list, block_rules: list) -> None:
    key = derive_key(generate_machine_id())
    encrypt_json(allow_rules, RULES_ALLOW_FILE, key)
    encrypt_json(block_rules, RULES_BLOCK_FILE, key)


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

    key = derive_key(generate_machine_id())
    logs = decrypt_json(LOG_FILE, key)
    if not isinstance(logs, list):
        logs = []
    logs.append(line.strip())
    encrypt_json(logs, LOG_FILE, key)
    update_integrity(LOG_FILE)


def log_disabled(username: str) -> None:
    """Append a timestamped entry to disable_log.txt with the given username."""
    now = datetime.now().astimezone()
    entry = f"{now:%Y-%m-%d %H:%M:%S %z} DISABLED_BY {username}\n"
    with open(DISABLE_LOG, "a", encoding="utf-8", errors="ignore") as f:
        f.write(entry)
    update_integrity(DISABLE_LOG)


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
    with open(WRONG_PW_LOG, "a", encoding="utf-8", errors="ignore") as f:
        f.write(entry)
    update_integrity(WRONG_PW_LOG)


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
    for p in [LOG_FILE, DISABLE_LOG, WRONG_PW_LOG]:
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

    if not os.path.exists(LOG_FILE):
        encrypt_json([], LOG_FILE, derive_key(generate_machine_id()))
    update_integrity(LOG_FILE)
    update_integrity(DISABLE_LOG)
    update_integrity(WRONG_PW_LOG)

    setup_autostart()
    threading.Thread(target=monitor_autostart, daemon=True).start()
    firewall_loop()


if __name__ == "__main__":
    main()
