Win-Firewall (Custom Personal Firewall)

**Purpose:**
A lightweight, Python-based personal firewall for Windows that uses WinDivert to intercept packets. Provides a simple GUI to manage allow/block rules.

---

## Prerequisites

- Windows 10/11 (x64)
- Administrator privileges (firewall engine must run as Admin)
- Python 3.8+ installed and on PATH

---

## Installation

1. **Clone this repo** (or copy the files into `C:\Users\<YourName>\Documents\win-fw`):
   ```powershell
   git clone https://github.com/walkchris/win-fw.git
   cd win-fw
   ```
2. **Install Python dependencies**:
   ```powershell
   pip install -r requirements.txt
   ```
3. **Download WinDivert** from <https://reqrypt.org/windivert.html> and place `WinDivert64.sys` and `WinDivert.dll` in this directory or somewhere on your `PATH`.

---

## Usage

### Launch the firewall

Run `main.py` from an elevated command prompt. On first run it will create
a scheduled task so the firewall starts automatically at Windows boot and
prompt you to set a username, choose a permission level and set an anti-tampering password. You must also supply your RSA public key:

```powershell
python main.py
```

The script loads rules from `rules.json` and logs blocked packets to `fw_log.txt`.
Timestamps include your local timezone.

### Launch the GUI panel

Run the redesigned GUI to manage rules and view logs:

```powershell
python gui.py
```

The GUI welcomes you by username and shows tabs on the left. Depending on your
permission level:

- **1** – full access including all logs and rule management.
- **2** – may add and delete allow/block rules.
- **3** – may add new block rules only.
- **4** – monitor firewall logs only.

Unusual entries in the firewall log are highlighted for quick review. Wrong
password attempts are recorded in `wrong_pw_log.txt` and only visible to level
1 users. All rule changes still update the shared `rules.json` file.

---

## Notes

- `main.py` and `gui.py` both require administrator privileges so WinDivert can operate. Start *Command Prompt* with **Run as administrator** before launching.
- `fw_log.txt` will be created in this directory containing a log of blocked connections.
- The first run installs a scheduled task named `WinFirewall`. Delete that task via
  **Task Scheduler** if you no longer want the firewall to start automatically.
- A background monitor recreates the scheduled task if it's removed, helping guard
  against tampering.
- To disable the firewall and remove the task, run `python main.py --stop`. The
  script prompts for your credentials and RSA private key. Only a level&nbsp;1
  user can disable the firewall. Username and password hashes are salted and
  encrypted with your public key in `password.json`. Each successful disable
  action is logged with username and timezone in `disable_log.txt`.
- Log files are checked for tampering at startup. Any modification is recorded
  in `tamper_log.txt`.
- Permission levels: **1** owner, **2** allow/block, **3** block-only,
  **4** monitor only.
