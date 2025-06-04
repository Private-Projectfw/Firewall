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
a scheduled task so the firewall starts automatically at Windows boot. You will
be asked whether this installation is for a **single PC** or for an
**organization**.

- **Single PC** – all data stays local and the firewall locks down only this
  machine.
- **Organization** – the first machine becomes the **Owner**. Additional
  machines may join by providing the owner machine ID and copies of the
  encrypted user and rule files. Only the Owner PC can manage users and disable
  ChrisFW.

During setup you also create the Disable‑Firewall and Recovery passwords. All
configuration, user data, rules and logs are AES‑encrypted on disk.

```powershell
python main.py
```

The script loads rules from the encrypted files `rules_allow.json.enc` and
`rules_block.json.enc` and logs blocked packets to `fw_log.txt.enc`.
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

Levels 2 and 3 see only a sanitized firewall log that omits IP addresses and
ports. They cannot view or open any raw files.

Unusual entries in the firewall log are highlighted for quick review. Wrong
password attempts are recorded in `wrong_pw_log.txt` and only visible to level
1 users. Rule changes update the encrypted rule files automatically.

---

## Notes

- `main.py` and `gui.py` both require administrator privileges so WinDivert can operate. Start *Command Prompt* with **Run as administrator** before launching.
- `fw_log.txt.enc` will be created in this directory containing encrypted firewall logs.
- The first run installs a scheduled task named `WinFirewall`. Delete that task via
  **Task Scheduler** if you no longer want the firewall to start automatically.
- A background monitor recreates the scheduled task if it's removed, helping guard
  against tampering.
- To disable the firewall and remove the task, run `python main.py --stop`. The
  script prompts for your username, password and the Disable-Firewall password.
  Only level 1 users may disable ChrisFW. Each successful disable action is logged
  in `disable_log.txt`.
- Log files are checked for tampering at startup. Any modification is recorded
  in `tamper_log.txt`.
- Permission levels: **1** owner, **2** allow/block, **3** block-only,
  **4** monitor only.
