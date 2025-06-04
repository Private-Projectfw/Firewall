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

Run `main.py` from an elevated command prompt. On first run it creates
a scheduled task so the firewall starts automatically at Windows boot and asks
whether the installation is for a **single PC** or an **organization**.

- **Single PC** – all data stays local and the firewall protects only the
  current machine.
- **Organization** – the first machine becomes the **Owner** and its Machine ID
  is recorded. You supply a shared folder path where encrypted rule and user
  databases are stored. Other machines join by pointing to that folder and using
  the Owner ID. Any Owner-level user can disable ChrisFW, but only the first
  Owner PC may add, remove or change accounts.

#### Organization mode setup

1. On the first PC run `python main.py` and choose `2` for organization mode.
   Confirm that this is the **Owner** machine when prompted.
2. Enter a path to a **shared folder** accessible to every PC in the network.
   The firewall stores encrypted user and rule databases here.
3. Create the **Disable‑Firewall** and **Recovery** passwords and supply an
   initial Owner username and password. After setup completes a file named
   `machine_id.txt` contains this PC's machine ID.
4. On each additional PC run `python main.py`, choose organization mode and
   answer `n` when asked if it is the Owner machine. Provide the same shared
   folder path and enter the machine ID from the Owner PC when prompted.
5. From the Owner PC manage accounts using the command line options
   `--add-user`, `--remove-user` and `--set-role`. Other PCs cannot modify
   Owner accounts.

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

Levels 2, 3 and 4 see only a sanitized firewall log that omits IP addresses and
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
- Manage accounts from the Owner PC using `--add-user`, `--remove-user <name>` or
`--set-role <name> <level>`. Other machines cannot modify Owner accounts.
- Log files are checked for tampering at startup. Any modification is recorded
  in `tamper_log.txt`. In organization mode the shared folder holds the encrypted
  user and rule files so all machines stay in sync.
- Permission levels: **1** owner, **2** allow/block, **3** block-only,
  **4** monitor only.
