import json
import os
import PySimpleGUI as sg
from main import (
    ensure_password_setup,
    prompt_credentials,
)

LOG_FILE = "fw_log.txt"
DISABLE_LOG = "disable_log.txt"
TAMPER_LOG = "tamper_log.txt"
WRONG_PW_LOG = "wrong_pw_log.txt"

RULES_FILE = "rules.json"

def load_rules():
    if not os.path.exists(RULES_FILE):
        return []
    with open(RULES_FILE, "r", encoding="utf-8", errors="ignore") as f:
        try:
            return json.load(f)
        except json.JSONDecodeError:
            return []

def save_rules(rules):
    with open(RULES_FILE, "w", encoding="utf-8", errors="ignore") as f:
        json.dump(rules, f, indent=2)

def rule_to_display(rule):
    """
    Convert rule dict to a readable string for the listbox, e.g.:
    [BLOCK][outbound][TCP][ANY:ANY → 8.8.8.8:53]
    """
    return f"[{rule['action'].upper()}][{rule['direction']}][{rule['protocol']}][{rule['src_ip']}:{rule['src_port']} → {rule['dst_ip']}:{rule['dst_port']}]"

def read_log_lines(path, limit=200):
    if not os.path.exists(path):
        return []
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        lines = f.readlines()[-limit:]
    return [line.strip() for line in lines]


def is_unusual(line: str) -> bool:
    return "OTHER" in line or ":0" in line


def build_rule_tab(rules, level):
    if level >= 4:
        return None
    actions = ["allow", "block"] if level in (1, 2) else ["block"]
    rule_display_list = [rule_to_display(r) for r in rules]
    rule_col = [
        [sg.Listbox(values=rule_display_list, size=(60, 10), key="-RULE LIST-", enable_events=True)],
        [
            sg.Frame(
                "Add / Edit Rule",
                [
                    [sg.Text("Action"), sg.Combo(actions, default_value=actions[0], key="-ACTION-")],
                    [sg.Text("Direction"), sg.Combo(["outbound", "inbound"], default_value="outbound", key="-DIRECTION-")],
                    [sg.Text("Protocol"), sg.Combo(["TCP", "UDP", "ANY"], default_value="ANY", key="-PROTOCOL-")],
                    [sg.Text("Src IP"), sg.Input("ANY", size=(15, 1), key="-SRC IP-"), sg.Text("Src Port"), sg.Input("ANY", size=(5, 1), key="-SRC PORT-")],
                    [sg.Text("Dst IP"), sg.Input("ANY", size=(15, 1), key="-DST IP-"), sg.Text("Dst Port"), sg.Input("ANY", size=(5, 1), key="-DST PORT-")],
                    [sg.Button("Add Rule", key="-ADD-"), sg.Button("Delete Selected", key="-DEL-")],
                ],
            )]
    ]
    return sg.Tab("Rules", rule_col, key="-TAB_RULES-")


def build_log_tab(title, path):
    lines = read_log_lines(path)
    table_data = [[line] for line in lines]
    colors = [
        (i, "yellow", None)
        for i, line in enumerate(lines)
        if title == "Firewall Logs" and is_unusual(line)
    ]
    tab_layout = [
        [
            sg.Table(
                values=table_data,
                headings=[title],
                auto_size_columns=True,
                num_rows=20,
                key=f"-TABLE-{title}-",
                row_colors=colors,
                justification="left",
                expand_x=True,
                expand_y=True,
            )
        ],
        [sg.Button("Refresh", key=f"-REFRESH-{title}-")],
    ]
    return sg.Tab(title, tab_layout)


def main():
    custom_theme = {
        "BACKGROUND": "#000000",
        "TEXT": "white",
        "INPUT": "#1A1A1A",
        "TEXT_INPUT": "white",
        "SCROLL": "#1A1A1A",
        "BUTTON": ("white", "#004080"),
        "PROGRESS": "#01826B",
        "BORDER": "#004080",
        "SLIDER_DEPTH": 0,
        "PROGRESS_DEPTH": 0,
    }
    sg.theme_add_new("ChFuturistic", custom_theme)
    sg.theme("ChFuturistic")

    ensure_password_setup()
    cred = prompt_credentials()
    if not cred:
        sg.popup("Invalid credentials")
        return
    user, level = cred

    rules = load_rules()
    tabs = [build_log_tab("Firewall Logs", LOG_FILE)]

    rule_tab = build_rule_tab(rules, level)
    if rule_tab:
        tabs.append(rule_tab)

    if level == 1:
        tabs.append(build_log_tab("Disable Logs", DISABLE_LOG))
        tabs.append(build_log_tab("Tamper Logs", TAMPER_LOG))
        tabs.append(build_log_tab("Wrong Passwords", WRONG_PW_LOG))

    layout = [
        [sg.Text(f"WELCOME {user}", font=("Helvetica", 20), justification="center")],
        [sg.TabGroup([[t for t in tabs if t]], tab_location="left", title_color="cyan", border_width=2, key="-TABS-")],
        [sg.Button("Exit")],
    ]

    window = sg.Window("chrisfw", layout, finalize=True, size=(800, 600))

    rule_display_list = [rule_to_display(r) for r in rules]
    if rule_tab:
        window["-RULE LIST-"].update(rule_display_list)

    while True:
        event, values = window.read()
        if event in (sg.WIN_CLOSED, "Exit"):
            break

        if event == "-ADD-":
            if level == 4:
                sg.popup("Permission denied")
                continue
            if level == 3 and values["-ACTION-"] != "block":
                sg.popup("Level 3 may only add block rules")
                continue
            new_rule = {
                "action": values["-ACTION-"],
                "direction": values["-DIRECTION-"],
                "protocol": values["-PROTOCOL-"],
                "src_ip": values["-SRC IP-"].strip() or "ANY",
                "src_port": values["-SRC PORT-"].strip() or "ANY",
                "dst_ip": values["-DST IP-"].strip() or "ANY",
                "dst_port": values["-DST PORT-"].strip() or "ANY",
            }
            rules.append(new_rule)
            save_rules(rules)
            rule_display_list.append(rule_to_display(new_rule))
            window["-RULE LIST-"].update(rule_display_list)

        elif event == "-DEL-":
            if level != 1:
                sg.popup("Only level 1 can delete rules")
                continue
            selected = values["-RULE LIST-"]
            if selected:
                idx = rule_display_list.index(selected[0])
                del rules[idx]
                del rule_display_list[idx]
                save_rules(rules)
                window["-RULE LIST-"].update(rule_display_list)

        elif event.startswith("-REFRESH-"):
            tab_title = event.replace("-REFRESH-", "")
            if tab_title == "Firewall Logs":
                lines = read_log_lines(LOG_FILE)
                data = [[l] for l in lines]
                colors = [
                    (i, "yellow", None)
                    for i, line in enumerate(lines)
                    if is_unusual(line)
                ]
                window["-TABLE-Firewall Logs-"].update(values=data, row_colors=colors)
            elif tab_title == "Disable Logs":
                data = [[l] for l in read_log_lines(DISABLE_LOG)]
                window["-TABLE-Disable Logs-"].update(values=data)
            elif tab_title == "Tamper Logs":
                data = [[l] for l in read_log_lines(TAMPER_LOG)]
                window["-TABLE-Tamper Logs-"].update(values=data)
            elif tab_title == "Wrong Passwords":
                data = [[l] for l in read_log_lines(WRONG_PW_LOG)]
                window["-TABLE-Wrong Passwords-"].update(values=data)

    window.close()

if __name__ == "__main__":
    main()
