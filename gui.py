import json
import os
import PySimpleGUI as sg

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

def main():
    sg.theme("DarkBlue3")

    # Load existing rules
    rules = load_rules()
    rule_display_list = [rule_to_display(r) for r in rules]

    # Layout
    layout = [
        [sg.Text("Personal Firewall Rule Manager", font=("Helvetica", 16))],
        [
            sg.Listbox(values=rule_display_list, size=(60, 10), key="-RULE LIST-", enable_events=True)
        ],
        [
            sg.Frame("Add / Edit Rule", [
                [
                    sg.Text("Action"), sg.Combo(["allow", "block"], default_value="block", key="-ACTION-"),
                    sg.Text("Direction"), sg.Combo(["outbound", "inbound"], default_value="outbound", key="-DIRECTION-")
                ],
                [
                    sg.Text("Protocol"), sg.Combo(["TCP", "UDP", "ANY"], default_value="ANY", key="-PROTOCOL-")
                ],
                [
                    sg.Text("Src IP"), sg.Input(default_text="ANY", size=(15,1), key="-SRC IP-"),
                    sg.Text("Src Port"), sg.Input(default_text="ANY", size=(5,1), key="-SRC PORT-")
                ],
                [
                    sg.Text("Dst IP"), sg.Input(default_text="ANY", size=(15,1), key="-DST IP-"),
                    sg.Text("Dst Port"), sg.Input(default_text="ANY", size=(5,1), key="-DST PORT-")
                ],
                [sg.Button("Add Rule", key="-ADD-"), sg.Button("Delete Selected", key="-DEL-")]
            ])
        ],
        [sg.Button("Exit")]
    ]

    window = sg.Window("Firewall GUI", layout)

    while True:
        event, values = window.read()
        if event in (sg.WIN_CLOSED, "Exit"):
            break

        if event == "-ADD-":
            # Read inputs
            new_rule = {
                "action": values["-ACTION-"],
                "direction": values["-DIRECTION-"],
                "protocol": values["-PROTOCOL-"],
                "src_ip": values["-SRC IP-"].strip() or "ANY",
                "src_port": values["-SRC PORT-"].strip() or "ANY",
                "dst_ip": values["-DST IP-"].strip() or "ANY",
                "dst_port": values["-DST PORT-"].strip() or "ANY"
            }
            # Append to rules list & save
            rules.append(new_rule)
            save_rules(rules)
            # Update display
            rule_display_list.append(rule_to_display(new_rule))
            window["-RULE LIST-"].update(rule_display_list)

        elif event == "-DEL-":
            selected = values["-RULE LIST-"]
            if selected:
                idx = rule_display_list.index(selected[0])
                # Remove from both lists
                del rules[idx]
                del rule_display_list[idx]
                save_rules(rules)
                window["-RULE LIST-"].update(rule_display_list)

    window.close()

if __name__ == "__main__":
    main()
