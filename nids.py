import tkinter as tk
from tkinter import ttk, messagebox
from scapy.all import sniff, IP, TCP, UDP, ICMP
import threading
import csv
import time
from datetime import datetime
from collections import defaultdict, deque

# ============================================================
# SETTINGS
# ============================================================

CSV_FILE = "nids_alerts.csv"

# Ports commonly worth monitoring in a lab NIDS
SUSPICIOUS_PORTS = {
    21: "FTP",
    23: "Telnet",
    445: "SMB",
    3389: "RDP",
    4444: "Test Port"
}

# Detection thresholds
PORT_SCAN_THRESHOLD = 8
ICMP_THRESHOLD = 20
PACKET_RATE_THRESHOLD = 50

monitoring = False

# Counters
total_packets = 0
tcp_packets = 0
udp_packets = 0
icmp_packets = 0
other_packets = 0
total_alerts = 0

# Detection data
source_ports = defaultdict(set)
icmp_count = defaultdict(int)
packet_times = deque()

# Avoid repeating the same alert continuously
recent_alerts = {}

# Graph data
graph_data = deque(maxlen=50)


# ============================================================
# CSV FILE
# ============================================================

try:
    with open(CSV_FILE, "x", newline="") as file:
        writer = csv.writer(file)

        writer.writerow([
            "Time",
            "Source IP",
            "Destination IP",
            "Protocol",
            "Source Port",
            "Destination Port",
            "Severity",
            "Alert"
        ])

except FileExistsError:
    pass


# ============================================================
# ALERT CREATOR
# ============================================================

def create_alert(
    src,
    dst,
    protocol,
    sport,
    dport,
    severity,
    message
):

    global total_alerts

    # Prevent duplicate alerts every packet
    alert_key = f"{src}-{message}"

    current_timestamp = time.time()

    if alert_key in recent_alerts:

        if current_timestamp - recent_alerts[alert_key] < 5:
            return

    recent_alerts[alert_key] = current_timestamp

    total_alerts += 1

    current_time = datetime.now().strftime("%H:%M:%S")

    alert_tree.insert(
        "",
        "end",
        values=(
            current_time,
            src,
            dst,
            protocol,
            sport,
            dport,
            severity,
            message
        )
    )

    # Save to CSV
    with open(CSV_FILE, "a", newline="") as file:

        writer = csv.writer(file)

        writer.writerow([
            current_time,
            src,
            dst,
            protocol,
            sport,
            dport,
            severity,
            message
        ])

    # Keep only recent 200 alerts in GUI
    rows = alert_tree.get_children()

    if len(rows) > 200:
        alert_tree.delete(rows[0])

    update_dashboard()


# ============================================================
# SUSPICIOUS PORT DETECTION
# ============================================================

def check_suspicious_port(
    src,
    dst,
    protocol,
    sport,
    dport
):

    if dport in SUSPICIOUS_PORTS:

        service = SUSPICIOUS_PORTS[dport]

        create_alert(
            src,
            dst,
            protocol,
            sport,
            dport,
            "MEDIUM",
            f"Suspicious {service} port detected"
        )


# ============================================================
# PORT SCAN DETECTION
# ============================================================

def check_port_scan(src, dport):

    source_ports[src].add(dport)

    if len(source_ports[src]) >= PORT_SCAN_THRESHOLD:

        create_alert(
            src,
            "Multiple",
            "TCP/UDP",
            "-",
            "-",
            "HIGH",
            "Possible Port Scan Detected"
        )

        # Reset after alert
        source_ports[src].clear()


# ============================================================
# ICMP DETECTION
# ============================================================

def check_icmp_activity(src, dst):

    icmp_count[src] += 1

    if icmp_count[src] >= ICMP_THRESHOLD:

        create_alert(
            src,
            dst,
            "ICMP",
            "-",
            "-",
            "HIGH",
            "High ICMP Traffic Detected"
        )

        icmp_count[src] = 0


# ============================================================
# PACKET RATE DETECTION
# ============================================================

def check_packet_rate():

    current_time = time.time()

    packet_times.append(current_time)

    # Keep only packets from last second
    while packet_times:

        if current_time - packet_times[0] <= 1:
            break

        packet_times.popleft()

    if len(packet_times) >= PACKET_RATE_THRESHOLD:

        create_alert(
            "Multiple Sources",
            "Local Network",
            "ALL",
            "-",
            "-",
            "HIGH",
            "Abnormally High Packet Rate"
        )

        packet_times.clear()


# ============================================================
# PACKET PROCESSOR
# ============================================================

def process_packet(packet):

    global total_packets
    global tcp_packets
    global udp_packets
    global icmp_packets
    global other_packets

    if not packet.haslayer(IP):
        return

    total_packets += 1

    src = packet[IP].src
    dst = packet[IP].dst

    protocol = "Other"

    sport = "-"
    dport = "-"

    # -------------------------
    # TCP
    # -------------------------

    if packet.haslayer(TCP):

        protocol = "TCP"

        tcp_packets += 1

        sport = packet[TCP].sport
        dport = packet[TCP].dport

        check_suspicious_port(
            src,
            dst,
            protocol,
            sport,
            dport
        )

        check_port_scan(
            src,
            dport
        )

    # -------------------------
    # UDP
    # -------------------------

    elif packet.haslayer(UDP):

        protocol = "UDP"

        udp_packets += 1

        sport = packet[UDP].sport
        dport = packet[UDP].dport

        check_suspicious_port(
            src,
            dst,
            protocol,
            sport,
            dport
        )

        check_port_scan(
            src,
            dport
        )

    # -------------------------
    # ICMP
    # -------------------------

    elif packet.haslayer(ICMP):

        protocol = "ICMP"

        icmp_packets += 1

        check_icmp_activity(
            src,
            dst
        )

    # -------------------------
    # OTHER
    # -------------------------

    else:

        other_packets += 1

    # Packet rate
    check_packet_rate()

    # Add packet to GUI
    current_time = datetime.now().strftime("%H:%M:%S")

    root.after(
        0,
        lambda: add_packet_row(
            current_time,
            src,
            dst,
            protocol,
            sport,
            dport
        )
    )

    root.after(
        0,
        update_dashboard
    )


# ============================================================
# ADD PACKET ROW
# ============================================================

def add_packet_row(
    current_time,
    src,
    dst,
    protocol,
    sport,
    dport
):

    packet_tree.insert(
        "",
        "end",
        values=(
            current_time,
            src,
            dst,
            protocol,
            sport,
            dport
        )
    )

    rows = packet_tree.get_children()

    if len(rows) > 300:
        packet_tree.delete(rows[0])


# ============================================================
# START MONITORING
# ============================================================

def start_monitoring():

    global monitoring

    if monitoring:
        return

    monitoring = True

    status_label.config(
        text="● MONITORING"
    )

    start_button.config(
        state="disabled"
    )

    stop_button.config(
        state="normal"
    )

    threading.Thread(
        target=capture_packets,
        daemon=True
    ).start()


# ============================================================
# PACKET CAPTURE
# ============================================================

def capture_packets():

    try:

        sniff(
            prn=process_packet,
            store=False,
            stop_filter=lambda packet: not monitoring
        )

    except Exception as error:

        root.after(
            0,
            lambda: messagebox.showerror(
                "Capture Error",
                str(error)
            )
        )

        root.after(
            0,
            stop_monitoring
        )


# ============================================================
# STOP
# ============================================================

def stop_monitoring():

    global monitoring

    monitoring = False

    status_label.config(
        text="● STOPPED"
    )

    start_button.config(
        state="normal"
    )

    stop_button.config(
        state="disabled"
    )


# ============================================================
# CLEAR
# ============================================================

def clear_all():

    for item in packet_tree.get_children():
        packet_tree.delete(item)

    for item in alert_tree.get_children():
        alert_tree.delete(item)


# ============================================================
# SEARCH / FILTER
# ============================================================

def search_alerts():

    keyword = search_entry.get().lower().strip()

    for item in alert_tree.get_children():

        values = alert_tree.item(item, "values")

        text = " ".join(
            str(value).lower()
            for value in values
        )

        if keyword == "" or keyword in text:

            alert_tree.reattach(
                item,
                "",
                "end"
            )

        else:

            alert_tree.detach(item)


def reset_search():

    search_entry.delete(
        0,
        tk.END
    )

    for item in alert_tree.get_children():

        alert_tree.reattach(
            item,
            "",
            "end"
        )


# ============================================================
# DASHBOARD
# ============================================================

def update_dashboard():

    total_label.config(
        text=f"Packets\n{total_packets}"
    )

    tcp_label.config(
        text=f"TCP\n{tcp_packets}"
    )

    udp_label.config(
        text=f"UDP\n{udp_packets}"
    )

    icmp_label.config(
        text=f"ICMP\n{icmp_packets}"
    )

    alert_label.config(
        text=f"Alerts\n{total_alerts}"
    )


# ============================================================
# GUI
# ============================================================

root = tk.Tk()

root.title(
    "Advanced Network Intrusion Detection System"
)

root.geometry(
    "1250x800"
)

root.minsize(
    1000,
    650
)


# ============================================================
# TITLE
# ============================================================

title = tk.Label(
    root,
    text="NETWORK INTRUSION DETECTION SYSTEM",
    font=("Arial", 21, "bold")
)

title.pack(pady=10)


subtitle = tk.Label(
    root,
    text="Real-Time Network Monitoring and Threat Detection",
    font=("Arial", 10)
)

subtitle.pack()


# ============================================================
# CONTROL BAR
# ============================================================

control_frame = tk.Frame(root)

control_frame.pack(
    pady=12
)


start_button = tk.Button(
    control_frame,
    text="START MONITORING",
    width=20,
    command=start_monitoring,
    font=("Arial", 10, "bold")
)

start_button.grid(
    row=0,
    column=0,
    padx=5
)


stop_button = tk.Button(
    control_frame,
    text="STOP",
    width=12,
    command=stop_monitoring,
    state="disabled",
    font=("Arial", 10, "bold")
)

stop_button.grid(
    row=0,
    column=1,
    padx=5
)


clear_button = tk.Button(
    control_frame,
    text="CLEAR",
    width=12,
    command=clear_all,
    font=("Arial", 10, "bold")
)

clear_button.grid(
    row=0,
    column=2,
    padx=5
)


status_label = tk.Label(
    control_frame,
    text="● STOPPED",
    font=("Arial", 10, "bold")
)

status_label.grid(
    row=0,
    column=3,
    padx=20
)


# ============================================================
# DASHBOARD CARDS
# ============================================================

dashboard = tk.Frame(root)

dashboard.pack(
    fill="x",
    padx=20,
    pady=5
)


total_label = tk.Label(
    dashboard,
    text="Packets\n0",
    width=15,
    height=3,
    relief="ridge",
    font=("Arial", 11, "bold")
)

total_label.pack(
    side="left",
    padx=5,
    expand=True,
    fill="x"
)


tcp_label = tk.Label(
    dashboard,
    text="TCP\n0",
    width=15,
    height=3,
    relief="ridge",
    font=("Arial", 11, "bold")
)

tcp_label.pack(
    side="left",
    padx=5,
    expand=True,
    fill="x"
)


udp_label = tk.Label(
    dashboard,
    text="UDP\n0",
    width=15,
    height=3,
    relief="ridge",
    font=("Arial", 11, "bold")
)

udp_label.pack(
    side="left",
    padx=5,
    expand=True,
    fill="x"
)


icmp_label = tk.Label(
    dashboard,
    text="ICMP\n0",
    width=15,
    height=3,
    relief="ridge",
    font=("Arial", 11, "bold")
)

icmp_label.pack(
    side="left",
    padx=5,
    expand=True,
    fill="x"
)


alert_label = tk.Label(
    dashboard,
    text="Alerts\n0",
    width=15,
    height=3,
    relief="ridge",
    font=("Arial", 11, "bold")
)

alert_label.pack(
    side="left",
    padx=5,
    expand=True,
    fill="x"
)


# ============================================================
# LIVE TRAFFIC
# ============================================================

traffic_title = tk.Label(
    root,
    text="LIVE NETWORK TRAFFIC",
    font=("Arial", 13, "bold")
)

traffic_title.pack(
    pady=(12, 5)
)


packet_frame = tk.Frame(root)

packet_frame.pack(
    fill="both",
    expand=True,
    padx=20
)


packet_columns = (
    "Time",
    "Source IP",
    "Destination IP",
    "Protocol",
    "Source Port",
    "Destination Port"
)


packet_tree = ttk.Treeview(
    packet_frame,
    columns=packet_columns,
    show="headings",
    height=9
)


for column in packet_columns:

    packet_tree.heading(
        column,
        text=column
    )

    packet_tree.column(
        column,
        width=150,
        anchor="center"
    )


packet_scroll = ttk.Scrollbar(
    packet_frame,
    orient="vertical",
    command=packet_tree.yview
)

packet_tree.configure(
    yscrollcommand=packet_scroll.set
)

packet_tree.pack(
    side="left",
    fill="both",
    expand=True
)

packet_scroll.pack(
    side="right",
    fill="y"
)


# ============================================================
# SEARCH
# ============================================================

search_frame = tk.Frame(root)

search_frame.pack(
    fill="x",
    padx=20,
    pady=8
)


tk.Label(
    search_frame,
    text="Search Alerts:"
).pack(
    side="left"
)


search_entry = tk.Entry(
    search_frame,
    width=35
)

search_entry.pack(
    side="left",
    padx=5
)


tk.Button(
    search_frame,
    text="Search",
    command=search_alerts
).pack(
    side="left",
    padx=3
)


tk.Button(
    search_frame,
    text="Reset",
    command=reset_search
).pack(
    side="left",
    padx=3
)


# ============================================================
# SECURITY ALERTS
# ============================================================

alert_title = tk.Label(
    root,
    text="SECURITY ALERTS",
    font=("Arial", 13, "bold")
)

alert_title.pack(
    pady=5
)


alert_frame = tk.Frame(root)

alert_frame.pack(
    fill="both",
    expand=True,
    padx=20,
    pady=(0, 15)
)


alert_columns = (
    "Time",
    "Source IP",
    "Destination IP",
    "Protocol",
    "Source Port",
    "Destination Port",
    "Severity",
    "Alert"
)


alert_tree = ttk.Treeview(
    alert_frame,
    columns=alert_columns,
    show="headings",
    height=7
)


for column in alert_columns:

    alert_tree.heading(
        column,
        text=column
    )

    alert_tree.column(
        column,
        width=135,
        anchor="center"
    )


alert_scroll = ttk.Scrollbar(
    alert_frame,
    orient="vertical",
    command=alert_tree.yview
)

alert_tree.configure(
    yscrollcommand=alert_scroll.set
)

alert_tree.pack(
    side="left",
    fill="both",
    expand=True
)

alert_scroll.pack(
    side="right",
    fill="y"
)


# ============================================================
# CLOSE
# ============================================================

def close_program():

    global monitoring

    monitoring = False

    root.destroy()


root.protocol(
    "WM_DELETE_WINDOW",
    close_program
)


# ============================================================
# START
# ============================================================

root.mainloop()