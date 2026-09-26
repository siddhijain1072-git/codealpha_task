import tkinter as tk
from tkinter import ttk, messagebox
from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw
import threading
import csv
from datetime import datetime
from collections import deque


class PacketSnifferGUI:

    def __init__(self, root):
        self.root = root
        self.root.title("Network Packet Sniffer & Traffic Analyzer")
        self.root.geometry("1200x750")

        self.running = False
        self.packets = []

        self.total = 0
        self.tcp = 0
        self.udp = 0
        self.icmp = 0
        self.other = 0

        # Traffic graph data
        self.graph_data = deque(maxlen=30)

        # ---------------- TITLE ----------------

        tk.Label(
            root,
            text="NETWORK PACKET SNIFFER & TRAFFIC ANALYZER",
            font=("Arial", 20, "bold")
        ).pack(pady=10)

        # ---------------- BUTTONS ----------------

        button_frame = tk.Frame(root)
        button_frame.pack(pady=5)

        self.start_btn = tk.Button(
            button_frame,
            text="▶ Start Capture",
            width=18,
            command=self.start_capture
        )
        self.start_btn.grid(row=0, column=0, padx=5)

        self.stop_btn = tk.Button(
            button_frame,
            text="■ Stop Capture",
            width=18,
            command=self.stop_capture,
            state=tk.DISABLED
        )
        self.stop_btn.grid(row=0, column=1, padx=5)

        tk.Button(
            button_frame,
            text="Clear Table",
            width=18,
            command=self.clear_table
        ).grid(row=0, column=2, padx=5)

        tk.Button(
            button_frame,
            text="Save CSV",
            width=18,
            command=self.save_csv
        ).grid(row=0, column=3, padx=5)

        # ---------------- STATUS ----------------

        self.status_label = tk.Label(
            root,
            text="Status: Ready",
            font=("Arial", 12)
        )
        self.status_label.pack(pady=5)

        # ---------------- STATISTICS ----------------

        self.stats_label = tk.Label(
            root,
            text="Total: 0    TCP: 0    UDP: 0    ICMP: 0    Other: 0",
            font=("Arial", 12, "bold")
        )
        self.stats_label.pack(pady=5)

        # ---------------- FILTER ----------------

        filter_frame = tk.Frame(root)
        filter_frame.pack(pady=5)

        tk.Label(
            filter_frame,
            text="Search IP:"
        ).grid(row=0, column=0, padx=5)

        self.search_var = tk.StringVar()

        self.search_entry = tk.Entry(
            filter_frame,
            textvariable=self.search_var,
            width=25
        )
        self.search_entry.grid(row=0, column=1, padx=5)

        self.search_var.trace_add(
            "write",
            lambda *args: self.apply_filter()
        )

        tk.Label(
            filter_frame,
            text="Protocol:"
        ).grid(row=0, column=2, padx=5)

        self.protocol_var = tk.StringVar(
            value="All"
        )

        protocol_box = ttk.Combobox(
            filter_frame,
            textvariable=self.protocol_var,
            values=["All", "TCP", "UDP", "ICMP", "Other"],
            state="readonly",
            width=12
        )
        protocol_box.grid(row=0, column=3, padx=5)

        protocol_box.bind(
            "<<ComboboxSelected>>",
            lambda event: self.apply_filter()
        )

        # ---------------- TABLE ----------------

        table_frame = tk.Frame(root)
        table_frame.pack(
            fill=tk.BOTH,
            expand=True,
            padx=10,
            pady=5
        )

        columns = (
            "Time",
            "Source IP",
            "Destination IP",
            "Protocol",
            "Source Port",
            "Destination Port",
            "Payload"
        )

        self.table = ttk.Treeview(
            table_frame,
            columns=columns,
            show="headings"
        )

        for column in columns:
            self.table.heading(
                column,
                text=column
            )

        self.table.column(
            "Time",
            width=150
        )
        self.table.column(
            "Source IP",
            width=130
        )
        self.table.column(
            "Destination IP",
            width=140
        )
        self.table.column(
            "Protocol",
            width=80
        )
        self.table.column(
            "Source Port",
            width=100
        )
        self.table.column(
            "Destination Port",
            width=120
        )
        self.table.column(
            "Payload",
            width=250
        )

        vertical_scroll = ttk.Scrollbar(
            table_frame,
            orient="vertical",
            command=self.table.yview
        )

        self.table.configure(
            yscrollcommand=vertical_scroll.set
        )

        self.table.grid(
            row=0,
            column=0,
            sticky="nsew"
        )

        vertical_scroll.grid(
            row=0,
            column=1,
            sticky="ns"
        )

        table_frame.rowconfigure(
            0,
            weight=1
        )

        table_frame.columnconfigure(
            0,
            weight=1
        )

        # ---------------- GRAPH ----------------

        graph_frame = tk.Frame(root)
        graph_frame.pack(
            fill=tk.X,
            padx=10,
            pady=5
        )

        tk.Label(
            graph_frame,
            text="Live Traffic Activity",
            font=("Arial", 12, "bold")
        ).pack()

        self.canvas = tk.Canvas(
            graph_frame,
            height=120,
            bg="white"
        )
        self.canvas.pack(
            fill=tk.X
        )

        self.update_graph()

    # =================================================
    # START
    # =================================================

    def start_capture(self):

        if self.running:
            return

        self.running = True

        self.start_btn.config(
            state=tk.DISABLED
        )

        self.stop_btn.config(
            state=tk.NORMAL
        )

        self.status_label.config(
            text="Status: Capturing packets..."
        )

        thread = threading.Thread(
            target=self.capture_packets,
            daemon=True
        )

        thread.start()

    # =================================================
    # STOP
    # =================================================

    def stop_capture(self):

        self.running = False

        self.start_btn.config(
            state=tk.NORMAL
        )

        self.stop_btn.config(
            state=tk.DISABLED
        )

        self.status_label.config(
            text="Status: Capture stopped"
        )

        self.save_csv()

    # =================================================
    # CAPTURE
    # =================================================

    def capture_packets(self):

        try:

            sniff(
                prn=self.analyze_packet,
                stop_filter=lambda packet:
                not self.running,
                store=False
            )

        except Exception as error:

            self.root.after(
                0,
                lambda: messagebox.showerror(
                    "Capture Error",
                    str(error)
                )
            )

    # =================================================
    # ANALYZE
    # =================================================

    def analyze_packet(self, packet):

        if not self.running:
            return

        if IP not in packet:
            return

        self.total += 1

        source_ip = packet[IP].src
        destination_ip = packet[IP].dst

        source_port = "-"
        destination_port = "-"
        payload = ""

        if TCP in packet:

            protocol = "TCP"
            self.tcp += 1

            source_port = packet[TCP].sport
            destination_port = packet[TCP].dport

        elif UDP in packet:

            protocol = "UDP"
            self.udp += 1

            source_port = packet[UDP].sport
            destination_port = packet[UDP].dport

        elif ICMP in packet:

            protocol = "ICMP"
            self.icmp += 1

        else:

            protocol = "Other"
            self.other += 1

        if Raw in packet:

            try:

                payload = bytes(
                    packet[Raw].load
                )[:50].decode(
                    "utf-8",
                    errors="replace"
                )

            except Exception:

                payload = "<binary data>"

        time = datetime.now().strftime(
            "%H:%M:%S"
        )

        data = (
            time,
            source_ip,
            destination_ip,
            protocol,
            source_port,
            destination_port,
            payload
        )

        self.packets.append(data)

        self.root.after(
            0,
            lambda d=data: self.add_packet(d)
        )

    # =================================================
    # ADD PACKET
    # =================================================

    def add_packet(self, data):

        self.graph_data.append(
            self.total
        )

        self.apply_filter()

        self.update_statistics()

    # =================================================
    # FILTER
    # =================================================

    def apply_filter(self):

        search_text = (
            self.search_var.get()
            .strip()
            .lower()
        )

        selected_protocol = (
            self.protocol_var.get()
        )

        # Clear current table

        for item in self.table.get_children():
            self.table.delete(item)

        # Add matching packets

        for packet in self.packets:

            source = str(
                packet[1]
            ).lower()

            destination = str(
                packet[2]
            ).lower()

            protocol = packet[3]

            ip_match = (
                search_text == ""
                or search_text in source
                or search_text in destination
            )

            protocol_match = (
                selected_protocol == "All"
                or protocol == selected_protocol
            )

            if ip_match and protocol_match:

                self.table.insert(
                    "",
                    tk.END,
                    values=packet
                )

    # =================================================
    # STATISTICS
    # =================================================

    def update_statistics(self):

        self.stats_label.config(
            text=
            f"Total: {self.total}    "
            f"TCP: {self.tcp}    "
            f"UDP: {self.udp}    "
            f"ICMP: {self.icmp}    "
            f"Other: {self.other}"
        )

    # =================================================
    # CLEAR
    # =================================================

    def clear_table(self):

        for item in self.table.get_children():
            self.table.delete(item)

        self.packets.clear()

        self.total = 0
        self.tcp = 0
        self.udp = 0
        self.icmp = 0
        self.other = 0

        self.graph_data.clear()

        self.update_statistics()

        self.status_label.config(
            text="Status: Table cleared"
        )

    # =================================================
    # CSV
    # =================================================

    def save_csv(self):

        if not self.packets:
            return

        filename = "captured_packets.csv"

        try:

            with open(
                filename,
                "w",
                newline="",
                encoding="utf-8"
            ) as file:

                writer = csv.writer(file)

                writer.writerow([
                    "Time",
                    "Source IP",
                    "Destination IP",
                    "Protocol",
                    "Source Port",
                    "Destination Port",
                    "Payload"
                ])

                writer.writerows(
                    self.packets
                )

        except Exception as error:

            messagebox.showerror(
                "CSV Error",
                str(error)
            )

    # =================================================
    # GRAPH
    # =================================================

    def update_graph(self):

        self.canvas.delete("all")

        width = self.canvas.winfo_width()
        height = self.canvas.winfo_height()

        if width < 10:
            width = 1000

        if height < 10:
            height = 120

        data = list(
            self.graph_data
        )

        if len(data) > 1:

            maximum = max(data)

            if maximum == 0:
                maximum = 1

            points = []

            for i, value in enumerate(data):

                x = (
                    i
                    * width
                    / (len(data) - 1)
                )

                y = (
                    height
                    - (value / maximum)
                    * (height - 20)
                    - 10
                )

                points.append(
                    (x, y)
                )

            for i in range(
                len(points) - 1
            ):

                self.canvas.create_line(
                    points[i][0],
                    points[i][1],
                    points[i + 1][0],
                    points[i + 1][1],
                    width=2
                )

        self.root.after(
            1000,
            self.update_graph
        )


# =====================================================
# MAIN
# =====================================================

root = tk.Tk()

app = PacketSnifferGUI(root)

root.mainloop()