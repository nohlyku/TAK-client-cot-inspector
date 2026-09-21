#!/usr/bin/env python3
"""TAK CoT Inspector — dark-themed GUI."""

import hashlib
import ipaddress
import os
import re
import socket
import ssl
import struct
import tempfile
import threading
import time
import tkinter as tk
import xml.dom.minidom as minidom
import xml.etree.ElementTree as ET
from datetime import datetime
from tkinter import filedialog, messagebox

import customtkinter as ctk
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import (
    Encoding, NoEncryption, PrivateFormat, pkcs12,
)

# ---- Theme (dark only) -----------------------------------------------------

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("dark-blue")

BG          = "#1b1f24"
PANEL       = "#22272e"
PANEL_ALT   = "#1a1d22"
BORDER      = "#30363d"
TEXT        = "#e6edf3"
TEXT_DIM    = "#8b949e"
ACCENT      = "#1f6feb"
ACCENT_HOV  = "#388bfd"
OK          = "#3fb950"
ERR         = "#f85149"
ENTRY_BG    = "#0d1117"
ENTRY_CONN  = "#1a3a52"  # subtle blue tint when connected

# XML syntax colors (VS Code-ish dark)
XML_TAG     = "#569cd6"
XML_ATTR    = "#9cdcfe"
XML_VALUE   = "#ce9178"
XML_TEXT    = "#d4d4d4"

MONO = ("Consolas", 10)
UI   = ("Segoe UI", 11)
UI_B = ("Segoe UI", 11, "bold")

# Defaults / limits
DEFAULT_TCP_PORT       = "8089"
DEFAULT_MULTICAST_GROUP = "239.2.3.1"
DEFAULT_MULTICAST_PORT  = "6969"   # TAK SA default
MAX_MESSAGES            = 5000     # cap retained history to bound memory/UI
DEDUP_WINDOW_SEC        = 2.0      # drop byte-identical datagrams within this window


# ---- Helpers ---------------------------------------------------------------

def split_cot_stream(buffer: str):
    """Pull complete <event>...</event> documents out of a streaming text buffer.

    Returns (messages, remaining_buffer). Anything before the first <event is
    discarded (stray XML declarations, whitespace, etc.).
    """
    messages = []
    while True:
        start = buffer.find('<event')
        if start == -1:
            buffer = buffer[-8:] if buffer else ''
            break
        end = buffer.find('</event>', start)
        if end == -1:
            buffer = buffer[start:]
            break
        end += len('</event>')
        messages.append(buffer[start:end])
        buffer = buffer[end:]
    return messages, buffer


def write_secure_temp(data: bytes, suffix: str = '') -> str:
    """Write bytes to a fresh temp file with 0600 perms. Returns the path."""
    fd, path = tempfile.mkstemp(suffix=suffix)
    try:
        os.write(fd, data)
    finally:
        os.close(fd)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return path


def _primary_route_ipv4() -> str | None:
    """Best-effort discovery of the IPv4 the OS would use for outbound traffic.

    Uses a connected UDP socket (no packets are actually sent) so it works even
    when gethostname() resolution is incomplete (common on Windows with VPN or
    multiple NICs).
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        return ip if isinstance(ip, str) and not ip.startswith("127.") else None
    except OSError:
        return None
    finally:
        s.close()


def _local_ipv4_addresses() -> list[str]:
    """Return all non-loopback IPv4 addresses for this machine."""
    addrs = set()
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            sockaddr = info[4]
            if not isinstance(sockaddr, tuple) or not sockaddr:
                continue
            ip = sockaddr[0]
            if isinstance(ip, str) and not ip.startswith("127."):
                addrs.add(ip)
    except socket.gaierror:
        pass
    # gethostname() frequently misses VPN/virtual/secondary NICs; add the
    # primary outbound route address as another candidate interface.
    route_ip = _primary_route_ipv4()
    if route_ip:
        addrs.add(route_ip)
    return sorted(addrs)


def _is_multicast_group(addr: str) -> bool:
    """True if addr is a valid IPv4 multicast address (224.0.0.0/4)."""
    try:
        return ipaddress.IPv4Address(addr).is_multicast
    except (ipaddress.AddressValueError, ValueError):
        return False


def _explain_socket_error(err: OSError, port: int) -> str:
    """Turn a winsock/posix bind error into something a human can act on."""
    code = getattr(err, "winerror", None) or err.errno
    if code in (10013, 13):  # WSAEACCES / EACCES
        return (
            f"Access denied binding UDP port {port} (WinError 10013).\n\n"
            "On Windows this usually means the port is in a reserved range "
            "(Hyper-V / WSL / IIS) or already in use.\n\n"
            "Try:\n"
            "  • Pick a different port (e.g. 8087, 8090, 17012).\n"
            "  • Check reserved ranges:\n"
            "      netsh int ipv4 show excludedportrange protocol=udp\n"
            "  • Make sure no other app is already listening on that port."
        )
    if code in (10048, 98):  # WSAEADDRINUSE / EADDRINUSE
        return f"Port {port} is already in use by another process."
    if code in (10049, 99):  # WSAEADDRNOTAVAIL
        return "That multicast group/address isn't valid on this machine."
    return f"{err} (code {code})"


def load_p12(p12_file: str, password):
    """Load cert + private key from a .p12 file as PEM bytes."""
    with open(p12_file, 'rb') as f:
        p12_data = f.read()
    private_key, certificate, _ = pkcs12.load_key_and_certificates(
        p12_data,
        password.encode() if password else None,
        backend=default_backend(),
    )
    cert_pem = certificate.public_bytes(Encoding.PEM)
    key_pem = private_key.private_bytes(
        encoding=Encoding.PEM,
        format=PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=NoEncryption(),
    )
    return cert_pem, key_pem


# ---- App -------------------------------------------------------------------

class TakInspectorApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("TAK CoT Inspector")
        self.geometry("1280x820")
        self.minsize(1000, 620)
        self.configure(fg_color=BG)

        # State
        self.connected = False
        self.sock: socket.socket | None = None
        self.transport: str | None = None  # "TLS" / "plain TCP" / "Multicast"
        self.multicast_group: str | None = None
        self.datagram_count = 0
        self.stop_receiving = False
        self.receive_thread: threading.Thread | None = None
        self._recent_digests: dict[bytes, float] = {}  # datagram dedup cache

        self.all_messages: list[dict] = []
        self.displayed_messages: list[dict] = []
        self.filtered_callsigns: set[str] = set()
        self.partial_match = False

        self._build_ui()

    # ---- UI construction ------------------------------------------------

    def _build_ui(self):
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(2, weight=1)

        self._build_connection_card()
        self._build_filter_card()
        self._build_messages_card()
        self._build_status_bar()

    def _card(self, parent, **grid):
        frame = ctk.CTkFrame(
            parent,
            fg_color=PANEL,
            border_color=BORDER,
            border_width=1,
            corner_radius=10,
        )
        frame.grid(**grid)
        return frame

    def _label(self, parent, text, **kwargs):
        return ctk.CTkLabel(parent, text=text, text_color=TEXT_DIM, font=UI, **kwargs)

    def _entry(self, parent, width=180, show=None):
        return ctk.CTkEntry(
            parent,
            width=width,
            height=32,
            fg_color=ENTRY_BG,
            border_color=BORDER,
            text_color=TEXT,
            font=UI,
            show=show or "",
            corner_radius=6,
        )

    def _button(self, parent, text, command, primary=False, danger=False):
        if primary:
            fg, hov = ACCENT, ACCENT_HOV
        elif danger:
            fg, hov = "#3a1e1e", "#5a2a2a"
        else:
            fg, hov = "#2d333b", "#3a414b"
        return ctk.CTkButton(
            parent,
            text=text,
            command=command,
            fg_color=fg,
            hover_color=hov,
            text_color=TEXT,
            font=UI_B,
            height=32,
            corner_radius=6,
        )

    def _build_connection_card(self):
        card = self._card(self, row=0, column=0, sticky="ew", padx=14, pady=(14, 7))
        card.grid_columnconfigure(0, weight=1)

        header_row = ctk.CTkFrame(card, fg_color="transparent")
        header_row.grid(row=0, column=0, sticky="ew", padx=14, pady=(10, 4))
        header_row.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(header_row, text="Connection", text_color=TEXT,
                     font=UI_B).grid(row=0, column=0, sticky="w")

        self.mode_var = tk.StringVar(value="TCP")
        self.mode_seg = ctk.CTkSegmentedButton(
            header_row,
            values=["TCP", "Multicast (UDP)"],
            variable=self.mode_var,
            command=lambda _v: self._on_mode_change(),
            fg_color=PANEL_ALT,
            selected_color=ACCENT,
            selected_hover_color=ACCENT_HOV,
            unselected_color=PANEL_ALT,
            unselected_hover_color="#2d333b",
            text_color=TEXT,
            font=UI,
        )
        self.mode_seg.grid(row=0, column=1, sticky="e")

        body = ctk.CTkFrame(card, fg_color="transparent")
        body.grid(row=1, column=0, sticky="ew", padx=12, pady=(0, 12))
        for c in range(8):
            body.grid_columnconfigure(c, weight=0)
        body.grid_columnconfigure(2, weight=1)
        body.grid_columnconfigure(6, weight=1)

        # Row 1: server / port / TLS / password
        self.server_label = self._label(body, "Server")
        self.server_label.grid(row=0, column=0, sticky="w", padx=(4, 6), pady=4)
        self.host_entry = self._entry(body, width=220)
        self.host_entry.insert(0, "localhost")
        self.host_entry.grid(row=0, column=1, sticky="w", pady=4)

        self._label(body, "Port").grid(row=0, column=2, sticky="e", padx=(12, 6), pady=4)
        self.port_entry = self._entry(body, width=90)
        self.port_entry.insert(0, DEFAULT_TCP_PORT)
        self.port_entry.grid(row=0, column=3, sticky="w", pady=4)

        self.use_tls_var = tk.BooleanVar(value=True)
        self.tls_check = ctk.CTkCheckBox(
            body, text="Use TLS", variable=self.use_tls_var,
            command=self._on_tls_toggle,
            fg_color=ACCENT, hover_color=ACCENT_HOV, border_color=BORDER,
            text_color=TEXT, font=UI,
        )
        self.tls_check.grid(row=0, column=4, sticky="e", padx=(12, 6), pady=4)

        self._label(body, "Password").grid(row=0, column=5, sticky="e", padx=(12, 6), pady=4)
        self.password_entry = self._entry(body, width=180, show="•")
        self.password_entry.grid(row=0, column=6, sticky="w", pady=4)

        # Row 2: P12 file + buttons
        self._label(body, "P12 File").grid(row=1, column=0, sticky="w", padx=(4, 6), pady=4)
        self.p12_entry = self._entry(body, width=520)
        self.p12_entry.grid(row=1, column=1, columnspan=4, sticky="ew", pady=4)

        self.browse_btn = self._button(body, "Browse…", self.browse_p12)
        self.browse_btn.grid(row=1, column=5, sticky="w", padx=(8, 0), pady=4)

        self.connect_btn = self._button(body, "Connect", self.toggle_connection, primary=True)
        self.connect_btn.configure(width=120)
        self.connect_btn.grid(row=1, column=6, sticky="e", padx=(12, 4), pady=4)

        self.status_label = ctk.CTkLabel(
            body, text="● Disconnected", text_color=ERR, font=UI_B,
        )
        self.status_label.grid(row=1, column=7, sticky="e", padx=(8, 4), pady=4)

    def _build_filter_card(self):
        card = self._card(self, row=1, column=0, sticky="ew", padx=14, pady=7)
        card.grid_columnconfigure(0, weight=1)

        header = ctk.CTkLabel(card, text="Filter", text_color=TEXT, font=UI_B)
        header.grid(row=0, column=0, sticky="w", padx=14, pady=(10, 4))

        body = ctk.CTkFrame(card, fg_color="transparent")
        body.grid(row=1, column=0, sticky="ew", padx=12, pady=(0, 12))
        body.grid_columnconfigure(1, weight=1)

        self._label(body, "Callsigns (comma-separated, empty = all)").grid(
            row=0, column=0, sticky="w", padx=(4, 6), pady=4)

        self.filter_entry = self._entry(body, width=400)
        self.filter_entry.grid(row=0, column=1, sticky="ew", pady=4)
        self.filter_entry.bind("<Return>", lambda _e: self.apply_filter())

        self.partial_var = tk.BooleanVar(value=False)
        self.partial_check = ctk.CTkCheckBox(
            body, text="Partial match", variable=self.partial_var,
            command=self.on_partial_toggle,
            fg_color=ACCENT, hover_color=ACCENT_HOV, border_color=BORDER,
            text_color=TEXT, font=UI,
        )
        self.partial_check.grid(row=0, column=2, padx=(12, 6), pady=4)

        self._button(body, "Apply", self.apply_filter, primary=True).grid(
            row=0, column=3, padx=(8, 4), pady=4)
        self._button(body, "Clear", self.clear_filter).grid(
            row=0, column=4, padx=(0, 4), pady=4)

    def _build_messages_card(self):
        card = self._card(self, row=2, column=0, sticky="nsew", padx=14, pady=7)
        card.grid_columnconfigure(0, weight=1, minsize=380)
        card.grid_columnconfigure(1, weight=2)
        card.grid_rowconfigure(1, weight=1)

        header = ctk.CTkLabel(card, text="CoT Messages", text_color=TEXT, font=UI_B)
        header.grid(row=0, column=0, columnspan=2, sticky="w", padx=14, pady=(10, 6))

        # Left: message list (use classic Listbox for performance, styled dark)
        left = ctk.CTkFrame(card, fg_color=PANEL_ALT, border_color=BORDER,
                            border_width=1, corner_radius=8)
        left.grid(row=1, column=0, sticky="nsew", padx=(12, 6), pady=(0, 12))
        left.grid_rowconfigure(0, weight=1)
        left.grid_columnconfigure(0, weight=1)

        self.message_list = tk.Listbox(
            left,
            bg=PANEL_ALT, fg=TEXT,
            selectbackground=ACCENT, selectforeground="#ffffff",
            highlightthickness=0, borderwidth=0,
            activestyle="none",
            font=MONO,
        )
        self.message_list.grid(row=0, column=0, sticky="nsew", padx=8, pady=8)
        self.message_list.bind("<<ListboxSelect>>", self.on_message_select)

        list_scroll = ctk.CTkScrollbar(left, command=self.message_list.yview,
                                       button_color=BORDER, button_hover_color=ACCENT)
        list_scroll.grid(row=0, column=1, sticky="ns", padx=(0, 6), pady=8)
        self.message_list.config(yscrollcommand=list_scroll.set)

        # Right: details
        right = ctk.CTkFrame(card, fg_color=PANEL_ALT, border_color=BORDER,
                             border_width=1, corner_radius=8)
        right.grid(row=1, column=1, sticky="nsew", padx=(6, 12), pady=(0, 12))
        right.grid_rowconfigure(1, weight=1)
        right.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(right, text="Message Details", text_color=TEXT_DIM,
                     font=UI).grid(row=0, column=0, sticky="w", padx=10, pady=(8, 0))

        self.details_text = tk.Text(
            right,
            bg=PANEL_ALT, fg=TEXT,
            insertbackground=TEXT,
            highlightthickness=0, borderwidth=0,
            font=MONO, wrap="word",
        )
        self.details_text.grid(row=1, column=0, sticky="nsew", padx=8, pady=8)
        self._configure_xml_tags()

        details_scroll = ctk.CTkScrollbar(right, command=self.details_text.yview,
                                          button_color=BORDER, button_hover_color=ACCENT)
        details_scroll.grid(row=1, column=1, sticky="ns", padx=(0, 6), pady=8)
        self.details_text.config(yscrollcommand=details_scroll.set)

        # Bottom action bar
        actions = ctk.CTkFrame(card, fg_color="transparent")
        actions.grid(row=2, column=0, columnspan=2, sticky="ew", padx=12, pady=(0, 12))
        actions.grid_columnconfigure(2, weight=1)

        self._button(actions, "Clear Messages", self.clear_messages, danger=True).grid(
            row=0, column=0, padx=(0, 8))
        self._button(actions, "Export…", self.export_messages).grid(row=0, column=1)

        self.msg_count_label = ctk.CTkLabel(
            actions, text="Messages: 0 / 0", text_color=TEXT_DIM, font=UI)
        self.msg_count_label.grid(row=0, column=2, sticky="e", padx=(8, 4))

    def _build_status_bar(self):
        bar = ctk.CTkFrame(self, fg_color=PANEL_ALT, height=24, corner_radius=0)
        bar.grid(row=3, column=0, sticky="ew")
        bar.grid_columnconfigure(0, weight=1)
        self.footer_label = ctk.CTkLabel(
            bar, text="Ready.", text_color=TEXT_DIM, font=("Segoe UI", 10))
        self.footer_label.grid(row=0, column=0, sticky="w", padx=12, pady=2)

    def _configure_xml_tags(self):
        self.details_text.tag_configure('xml_tag',   foreground=XML_TAG)
        self.details_text.tag_configure('xml_attr',  foreground=XML_ATTR)
        self.details_text.tag_configure('xml_value', foreground=XML_VALUE)
        self.details_text.tag_configure('xml_text',  foreground=XML_TEXT)
        self.details_text.tag_configure('hdr_key',   foreground=TEXT_DIM)
        self.details_text.tag_configure('hdr_val',   foreground=TEXT)
        self.details_text.tag_configure('rule',      foreground=BORDER)

    # ---- Connection lifecycle ------------------------------------------

    def browse_p12(self):
        filename = filedialog.askopenfilename(
            title="Select P12 Certificate File",
            filetypes=[("P12 Files", "*.p12"), ("All Files", "*.*")],
        )
        if filename:
            self.p12_entry.delete(0, tk.END)
            self.p12_entry.insert(0, filename)

    def toggle_connection(self):
        if not self.connected:
            self.connect()
        else:
            self.disconnect()

    def connect(self):
        mode = self.mode_var.get()
        host = self.host_entry.get().strip()
        port_str = self.port_entry.get().strip()

        if not host or not port_str:
            messagebox.showerror("Error", "Please enter address and port.")
            return
        try:
            port = int(port_str)
        except ValueError:
            messagebox.showerror("Error", "Invalid port number.")
            return

        if mode == "Multicast (UDP)":
            self._connect_multicast(host, port)
            return

        # TCP path (optionally TLS)
        use_tls = self.use_tls_var.get()
        p12_file = self.p12_entry.get().strip()
        password = self.password_entry.get()
        if use_tls and (not p12_file or not os.path.exists(p12_file)):
            messagebox.showerror("Error", "Please select a valid P12 file (or disable TLS).")
            return

        scheme = "TLS" if use_tls else "plain TCP"
        self.footer_label.configure(text=f"Connecting to {host}:{port} ({scheme})…")
        self.connect_btn.configure(state="disabled")

        def worker():
            try:
                raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                raw_sock.settimeout(30)

                if use_tls:
                    context = ssl.create_default_context(purpose=ssl.Purpose.SERVER_AUTH)
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE

                    cert_pem, key_pem = load_p12(p12_file, password)
                    temp_cert = write_secure_temp(cert_pem, '.pem')
                    temp_key = write_secure_temp(key_pem, '.pem')
                    try:
                        context.load_cert_chain(certfile=temp_cert, keyfile=temp_key)
                    finally:
                        for p in (temp_cert, temp_key):
                            try:
                                os.unlink(p)
                            except OSError:
                                pass

                    self.after(0, lambda: self.password_entry.delete(0, tk.END))

                    self.sock = context.wrap_socket(raw_sock, server_hostname=host)
                else:
                    self.sock = raw_sock

                self.sock.connect((host, port))
                self.transport = scheme
                self.after(0, lambda: self.on_connected(host, port, scheme))
                self.stop_receiving = False
                self.receive_messages()
            except Exception as e:
                err = str(e)
                self.after(0, lambda: self._connection_failed(err))
                if self.sock:
                    try:
                        self.sock.close()
                    except OSError:
                        pass
                    self.sock = None

        self.receive_thread = threading.Thread(target=worker, daemon=True)
        self.receive_thread.start()

    def _connect_multicast(self, group, port):
        if not _is_multicast_group(group):
            messagebox.showerror(
                "Error",
                f"'{group}' is not a valid IPv4 multicast group.\n\n"
                "Multicast addresses are in the range 224.0.0.0 – 239.255.255.255 "
                "(e.g. the TAK SA default 239.2.3.1).",
            )
            return
        self.footer_label.configure(text=f"Joining multicast {group}:{port}…")
        self.connect_btn.configure(state="disabled")
        self._recent_digests.clear()


        def worker():
            try:
                udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
                udp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                if hasattr(socket, "SO_REUSEPORT"):
                    try:
                        udp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
                    except OSError:
                        pass
                # Larger kernel recv buffer so we don't drop bursts.
                try:
                    udp.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1 << 20)
                except OSError:
                    pass

                # Bind to the multicast port on all interfaces.
                udp.bind(("", port))

                # Join the group on EVERY local IPv4 interface. On Windows,
                # passing INADDR_ANY only joins on the OS's default-route NIC,
                # which is rarely the one carrying TAK traffic.
                joined = []
                interfaces = _local_ipv4_addresses()
                for iface in interfaces:
                    try:
                        mreq = struct.pack("4s4s",
                                           socket.inet_aton(group),
                                           socket.inet_aton(iface))
                        udp.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
                        joined.append(iface)
                    except OSError:
                        pass
                if not joined:
                    # Fallback to the default interface
                    mreq = struct.pack("4sl",
                                       socket.inet_aton(group),
                                       socket.INADDR_ANY)
                    udp.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
                    joined = ["default"]

                self.sock = udp
                self.multicast_group = group
                self.transport = "Multicast"
                self.datagram_count = 0
                self.after(0, lambda: self.on_connected(
                    group, port, f"Multicast on {len(joined)} iface(s)"))
                self.stop_receiving = False
                self.receive_messages()
            except OSError as e:
                err = _explain_socket_error(e, port)
                self.after(0, lambda: self._connection_failed(err))
                if self.sock:
                    try:
                        self.sock.close()
                    except OSError:
                        pass
                    self.sock = None
            except Exception as e:
                err = str(e)
                self.after(0, lambda: self._connection_failed(err))
                if self.sock:
                    try:
                        self.sock.close()
                    except OSError:
                        pass
                    self.sock = None

        self.receive_thread = threading.Thread(target=worker, daemon=True)
        self.receive_thread.start()

    def _connection_failed(self, msg):
        self.connect_btn.configure(state="normal")
        self.footer_label.configure(text=f"Connection failed: {msg}")
        messagebox.showerror("Connection Error", msg)

    def on_connected(self, host, port, scheme="TLS"):
        self.connected = True
        self.status_label.configure(text=f"● Connected ({scheme}) — {host}:{port}", text_color=OK)
        self.connect_btn.configure(text="Disconnect", state="normal", fg_color=ERR,
                                   hover_color="#c43c3c")
        self.footer_label.configure(text=f"Connected to {host}:{port} ({scheme})")

        for widget in (self.host_entry, self.port_entry, self.p12_entry,
                       self.password_entry, self.browse_btn, self.tls_check):
            widget.configure(state="disabled")
        self.mode_seg.configure(state="disabled")
        # Tint locked entries
        for widget in (self.host_entry, self.port_entry, self.p12_entry,
                       self.password_entry):
            widget.configure(fg_color=ENTRY_CONN)

    def disconnect(self):
        self.stop_receiving = True
        if self.sock:
            # If we joined a multicast group, drop membership before closing.
            try:
                if self.transport == "Multicast" and self.multicast_group:
                    mreq = struct.pack("4sl",
                                       socket.inet_aton(self.multicast_group),
                                       socket.INADDR_ANY)
                    self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_DROP_MEMBERSHIP, mreq)
            except OSError:
                pass
            try:
                self.sock.close()
            except OSError:
                pass
            self.sock = None
        self.transport = None
        self.multicast_group = None

        self.connected = False
        self.status_label.configure(text="● Disconnected", text_color=ERR)
        self.connect_btn.configure(text="Connect", fg_color=ACCENT, hover_color=ACCENT_HOV)
        self.footer_label.configure(text="Disconnected.")

        for widget in (self.host_entry, self.port_entry, self.p12_entry,
                       self.password_entry, self.browse_btn, self.tls_check):
            widget.configure(state="normal")
        self.mode_seg.configure(state="normal")
        for widget in (self.host_entry, self.port_entry, self.p12_entry,
                       self.password_entry):
            widget.configure(fg_color=ENTRY_BG)
        self._on_mode_change()  # re-apply enabled state for current mode

    def _on_tls_toggle(self):
        """Enable/disable cert fields based on the TLS checkbox (TCP mode only)."""
        if self.connected or self.mode_var.get() != "TCP":
            return
        state = "normal" if self.use_tls_var.get() else "disabled"
        for widget in (self.p12_entry, self.password_entry, self.browse_btn):
            widget.configure(state=state)

    def _on_mode_change(self):
        """Show/disable the right inputs for the selected transport."""
        if self.connected:
            return
        mode = self.mode_var.get()
        if mode == "Multicast (UDP)":
            self.server_label.configure(text="Group")
            # Suggest TAK SA defaults only if the fields are still at the
            # initial TCP defaults; otherwise leave the user's values alone.
            if self.host_entry.get().strip() in ("", "localhost"):
                self.host_entry.delete(0, tk.END)
                self.host_entry.insert(0, DEFAULT_MULTICAST_GROUP)
            if self.port_entry.get().strip() in ("", DEFAULT_TCP_PORT):
                self.port_entry.delete(0, tk.END)
                self.port_entry.insert(0, DEFAULT_MULTICAST_PORT)
            self.tls_check.configure(state="disabled")
            for widget in (self.p12_entry, self.password_entry, self.browse_btn):
                widget.configure(state="disabled")
        else:
            self.server_label.configure(text="Server")
            if self.host_entry.get().strip() == DEFAULT_MULTICAST_GROUP:
                self.host_entry.delete(0, tk.END)
                self.host_entry.insert(0, "localhost")
            if self.port_entry.get().strip() in ("", DEFAULT_MULTICAST_PORT):
                self.port_entry.delete(0, tk.END)
                self.port_entry.insert(0, DEFAULT_TCP_PORT)
            self.tls_check.configure(state="normal")
            self._on_tls_toggle()


    # ---- Receive / parse -----------------------------------------------

    def receive_messages(self):
        sock = self.sock
        if sock is None:
            return
        sock.settimeout(1.0)
        buffer = ''
        is_udp = self.transport == "Multicast"
        while not self.stop_receiving and self.sock:
            try:
                if is_udp:
                    # Each UDP datagram is a complete CoT message; no buffering needed.
                    data, addr = sock.recvfrom(65535)
                    if not data:
                        continue
                    # The group may be joined on several interfaces, so the same
                    # datagram can be delivered more than once. Drop byte-identical
                    # copies seen within a short window.
                    if self._is_duplicate_datagram(data):
                        continue
                    self.datagram_count += 1
                    sender = f"{addr[0]}:{addr[1]}"
                    self.after(0, lambda c=self.datagram_count, s=sender:
                               self.footer_label.configure(
                                   text=f"Multicast: {c} datagram(s) received "
                                        f"(latest from {s})"))
                    text = data.decode('utf-8', errors='replace')
                    messages, _ = split_cot_stream(text)
                    if not messages and '<event' in text:
                        messages = [text]  # fallback if XML decl prefix etc.
                else:
                    data = sock.recv(4096)
                    if not data:
                        break
                    buffer += data.decode('utf-8', errors='replace')
                    messages, buffer = split_cot_stream(buffer)

                for cot_xml in messages:
                    parsed = self.parse_cot_message(cot_xml)
                    if parsed:
                        self.after(0, lambda m=parsed: self.add_message(m))
            except socket.timeout:
                continue
            except OSError:
                # Socket closed from another thread (disconnect) or a transient
                # network error; exit the loop cleanly.
                break
            except Exception as e:
                if not self.stop_receiving:
                    err = str(e)
                    self.after(0, lambda m=err: self.footer_label.configure(
                        text=f"Receive error: {m}"))
                break
        if not self.stop_receiving:
            self.after(0, self.disconnect)

    def _is_duplicate_datagram(self, data: bytes) -> bool:
        """True if this exact datagram was seen within DEDUP_WINDOW_SEC."""
        now = time.monotonic()
        digest = hashlib.blake2b(data, digest_size=16).digest()
        # Prune expired entries so the cache can't grow unbounded.
        if self._recent_digests:
            cutoff = now - DEDUP_WINDOW_SEC
            for key in [k for k, t in self._recent_digests.items() if t < cutoff]:
                del self._recent_digests[key]
        if digest in self._recent_digests:
            self._recent_digests[digest] = now
            return True
        self._recent_digests[digest] = now
        return False


    def parse_cot_message(self, xml_string):
        try:
            root = ET.fromstring(xml_string)
        except ET.ParseError:
            return None
        msg = {
            'timestamp': datetime.now(),
            'type':  root.get('type',  'N/A'),
            'uid':   root.get('uid',   'N/A'),
            'time':  root.get('time',  'N/A'),
            'stale': root.get('stale', 'N/A'),
            'how':   root.get('how',   'N/A'),
            'callsign': 'N/A',
            'lat': 'N/A', 'lon': 'N/A', 'hae': 'N/A',
            'xml': xml_string,
        }
        detail = root.find('detail')
        if detail is not None:
            contact = detail.find('contact')
            if contact is not None:
                msg['callsign'] = contact.get('callsign', 'N/A')
        point = root.find('point')
        if point is not None:
            msg['lat'] = point.get('lat', 'N/A')
            msg['lon'] = point.get('lon', 'N/A')
            msg['hae'] = point.get('hae', 'N/A')
        return msg

    # ---- Filter / display ----------------------------------------------

    def _format_row(self, message):
        ts = message['timestamp'].strftime("%H:%M:%S")
        return f"{ts}  {message['callsign']:<20}  {message['type']}"

    def should_display(self, message):
        if not self.filtered_callsigns:
            return True
        callsign = message['callsign']
        if self.partial_match:
            return any(term.lower() in callsign.lower() for term in self.filtered_callsigns)
        return callsign in self.filtered_callsigns

    def add_message(self, message):
        self.all_messages.append(message)
        if self.should_display(message):
            self.message_list.insert(tk.END, self._format_row(message))
            self.displayed_messages.append(message)
            self.message_list.see(tk.END)
        self._enforce_message_cap()
        self._update_counts()

    def _enforce_message_cap(self):
        """Bound retained history so long sessions don't exhaust memory/UI."""
        while len(self.all_messages) > MAX_MESSAGES:
            old = self.all_messages.pop(0)
            # Order is preserved, so if it was displayed it's the first row.
            if self.displayed_messages and self.displayed_messages[0] is old:
                self.displayed_messages.pop(0)
                self.message_list.delete(0)


    def rebuild_message_list(self):
        self.message_list.delete(0, tk.END)
        self.displayed_messages = []
        for message in self.all_messages:
            if self.should_display(message):
                self.message_list.insert(tk.END, self._format_row(message))
                self.displayed_messages.append(message)
        self._update_counts()

    def _update_counts(self):
        self.msg_count_label.configure(
            text=f"Messages: {len(self.displayed_messages)} / {len(self.all_messages)}"
        )

    def apply_filter(self):
        text = self.filter_entry.get().strip()
        self.filtered_callsigns = {c.strip() for c in text.split(',') if c.strip()}
        self.rebuild_message_list()

    def clear_filter(self):
        self.filter_entry.delete(0, tk.END)
        self.filtered_callsigns = set()
        self.rebuild_message_list()

    def on_partial_toggle(self):
        self.partial_match = self.partial_var.get()
        if self.filtered_callsigns:
            self.rebuild_message_list()

    def on_message_select(self, _event):
        selection = self.message_list.curselection()
        if not selection:
            return
        index = selection[0]
        if 0 <= index < len(self.displayed_messages):
            self.display_message_details(self.displayed_messages[index])

    def display_message_details(self, message):
        self.details_text.delete(1.0, tk.END)

        rows = [
            ("Timestamp", message['timestamp'].strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]),
            ("Callsign",  message['callsign']),
            ("Type",      message['type']),
            ("UID",       message['uid']),
            ("Time",      message['time']),
            ("Stale",     message['stale']),
            ("How",       message['how']),
            ("Location",  f"Lat {message['lat']}, Lon {message['lon']}, HAE {message['hae']} m"),
        ]
        for k, v in rows:
            self.details_text.insert(tk.END, f"{k:<11} ", 'hdr_key')
            self.details_text.insert(tk.END, f"{v}\n", 'hdr_val')

        self.details_text.insert(tk.END, "\nFull XML\n", 'hdr_key')
        self.details_text.insert(tk.END, "─" * 60 + "\n", 'rule')

        try:
            root = ET.fromstring(message['xml'])
            rough = ET.tostring(root, encoding='unicode')
            pretty = minidom.parseString(rough).toprettyxml(indent="  ")
            pretty = '\n'.join(
                line for line in pretty.split('\n')
                if line.strip() and not line.strip().startswith('<?xml')
            )
            self._insert_highlighted_xml(pretty)
        except ET.ParseError:
            self.details_text.insert(tk.END, message['xml'])

    def _insert_highlighted_xml(self, xml_text):
        attr_re = re.compile(r'(\s+)([\w:-]+)="([^"]*)"')
        tag_re = re.compile(r'^(\s*)(</?[^>]+>)(.*)$')

        for line in xml_text.split('\n'):
            m = tag_re.match(line)
            if not m:
                self.details_text.insert(tk.END, line + '\n', 'xml_text')
                continue

            indent, tag, trailing = m.group(1), m.group(2), m.group(3)
            self.details_text.insert(tk.END, indent)

            bracket = re.match(r'(</?)([\w:-]+)', tag)
            if not bracket:
                self.details_text.insert(tk.END, tag + '\n', 'xml_tag')
                continue

            self.details_text.insert(tk.END, bracket.group(1), 'xml_tag')
            self.details_text.insert(tk.END, bracket.group(2), 'xml_tag')

            rest = tag[len(bracket.group(0)):]
            pos = 0
            for am in attr_re.finditer(rest):
                self.details_text.insert(tk.END, rest[pos:am.start()])
                self.details_text.insert(tk.END, am.group(1))
                self.details_text.insert(tk.END, am.group(2), 'xml_attr')
                self.details_text.insert(tk.END, '="',         'xml_attr')
                self.details_text.insert(tk.END, am.group(3),  'xml_value')
                self.details_text.insert(tk.END, '"',          'xml_attr')
                pos = am.end()
            self.details_text.insert(tk.END, rest[pos:], 'xml_tag')

            if trailing:
                self.details_text.insert(tk.END, trailing, 'xml_text')
            self.details_text.insert(tk.END, '\n')

    # ---- Misc ----------------------------------------------------------

    def clear_messages(self):
        if not self.all_messages:
            return
        if messagebox.askyesno("Clear Messages", "Clear all received messages?"):
            self.all_messages = []
            self.displayed_messages = []
            self.message_list.delete(0, tk.END)
            self.details_text.delete(1.0, tk.END)
            self._update_counts()

    def export_messages(self):
        if not self.all_messages:
            messagebox.showinfo("Export", "No messages to export.")
            return
        filename = filedialog.asksaveasfilename(
            title="Export Messages",
            defaultextension=".txt",
            filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")],
        )
        if not filename:
            return
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                for msg in self.all_messages:
                    if not self.should_display(msg):
                        continue
                    f.write("=" * 80 + "\n")
                    f.write(f"Timestamp: {msg['timestamp']}\n")
                    f.write(f"Callsign:  {msg['callsign']}\n")
                    f.write(f"Type:      {msg['type']}\n")
                    f.write(f"UID:       {msg['uid']}\n\n")
                    f.write(msg['xml'] + "\n\n")
            messagebox.showinfo("Export", f"Exported {len(self.displayed_messages)} messages.")
        except OSError as e:
            messagebox.showerror("Export Error", str(e))


def main():
    app = TakInspectorApp()
    app.mainloop()


if __name__ == '__main__':
    main()
