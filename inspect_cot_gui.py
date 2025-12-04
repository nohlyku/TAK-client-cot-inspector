#!/usr/bin/env python3

"""
TAK CoT Inspector - GUI Version
A simple GUI application to connect to TAK servers, view CoT messages, and filter by callsign.
"""

import ssl
import socket
import os
import threading
import xml.etree.ElementTree as ET
from datetime import datetime
from cryptography.hazmat.primitives.serialization import pkcs12, Encoding, PrivateFormat, NoEncryption
from cryptography.hazmat.backends import default_backend
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext


class TakInspectorGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("TAK CoT Inspector")
        self.root.geometry("1200x800")
        
        # Connection state
        self.connected = False
        self.ssl_socket = None
        self.receive_thread = None
        self.stop_receiving = False
        
        # Session data
        self.p12_path = None
        self.p12_password = None
        self.all_messages = []  # Store all received messages
        self.filtered_callsigns = set()  # Empty = show all
        self.partial_match = False  # Partial match mode for filtering
        
        self.dark_mode = False
        self.themes = {
            'light': {
                'bg': '#fafafa',
                'fg': '#000000',
                'select_bg': '#0078d7',
                'select_fg': '#ffffff',
                'listbox_bg': '#ffffff',
                'listbox_fg': '#000000',
                'text_bg': '#ffffff',
                'text_fg': '#000000',
                'entry_bg': '#ffffff',
                'entry_fg': '#000000',
                'entry_border': '#c0c0c0',
                'entry_bg_connected': '#cce5ff',
                'frame_bg': '#fafafa',
                'label_fg': '#000000',
                'button_bg': '#e8e8e8',
                'button_fg': '#000000',
                'button_hover': '#d0d0d0',
                'button_border': '#a0a0a0',
                # XML syntax highlighting colors (VS Code light theme)
                'xml_tag': '#0000ff',
                'xml_attr': '#ff0000',
                'xml_value': '#a31515',
                'xml_text': '#000000'
            },
            'dark': {
                'bg': '#1c1c1c',
                'fg': '#e4e4e4',
                'select_bg': '#0078d7',
                'select_fg': '#ffffff',
                'listbox_bg': '#1e1e1e',
                'listbox_fg': '#d4d4d4',
                'text_bg': '#1e1e1e',
                'text_fg': '#e4e4e4',
                'entry_bg': '#0d0d0d',
                'entry_fg': '#e4e4e4',
                'entry_border': '#3e3e3e',
                'entry_bg_connected': '#1a3a52',
                'frame_bg': '#1c1c1c',
                'label_fg': '#d4d4d4',
                'button_bg': '#0d47a1',
                'button_fg': '#ffffff',
                'button_hover': '#1565c0',
                # XML syntax highlighting colors (VS Code dark theme)
                'xml_tag': '#569cd6',
                'xml_attr': '#9cdcfe',
                'xml_value': '#ce9178',
                'xml_text': '#d4d4d4'
            }
        }
        
        self.setup_ui()
        self.apply_theme()
    
    def setup_ui(self):
        """Create the GUI layout"""
        
        # Top frame - Connection settings
        conn_frame = ttk.LabelFrame(self.root, text="Connection Settings", padding=10)
        conn_frame.pack(fill=tk.X, padx=10, pady=5)
        
        # Server settings
        row1 = ttk.Frame(conn_frame)
        row1.pack(fill=tk.X, pady=2)
        
        ttk.Label(row1, text="Server:").pack(side=tk.LEFT, padx=5)
        self.host_entry = tk.Entry(row1, width=30)
        self.host_entry.pack(side=tk.LEFT, padx=5)
        self.host_entry.insert(0, "localhost")
        
        ttk.Label(row1, text="Port:").pack(side=tk.LEFT, padx=5)
        self.port_entry = tk.Entry(row1, width=10)
        self.port_entry.pack(side=tk.LEFT, padx=5)
        self.port_entry.insert(0, "8089")
        
        # Certificate settings
        row2 = ttk.Frame(conn_frame)
        row2.pack(fill=tk.X, pady=2)
        
        ttk.Label(row2, text="P12 File:").pack(side=tk.LEFT, padx=5)
        self.p12_entry = tk.Entry(row2, width=50)
        self.p12_entry.pack(side=tk.LEFT, padx=5)
        
        self.browse_btn = tk.Button(row2, text="Browse", command=self.browse_p12)
        self.browse_btn.pack(side=tk.LEFT, padx=5)
        
        ttk.Label(row2, text="Password:").pack(side=tk.LEFT, padx=5)
        self.password_entry = tk.Entry(row2, width=20, show="*")
        self.password_entry.pack(side=tk.LEFT, padx=5)
        
        # Connect/Disconnect button
        row3 = ttk.Frame(conn_frame)
        row3.pack(fill=tk.X, pady=5)
        
        self.connect_btn = tk.Button(row3, text="Connect", command=self.toggle_connection)
        self.connect_btn.pack(side=tk.LEFT, padx=5)
        
        self.status_label = ttk.Label(row3, text="Disconnected", foreground="red")
        self.status_label.pack(side=tk.LEFT, padx=10)
        
        # Dark mode toggle
        self.dark_mode_var = tk.BooleanVar(value=False)
        dark_mode_check = ttk.Checkbutton(row3, text="Dark Mode", variable=self.dark_mode_var, command=self.toggle_dark_mode)
        dark_mode_check.pack(side=tk.RIGHT, padx=5)
        
        # Middle frame - Filter settings
        filter_frame = ttk.LabelFrame(self.root, text="Filter Options", padding=10)
        filter_frame.pack(fill=tk.X, padx=10, pady=5)
        
        row4 = ttk.Frame(filter_frame)
        row4.pack(fill=tk.X)
        
        ttk.Label(row4, text="Filter by Callsign (comma-separated, empty = show all):").pack(side=tk.LEFT, padx=5)
        self.filter_entry = tk.Entry(row4, width=50)
        self.filter_entry.pack(side=tk.LEFT, padx=5)
        
        self.apply_filter_btn = tk.Button(row4, text="Apply Filter", command=self.apply_filter)
        self.apply_filter_btn.pack(side=tk.LEFT, padx=5)
        self.clear_filter_btn = tk.Button(row4, text="Clear Filter", command=self.clear_filter)
        self.clear_filter_btn.pack(side=tk.LEFT, padx=5)
        
        # Partial match option
        self.partial_match_var = tk.BooleanVar(value=False)
        partial_check = ttk.Checkbutton(row4, text="Partial Match", variable=self.partial_match_var, command=self.on_partial_match_toggle)
        partial_check.pack(side=tk.LEFT, padx=10)
        
        # Bottom frame - Message display
        display_frame = ttk.LabelFrame(self.root, text="CoT Messages", padding=10)
        display_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # Message list with scrollbar
        list_frame = ttk.Frame(display_frame)
        list_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        self.message_list = tk.Listbox(list_frame, font=("Courier", 9))
        self.message_list.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.message_list.bind('<<ListboxSelect>>', self.on_message_select)
        
        list_scrollbar = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=self.message_list.yview)
        list_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.message_list.config(yscrollcommand=list_scrollbar.set)
        
        # Message details
        details_frame = ttk.Frame(display_frame)
        details_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=(10, 0))
        
        ttk.Label(details_frame, text="Message Details:").pack(anchor=tk.W)
        
        self.details_text = scrolledtext.ScrolledText(details_frame, wrap=tk.WORD, font=("Courier", 9))
        self.details_text.pack(fill=tk.BOTH, expand=True)
        
        # Configure text tags for XML syntax highlighting
        self.setup_syntax_highlighting()
        
        # Button row
        btn_row = ttk.Frame(display_frame)
        btn_row.pack(fill=tk.X, pady=(5, 0))
        
        self.clear_msg_btn = tk.Button(btn_row, text="Clear Messages", command=self.clear_messages)
        self.clear_msg_btn.pack(side=tk.LEFT, padx=5)
        self.export_btn = tk.Button(btn_row, text="Export to File", command=self.export_messages)
        self.export_btn.pack(side=tk.LEFT, padx=5)
        
        self.msg_count_label = ttk.Label(btn_row, text="Messages: 0")
        self.msg_count_label.pack(side=tk.RIGHT, padx=5)
    
    def browse_p12(self):
        """Open file dialog to select P12 file"""
        filename = filedialog.askopenfilename(
            title="Select P12 Certificate File",
            filetypes=[("P12 Files", "*.p12"), ("All Files", "*.*")]
        )
        if filename:
            self.p12_entry.delete(0, tk.END)
            self.p12_entry.insert(0, filename)
            self.p12_path = filename
    
    def load_p12_certificate(self, p12_file, password=None):
        """Load certificate and key from a .p12 file"""
        try:
            with open(p12_file, 'rb') as f:
                p12_data = f.read()
            
            private_key, certificate, additional_certs = pkcs12.load_key_and_certificates(
                p12_data, 
                password.encode() if password else None,
                backend=default_backend()
            )
            
            cert_pem = certificate.public_bytes(Encoding.PEM)
            key_pem = private_key.private_bytes(
                encoding=Encoding.PEM,
                format=PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=NoEncryption()
            )
            
            return cert_pem, key_pem
            
        except Exception as e:
            raise Exception(f"Error loading .p12 file: {e}")
    
    def toggle_connection(self):
        """Connect or disconnect from server"""
        if not self.connected:
            self.connect()
        else:
            self.disconnect()
    
    def connect(self):
        """Connect to TAK server"""
        # Validate inputs
        host = self.host_entry.get().strip()
        port_str = self.port_entry.get().strip()
        p12_file = self.p12_entry.get().strip()
        password = self.password_entry.get()
        
        if not host or not port_str:
            messagebox.showerror("Error", "Please enter server and port")
            return
        
        try:
            port = int(port_str)
        except ValueError:
            messagebox.showerror("Error", "Invalid port number")
            return
        
        if not p12_file or not os.path.exists(p12_file):
            messagebox.showerror("Error", "Please select a valid P12 file")
            return
        
        # Save credentials for session
        self.p12_path = p12_file
        self.p12_password = password if password else None
        
        # Try to connect in background
        def connect_thread():
            try:
                # Create SSL context
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                
                # Load P12 certificate
                cert_pem, key_pem = self.load_p12_certificate(p12_file, password)
                
                # Write temporary PEM files
                import tempfile
                with tempfile.NamedTemporaryFile(mode='wb', delete=False, suffix='.pem') as cert_tmp:
                    cert_tmp.write(cert_pem)
                    temp_cert = cert_tmp.name
                with tempfile.NamedTemporaryFile(mode='wb', delete=False, suffix='.pem') as key_tmp:
                    key_tmp.write(key_pem)
                    temp_key = key_tmp.name
                
                try:
                    context.load_cert_chain(certfile=temp_cert, keyfile=temp_key)
                finally:
                    os.unlink(temp_cert)
                    os.unlink(temp_key)
                
                # Allow self-signed certificates
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                
                # Create socket and connect
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(30)
                
                self.ssl_socket = context.wrap_socket(sock, server_hostname=host)
                self.ssl_socket.connect((host, port))
                
                # Update UI
                self.root.after(0, lambda: self.on_connected(host, port))
                
                # Start receiving messages
                self.stop_receiving = False
                self.receive_messages()
                
            except Exception as e:
                self.root.after(0, lambda: messagebox.showerror("Connection Error", str(e)))
                if self.ssl_socket:
                    self.ssl_socket.close()
                    self.ssl_socket = None
        
        self.receive_thread = threading.Thread(target=connect_thread, daemon=True)
        self.receive_thread.start()
    
    def on_connected(self, host, port):
        """Update UI when connected"""
        self.connected = True
        self.status_label.config(text=f"Connected to {host}:{port}", foreground="green")
        self.connect_btn.config(text="Disconnect")
        
        # Change entry boxes to light blue when connected
        theme = self.themes['dark'] if self.dark_mode else self.themes['light']
        connected_bg = theme.get('entry_bg_connected', theme['entry_bg'])
        
        self.host_entry.config(state=tk.DISABLED, disabledbackground=connected_bg)
        self.port_entry.config(state=tk.DISABLED, disabledbackground=connected_bg)
        self.p12_entry.config(state=tk.DISABLED, disabledbackground=connected_bg)
        self.password_entry.config(state=tk.DISABLED, disabledbackground=connected_bg)
    
    def disconnect(self):
        """Disconnect from server"""
        self.stop_receiving = True
        if self.ssl_socket:
            try:
                self.ssl_socket.close()
            except:
                pass
            self.ssl_socket = None
        
        self.connected = False
        self.status_label.config(text="Disconnected", foreground="red")
        self.connect_btn.config(text="Connect")
        
        # Restore normal background color
        theme = self.themes['dark'] if self.dark_mode else self.themes['light']
        
        self.host_entry.config(state=tk.NORMAL)
        self.port_entry.config(state=tk.NORMAL)
        self.p12_entry.config(state=tk.NORMAL)
        self.password_entry.config(state=tk.NORMAL)
    
    def receive_messages(self):
        """Receive and process messages from server"""
        self.ssl_socket.settimeout(1.0)
        
        while not self.stop_receiving and self.ssl_socket:
            try:
                data = self.ssl_socket.recv(4096)
                if not data:
                    break
                
                try:
                    decoded = data.decode('utf-8', errors='replace')
                    # Parse CoT message
                    message_data = self.parse_cot_message(decoded)
                    if message_data:
                        self.root.after(0, lambda m=message_data: self.add_message(m))
                except Exception as e:
                    print(f"Error parsing message: {e}")
                    
            except socket.timeout:
                continue
            except Exception as e:
                if not self.stop_receiving:
                    print(f"Receive error: {e}")
                break
        
        if not self.stop_receiving:
            self.root.after(0, self.disconnect)
    
    def parse_cot_message(self, xml_string):
        """Parse CoT XML and extract key fields"""
        try:
            root = ET.fromstring(xml_string)
            
            message = {
                'timestamp': datetime.now(),
                'type': root.get('type', 'N/A'),
                'uid': root.get('uid', 'N/A'),
                'time': root.get('time', 'N/A'),
                'stale': root.get('stale', 'N/A'),
                'how': root.get('how', 'N/A'),
                'callsign': 'N/A',
                'lat': 'N/A',
                'lon': 'N/A',
                'hae': 'N/A',
                'xml': xml_string
            }
            
            # Extract callsign
            detail = root.find('detail')
            if detail is not None:
                contact = detail.find('contact')
                if contact is not None:
                    message['callsign'] = contact.get('callsign', 'N/A')
            
            # Extract location
            point = root.find('point')
            if point is not None:
                message['lat'] = point.get('lat', 'N/A')
                message['lon'] = point.get('lon', 'N/A')
                message['hae'] = point.get('hae', 'N/A')
            
            return message
            
        except ET.ParseError:
            return None
    
    def add_message(self, message):
        """Add a message to the display"""
        self.all_messages.append(message)
        
        # Check if it passes the filter
        if self.should_display_message(message):
            timestamp_str = message['timestamp'].strftime("%H:%M:%S")
            display_text = f"{timestamp_str} | {message['callsign']:<20} | {message['type']}"
            self.message_list.insert(tk.END, display_text)
            self.message_list.see(tk.END)  # Auto-scroll
        
        # Update count
        displayed = self.message_list.size()
        total = len(self.all_messages)
        self.msg_count_label.config(text=f"Messages: {displayed} / {total}")
    
    def should_display_message(self, message):
        """Check if message should be displayed based on filter"""
        if not self.filtered_callsigns:
            return True  # No filter, show all
        
        callsign = message['callsign']
        
        if self.partial_match:
            # Partial match: check if any filter term is contained in the callsign
            return any(filter_term.lower() in callsign.lower() for filter_term in self.filtered_callsigns)
        else:
            # Exact match
            return callsign in self.filtered_callsigns
    
    def apply_filter(self):
        """Apply callsign filter"""
        filter_text = self.filter_entry.get().strip()
        
        if filter_text:
            # Parse comma-separated callsigns
            self.filtered_callsigns = set(c.strip() for c in filter_text.split(',') if c.strip())
        else:
            self.filtered_callsigns = set()
        
        # Rebuild display
        self.rebuild_message_list()
    
    def clear_filter(self):
        """Clear the callsign filter"""
        self.filter_entry.delete(0, tk.END)
        self.filtered_callsigns = set()
        self.rebuild_message_list()
    
    def rebuild_message_list(self):
        """Rebuild the message list based on current filter"""
        self.message_list.delete(0, tk.END)
        
        for message in self.all_messages:
            if self.should_display_message(message):
                timestamp_str = message['timestamp'].strftime("%H:%M:%S")
                display_text = f"{timestamp_str} | {message['callsign']:<20} | {message['type']}"
                self.message_list.insert(tk.END, display_text)
        
        displayed = self.message_list.size()
        total = len(self.all_messages)
        self.msg_count_label.config(text=f"Messages: {displayed} / {total}")
    
    def on_message_select(self, event):
        """Handle message selection"""
        selection = self.message_list.curselection()
        if not selection:
            return
        
        index = selection[0]
        
        # Find the actual message (accounting for filter)
        displayed_index = 0
        for message in self.all_messages:
            if self.should_display_message(message):
                if displayed_index == index:
                    self.display_message_details(message)
                    break
                displayed_index += 1
    
    def display_message_details(self, message):
        """Display full message details with syntax highlighting"""
        self.details_text.delete(1.0, tk.END)
        
        # Insert header information
        header = [
            f"Timestamp: {message['timestamp'].strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]}",
            f"Callsign: {message['callsign']}",
            f"Type: {message['type']}",
            f"UID: {message['uid']}",
            f"Time: {message['time']}",
            f"Stale: {message['stale']}",
            f"How: {message['how']}",
            f"Location: Lat: {message['lat']}, Lon: {message['lon']}, HAE: {message['hae']}m",
            f"\nFull XML:\n{'-'*60}\n"
        ]
        self.details_text.insert(tk.END, '\n'.join(header))
        
        # Pretty print and highlight XML
        try:
            root = ET.fromstring(message['xml'])
            import xml.dom.minidom as minidom
            rough_string = ET.tostring(root, encoding='unicode')
            reparsed = minidom.parseString(rough_string)
            pretty_xml = reparsed.toprettyxml(indent="  ")
            pretty_xml = '\n'.join([line for line in pretty_xml.split('\n') if line.strip() and not line.strip().startswith('<?xml')])
            self.insert_highlighted_xml(pretty_xml)
        except:
            self.details_text.insert(tk.END, message['xml'])
    
    def clear_messages(self):
        """Clear all messages"""
        if messagebox.askyesno("Clear Messages", "Clear all received messages?"):
            self.all_messages = []
            self.message_list.delete(0, tk.END)
            self.details_text.delete(1.0, tk.END)
            self.msg_count_label.config(text="Messages: 0")
    
    def export_messages(self):
        """Export messages to a file"""
        if not self.all_messages:
            messagebox.showinfo("Export", "No messages to export")
            return
        
        filename = filedialog.asksaveasfilename(
            title="Export Messages",
            defaultextension=".txt",
            filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")]
        )
        
        if filename:
            try:
                with open(filename, 'w', encoding='utf-8') as f:
                    for message in self.all_messages:
                        if self.should_display_message(message):
                            f.write(f"{'='*80}\n")
                            f.write(f"Timestamp: {message['timestamp']}\n")
                            f.write(f"Callsign: {message['callsign']}\n")
                            f.write(f"Type: {message['type']}\n")
                            f.write(f"UID: {message['uid']}\n")
                            f.write(f"\n{message['xml']}\n\n")
                
                messagebox.showinfo("Export", f"Exported {len(self.all_messages)} messages to {filename}")
            except Exception as e:
                messagebox.showerror("Export Error", str(e))
    
    def setup_syntax_highlighting(self):
        """Configure text tags for XML syntax highlighting"""
        theme = self.themes['dark'] if self.dark_mode else self.themes['light']
        
        self.details_text.tag_configure('xml_tag', foreground=theme['xml_tag'])
        self.details_text.tag_configure('xml_attr', foreground=theme['xml_attr'])
        self.details_text.tag_configure('xml_value', foreground=theme['xml_value'])
        self.details_text.tag_configure('xml_text', foreground=theme['xml_text'])
    
    def insert_highlighted_xml(self, xml_text):
        """Insert XML text with syntax highlighting"""
        import re
        
        # Regex patterns for XML elements
        lines = xml_text.split('\n')
        for line in lines:
            pos = 0
            while pos < len(line):
                # Check for tags
                tag_match = re.match(r'(\s*)(</?[^>]+>)', line[pos:])
                if tag_match:
                    indent = tag_match.group(1)
                    tag_content = tag_match.group(2)
                    
                    # Insert indent
                    self.details_text.insert(tk.END, indent)
                    
                    # Parse tag content for attributes
                    tag_pos = 0
                    # Insert opening bracket and tag name
                    bracket_match = re.match(r'(</?)([\w]+)', tag_content)
                    if bracket_match:
                        self.details_text.insert(tk.END, bracket_match.group(1), 'xml_tag')
                        self.details_text.insert(tk.END, bracket_match.group(2), 'xml_tag')
                        tag_pos = len(bracket_match.group(0))
                        
                        # Find and highlight attributes
                        rest = tag_content[tag_pos:]
                        while True:
                            attr_match = re.search(r'\s+([\w]+)="([^"]*?)"', rest)
                            if not attr_match:
                                break
                            
                            # Space before attribute
                            self.details_text.insert(tk.END, rest[:attr_match.start(1)])
                            # Attribute name
                            self.details_text.insert(tk.END, attr_match.group(1), 'xml_attr')
                            # Equals and quote
                            self.details_text.insert(tk.END, '="', 'xml_attr')
                            # Value
                            self.details_text.insert(tk.END, attr_match.group(2), 'xml_value')
                            # Closing quote
                            self.details_text.insert(tk.END, '"', 'xml_attr')
                            
                            rest = rest[attr_match.end():]
                        
                        # Insert remaining (closing bracket)
                        self.details_text.insert(tk.END, rest, 'xml_tag')
                    else:
                        # Couldn't parse, just insert as tag
                        self.details_text.insert(tk.END, tag_content[tag_pos:], 'xml_tag')
                    
                    pos += len(indent) + len(tag_content)
                else:
                    # Regular text content
                    self.details_text.insert(tk.END, line[pos])
                    pos += 1
            
            self.details_text.insert(tk.END, '\n')
    
    def toggle_dark_mode(self):
        """Toggle between light and dark mode"""
        self.dark_mode = self.dark_mode_var.get()
        self.apply_theme()
    
    def on_partial_match_toggle(self):
        """Handle partial match toggle"""
        self.partial_match = self.partial_match_var.get()
        # Rebuild the list if there's an active filter
        if self.filtered_callsigns:
            self.rebuild_message_list()
    
    def apply_theme(self):
        """Apply the current theme to all widgets"""
        theme = self.themes['dark'] if self.dark_mode else self.themes['light']
        
        # Apply to root window
        self.root.configure(bg=theme['bg'])
        
        # Apply to message list
        self.message_list.configure(
            bg=theme['listbox_bg'],
            fg=theme['listbox_fg'],
            selectbackground=theme['select_bg'],
            selectforeground=theme['select_fg']
        )
        
        # Apply to details text
        self.details_text.configure(
            bg=theme['text_bg'],
            fg=theme['text_fg'],
            insertbackground=theme['text_fg']
        )
        
        # Apply to all Entry widgets with better styling
        for widget in [self.host_entry, self.port_entry, self.p12_entry, self.password_entry, self.filter_entry]:
            widget.configure(
                fg=theme['entry_fg'],
                bg=theme['entry_bg'],
                insertbackground=theme['entry_fg'],
                selectbackground=theme['select_bg'],
                selectforeground=theme['select_fg'],
                relief=tk.FLAT,
                borderwidth=2,
                highlightthickness=1,
                highlightbackground=theme['entry_border'],
                highlightcolor=theme['select_bg']
            )
        
        # Apply to all Button widgets
        for widget in [self.connect_btn, self.browse_btn, self.apply_filter_btn, 
                      self.clear_filter_btn, self.clear_msg_btn, self.export_btn]:
            if self.dark_mode:
                widget.configure(
                    fg=theme.get('button_fg', theme['fg']),
                    bg=theme.get('button_bg', theme['entry_bg']),
                    activeforeground=theme['select_fg'],
                    activebackground=theme.get('button_hover', theme['select_bg']),
                    relief=tk.FLAT,
                    borderwidth=0,
                    padx=10,
                    pady=5,
                    cursor='hand2'
                )
            else:
                widget.configure(
                    fg=theme.get('button_fg', theme['fg']),
                    bg=theme.get('button_bg', '#e8e8e8'),
                    activeforeground=theme['fg'],
                    activebackground=theme.get('button_hover', '#d0d0d0'),
                    relief=tk.FLAT,
                    borderwidth=0,
                    padx=10,
                    pady=5,
                    cursor='hand2',
                    highlightthickness=1,
                    highlightbackground=theme.get('button_border', "#a0a0a0eb")
                )
        
        # Update ttk style for frames and labels
        style = ttk.Style()
        
        # Configure all ttk widgets with theme colors
        if self.dark_mode:
            # Dark mode configuration
            style.configure('TFrame', background=theme['frame_bg'])
            style.configure('TLabelframe', background=theme['bg'], foreground=theme['fg'], 
                          bordercolor=theme['entry_border'])
            style.configure('TLabelframe.Label', background=theme['bg'], foreground=theme['fg'])
            style.configure('TLabel', background=theme['bg'], foreground=theme['label_fg'])
            style.configure('TButton', 
                          background=theme.get('button_bg', theme['entry_bg']), 
                          foreground=theme.get('button_fg', theme['fg']),
                          bordercolor=theme['entry_border'],
                          darkcolor=theme['frame_bg'],
                          lightcolor=theme.get('button_bg', theme['entry_bg']))
            style.map('TButton',
                     background=[('active', theme.get('button_hover', theme['select_bg'])), 
                                ('pressed', theme['select_bg'])],
                     foreground=[('active', theme['fg']), ('pressed', theme['select_fg'])])
            style.configure('TCheckbutton', 
                          background=theme['bg'], 
                          foreground=theme['fg'])
            style.map('TCheckbutton', 
                     background=[('active', theme['bg'])],
                     foreground=[('active', theme['fg'])])
            style.configure('TEntry', 
                          fieldbackground=theme['entry_bg'], 
                          foreground=theme['entry_fg'],
                          bordercolor=theme['entry_border'],
                          darkcolor=theme['frame_bg'],
                          lightcolor=theme['entry_bg'])
            style.map('TEntry',
                     fieldbackground=[('readonly', theme['listbox_bg']), ('disabled', theme['frame_bg'])],
                     foreground=[('readonly', theme['listbox_fg']), ('disabled', theme['label_fg'])])
            # Scrollbar styling for dark mode
            style.configure('Vertical.TScrollbar',
                          background=theme.get('button_bg', theme['entry_bg']),
                          troughcolor=theme['listbox_bg'],
                          bordercolor=theme['entry_border'],
                          arrowcolor=theme['fg'],
                          darkcolor=theme['frame_bg'],
                          lightcolor=theme.get('button_bg', theme['entry_bg']),
                          arrowsize=15)
            style.map('Vertical.TScrollbar',
                     background=[('active', theme.get('button_hover', theme['select_bg']))],
                     arrowcolor=[('disabled', theme['entry_border'])])
        else:
            # Light mode configuration
            style.configure('TFrame', background=theme['frame_bg'])
            style.configure('TLabelframe', background=theme['bg'], foreground='#000000',
                          bordercolor=theme['entry_border'])
            style.configure('TLabelframe.Label', background=theme['bg'], foreground='#000000')
            style.configure('TLabel', background=theme['bg'], foreground='#000000')
            style.configure('TButton', 
                          background='#e1e1e1', 
                          foreground='#000000',
                          bordercolor='#adadad')
            style.map('TButton',
                     background=[('active', '#0078d7'), ('pressed', '#005a9e')],
                     foreground=[('active', '#ffffff'), ('pressed', '#ffffff')])
            style.configure('TCheckbutton', background=theme['bg'], foreground='#000000')
            style.map('TCheckbutton', background=[('active', theme['bg'])])
            style.configure('TEntry', 
                          fieldbackground=theme['entry_bg'], 
                          foreground=theme['entry_fg'],
                          bordercolor=theme['entry_border'])
            # Scrollbar styling for light mode
            style.configure('Vertical.TScrollbar',
                          background='#e1e1e1',
                          troughcolor='#f0f0f0',
                          bordercolor='#adadad',
                          arrowcolor='#000000',
                          arrowsize=15)
            style.map('Vertical.TScrollbar',
                     background=[('active', '#0078d7')],
                     arrowcolor=[('disabled', '#adadad')])
        
        # Update syntax highlighting colors
        self.setup_syntax_highlighting()


def main():
    root = tk.Tk()
    app = TakInspectorGUI(root)
    root.mainloop()


if __name__ == '__main__':
    main()
