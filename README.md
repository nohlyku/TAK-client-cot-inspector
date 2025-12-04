# TAK TLS/SSL CoT Monitor

A Python script for connecting to a TAK server with client certificate authentication and displaying received data in real-time.

## Features

### CLI Version (`inspect_cot_cli.py`)
- **Multiple certificate formats**: Supports both .p12 (PKCS#12) and separate .pem certificate/key files
- **Real-time data display**: Shows all data received from the server with timestamps
- **Pretty CoT XML formatting**: Automatic parsing and colorized display of CoT messages with key field extraction
- **Output logging**: Optional file logging to save all received data to a text file
- **Connection details**: Displays TLS protocol version, cipher suite, and server certificate information
- **Smart data handling**: Automatically decodes text or displays hex for binary data
- **Activity monitoring**: Shows waiting indicator when connected but no data is being received
- **Self-signed cert support**: Accepts self-signed certificates by default

### GUI Version (`inspect_cot_gui.py`)
- **Modern interface**: Light/dark mode toggle with custom color themes
- **Visual connection status**: Entry boxes change to light blue when connected
- **Real-time message filtering**: Filter CoT messages by callsign with partial match support
- **Session management**: Load and save P12 certificates for the session
- **Syntax highlighting**: Color-coded XML display in message details (tags, attributes, values)
- **Message history**: View all received messages with searchable list
- **Export functionality**: Save filtered messages to file
- **Connection management**: Easy connect/disconnect with visual status indicators

## Requirements

- Python 3.6+
- cryptography library

### Installation

```bash
pip install -r requirements.txt
```

Or manually:
```bash
pip install cryptography
```

## Usage

### CLI Version - With .p12 Certificate File

```bash
python inspect_cot_cli.py <host> <port> --p12 <file.p12> [--password <password>] [--output <file.txt>]
```

**Examples:**
```bash
# .p12 file with password (with pretty CoT formatting)
python inspect_cot_cli.py demo.tak-ops.com 8089 --p12 client.p12 --password mypassword

# .p12 file without password
python inspect_cot_cli.py server.example.com 443 --p12 client.p12

# Save output to file
python inspect_cot_cli.py demo.tak-ops.com 8089 --p12 client.p12 --password mypassword -o output.txt
```

### CLI Version - With Separate Certificate and Key Files

```bash
python inspect_cot_cli.py <host> <port> --cert <cert.pem> --key <key.pem> [--output <file.txt>]
```

### GUI Version

```bash
python inspect_cot_gui.py
```

**GUI Features:**
1. **Connection**: Enter server, port, and P12 certificate details
2. **Dark Mode**: Toggle between light and dark themes
3. **Filtering**: 
   - Enter callsigns separated by commas (e.g., "ALPHA,BRAVO,CHARLIE")
   - Enable "Partial Match" to match substrings (e.g., "TEAM" matches "TEAM-1", "ALPHA-TEAM")
   - Clear filter to show all messages
4. **Message Details**: Click any message to view full XML with syntax highlighting
5. **Export**: Save filtered messages to a text file

**Example:**
```bash
python3 inspect_cot_cli server.example.com 443 --cert client.pem --key client-key.pem

# With output file
python3 inspect_cot_cli server.example.com 443 --cert client.pem --key client-key.pem -o log.txt
```

## Command Line Options

| Option | Required | Description |
|--------|----------|-------------|
| `host` | Yes | Remote server hostname or IP address |
| `port` | Yes | Remote server port number |
| `--p12` | Either this or --cert | Path to .p12 certificate file |
| `--cert` | Either this or --p12 | Path to client certificate file (.pem) |
| `--key` | Required with --cert | Path to private key file (.pem) |
| `--password` | Optional | Password for encrypted .p12 file |
| `--timeout` | Optional | Connection timeout in seconds (default: 30) |
| `--output` or `-o` | Optional | Output file to save received data |

## Output

The script displays:

1. **Connection Information:**
   - Certificate/key loading status
   - TLS protocol version (e.g., TLSv1.3)
   - Cipher suite in use
   - Server certificate subject
2. **Real-time Data:**
   - Timestamp for each received packet
   - Data size in bytes
   - Decoded text content or hex representation
   - Activity dots when waiting for data (appears every 10 seconds)
   - Optional file output (displays to screen and writes to file simultaneously)
   - Activity dots when waiting for data (appears every 10 seconds)

### Sample Output

```
============================================================
TLS/SSL Connection Monitor
============================================================
Loading .p12 file: client.p12
✓ Loaded certificate and key from .p12 file

Connecting to demo.tak-ops.com:8089...
✓ Connected successfully!
  Protocol: TLSv1.3
  Cipher: ('TLS_AES_256_GCM_SHA384', 'TLSv1.3', 256)
  Server certificate subject: {'commonName': 'demo.tak-ops.com'}

============================================================
RECEIVING DATA (press Ctrl+C to stop)
============================================================

[2025-12-01 18:30:45.123] Received 156 bytes:
<?xml version="1.0" encoding="UTF-8"?>
<event version="2.0" uid="server-status">
  <point lat="0.0" lon="0.0" hae="0.0" ce="999999.0" le="999999.0"/>
</event>
------------------------------------------------------------
...
```

## Stopping the Script

Press `Ctrl+C` to gracefully stop the connection and exit.

## Troubleshooting

### Certificate/Key Mismatch Error

If you get a "KEY_VALUES_MISMATCH" error with separate .pem files:
- Verify the certificate and key files were generated together
- Try using the .p12 file instead (it contains both cert and key bundled)

### Connection Hangs

If the script appears to hang after "Connected successfully!":
- The connection is established but the server isn't sending data yet
- Look for activity dots (`.`) appearing every 10 seconds
- Some servers only send data when specific events occur
- Try triggering an event on the server side

### Module Not Found Error

If you see `ModuleNotFoundError: No module named 'cryptography'`:
```bash
pip install cryptography
```

### Connection Refused

If you see "Connection refused":
- Verify the server hostname/IP and port are correct
- Check if the server is running and accessible
- Verify firewall rules allow the connection

## Security Notes

- The script disables hostname verification and accepts self-signed certificates
- For production use, consider enabling proper certificate verification
- Store certificate files and passwords securely
- Use appropriate file permissions for private keys (chmod 600 on Linux/Mac)
- Be cautious with captured data - it may contain sensitive information

## Common Use Cases

- **TAK Server monitoring**: Connect to TAK servers and view real-time CoT messages
- **API testing**: Test TLS client certificate authentication
- **Debugging**: Troubleshoot TLS connection issues
- **Protocol analysis**: Examine data exchanged over TLS connections

## License

GNU General Public License v3.0	(GPL3)

