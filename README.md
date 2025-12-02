# TLS/SSL Connection Monitor

A Python script for connecting to TLS/SSL servers with client certificate authentication and displaying received data in real-time.

## Features

- **Multiple certificate formats**: Supports both .p12 (PKCS#12) and separate .pem certificate/key files
- **Real-time data display**: Shows all data received from the server with timestamps
- **Output logging**: Optional file logging to save all received data to a text file
- **Connection details**: Displays TLS protocol version, cipher suite, and server certificate information
- **Smart data handling**: Automatically decodes text or displays hex for binary data
- **Activity monitoring**: Shows waiting indicator when connected but no data is being received
- **Self-signed cert support**: Accepts self-signed certificates by default

## Requirements

- Python 3.6+
- cryptography library

### Installation

```bash
pip install cryptography
```

## Usage

### With .p12 Certificate File

```bash
python3 inspect_cot_tls <host> <port> --p12 <file.p12> [--password <password>] [--output <file.txt>]
```

**Examples:**
```bash
# .p12 file with password
python3 inspect_cot_tls demo.tak-ops.com 8089 --p12 client.p12 --password mypassword

# .p12 file without password
python3 inspect_cot_tls server.example.com 443 --p12 client.p12

# Save output to file
python3 inspect_cot_tls demo.tak-ops.com 8089 --p12 client.p12 --password mypassword -o output.txt
```

### With Separate Certificate and Key Files

```bash
python3 inspect_cot_tls <host> <port> --cert <cert.pem> --key <key.pem> [--output <file.txt>]
```

**Example:**
```bash
python3 inspect_cot_tls server.example.com 443 --cert client.pem --key client-key.pem

# With output file
python3 inspect_cot_tls server.example.com 443 --cert client.pem --key client-key.pem -o log.txt
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
