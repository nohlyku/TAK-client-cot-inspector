# TAK CoT Inspector (GUI)

A small Tkinter app that connects to a TAK server over TLS with client-certificate authentication and shows incoming Cursor-on-Target (CoT) messages in real time.

## Features

- Connect to a TAK server using a `.p12` client certificate (optional password)
- Real-time list of incoming CoT messages with timestamp, callsign, and type
- Click any message to view the full XML with syntax highlighting
- Filter messages by callsign (comma-separated, exact or partial match)
- Light / dark theme toggle
- Export the currently displayed messages to a text file
- Accepts self-signed server certificates (TAK default)

## Requirements

- Python 3.9+ (Tkinter is included with the standard Windows installer)
- `cryptography`

```bash
pip install -r requirements.txt
```

## Run from source

```bash
python inspect_cot_gui.py
```

1. Enter server host and port (default `8089`).
2. Browse to your `.p12` file and enter the password if it has one.
3. Click **Connect**.
4. Optionally enter callsigns to filter on, separated by commas, and toggle **Partial Match**.
5. Click a row to see the full XML; **Export to File** writes the visible messages to disk.

## Build a standalone Windows EXE

```cmd
pip install -r requirements-build.txt
build_exe.bat
```

This produces `dist\inspect_cot_gui.exe` — a single windowed executable with no Python install required on the target machine.

Build settings live in [inspect_cot_gui.spec](inspect_cot_gui.spec). Edit that file to add an icon (`icon='app.ico'` on the `EXE(...)` call) or bundle extra data.

## Security notes

- Hostname verification and certificate validation are **disabled** so the app works with the self-signed certs typical of TAK deployments. Don't reuse this code where you need real server-identity checking.
- The `.p12` password is held in memory only until the SSL context is built, then cleared.
- The cert and key are written to OS temp files (mode 0600) just long enough for `ssl.SSLContext.load_cert_chain` to read them, then deleted.
- Don't commit `.p12`, `.pem`, or `.key` files — they are ignored by `.gitignore`.

## License

See [LICENSE](LICENSE).
