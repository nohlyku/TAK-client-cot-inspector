#!/usr/bin/env python3

import ssl
import socket
import sys
import argparse
import os
from datetime import datetime
from cryptography.hazmat.primitives.serialization import pkcs12, Encoding, PrivateFormat, NoEncryption
from cryptography.hazmat.backends import default_backend

#README
#this is to emulatede a TAK client connecting to a TAK server using TLS with client certificate authentication
# it can use either separate PEM files for the client certificate and private key, or a single .p12 file
# it will connect to the server, authenticate using the client certificate, and display any data received in real-time
# it will also print connection details such as protocol version and cipher suite used

# To setup: pip install cryptography
# to use: python3 inspect_cot_tls.py server port --p12 client.p12 --password mypassword
# or if you want to output into a file: python3 inspect_cot_tls.py server port --p12 client.p12 --password mypassword -o output.txt
#example: python3 inspect_cot_tls.py mytakserver 8087 --p12 client.p12 --password mypassword -o output.txt

def load_p12_certificate(p12_file, password=None):
    """
    Load certificate and key from a .p12 file
    Returns tuple of (cert_data, key_data) as PEM strings
    """
    try:
        with open(p12_file, 'rb') as f:
            p12_data = f.read()
        
        # Load the p12 file
        private_key, certificate, additional_certs = pkcs12.load_key_and_certificates(
            p12_data, 
            password.encode() if password else None,
            backend=default_backend()
        )
        
        # Convert to PEM format
        cert_pem = certificate.public_bytes(Encoding.PEM)
        key_pem = private_key.private_bytes(
            encoding=Encoding.PEM,
            format=PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=NoEncryption()
        )
        
        return cert_pem, key_pem
        
    except Exception as e:
        print(f"Error loading .p12 file: {e}")
        sys.exit(1)

def connect_and_display(host, port, cert_file, key_file, timeout=30, p12_file=None, p12_password=None, output_file=None):
    """
    Connect to a TLS/SSL server with client certificate and display data in real-time
    """
    
    # Open output file if specified
    log_file = None
    if output_file:
        try:
            log_file = open(output_file, 'w', encoding='utf-8')
            print(f"Logging output to: {output_file}")
        except Exception as e:
            print(f"Warning: Could not open output file {output_file}: {e}")
            log_file = None
    
    # Create SSL context
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    
    # Handle .p12 file
    if p12_file:
        print(f"Loading .p12 file: {p12_file}")
        cert_pem, key_pem = load_p12_certificate(p12_file, p12_password)
        
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
            print(f"✓ Loaded certificate and key from .p12 file")
        finally:
            # Clean up temp files
            os.unlink(temp_cert)
            os.unlink(temp_key)
    else:
        # Load client certificate and key from separate files
        try:
            # Check if files exist
            if not os.path.isfile(cert_file):
                print(f"Error: Certificate file not found: {cert_file}")
                sys.exit(1)
            if not os.path.isfile(key_file):
                print(f"Error: Key file not found: {key_file}")
                sys.exit(1)
            
            # Try to load them
            context.load_cert_chain(certfile=cert_file, keyfile=key_file)
            print(f"✓ Loaded client certificate: {cert_file}")
            print(f"✓ Loaded private key: {key_file}")
        except ssl.SSLError as e:
            if "KEY_VALUES_MISMATCH" in str(e):
                print(f"\nError: The certificate and key files don't match!")
                print(f"  Certificate: {cert_file}")
                print(f"  Key: {key_file}")
                print(f"\nTroubleshooting:")
                print(f"  1. Verify these files were generated together")
                print(f"  2. Use the .p12 file instead:")
                print(f"     python3 inspect_cot_tls.py {host} {port} --p12 <file.p12>")
            else:
                print(f"Error loading certificate/key: {e}")
            sys.exit(1)
        except Exception as e:
            print(f"Error loading certificate/key: {e}")
            sys.exit(1)
    
    # Allow self-signed certificates (disable hostname verification)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    
    # Create socket and wrap with SSL
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    
    try:
        print(f"\nConnecting to {host}:{port}...")
        ssl_sock = context.wrap_socket(sock, server_hostname=host)
        ssl_sock.connect((host, port))
        
        print(f"✓ Connected successfully!")
        print(f"  Protocol: {ssl_sock.version()}")
        print(f"  Cipher: {ssl_sock.cipher()}")
        
        # Get server certificate info
        cert = ssl_sock.getpeercert()
        if cert:
            print(f"  Server certificate subject: {dict(x[0] for x in cert['subject'])}")
        
        print("\n" + "="*60)
        print("RECEIVING DATA (press Ctrl+C to stop)")
        print("="*60 + "\n")
        
        # Set socket to non-blocking mode with a short timeout
        ssl_sock.settimeout(1.0)
        
        # Receive and display data in real-time
        no_data_count = 0
        while True:
            try:
                data = ssl_sock.recv(4096)
                if not data:
                    print("\n[Connection closed by server]")
                    break
                
                no_data_count = 0  # Reset counter when data is received
                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
                
                # Try to decode as text
                try:
                    decoded = data.decode('utf-8', errors='replace')
                    output = f"[{timestamp}] Received {len(data)} bytes:\n{decoded}\n{'-' * 60}"
                    print(output)
                    if log_file:
                        log_file.write(output + "\n")
                        log_file.flush()
                except:
                    # Display as hex if not text
                    output = f"[{timestamp}] Received {len(data)} bytes (hex):\n{data.hex()}\n{'-' * 60}"
                    print(output)
                    if log_file:
                        log_file.write(output + "\n")
                        log_file.flush()
                    
            except socket.timeout:
                # Print a dot every 10 seconds to show we're still waiting
                no_data_count += 1
                if no_data_count % 10 == 0:
                    print(".", end="", flush=True)
                continue
            except KeyboardInterrupt:
                print("\n\n[Interrupted by user]")
                break
                
    except socket.timeout:
        print(f"Error: Connection timeout after {timeout} seconds")
        sys.exit(1)
    except ConnectionRefusedError:
        print(f"Error: Connection refused to {host}:{port}")
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)
    finally:
        ssl_sock.close()
        if log_file:
            log_file.close()
            print(f"\nLog saved to: {output_file}")
        print("\nConnection closed.")

def main():
    parser = argparse.ArgumentParser(
        description='Connect to TLS/SSL server with client certificate and display data in real-time'
    )
    parser.add_argument('host', help='Remote server hostname or IP')
    parser.add_argument('port', type=int, help='Remote server port')
    
    # Certificate options - either separate files or p12
    cert_group = parser.add_mutually_exclusive_group(required=True)
    cert_group.add_argument('--p12', help='Path to .p12 certificate file')
    cert_group.add_argument('--cert', help='Path to client certificate file (.pem)')
    
    parser.add_argument('--key', help='Path to private key file (.pem) - required if using --cert')
    parser.add_argument('--password', help='Password for .p12 file (if encrypted)')
    parser.add_argument('--timeout', type=int, default=30, help='Connection timeout in seconds (default: 30)')
    parser.add_argument('--output', '-o', help='Output file to save received data (optional)')
    
    args = parser.parse_args()
    
    # Validate arguments
    if args.cert and not args.key:
        parser.error("--key is required when using --cert")
    
    print("="*60)
    print("TLS/SSL Connection Monitor")
    print("="*60)
    
    if args.p12:
        connect_and_display(args.host, args.port, None, None, args.timeout, 
                          p12_file=args.p12, p12_password=args.password, output_file=args.output)
    else:
        connect_and_display(args.host, args.port, args.cert, args.key, args.timeout, 
                          output_file=args.output)

if __name__ == '__main__':
    main()
