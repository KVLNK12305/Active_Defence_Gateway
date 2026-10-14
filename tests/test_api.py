import socket
import sys

def query_adg(query):
    sock_path = "/tmp/adg_trust.sock"
    try:
        # Create a UDS socket
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.connect(sock_path)
        
        # Send query
        sock.sendall((query + "\n").encode('utf-8'))
        
        # Receive response
        response = sock.recv(4096).decode('utf-8')
        print(f"[{query}] -> {response.strip()}")
        
    except FileNotFoundError:
        print(f"Error: Could not connect to {sock_path}. Is the ADG monitor running?")
    finally:
        sock.close()

if __name__ == "__main__":
    if len(sys.argv) > 1:
        query_adg(sys.argv[1])
    else:
        print("Usage: python3 test_api.py <IP or ALL>")
        print("Testing with 'ALL' command:")
        query_adg("ALL")
