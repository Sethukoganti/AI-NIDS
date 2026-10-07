"""
Port scan test — sends SYN-like connection attempts to the hotspot gateway.
Traffic goes OUT through the Wi-Fi adapter and back, so Npcap captures it.
Run this while live capture is active in the browser.
"""
import socket
import threading
import time

TARGET = "10.202.52.94"  # hotspot gateway (phone IP)
START_PORT = 1
END_PORT = 1024
TIMEOUT = 0.05
THREADS = 100  # send fast — port scan needs rapid connections

print(f"Scanning {TARGET} ports {START_PORT}-{END_PORT} with {THREADS} threads...")
print("Watch the Live Capture page — threat should appear in ~15 seconds\n")

def scan_range(ports):
    for port in ports:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(TIMEOUT)
            s.connect((TARGET, port))
            print(f"  [OPEN] port {port}")
            s.close()
        except:
            pass

# Split ports across threads
port_list = list(range(START_PORT, END_PORT + 1))
chunk_size = len(port_list) // THREADS
chunks = [port_list[i:i+chunk_size] for i in range(0, len(port_list), chunk_size)]

threads = []
for chunk in chunks:
    t = threading.Thread(target=scan_range, args=(chunk,))
    t.daemon = True
    threads.append(t)

start = time.time()
for t in threads:
    t.start()
for t in threads:
    t.join()

elapsed = time.time() - start
print(f"\nScan complete in {elapsed:.1f}s")
print("Wait 15 seconds for idle flows to expire and get scored...")
print("Then check the Live Capture page for Port Scan detection.")
