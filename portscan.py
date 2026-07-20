import socket

# This is usually your home router's IP address. 
# If yours is different (e.g., 192.168.0.1), change it here.
target_ip = "192.168.1.1" 

print(f"Initiating simulated Port Scan against {target_ip}...")

# Blast the first 1000 ports as fast as possible
for port in range(1, 1000):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.01) # Ultra-low timeout to move fast
        s.connect((target_ip, port))
        s.close()
    except Exception:
        pass

print("Scan complete. Check your NIDS terminal!")