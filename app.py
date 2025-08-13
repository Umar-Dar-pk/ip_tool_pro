from flask import Flask, render_template, request, jsonify
import requests
import socket
import time

app = Flask(__name__)

def get_server_public_ip():
    try:
        return requests.get("https://api64.ipify.org?format=json", timeout=4).json().get("ip", "Unavailable")
    except:
        return "Unavailable"

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/server_info")
def server_info():
    client_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    server_ip = get_server_public_ip()

    city = country = org = "Unknown"
    try:
        geo = requests.get(f"https://ipapi.co/{client_ip}/json/", timeout=4).json()
        city = geo.get("city", "Unknown")
        country = geo.get("country_name", "Unknown")
        org = geo.get("org", "Unknown")
    except:
        pass

    return jsonify({
        "client_ip": client_ip,
        "server_ip": server_ip,
        "city": city,
        "country": country,
        "org": org
    })

@app.route("/ping_test")
def ping_test():
    # simple small response for client-side ping/packet-loss test
    return jsonify({"ok": True, "ts": time.time()}), 200

@app.route("/port_scan", methods=["POST"])
def port_scan():
    """
    Expect JSON:
    {
      "host": "example.com or IP",
      "ports": "22,80,443"  // comma separated or list
    }
    Returns JSON with each port open/closed and any error.
    """
    data = request.get_json(force=True)
    host = data.get("host", "").strip()
    ports_raw = data.get("ports", "")
    if not host:
        return jsonify({"ok": False, "error": "No host provided"}), 400

    # normalize ports
    if isinstance(ports_raw, str):
        ports = []
        for p in ports_raw.split(","):
            p = p.strip()
            if not p:
                continue
            try:
                ports.append(int(p))
            except:
                pass
    elif isinstance(ports_raw, list):
        ports = [int(p) for p in ports_raw]
    else:
        ports = []

    if not ports:
        return jsonify({"ok": False, "error": "No valid ports found"}), 400

    results = {}
    for port in ports:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1.5)  # short timeout
        try:
            res = s.connect_ex((host, port))
            results[port] = "open" if res == 0 else "closed"
        except Exception as e:
            results[port] = f"error: {str(e)}"
        finally:
            s.close()

    return jsonify({"ok": True, "host": host, "results": results})

@app.route("/port_commands", methods=["POST"])
def port_commands():
    """
    Returns suggested commands to open/close a port on common OSes.
    This endpoint only generates commands; it DOES NOT execute them.
    JSON input: {"port": 1234, "action": "open" or "close"}
    """
    data = request.get_json(force=True)
    port = int(data.get("port", 0))
    action = data.get("action", "open").lower()
    if port <= 0 or port > 65535:
        return jsonify({"ok": False, "error": "Invalid port"}), 400
    if action not in ("open", "close"):
        return jsonify({"ok": False, "error": "Invalid action"}), 400

    # commands (examples) — user must run these as root/administrator
    cmd = {}
    if action == "open":
        cmd['ufw'] = f"sudo ufw allow {port} && sudo ufw reload"
        cmd['iptables'] = f"sudo iptables -A INPUT -p tcp --dport {port} -j ACCEPT && sudo iptables-save"
        cmd['firewall-cmd'] = f"sudo firewall-cmd --permanent --add-port={port}/tcp && sudo firewall-cmd --reload"
        cmd['windows_netsh'] = f'netsh advfirewall firewall add rule name="Allow Port {port}" dir=in action=allow protocol=TCP localport={port}'
    else:
        cmd['ufw'] = f"sudo ufw delete allow {port} && sudo ufw reload"
        cmd['iptables'] = f"sudo iptables -D INPUT -p tcp --dport {port} -j ACCEPT && sudo iptables-save"
        cmd['firewall-cmd'] = f"sudo firewall-cmd --permanent --remove-port={port}/tcp && sudo firewall-cmd --reload"
        cmd['windows_netsh'] = f'netsh advfirewall firewall delete rule name="Allow Port {port}" protocol=TCP localport={port}'

    return jsonify({"ok": True, "port": port, "action": action, "commands": cmd})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
