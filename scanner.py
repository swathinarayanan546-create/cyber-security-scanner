import requests
import socket

def scan_ports(host):
    print("\n🔌 Checking Open Ports...")
    common_ports = [21, 22, 23, 80, 443]

    open_ports = []

    for port in common_ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        socket.setdefaulttimeout(1)

        result = sock.connect_ex((host, port))
        if result == 0:
            print(f"Port {port}: OPEN 🔓")
            open_ports.append(port)
        else:
            print(f"Port {port}: Closed 🔒")

        sock.close()

    return open_ports


def check_website(url):
    if not url.startswith("http"):
        url = "https://" + url

    print(f"\n🔍 Scanning: {url}")

    result = f"\nScanning {url}\n"

    try:
        response = requests.get(url, timeout=5)

        result += "Status: Active\n"

        if url.startswith("https"):
            result += "Protocol: HTTPS (Secure)\n"
        else:
            result += "Protocol: HTTP (Not Secure)\n"

        headers = response.headers
        vulnerabilities = []

        if "X-Frame-Options" not in headers:
            vulnerabilities.append("Missing X-Frame-Options")

        if "Content-Security-Policy" not in headers:
            vulnerabilities.append("Missing Content-Security-Policy")

        if "Strict-Transport-Security" not in headers:
            vulnerabilities.append("Missing Strict-Transport-Security")

        if vulnerabilities:
            result += "Vulnerabilities Found:\n"
            for v in vulnerabilities:
                result += f"- {v}\n"
        else:
            result += "No major vulnerabilities found\n"

        # 🔥 Extract host for port scanning
        host = url.replace("http://", "").replace("https://", "").split("/")[0]

        open_ports = scan_ports(host)

        if open_ports:
            result += f"Open Ports: {open_ports}\n"
        else:
            result += "No common ports open\n"

    except:
        result += "Website not reachable\n"

    print(result)
    return result


# 🔽 MAIN
sites = input("Enter websites (comma separated): ").split(",")

all_results = ""

for site in sites:
    site = site.strip()
    all_results += check_website(site)

with open("report.txt", "w") as file:
    file.write(all_results)

print("\n📄 Scan results saved in report.txt")