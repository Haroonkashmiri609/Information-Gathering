import socket
import subprocess
import whois
from bs4 import BeautifulSoup
import requests
from tkinter import Tk, Label, Entry, Button, Text, Scrollbar, END
import threading


def get_website_ip(domain):
    """Get the IP address of the domain."""
    try:
        ip_address = socket.gethostbyname(domain)
        return f"[+] IP Address: {ip_address}\n"
    except Exception as e:
        return f"[-] Error getting IP: {e}\n"


def get_domain_info(domain):
    """Fetch domain WHOIS information."""
    try:
        domain_info = whois.whois(domain)
        info = "\n[+] Domain WHOIS Information:\n"
        for key, value in domain_info.items():
            info += f"{key}: {value}\n"
        return info
    except Exception as e:
        return f"[-] Error getting domain information: {e}\n"


def get_open_ports_and_services(ip):
    """Scan for open ports 21, 80, and 443 with service and version detection."""
    try:
        result = subprocess.check_output(["nmap", "-p", "21,80,443", "-sV", "-Pn", ip]).decode()
        return f"\n[+] Open Ports and Services:\n{result}\n"
    except Exception as e:
        return f"[-] Error scanning ports and services: {e}\n"


def get_website_details(url):
    """Scrape website details."""
    try:
        response = requests.get(url, timeout=10)
        soup = BeautifulSoup(response.text, "html.parser")
        title = soup.title.string if soup.title else "No Title Found"
        description = soup.find("meta", attrs={"name": "description"})
        description = description["content"] if description else "No Description Found"
        return f"\n[+] Website Details:\nTitle: {title}\nDescription: {description}\n"
    except Exception as e:
        return f"[-] Error getting website details: {e}\n"


def check_vulnerabilities(ip):
    """Perform a CVE vulnerability check and display potential vulnerabilities."""
    try:
        url = f"https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword={ip}"
        response = requests.get(url, timeout=10)
        if "No matching records" in response.text:
            return "\n[+] No known vulnerabilities found for this IP.\n"
        else:
            soup = BeautifulSoup(response.text, "html.parser")
            vulnerabilities = soup.find_all("a", href=True)
            cve_list = "\n".join([f"- {vul.text.strip()}" for vul in vulnerabilities if "CVE-" in vul.text])
            return f"\n[+] Potential Vulnerabilities Found:\n{cve_list}\n"
    except Exception as e:
        return f"[-] Error checking vulnerabilities: {e}\n"


def gather_info():
    """Gather all information and display in the GUI."""
    domain = domain_entry.get().strip()
    if not domain:
        output_text.insert(END, "[-] Please enter a domain!\n")
        return

    # Remove protocol if present
    if domain.startswith("http://") or domain.startswith("https://"):
        domain = domain.split("//")[1].strip("/")

    output_text.delete(1.0, END)  # Clear previous output
    output_text.insert(END, f"[!] Gathering information for {domain}...\n")

    try:
        ip_address = socket.gethostbyname(domain)
        output_text.insert(END, get_website_ip(domain))
        output_text.insert(END, get_website_details(f"http://{domain}"))
        output_text.insert(END, get_domain_info(domain))
        output_text.insert(END, get_open_ports_and_services(ip_address))
        output_text.insert(END, check_vulnerabilities(ip_address))
        output_text.insert(END, "\n[!] Scan completed successfully.\n")
    except Exception as e:
        output_text.insert(END, f"[-] Error during scan: {e}\n")


def on_focus_in(event):
    """Clear the placeholder text when the user clicks on the entry field."""
    if domain_entry.get() == "https://example.com":
        domain_entry.delete(0, END)

def on_focus_out(event):
    """Restore the placeholder text if the user leaves the field empty."""
    if domain_entry.get() == "":
        domain_entry.insert(0, "https://example.com")


def start_scan():
    """Start the scan in a separate thread."""
    threading.Thread(target=gather_info).start()


# GUI setup
root = Tk()
root.title("Pro Domain Info GUI")
root.geometry("1000x750")
root.configure(bg="#1e1e2e")

# Input field
Label(root, text="Enter Website Domain:", fg="white", bg="#1e1e2e", font=("Arial", 14, "bold")).pack(pady=5)
domain_entry = Entry(root, width=50, font=("Arial", 14))
domain_entry.insert(0, "https://example.com")  # Placeholder text
domain_entry.bind("<FocusIn>", on_focus_in)  # Clear text on focus
domain_entry.bind("<FocusOut>", on_focus_out)  # Restore text on focus out
domain_entry.pack(pady=5)

# Buttons
Button(root, text="Start Scan", command=start_scan, bg="#4CAF50", fg="white", font=("Arial", 14)).pack(pady=10)

# Output area
Label(root, text="Output:", fg="white", bg="#1e1e2e", font=("Arial", 14, "bold")).pack(pady=5)
scrollbar = Scrollbar(root)
scrollbar.pack(side="right", fill="y")

output_text = Text(root, wrap="word", yscrollcommand=scrollbar.set, width=100, height=25, bg="#2b2b2b", fg="#dcdcdc", font=("Courier New", 12))
output_text.pack(padx=10, pady=5)

scrollbar.config(command=output_text.yview)

# Run the GUI
root.mainloop()
