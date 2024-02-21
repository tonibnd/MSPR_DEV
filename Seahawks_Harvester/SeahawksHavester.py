import tkinter as tk
from tkinter import ttk, scrolledtext
from tkinter import scrolledtext
import nmap
import concurrent.futures
import time
import socket
from scapy.all import ARP, Ether, srp
import requests
import threading
import os
import re
import sys
import subprocess

# Fonction pour envoyer des données à un serveur
def send_data_to_server(url, data):
    try:
        response = requests.post(url, json=data)
        print(data)
        if response.status_code == 200:
            print("Data successfully sent to server.")
        else:
            print(f"Failed to send data to server. Status code: {response.status_code}")
    except Exception as e:
        print(f"Error sending data to server: {e}")

# Obtenir la plage d'adresses IP locales
def get_local_ip_range():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    local_ip_address = s.getsockname()[0]
    s.close()
    ip_prefix = local_ip_address.rsplit('.', 1)[0] + '.0'
    ip_range = f"{ip_prefix}/24"
    return ip_range

# Fonction pour effectuer un balayage ping
def ping_sweep(ip_range):
    arp_request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip_range)
    answered, _ = srp(arp_request, timeout=2, verbose=False)
    return [received_packet[1].psrc for received_packet in answered]

# Fonction pour scanner avec Nmap
def nmapscan(target, total_targets, scanned_count, results_container, progress_var, percentage_label, root):
    nm = nmap.PortScanner()
    nm.scan(target, arguments='-A')

    results = []

    for host in nm.all_hosts():
        if nm[host].state() == 'up':
            host_info = {
                'host': host,
                'hostname': '',
                'state': nm[host].state(),
                'open_ports': []
            }
            try:
                # Utilisation de la résolution de nom inverse du module socket
                host_info['hostname'] = socket.gethostbyaddr(host)[0]
            except socket.herror:
                host_info['hostname'] = "N/A"

            for proto in nm[host].all_protocols():
                if proto == 'tcp':
                    for port in nm[host][proto]:
                        if nm[host][proto][port]['state'] == 'open':
                            host_info['open_ports'].append({
                                'port': port,
                                'service': nm[host][proto][port]['name']
                            })

            results.append(host_info)

    scanned_count[0] += 1
    progress_percentage = (scanned_count[0] / total_targets) * 100
    progress_var.set(progress_percentage)
    percentage_label.config(text=f"{int(progress_percentage)}%")
    root.update_idletasks()  # Mettre à jour l'interface utilisateur avec le pourcentage de progression

    send_data_to_server("http://192.168.206.143:5000/api/data", results)

    results_container.extend(results)

# Fonction principale pour démarrer le scan
def start_scan(progress_var, percentage_label, text_widget, root):
    text_widget.configure(state='normal')
    text_widget.delete(1.0, tk.END)
    text_widget.configure(state='disabled')
    progress_var.set(0)
    start_time = time.time()
    local_ip_range = get_local_ip_range()
    responding_ips = ping_sweep(local_ip_range)
    responding_ips.remove('192.168.1.200')  # A retirer pour le rendu final
    all_results = []
    scanned_count = [0]

    if responding_ips:
        total_targets = len(responding_ips)
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
            futures = [executor.submit(nmapscan, ip, total_targets, scanned_count, all_results, progress_var, percentage_label, root) for ip in responding_ips]
            for future in concurrent.futures.as_completed(futures):
                try:
                    future.result()
                except Exception as exc:
                    print(f"Error scanning target: {exc}")

    end_time = time.time()
    execution_time = end_time - start_time
    text_widget.configure(state='normal')
    text_widget.insert(tk.END, f"\nTemps d'exécution total : {execution_time} secondes\n")
    for index, result in enumerate(all_results, start=1):
        text_widget.insert(tk.END, f"\nScan Result {index}:\n")
        text_widget.insert(tk.END, f"Host: {result['host']}\n")
        text_widget.insert(tk.END, f"Hostname: {result['hostname']}\n")
        text_widget.insert(tk.END, f"State: {result['state']}\n")
        
        if result['open_ports']:
            text_widget.insert(tk.END, "Open Ports:\n")
            for port_info in result['open_ports']:
                text_widget.insert(tk.END, f"- Port: {port_info['port']}, Service: {port_info['service']}\n")
        else:
            text_widget.insert(tk.END, "No open ports found.\n")
    text_widget.configure(state='disabled')

# Ajoutons une fonction pour obtenir le nom de l'hôte et l'adresse IP locale
def get_host_info():
    host_name = socket.gethostname()
    local_ip = socket.gethostbyname(host_name)
    return host_name, local_ip

# Ajoutons une fonction pour calculer la latence moyenne d'accès WAN
def get_wan_latency(target='8.8.8.8', count=4):
    ping_cmd = f"ping -c {count} {target}"
    response = os.popen(ping_cmd).read()
    match = re.search(r'(\d+\.\d+)/(\d+\.\d+)/(\d+\.\d+)', response)
    if match:
        return match.group(2)  # Retourne la latence moyenne
    return "N/A"

def update_application():
    try:
        # Définissez l'URL de votre dépôt GitLab
        repo_url = 'https://gitlab.com/msprs/TPRE511'
        # Définissez le chemin local de votre application
        local_repo_path = '"D:\cours\EPSI\MSPRs\MSPR_DEV"'

        # Vérifier les mises à jour en utilisant git fetch
        subprocess.check_call(['git', 'fetch'], cwd=local_repo_path)

        # Vérifier si le HEAD actuel est différent du remote/origin
        local_head = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=local_repo_path).strip()
        remote_head = subprocess.check_output(['git', 'rev-parse', 'origin/main'], cwd=local_repo_path).strip()

        if local_head != remote_head:
            # Appliquer les mises à jour en utilisant git pull
            subprocess.check_call(['git', 'pull', 'origin', 'main'], cwd=local_repo_path)
            print("Application updated. Restarting...")
            # Relancer l'application
            os.execl(sys.executable, sys.executable, *sys.argv)
        else:
            print("No updates available.")

    except subprocess.CalledProcessError as e:
        print(f"An error occurred while updating the application: {e}")

# Interface graphique
def create_gui():
    root = tk.Tk()
    root.title("Network Scanner")
    
    # Style configuration
    style = ttk.Style(root)
    style.theme_use("clam")  # Using a theme for a more modern look

    # Main frame
    main_frame = ttk.Frame(root, padding="10")
    main_frame.pack(fill=tk.BOTH, expand=True)

    # Host info
    host_name, local_ip = get_host_info()
    host_info_frame = ttk.Frame(main_frame, padding="10")
    host_info_frame.pack(fill=tk.X)
    host_info_label = ttk.Label(host_info_frame, text=f"Host: {host_name}, Local IP: {local_ip}")
    host_info_label.pack(side=tk.LEFT)

    # WAN Latency
    latency_label = ttk.Label(main_frame, text=f"WAN Latency: {get_wan_latency()} ms")
    latency_label.pack(fill=tk.X)

    # Ajoutez un bouton pour mettre à jour l'application
    update_btn = ttk.Button(main_frame, text="Update Application", command=update_application)
    update_btn.pack(pady="10")

    # Scan button with an icon
    scan_icon = tk.PhotoImage(file="Seahawks_Harvester\scan_icon.png") 
    scan_icon = scan_icon.subsample(5, 5)
    scan_btn = ttk.Button(main_frame, text="Start Scan", image=scan_icon, compound=tk.LEFT, command=lambda: threading.Thread(target=start_scan, args=(progress_var, percentage_label, result_text, root)).start())
    scan_btn.pack(pady="10")

    # Configure the style for the green progress bar
    style.configure('green.Horizontal.TProgressbar', background='green')

    # Progress bar
    progress_var = tk.DoubleVar()
    progress_bar = ttk.Progressbar(main_frame, variable=progress_var, maximum=100, length=250, style='green.Horizontal.TProgressbar')
    progress_bar.pack(pady="10")

    # Percentage label
    percentage_label = ttk.Label(main_frame, text="0%")
    percentage_label.pack()

    # Results area
    result_text = scrolledtext.ScrolledText(main_frame, width=70, height=30, state='disabled', font=("Courier", 10))
    result_text.pack(fill=tk.BOTH, expand=True)

    # Version label at the bottom
    version_label = ttk.Label(main_frame, text="Application Version: 1.0.0")
    version_label.pack(side=tk.RIGHT)

    root.mainloop()

if __name__ == "__main__":
    create_gui()
