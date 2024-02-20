import tkinter as tk
from tkinter import scrolledtext
import nmap
import concurrent.futures
import time
import socket
from scapy.all import ARP, Ether, srp
import requests
import threading

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
def nmapscan(target, total_targets, scanned_count, results_container, progress_var, root):
    nm = nmap.PortScanner()
    nm.scan(target, arguments='-sN')

    results = []

    for host in nm.all_hosts():
        if nm[host].state() == 'up':
            host_info = {
                'host': host,
                'hostname': nm[host].hostname(),
                'state': nm[host].state(),
                'open_ports': []
            }

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
    progress_var.set(f"Scanning progress: {progress_percentage:.2f}%")
    root.update_idletasks()  # Mettre à jour l'interface utilisateur avec le pourcentage de progression

    send_data_to_server("http://192.168.206.143:5000/api/data", results)

    results_container.extend(results)

# Fonction principale pour démarrer le scan
def start_scan(progress_var, text_widget, root):
    text_widget.configure(state='normal')
    text_widget.delete(1.0, tk.END)
    text_widget.configure(state='disabled')
    start_time = time.time()
    local_ip_range = get_local_ip_range()
    responding_ips = ping_sweep(local_ip_range)
    responding_ips.remove('192.168.206.143')  # A retirer pour le rendu final
    all_results = []
    scanned_count = [0]

    if responding_ips:
        total_targets = len(responding_ips)
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
            futures = [executor.submit(nmapscan, ip, total_targets, scanned_count, all_results, progress_var, root) for ip in responding_ips]
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

# Interface graphique
def create_gui():
    root = tk.Tk()
    root.title("Network Scanner")
    root.geometry("800x600")

    progress_var = tk.StringVar()
    progress_label = tk.Label(root, textvariable=progress_var)
    progress_label.pack(pady=10)
    progress_var.set("Scanning progress: 0.00%")

    scan_btn = tk.Button(root, text="Start Scan", command=lambda: threading.Thread(target=start_scan, args=(progress_var, result_text, root)).start())
    scan_btn.pack(pady=10)

    result_text = tk.Text(root, width=70, height=30, state='disabled')
    result_text.pack(pady=10)
    scroll = tk.Scrollbar(root, command=result_text.yview)
    scroll.pack(side=tk.RIGHT, fill=tk.Y)
    result_text.config(yscrollcommand=scroll.set)

    root.mainloop()

if __name__ == "__main__":
    create_gui()
