import nmap
import concurrent.futures
import time
import socket
from scapy.all import ARP, Ether, srp

def get_local_ip_range():
    # Obtenir l'adresse IP de l'hôte local
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))  # Connectez-vous à un serveur de test (Google DNS)
    local_ip_address = s.getsockname()[0]
    s.close()
    # Extraire le préfixe réseau (par exemple, "192.168.1.")
    ip_prefix = local_ip_address.rsplit('.', 1)[0] + '.0'
    # Définir la plage d'adresses IP à scanner (par exemple, "192.168.1.0/24")
    ip_range = f"{ip_prefix}/24"
    return ip_range

def ping_sweep(ip_range):
    arp_request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip_range)
    answered, _ = srp(arp_request, timeout=2, verbose=False)
    return [received_packet[1].psrc for received_packet in answered]

def print_scan_results(results):
    for index, result in enumerate(results, start=1):
        print(f"\nScan Result {index}:")
        print(f"Host: {result['host']}")
        print(f"Hostname: {result['hostname']}")
        print(f"State: {result['state']}")
        
        if result['open_ports']:
            print("Open Ports:")
            for port_info in result['open_ports']:
                print(f"- Port: {port_info['port']}, Service: {port_info['service']}")
        else:
            print("No open ports found.")

def nmapscan(target, total_targets, scanned_count):
    nm = nmap.PortScanner()
    nm.scan(target, arguments='-sN')

    results = []

    for host in nm.all_hosts():
        print(nm[host])
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
    
    # Mettre à jour le nombre d'adresses IP scannées jusqu'à présent
    scanned_count[0] += 1
    # Calculer le pourcentage d'avancement
    progress_percentage = (scanned_count[0] / total_targets) * 100
    print(f"Scanning progress: {progress_percentage:.2f}%", end='\r')  # Utilisation de \r pour écraser la ligne précédente

    return results



def scan_targets(target_list):
    all_results = []
    total_targets = len(target_list)
    scanned_count = [0]

    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor: #utilisation de 4 ou 3 threads pour scanner les adresses IP car meilleurs performances
        futures = {executor.submit(nmapscan, target, total_targets, scanned_count): target for target in target_list}
        for future in concurrent.futures.as_completed(futures):
            try:
                result = future.result()
                all_results.extend(result)
            except Exception as exc:
                print(f"Error scanning target: {futures[future]}\n{exc}")

    return all_results

if __name__ == "__main__":
    start_time = time.time()

    local_ip_range = get_local_ip_range()
    print(f"Scanning IP range: {local_ip_range}")
    responding_ips = ping_sweep(local_ip_range)
    
    if responding_ips:
        print("Responding IP addresses found. \nScanning with Nmap...")
        print("Scanning progress: 0.00%", end="\r")
    else:
        print("No responding IP addresses found.")
        exit()
    all_results = scan_targets(responding_ips)

    print()
    print_scan_results(all_results)

    end_time = time.time()
    execution_time = end_time - start_time
    print(f"Temps d'exécution total : {execution_time} secondes")
