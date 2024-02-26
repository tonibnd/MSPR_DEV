import subprocess
import sys

# Vérifier si un argument de chemin a été fourni
if len(sys.argv) > 1:
    local_repo_path = sys.argv[1]  # Le chemin d'installation est le premier argument
else:
    print("No local repository path provided.")
    sys.exit(1)

def install_setuptools():
    """
    Vérifie si setuptools est installé. S'il ne l'est pas, l'installe.
    """
    try:
        # Essaye d'importer setuptools
        import setuptools
        print("setuptools est déjà installé.")
    except ImportError:
        print("Installation de setuptools...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "setuptools"])
        print("setuptools a été installé avec succès.")

# Liste des dépendances requises par l'application, incluant maintenant setuptools dans la vérification.
required_packages = ['requests', 'scapy', 'python-nmap', 'setuptools']

def install_packages(packages):
    """
    Installe les paquets spécifiés qui ne sont pas déjà installés.

    Parameters:
    - packages (list): Une liste de noms de paquets à installer.
    """
    try:
        import pkg_resources
    except ImportError:
        install_setuptools()
        import pkg_resources  # Réessaye l'importation après l'installation de setuptools

    installed_packages = {pkg.key for pkg in pkg_resources.working_set}
    missing_packages = [pkg for pkg in packages if pkg not in installed_packages]
    if missing_packages:
        print("Installation des paquets manquants : " + ", ".join(missing_packages))
        subprocess.check_call([sys.executable, '-m', 'pip', 'install', *missing_packages])

# Assurez-vous que toutes les dépendances, y compris setuptools, sont installées au démarrage.
install_packages(required_packages)

# Importations après l'installation des paquets pour éviter des erreurs d'importation.
import tkinter as tk
from tkinter import ttk, scrolledtext
import nmap
import concurrent.futures
import socket
from scapy.all import ARP, Ether, srp
import requests
import threading
import os
import re
import platform
import time


def send_data_to_server(url, data):
    """
    Envoie des données à un serveur via une requête POST.

    Parameters:
    - url (str): L'URL du serveur auquel envoyer les données.
    - data (dict): Le dictionnaire contenant les données à envoyer.

    Cette fonction tente d'envoyer des données à un serveur spécifié par URL.
    Elle imprime le statut de la requête. En cas de succès, un message de confirmation est affiché.
    En cas d'échec, le code de statut de la réponse est affiché.
    """
    try:
        response = requests.post(url, json=data)
        print(data)
        if response.status_code == 200:
            print("Data successfully sent to server.")
        else:
            print(f"Failed to send data to server. Status code: {response.status_code}")
    except Exception as e:
        print(f"Error sending data to server: {e}")


def get_local_ip_range():
    """
    Détermine la plage d'adresses IP locales de la machine en se basant sur son adresse IP actuelle.

    Cette fonction crée une socket UDP temporaire pour se connecter à un serveur DNS public (ici, 8.8.8.8 sur le port 80),
    afin de déterminer l'adresse IP actuelle de la machine sur le réseau. Elle ne transmet pas de données.
    Ensuite, elle extrait le préfixe de l'adresse IP et construit une plage d'adresses IP au format CIDR (Classless Inter-Domain Routing),
    supposant un masque de sous-réseau de 24 bits (255.255.255.0).

    Returns:
    str: La plage d'adresses IP locales au format CIDR.
    """

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    local_ip_address = s.getsockname()[0]
    s.close()
    ip_prefix = local_ip_address.rsplit('.', 1)[0] + '.0'
    ip_range = f"{ip_prefix}/24"
    return ip_range


def ping_sweep(ip_range):
    """
    Exécute un balayage de ping sur une plage d'adresses IP pour déterminer les hôtes actifs.

    Parameters:
    - ip_range (str): La plage d'adresses IP à balayer.

    Returns:
    list: Une liste d'adresses IP qui ont répondu au ping.
    """

    arp_request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip_range)
    answered, _ = srp(arp_request, timeout=2, verbose=False)
    return [received_packet[1].psrc for received_packet in answered]


def nmapscan(target, total_targets, scanned_count, results_container, progress_var, percentage_label, root):
    """
    Exécute un scan Nmap sur une adresse IP cible.

    Parameters:
    - target (str): L'adresse IP cible à scanner.
    - total_targets (int): Le nombre total d'adresses IP à scanner.
    - scanned_count (list): Une liste contenant un seul élément, le nombre d'adresses IP déjà scannées.
    - results_container (list): Une liste pour stocker les résultats du scan.
    - progress_var (tkinter.DoubleVar): Une variable de progression pour mettre à jour l'interface utilisateur.
    - percentage_label (tkinter.Label): Un label pour afficher le pourcentage de progression.
    - root (tkinter.Tk): La fenêtre principale de l'application.

    Cette fonction utilise le module python-nmap pour exécuter un scan Nmap sur une adresse IP cible.
    Elle met à jour l'interface utilisateur avec le pourcentage de progression à l'aide de la variable de progression et du label.
    Elle stocke les résultats du scan dans une liste pour les envoyer au serveur ultérieurement.
    """

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
    # Mettre à jour l'interface utilisateur avec le pourcentage de progression
    root.update_idletasks() 

    send_data_to_server("http://192.168.206.143:5000/api/data", results)

    results_container.extend(results)


def start_scan(progress_var, percentage_label, text_widget, root):
    """
    Démarre un scan de réseau en utilisant un balayage de ping pour déterminer les hôtes actifs,
    puis un scan Nmap pour obtenir des informations détaillées sur chaque hôte actif.

    Parameters:
    - progress_var (tkinter.DoubleVar): Une variable de progression pour mettre à jour l'interface utilisateur.
    - percentage_label (tkinter.Label): Un label pour afficher le pourcentage de progression.
    - text_widget (tkinter.scrolledtext.ScrolledText): Un widget de texte pour afficher les résultats du scan.
    - root (tkinter.Tk): La fenêtre principale de l'application.

    Cette fonction utilise le module concurrent.futures pour exécuter plusieurs scans Nmap en parallèle.
    Elle met à jour l'interface utilisateur avec le pourcentage de progression à l'aide de la variable de progression et du label.
    Elle affiche les résultats du scan dans un widget de texte.
    """

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


def get_host_info():
    """
    Obtient le nom de l'hôte et l'adresse IP locale de la machine.

    Returns:
    tuple: Un tuple contenant le nom de l'hôte et l'adresse IP locale.
    """

    host_name = socket.gethostname()
    local_ip = socket.gethostbyname(host_name)
    return host_name, local_ip


def get_wan_latency(target='8.8.8.8', count=4):
    """
    Calcule la latence moyenne d'accès WAN en utilisant la commande ping.

    Parameters:
    - target (str): L'adresse IP ou le nom d'hôte à pinguer.
    - count (int): Le nombre de paquets à envoyer.

    Returns:
    str: La latence moyenne en millisecondes, ou "N/A" si la commande ping a échoué.
    """

    # Déterminer le système d'exploitation
    oper = platform.system()

    # Configurer la commande ping en fonction du système d'exploitation
    if oper == "Windows":
        ping_cmd = f"ping -n {count} {target}"
    else:
        ping_cmd = f"ping -c {count} {target}"

    try:
        response = subprocess.check_output(ping_cmd, stderr=subprocess.STDOUT, shell=True, universal_newlines=True)

        # Rechercher la latence moyenne dans la réponse en fonction de l'OS
        if oper == "Windows":
            match = re.search(r'Moyenne = (\d+)ms', response)
        else:
            match = re.search(r'/(\d+\.\d+)/', response)

        if match:
            return match.group(1)
    except subprocess.CalledProcessError as e:
        print(f"Command failed: {e.output}")

    return "N/A"


def update_application():
    """
    Met à jour l'application en récupérant les dernières modifications à partir du dépôt GitLab.

    Cette fonction utilise git fetch pour vérifier les mises à jour, puis git pull pour appliquer les modifications.
    Si des mises à jour sont disponibles, l'application est redémarrée pour les appliquer.
    """

    try:
        repo_url = 'https://github.com/tonibnd/MSPR_DEV'

        current_repo_url = subprocess.check_output(['git', 'config', '--get', 'remote.origin.url'], cwd=local_repo_path).decode('utf-8').strip()
        if current_repo_url != repo_url:
            print(f"Le dépôt local est configuré pour utiliser {current_repo_url}, qui est différent de {repo_url}")
            return

        # Vérifier les mises à jour en utilisant git fetch
        subprocess.check_call(['git', 'fetch'], cwd=local_repo_path)

        # Vérifier si le HEAD actuel est différent du remote/origin
        local_head = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=local_repo_path).decode('utf-8').strip()
        remote_head = subprocess.check_output(['git', 'rev-parse', 'origin/main'], cwd=local_repo_path).decode('utf-8').strip()

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


def create_gui():
    """
    Crée l'interface graphique de l'application.

    Cette fonction utilise le module tkinter pour créer une interface utilisateur simple.
    Elle crée une fenêtre principale avec des widgets pour afficher les informations sur l'hôte, la latence WAN,
    un bouton pour mettre à jour l'application, un bouton pour démarrer le scan, une barre de progression, un label de pourcentage,
    un widget de texte pour afficher les résultats du scan, et un label de version.
    """
    
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

    # Scan button 
    scan_btn = ttk.Button(main_frame, text="Start Scan", compound=tk.LEFT, command=lambda: threading.Thread(target=start_scan, args=(progress_var, percentage_label, result_text, root)).start())
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
    update_application()
