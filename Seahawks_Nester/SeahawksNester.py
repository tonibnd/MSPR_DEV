from flask import Flask, request, jsonify, render_template, send_from_directory, abort
import json
import os
from datetime import datetime

app = Flask(__name__)

# Dictionnaire pour stocker les données, structurées par client_id
data_store = {"clients": {}}

# Dictionnaire pour associer les adresses IP aux IDs clients
ip_to_client_id = {}

# Compteur pour générer de nouveaux IDs clients
next_client_id = 1

# Emplacement des fichiers de données des clients
CLIENT_DATA_FOLDER = os.path.join(app.root_path, 'client_data')

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/api/data', methods=['POST'])
def receive_data():
    global next_client_id  # Permet de modifier la variable globale
    data = request.json
    client_ip = request.remote_addr  # Récupère l'adresse IP du client envoyant les données

    # Vérifie si l'adresse IP est déjà associée à un client_id
    if client_ip not in ip_to_client_id:
        # Si nouvelle IP, attribue un nouvel ID client et l'associe à l'IP
        ip_to_client_id[client_ip] = next_client_id
        client_id = next_client_id
        next_client_id += 1  # Prépare l'ID pour le prochain nouveau client
    else:
        # Si IP connue, récupère l'ID client existant
        client_id = ip_to_client_id[client_ip]

    # Crée un dossier pour le client_id s'il n'existe pas déjà
    client_folder = os.path.join(CLIENT_DATA_FOLDER, str(client_id))
    if not os.path.exists(client_folder):
        os.makedirs(client_folder)

    # Génère le nom de fichier basé sur la date et l'heure actuelle
    timestamp = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
    filename = os.path.join(client_folder, f'{timestamp}.json')

    # Écrit les données dans le fichier
    with open(filename, 'w') as f:
        json.dump(data, f, indent=4)

    # Ajoute ou met à jour les données pour ce client_id dans la mémoire
    if client_id not in data_store["clients"]:
        data_store["clients"][client_id] = []
    data_store["clients"][client_id].append(data)

    return jsonify({"message": "Data received successfully", "client_id": client_id}), 200

@app.route('/api/clients', methods=['GET'])
def list_clients():
    """Liste tous les clients disponibles en parcourant le dossier de données des clients."""
    try:
        clients = [f for f in os.listdir(CLIENT_DATA_FOLDER) if os.path.isdir(os.path.join(CLIENT_DATA_FOLDER, f))]
        return jsonify(clients)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/clients/<client_id>', methods=['GET'])
def get_client_data(client_id):
    """Récupère les données pour un client spécifique, uniquement le scan le plus récent."""
    client_folder = os.path.join(CLIENT_DATA_FOLDER, client_id)
    if os.path.exists(client_folder):
        try:
            files = os.listdir(client_folder)
            # Filtre pour inclure seulement les fichiers JSON
            json_files = [f for f in files if f.endswith('.json')]
            if not json_files:
                return jsonify({"error": "No data available for this client"}), 404
            # Trie les fichiers par leur timestamp (du plus récent au plus ancien)
            json_files.sort(key=lambda f: datetime.strptime(f, '%Y-%m-%d_%H-%M-%S.json'), reverse=True)
            # Ouvre seulement le fichier le plus récent
            with open(os.path.join(client_folder, json_files[0]), 'r') as file:
                data = json.load(file)
            return jsonify(data)
        except Exception as e:
            return jsonify({"error": str(e)}), 500
    else:
        return abort(404, description="Client not found")


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
