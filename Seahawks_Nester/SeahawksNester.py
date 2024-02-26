from flask import Flask, request, jsonify
import json

app = Flask(__name__)

# Dictionnaire pour stocker les données, structurées par client_id
data_store = {"clients": {}}

# Dictionnaire pour associer les adresses IP aux IDs clients
ip_to_client_id = {}

# Compteur pour générer de nouveaux IDs clients
next_client_id = 1

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

    # Assure l'existence d'une entrée pour ce client_id
    if client_id not in data_store["clients"]:
        data_store["clients"][client_id] = []

    # Ajoute ou met à jour les données pour ce client_id
    data_store["clients"][client_id].append(data)

    return jsonify({"message": "Data received successfully", "client_id": client_id}), 200

@app.route('/api/data', methods=['GET'])
def send_data():
    # Envoie les données structurées par client
    return jsonify(data_store["clients"])

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
