from flask import Flask, render_template, request, jsonify
import json

app = Flask(__name__)

# Changer le stockage des données pour les regrouper par client_id
data_store = {"clients": {}}

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/api/data', methods=['POST'])
def receive_data():
    data = request.json
    client_id = data.get("client_id")  # Assurez-vous que le client envoie bien ce champ.
    if client_id not in data_store["clients"]:
        data_store["clients"][client_id] = []  # Initialise la liste pour ce client_id
    data_store["clients"][client_id].append(data)
    return jsonify({"message": "Data received successfully"}), 200

@app.route('/api/data', methods=['GET'])
def send_data():
    return jsonify(data_store["clients"])  # Envoie les données structurées par client

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
