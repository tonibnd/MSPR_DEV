from flask import Flask, request, jsonify

app = Flask(__name__)
donnees_scannees = []

@app.route('/api/reception', methods=['POST'])
def reception():
    data = request.json
    donnees_scannees.append(data)
    return jsonify({"message": "Données reçues avec succès"}), 200

if __name__ == "__main__":
    app.run(debug=True, host='0.0.0.0')
