from flask import Flask, render_template, request, jsonify
import json

app = Flask(__name__)

# Simuler une base de données avec un dictionnaire
data_store = {"scans": []}

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/api/data', methods=['POST'])
def receive_data():
    data = request.json
    data_store["scans"].append(data)
    return jsonify({"message": "Data received successfully"}), 200

@app.route('/api/data', methods=['GET'])
def send_data():
    return jsonify(data_store)

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
