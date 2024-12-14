from flask import Flask, render_template, request, jsonify
from Services.Analyze import *
import threading
import scapy.all as scapy

app = Flask(__name__)
@app.route('/')
def home():
    return render_template('index.html')

@app.route('/start_sniffing', methods=['POST'])
def start_sniffing():
    global selected_interface, sniffing, log_messages
    interface = request.json.get('interface')
    if not interface:
        return jsonify({'error': 'No interface provided'}), 400

    selected_interface = interface
    log_messages = []

    thread = threading.Thread(target=sniff, args=(selected_interface,))
    thread.daemon = True
    thread.start()

    return jsonify({'message': f'Sniffing started on {selected_interface}'}), 200

@app.route('/stop_sniffing', methods=['POST'])
def stop_sniffing():
    global sniffing
    sniffing = False
    return jsonify({'message': 'Sniffing stopped'}), 200

@app.route('/logs', methods=['GET'])
def get_logs():
    return jsonify({'logs': log_messages})

@app.route('/interfaces', methods=['GET'])
def get_interfaces():
    interfaces = scapy.get_if_list()
    return jsonify({'interfaces': interfaces})

if __name__ == '__main__':
    app.run(debug=True)
