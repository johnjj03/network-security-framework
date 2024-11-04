from flask import Flask, render_template, request, jsonify, session, send_from_directory
from flask_cors import CORS
import os
from analysis import detect_dos
from visualisation import plot_packet_rate
from malware import analyze_malware
from scapy.all import rdpcap
from werkzeug.utils import secure_filename
from nmap import extract_addresses_and_ports
app = Flask(__name__)
CORS(app)  # Enable CORS for all routes

# Set base directory dynamically based on the project location
base_dir = os.path.abspath(os.path.dirname(__file__))

# Set the upload folder and graph folder paths relative to your project directory
PCAP_FOLDER = os.path.join(base_dir, 'static', 'uploads')
GRAPH_FOLDER = os.path.join(base_dir, 'static', 'graphs')

# Create directories if they don't exist
os.makedirs(PCAP_FOLDER, exist_ok=True)
os.makedirs(GRAPH_FOLDER, exist_ok=True)

app.config['PCAP_FOLDER'] = PCAP_FOLDER
app.config['GRAPH_FOLDER'] = GRAPH_FOLDER
app.config['STATIC_FOLDER'] = os.path.join(base_dir, 'static')

# Define allowed file extensions
ALLOWED_EXTENSIONS = {'pcap', 'pcapng'}

# Set a secret key for sessions
app.config['SECRET_KEY'] = 'your-secret-key'

# Helper function to check if a file has the allowed extension
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Route to handle the homepage
@app.route('/')
def index():
    return render_template('index.html')

# Route to download results
@app.route('/results/<path:filename>')
def download_file(filename):
    return send_from_directory('.', filename)

# Static route to serve graph images (only defined **once**)
@app.route('/static/graphs/<filename>')
def serve_graph(filename):
    return send_from_directory(app.config['GRAPH_FOLDER'], filename)

# Route for DDoS detection
@app.route('/detect', methods=['POST'])
def detect_ddos():
    if 'file' not in request.files:
        return jsonify({'error': 'No file part in the request'}), 400

    file = request.files['file']

    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400

    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['PCAP_FOLDER'], filename)
        file.save(filepath)

        try:
            packets = rdpcap(filepath)
            result = detect_dos(packets)

            response = {
                'status': 'success',
                'message': f'File "{filename}" was successfully analyzed for DDoS attacks.',
                'result': result,
                'recommendation': 'Please review the report and take immediate action if threats are detected.'
            }
            return jsonify(response), 200

        except Exception as e:
            return jsonify({'error': f'Error processing file: {str(e)}'}), 500

    return jsonify({'error': 'Invalid file type. Upload a .pcap or .pcapng file.'}), 400

# Route to visualize traffic
@app.route('/visualize_traffic', methods=['POST'])
def visualize_traffic():
    if 'file' not in request.files:
        return jsonify({'error': 'No file part in the request'}), 400

    file = request.files['file']

    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400

    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['PCAP_FOLDER'], filename)
        file.save(filepath)

        try:
            image_path = plot_packet_rate(filepath)

            relative_image_path = os.path.relpath(image_path, start=app.config['GRAPH_FOLDER'])

            return jsonify({'image_path': f'static/graphs/{relative_image_path}'})

        except Exception as e:
            return jsonify({'error': f'Error generating graph: {str(e)}'}), 500

    return jsonify({'error': 'Invalid file type. Upload a .pcap or .pcapng file.'}), 400

# Route for malware analysis
@app.route('/malware', methods=['POST'])
def malware():
    if 'file' not in request.files:
        return jsonify({'error': 'No file part in the request'}), 400

    file = request.files['file']

    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['PCAP_FOLDER'], filename)
        file.save(filepath)

        try:
            results = analyze_malware(filepath)

            return jsonify({'result': results}), 200

        except Exception as e:
            return jsonify({'error': f'Error during malware analysis: {str(e)}'}), 500

    return jsonify({'error': 'Invalid file type. Upload a .pcap or .pcapng file.'}), 400

# Serve the malware results page
@app.route('/malware_results')
def malware_results():
    results = session.get('results')
    return render_template('malware_results.html', results=results)


@app.route('/nmap', methods=['POST'])
def nmap():
    if 'file' not in request.files:
        return jsonify({'error': 'No file part in the request'}), 400

    file = request.files['file']

    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['PCAP_FOLDER'], filename)
        file.save(filepath)

        try:
            results = extract_addresses_and_ports(filepath)

            return jsonify({'result': results}), 200

        except Exception as e:
            return jsonify({'error': f'Error during Nmap analysis: {str(e)}'}), 500

    return jsonify({'error': 'Invalid file type. Upload a .pcap or .pcapng file.'}), 400

if __name__ == '__main__':
    app.run(debug=True)
