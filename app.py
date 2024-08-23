from flask import Flask, render_template, request, redirect, url_for, session, send_from_directory
import os
from analysis import *
from visualisation import *
import time

app = Flask(__name__)

# Set the upload folder
PCAP_FOLDER = r'C:\Users\johng\Documents\College\Capstone\Framework\static\uploads'
GRAPH_FOLDER = r'C:\Users\johng\Documents\College\Capstone\Framework\static\graphs'
app.config['PCAP_FOLDER'] = PCAP_FOLDER
app.config['GRAPH_FOLDER'] =GRAPH_FOLDER
app.config['STATIC_FOLDER'] = 'static'

# Define allowed file extensions
ALLOWED_EXTENSIONS = {'pcap', 'pcapng'}

# Set a secret key for sessions
app.config['SECRET_KEY'] = 'your-secret-key'


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS



@app.route('/')
def index():
    return render_template('index.html')

@app.route('/serve_image')
def serve_image():
    image_path = session.get('image_path')
    if image_path:
        return send_from_directory(app.config['STATIC_FOLDER'], image_path)
    else:
        return 'No image found', 404

@app.route('/detect', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return redirect(request.url)
    file = request.files['file']
    if file.filename == '':
        return redirect(request.url)
    if file and allowed_file(file.filename):
        filename = file.filename
        filename_with_path = os.path.join(app.config['PCAP_FOLDER'], filename)
        file.save(filename_with_path)
        packets = rdpcap(filename_with_path)
        result = detect_dos(packets)
        session['result'] = result 
        return redirect(url_for('results'))
    else:
        return 'Invalid file'

@app.route('/results')
def results():
    result = session.get('result')  
    return render_template('results.html', result=result)

@app.route('/visualize', methods=['POST'])
def visualize():
    if 'file' not in request.files:
        return redirect(request.url)
    file = request.files['file']
    if file.filename == '':
        return redirect(request.url)
    if file and allowed_file(file.filename):
        filename = file.filename
        filename_with_path = os.path.join(app.config['PCAP_FOLDER'], filename)
        file.save(filename_with_path)
        image_path = plot_packet_rate(filename_with_path)
        
        # Convert the absolute path to a relative path from the static directory
        relative_image_path = os.path.relpath(image_path, start=app.config['STATIC_FOLDER'])
        session['image_path'] = relative_image_path.replace('\\', '/')
        
        return redirect(url_for('graph'))
    else:
        return 'Invalid file'

@app.route('/graph')
def graph():
    image_path = session.get('image_path')
    return render_template('graph.html', image_path=image_path)




if __name__ == '__main__':
    app.run(debug=True)