from flask import Flask, request, jsonify
from flask_cors import CORS

app = Flask(__name__)
CORS(app)  # This allows the Chrome extension to talk to your server

@app.route('/analyze', methods=['POST'])
def analyze_text():
    data = request.json
    text = data.get('text', '').lower()

    # Define threat indicators
    threat_patterns = [
        {'pattern': 'verify your account', 'risk': 'High'},
        {'pattern': 'suspended', 'risk': 'High'},
        {'pattern': 'click here to claim', 'risk': 'Medium'},
        {'pattern': 'bank alert', 'risk': 'High'},
        {'pattern': 'password reset', 'risk': 'Medium'}
    ]
    
    # Analyze
    found_threats = [t for t in threat_patterns if t['pattern'] in text]
    
    if found_threats:
        return jsonify({
            "status": "Phishing Risk Detected!",
            "details": f"Flagged for: {found_threats[0]['pattern']}",
            "confidence": "High"
        })
    
    return jsonify({"status": "Safe", "confidence": "High"})

if __name__ == '__main__':
    app.run(debug=True, port=5000)