from flask import Flask, request, jsonify
from flask_cors import CORS
import joblib, re, math
from urllib.parse import urlparse

app = Flask(__name__)
CORS(app)   # allows requests from the extension

model  = joblib.load('phishing_model.pkl')
scaler = joblib.load('phishing_scaler.pkl')
le     = joblib.load('phishing_le.pkl')

TRUSTED_DOMAINS = [
    'google.com', 'github.com', 'youtube.com', 'microsoft.com',
    'apple.com', 'amazon.com', 'linkedin.com', 'wikipedia.org',
    'claude.ai', 'openai.com', 'notion.so', 'figma.com',
    'netlify.app', 'vercel.app', 'stackoverflow.com',
]

def is_trusted(hostname):
    return any(hostname == d or hostname.endswith('.' + d) for d in TRUSTED_DOMAINS)

def extract_features(url):
    parsed = urlparse(url)
    hostname = parsed.hostname or ''
    path = parsed.path or ''

    uuid_pattern = r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'
    clean_url = re.sub(uuid_pattern, '', url, flags=re.IGNORECASE)

    freq = {c: clean_url.count(c)/len(clean_url) for c in set(clean_url)} if clean_url else {'a':1}
    entropy = -sum(p * math.log2(p) for p in freq.values())

    tld = hostname.split('.')[-1] if '.' in hostname else 'com'
    try:
        tld_enc = le.transform([tld])[0]
    except ValueError:
        tld_enc = le.transform(['com'])[0]

    suspicious = ['login','verify','secure','account','update',
                  'banking','confirm','password','signin','free']
    
    return [
        len(clean_url),
        url.count('.'),
        1 if url.startswith('https') else 0,
        1 if re.match(r'\d{1,3}(\.\d{1,3}){3}', hostname) else 0,
        len([p for p in path.split('/') if p]),
        len(parsed.query.split('&')) if parsed.query else 0,
        sum(1 for w in suspicious if w in url.lower()),
        len(re.findall(r'[@_!#$%^&*()<>?/|}{~:\[\]]', url)),
        sum(c.isdigit() for c in url),
        entropy,
        tld_enc
    ]

@app.route('/predict', methods=['POST'])
def predict():
    data = request.get_json()
    url  = data.get('url', '')

    if not url:
        return jsonify({'error': 'No URL provided'}), 400

    parsed   = urlparse(url)
    hostname = parsed.hostname or ''

    # whitelist check
    if is_trusted(hostname):
        return jsonify({
            'phishing': False,
            'score': 0.01,
            'risk': 'low',
            'reason': 'trusted_domain'
        })

    features = extract_features(url)
    scaled   = scaler.transform([features])
    prob     = float(model.predict_proba(scaled)[0][1])

    THRESHOLD = 0.75
    return jsonify({
        'phishing': prob >= THRESHOLD,
        'score': round(prob, 4),
        'risk': 'high' if prob >= 0.75 else 'medium' if prob >= 0.45 else 'low'
    })

@app.route('/', methods=['GET'])
def health():
    return jsonify({'status': 'Phishing API running'})

if __name__ == '__main__':
    app.run(debug=False)