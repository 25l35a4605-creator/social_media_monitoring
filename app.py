import psycopg2
import psycopg2.extras
import os
import csv
import io
import json
import re
from datetime import datetime, timedelta
import random

from functools import wraps
from flask import (Flask, render_template, request, redirect, url_for,
                   session, flash, jsonify, Response, send_file)
from werkzeug.security import generate_password_hash, check_password_hash

try:
    from reportlab.lib.pagesizes import letter
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.lib import colors as rl_colors
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False

try:
    import openpyxl
    OPENPYXL_AVAILABLE = True
except ImportError:
    OPENPYXL_AVAILABLE = False

try:
    import praw
    PRAW_AVAILABLE = True
except ImportError:
    PRAW_AVAILABLE = False

try:
    import requests as http_requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

app = Flask(__name__)
app.secret_key = 'super_secret_social_media_key_2026'

# ─── ROLE-BASED ACCESS CONTROL ─────────────────────────────────────────────────

# Role hierarchy: Admin > Analyst > Viewer
ROLE_HIERARCHY = {'Admin': 3, 'Analyst': 2, 'Viewer': 1}

def login_required(f):
    """Ensure the user is logged in."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

def require_role(min_role):
    """Restrict access to users whose role meets or exceeds min_role."""
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if 'user_id' not in session:
                return redirect(url_for('login'))
            user_role = session.get('role', 'Viewer')
            if ROLE_HIERARCHY.get(user_role, 0) < ROLE_HIERARCHY.get(min_role, 99):
                flash(f'Access denied. {min_role} role or higher required.', 'error')
                return redirect(url_for('dashboard'))
            return f(*args, **kwargs)
        return decorated
    return decorator

def get_visibility_filter():
    return "1=1", []

import sqlite3

# PostgreSQL connection via DATABASE_URL environment variable
DATABASE_URL = os.environ.get('DATABASE_URL', '')

def is_postgres():
    return bool(DATABASE_URL and DATABASE_URL.startswith('postgres'))

# ─── DATABASE ──────────────────────────────────────────────────────────────────

def get_db():
    if is_postgres():
        return psycopg2.connect(DATABASE_URL, cursor_factory=psycopg2.extras.RealDictCursor)
    else:
        conn = sqlite3.connect('database.db')
        conn.row_factory = sqlite3.Row
        return conn

def format_query(query):
    if not is_postgres():
        return query.replace('%s', '?')
    return query

def db_fetchone(conn, query, params=()):
    """Execute a query and return one row as a dict (or None)."""
    cur = conn.cursor()
    cur.execute(format_query(query), params)
    row = cur.fetchone()
    cur.close()
    return dict(row) if row else None

def db_fetchall(conn, query, params=()):
    """Execute a query and return all rows as a list of dicts."""
    cur = conn.cursor()
    cur.execute(format_query(query), params)
    rows = cur.fetchall()
    cur.close()
    return [dict(row) for row in rows]

def db_execute(conn, query, params=()):
    """Execute a write query (INSERT/UPDATE/DELETE) and commit."""
    cur = conn.cursor()
    cur.execute(format_query(query), params)
    cur.close()
    conn.commit()

def init_db():
    conn = get_db()
    c = conn.cursor()
    
    pk_type = "SERIAL PRIMARY KEY" if is_postgres() else "INTEGER PRIMARY KEY AUTOINCREMENT"
    
    c.execute(f'''CREATE TABLE IF NOT EXISTS users (
        id {pk_type},
        name TEXT NOT NULL,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        role TEXT DEFAULT 'Analyst'
    )''')
    c.execute(f'''CREATE TABLE IF NOT EXISTS watchwords (
        id {pk_type},
        user_id INTEGER NOT NULL,
        keyword TEXT NOT NULL,
        added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users (id)
    )''')
    c.execute(f'''CREATE TABLE IF NOT EXISTS posts (
        id {pk_type},
        user_id INTEGER NOT NULL,
        platform TEXT NOT NULL,
        username TEXT NOT NULL,
        post_text TEXT NOT NULL,
        timestamp TEXT NOT NULL,
        keyword TEXT NOT NULL,
        category TEXT NOT NULL,
        is_high_risk BOOLEAN DEFAULT FALSE,
        threat_score INTEGER DEFAULT 0,
        sentiment TEXT DEFAULT 'Neutral',
        FOREIGN KEY (user_id) REFERENCES users (id)
    )''')
    c.execute(f'''CREATE TABLE IF NOT EXISTS threats (
        id {pk_type},
        user_id INTEGER NOT NULL,
        platform TEXT NOT NULL,
        username TEXT NOT NULL,
        post_text TEXT NOT NULL,
        timestamp TEXT NOT NULL,
        threat_type TEXT NOT NULL,
        matched_keyword TEXT NOT NULL,
        severity TEXT DEFAULT 'Low',
        threat_score INTEGER DEFAULT 0,
        location TEXT DEFAULT 'Unknown',
        sentiment TEXT DEFAULT 'Neutral',
        is_high_risk BOOLEAN DEFAULT FALSE,
        is_reviewed BOOLEAN DEFAULT FALSE,
        entities TEXT DEFAULT '',
        FOREIGN KEY (user_id) REFERENCES users (id)
    )''')
    c.execute(f'''CREATE TABLE IF NOT EXISTS user_logs (
        id {pk_type},
        user_id INTEGER NOT NULL,
        username TEXT NOT NULL,
        action TEXT NOT NULL,
        details TEXT DEFAULT '',
        ip_address TEXT DEFAULT '',
        timestamp TEXT NOT NULL
    )''')
    conn.commit()

    # Safe column migrations
    migrations = [
        "ALTER TABLE users ADD COLUMN role TEXT DEFAULT 'Analyst'",
        "ALTER TABLE posts ADD COLUMN threat_score INTEGER DEFAULT 0",
        "ALTER TABLE posts ADD COLUMN sentiment TEXT DEFAULT 'Neutral'",
        "ALTER TABLE threats ADD COLUMN severity TEXT DEFAULT 'Low'",
        "ALTER TABLE threats ADD COLUMN threat_score INTEGER DEFAULT 0",
        "ALTER TABLE threats ADD COLUMN location TEXT DEFAULT 'Unknown'",
        "ALTER TABLE threats ADD COLUMN sentiment TEXT DEFAULT 'Neutral'",
        "ALTER TABLE threats ADD COLUMN is_reviewed BOOLEAN DEFAULT FALSE",
        "ALTER TABLE threats ADD COLUMN entities TEXT DEFAULT ''",
    ]
    for migration in migrations:
        try:
            if is_postgres():
                c.execute(migration.replace("ADD COLUMN", "ADD COLUMN IF NOT EXISTS"))
            else:
                c.execute(migration)
        except Exception:
            pass
    conn.commit()
    conn.close()

DB_INITIALIZED = False

@app.before_request
def before_request():
    global DB_INITIALIZED
    if not DB_INITIALIZED:
        try:
            init_db()
        except Exception:
            pass
        DB_INITIALIZED = True

def log_action(user_id, username, action, details=''):
    """Record user activity to the user_logs table."""
    try:
        db = get_db()
        ip = request.remote_addr or ''
        db_execute(db, 'INSERT INTO user_logs (user_id, username, action, details, ip_address, timestamp) VALUES (%s,%s,%s,%s,%s,%s)',
                   (user_id, username, action, details, ip, datetime.now().strftime('%Y-%m-%d %H:%M:%S')))
        db.close()
    except Exception:
        pass

IP_PATTERN = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
URL_PATTERN = re.compile(r'https?://[^\s<>"{}|\\^`\[\]]+')
ORG_KEYWORDS = ['microsoft','google','cloudflare','amazon','facebook','twitter','telegram','whatsapp',
                'interpol','fbi','cia','nsa','dhs','cisa','nato','un','who','govt','government',
                'bank','hospital','university','ministry','army','police','intel','cisco','palo alto']

def extract_entities(text):
    """Extract IPs, URLs, and organization names from post text."""
    t = text.lower()
    ips = IP_PATTERN.findall(text)
    urls = URL_PATTERN.findall(text)
    orgs = [o.title() for o in ORG_KEYWORDS if o in t]
    parts = []
    if ips: parts.append('IPs: ' + ', '.join(ips))
    if urls: parts.append('URLs: ' + ', '.join(urls[:2]))
    if orgs: parts.append('Orgs: ' + ', '.join(orgs[:3]))
    return ' | '.join(parts) if parts else ''

# ─── THREAT ENGINE DATA ────────────────────────────────────────────────────────

THREAT_DICTIONARY = {
    'Cyber Attack': [
        'ransomware', 'malware', 'phishing', 'ddos', 'hack', 'data breach',
        'spyware', 'credential leak', 'botnet', 'zero-day', 'network intrusion',
        'corporate espionage', 'information leak', 'exploit', 'backdoor',
        'trojan', 'keylogger', 'worm', 'rootkit', 'sql injection',
        'xss attack', 'man in the middle', 'apt attack', 'ransomware attack',
        'malware distribution', 'account hacking', 'zero-day exploit', 
        'remote code execution (rce)', 'exploit kit', 'brute force', 
        'suspicious login', 'unauthorized access', 'account takeover', 
        'port scanning', 'failed login attempts'
    ],
    'Threat Intel & Vulnerabilities': [
        'bug', 'vulnerability', 'patch', 'update', 'firewall', 'debugging',
        'security discussion', 'ip address', 'url / link', 'domain name',
        '.onion link', 'email address', 'organization name in threat intel'
    ],
    'Financial Crime': [
        'online scam', 'crypto scam', 'cryptocurrency fraud', 'banking fraud',
        'investment scam', 'fake giveaway', 'marketplace fraud',
        'payment fraud', 'identity theft', 'money laundering',
        'ponzi scheme', 'romance scam', 'wire fraud', 'phishing scam'
    ],
    'Security Threat': [
        'bomb threat', 'terror attack', 'mass attack', 'weapon sale',
        'drug trafficking', 'human trafficking', 'organized crime',
        'violent crime', 'assassination', 'arson', 'murder plot',
        'explosive device', 'terrorism', 'extremist', 'militia'
    ],
    'Social Media Abuse': [
        'fake news', 'misinformation', 'hate speech', 'cyberbullying',
        'online harassment', 'doxxing', 'blackmail', 'impersonation',
        'deepfake', 'disinformation', 'propaganda', 'stalking',
        'sextortion', 'trolling', 'doxing'
    ]
}

SEVERITY_MAP = {
    'Cyber Attack':     {'default': 'High',     'keywords': {'zero-day': 'Critical', 'zero-day exploit': 'Critical', 'remote code execution (rce)': 'Critical', 'apt attack': 'Critical', 'ransomware attack': 'Critical', 'ransomware': 'Critical', 'data breach': 'High', 'phishing': 'Medium', 'sql injection': 'High', 'backdoor': 'High', 'exploit kit': 'High', 'account takeover': 'High'}},
    'Threat Intel & Vulnerabilities': {'default': 'Medium', 'keywords': {'.onion link': 'High', 'vulnerability': 'High', 'bug': 'Medium'}},
    'Financial Crime':  {'default': 'Medium',   'keywords': {'money laundering': 'High', 'wire fraud': 'High', 'banking fraud': 'High', 'crypto scam': 'Medium', 'phishing scam': 'High'}},
    'Security Threat':  {'default': 'Critical', 'keywords': {'bomb threat': 'Critical', 'terror attack': 'Critical', 'weapon sale': 'High', 'drug trafficking': 'High', 'organized crime': 'High'}},
    'Social Media Abuse': {'default': 'Low',    'keywords': {'doxxing': 'Medium', 'blackmail': 'High', 'sextortion': 'High', 'hate speech': 'Medium', 'deepfake': 'Medium'}}
}

THREAT_SCORE_MAP = {'Low': random.randint(1,3), 'Medium': random.randint(4,6), 'High': random.randint(7,8), 'Critical': random.randint(9,10)}

LOCATIONS = [
    ('India', 20.5937, 78.9629), ('USA', 37.0902, -95.7129),
    ('UK', 55.3781, -3.4360), ('Germany', 51.1657, 10.4515),
    ('Russia', 61.5240, 105.3188), ('China', 35.8617, 104.1954),
    ('Brazil', -14.2350, -51.9253), ('Australia', -25.2744, 133.7751),
    ('Canada', 56.1304, -106.3468), ('France', 46.2276, 2.2137),
    ('Japan', 36.2048, 138.2529), ('Nigeria', 9.0820, 8.6753),
    ('Pakistan', 30.3753, 69.3451), ('Iran', 32.4279, 53.6880),
    ('North Korea', 40.3399, 127.5101), ('Ukraine', 48.3794, 31.1656),
    ('UAE', 23.4241, 53.8478), ('Singapore', 1.3521, 103.8198),
    ('South Korea', 35.9078, 127.7669), ('Netherlands', 52.1326, 5.2913),
]

HIGH_RISK_THREAT_KEYWORDS = [
    'bomb', 'terror attack', 'mass attack', 'critical infrastructure',
    'weapon attack', 'assassination', 'explosive', 'terrorism', 'ransomware attack'
]

THREAT_POST_TEMPLATES = [
    "URGENT: Major {keyword} detected targeting critical systems",
    "Breaking: Authorities investigating serious {keyword} online",
    "Warning: New {keyword} campaign spreading across platforms",
    "Alert: {keyword} activity reported by multiple security agencies",
    "Users warned about widespread {keyword} affecting thousands",
    "Intelligence confirms coordinated {keyword} operation ongoing",
    "Law enforcement tracking {keyword} network on social media",
    "Security researchers expose new {keyword} targeting users",
    "Government agencies issue warning about {keyword} surge",
    "Dark web forums discussing large-scale {keyword} plans",
    "Multiple victims report {keyword} activity in their region",
    "Interpol releases advisory on {keyword} operations worldwide",
]

def classify_severity(threat_type, keyword):
    entry = SEVERITY_MAP.get(threat_type, {'default': 'Low', 'keywords': {}})
    for kw, sev in entry['keywords'].items():
        if kw in keyword.lower():
            return sev
    return entry['default']

def classify_sentiment(post_text):
    pos = ['warning', 'alert', 'advisory', 'authorities', 'interpol', 'law enforcement', 'report']
    neg = ['attack', 'threat', 'crime', 'fraud', 'scam', 'breach', 'hack', 'bomb', 'terror']
    t = post_text.lower()
    neg_count = sum(1 for w in neg if w in t)
    pos_count = sum(1 for w in pos if w in t)
    if neg_count > pos_count: return 'Negative'
    if pos_count > neg_count: return 'Positive'
    return 'Neutral'

def get_threat_score(severity):
    mapping = {'Low': random.randint(1,3), 'Medium': random.randint(4,6), 'High': random.randint(7,8), 'Critical': random.randint(9,10)}
    return mapping.get(severity, 3)

def get_real_location(text):
    t = text.lower()
    for loc_name, lat, lng in LOCATIONS:
        if loc_name.lower() in t:
            return json.dumps({'name': loc_name, 'lat': lat, 'lng': lng})
    extra_locs = [
        ('New York', 40.7128, -74.0060), ('London', 51.5074, -0.1278),
        ('Paris', 48.8566, 2.3522), ('Tokyo', 35.6762, 139.6503),
        ('Washington', 38.9072, -77.0369), ('Beijing', 39.9042, 116.4074),
        ('Moscow', 55.7558, 37.6173), ('California', 36.7783, -119.4179)
    ]
    for loc_name, lat, lng in extra_locs:
        if loc_name.lower() in t:
            return json.dumps({'name': loc_name, 'lat': lat, 'lng': lng})
    idx = sum(ord(c) for c in text[:20]) % len(LOCATIONS)
    loc = LOCATIONS[idx]
    return json.dumps({'name': f"{loc[0]} (Inferred)", 'lat': loc[1], 'lng': loc[2]})

def simulate_threat_scan(user_id):
    count = 0
    if REQUESTS_AVAILABLE:
        db = get_db()
        for threat_type, keywords in THREAT_DICTIONARY.items():
            sample_keywords = random.sample(keywords, min(2, len(keywords)))
            for kw in sample_keywords:
                try:
                    url = f'https://hn.algolia.com/api/v1/search?query={kw}&tags=story&hitsPerPage=5'
                    resp = http_requests.get(url, timeout=5)
                    if resp.status_code == 200:
                        hits = resp.json().get('hits', [])
                        for hit in hits:
                            title = hit.get('title', '')
                            body = hit.get('story_text') or ''
                            post_text = (title + ' ' + body)[:500].strip()
                            if not post_text:
                                continue
                            severity = classify_severity(threat_type, kw)
                            sentiment = classify_sentiment(post_text)
                            score = get_threat_score(severity)
                            location_json = get_real_location(post_text)
                            is_high_risk = True if severity == 'Critical' or any(w in post_text.lower() or w in kw.lower() for w in HIGH_RISK_THREAT_KEYWORDS) else False
                            author = hit.get('author', f"user_{random.randint(100, 9999)}")
                            created_at = hit.get('created_at', datetime.now().isoformat())
                            try:
                                ts = datetime.fromisoformat(created_at.replace('Z','')).strftime('%Y-%m-%d %H:%M:%S')
                            except Exception:
                                ts = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                            entities = extract_entities(post_text)
                            db_execute(db, '''
                                INSERT INTO threats (user_id, platform, username, post_text, timestamp,
                                    threat_type, matched_keyword, severity, threat_score, location, sentiment, is_high_risk, entities)
                                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                            ''', (user_id, 'HackerNews', author, post_text, ts,
                                  threat_type, kw, severity, score, location_json, sentiment, is_high_risk, entities))
                            count += 1
                except Exception:
                    pass
                    
        # GitHub Issues Fetch (Unauthenticated)
        for threat_type, keywords in THREAT_DICTIONARY.items():
            sample_keywords = random.sample(keywords, min(1, len(keywords)))
            for kw in sample_keywords:
                try:
                    url = f'https://api.github.com/search/issues?q={kw}&per_page=3&sort=created&order=desc'
                    headers = {'User-Agent': 'CyberIntelPlatform/1.0'}
                    resp = http_requests.get(url, headers=headers, timeout=5)
                    if resp.status_code == 200:
                        items = resp.json().get('items', [])
                        for item in items:
                            title = item.get('title', '')
                            body = item.get('body') or ''
                            post_text = (title + ' ' + body)[:500].strip()
                            if not post_text:
                                continue
                            severity = classify_severity(threat_type, kw)
                            sentiment = classify_sentiment(post_text)
                            score = get_threat_score(severity)
                            location_json = get_real_location(post_text)
                            is_high_risk = True if severity == 'Critical' or any(w in post_text.lower() or w in kw.lower() for w in HIGH_RISK_THREAT_KEYWORDS) else False
                            user_data = item.get('user', {})
                            author = user_data.get('login', f"gh_{random.randint(100, 9999)}")
                            created_at = item.get('created_at', datetime.now().isoformat())
                            try:
                                ts = datetime.fromisoformat(created_at.replace('Z','')).strftime('%Y-%m-%d %H:%M:%S')
                            except Exception:
                                ts = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                            entities = extract_entities(post_text)
                            db_execute(db, '''
                                INSERT INTO threats (user_id, platform, username, post_text, timestamp,
                                    threat_type, matched_keyword, severity, threat_score, location, sentiment, is_high_risk, entities)
                                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                            ''', (user_id, 'GitHub', author, post_text, ts,
                                  threat_type, kw, severity, score, location_json, sentiment, is_high_risk, entities))
                            count += 1
                except Exception:
                    pass

        import re
        # Wikipedia Search Fetch (Unauthenticated)
        for threat_type, keywords in THREAT_DICTIONARY.items():
            sample_keywords = random.sample(keywords, min(2, len(keywords)))
            for kw in sample_keywords:
                try:
                    url = f'https://en.wikipedia.org/w/api.php?action=query&list=search&srsearch={kw}&utf8=1&format=json&srlimit=3'
                    headers = {'User-Agent': 'CyberIntelPlatform/1.0'}
                    resp = http_requests.get(url, headers=headers, timeout=5)
                    if resp.status_code == 200:
                        results = resp.json().get('query', {}).get('search', [])
                        for item in results:
                            title = item.get('title', '')
                            snippet = item.get('snippet', '')
                            clean_snippet = re.sub(r'<[^>]+>', ' ', snippet)
                            post_text = f"{title}: {clean_snippet}"[:500].strip()
                            if not post_text:
                                continue
                            severity = classify_severity(threat_type, kw)
                            sentiment = classify_sentiment(post_text)
                            score = get_threat_score(severity)
                            location_json = get_real_location(post_text)
                            is_high_risk = True if severity == 'Critical' or any(w in post_text.lower() or w in kw.lower() for w in HIGH_RISK_THREAT_KEYWORDS) else False
                            author = "Wiki Contributor"
                            ts = item.get('timestamp', datetime.now().isoformat())
                            try:
                                ts = datetime.fromisoformat(ts.replace('Z','')).strftime('%Y-%m-%d %H:%M:%S')
                            except Exception:
                                ts = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                            entities = extract_entities(post_text)
                            db_execute(db, '''
                                INSERT INTO threats (user_id, platform, username, post_text, timestamp,
                                    threat_type, matched_keyword, severity, threat_score, location, sentiment, is_high_risk, entities)
                                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                            ''', (user_id, 'Wikipedia', author, post_text, ts,
                                  threat_type, kw, severity, score, location_json, sentiment, is_high_risk, entities))
                            count += 1
                except Exception:
                    pass

        # Reddit JSON Fetch (Unauthenticated)
        for threat_type, keywords in THREAT_DICTIONARY.items():
            sample_keywords = random.sample(keywords, min(1, len(keywords)))
            for kw in sample_keywords:
                try:
                    url = f'https://www.reddit.com/search.json?q={kw}&limit=3&sort=new'
                    headers = {'User-Agent': 'CyberIntelPlatform/1.0 (Windows)'}
                    resp = http_requests.get(url, headers=headers, timeout=5)
                    if resp.status_code == 200:
                        children = resp.json().get('data', {}).get('children', [])
                        for child in children:
                            post_data = child.get('data', {})
                            title = post_data.get('title', '')
                            body = post_data.get('selftext', '')
                            post_text = (title + ' ' + body)[:500].strip()
                            if not post_text:
                                continue
                            severity = classify_severity(threat_type, kw)
                            sentiment = classify_sentiment(post_text)
                            score = get_threat_score(severity)
                            location_json = get_real_location(post_text)
                            is_high_risk = True if severity == 'Critical' or any(w in post_text.lower() or w in kw.lower() for w in HIGH_RISK_THREAT_KEYWORDS) else False
                            author = post_data.get('author', f"rdt_{random.randint(100, 9999)}")
                            created_utc = post_data.get('created_utc', 0)
                            if created_utc:
                                ts = datetime.fromtimestamp(created_utc).strftime('%Y-%m-%d %H:%M:%S')
                            else:
                                ts = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                            entities = extract_entities(post_text)
                            subreddit = post_data.get('subreddit', 'all')
                            db_execute(db, '''
                                INSERT INTO threats (user_id, platform, username, post_text, timestamp,
                                    threat_type, matched_keyword, severity, threat_score, location, sentiment, is_high_risk, entities)
                                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                            ''', (user_id, 'Reddit', author, post_text, ts,
                                  threat_type, kw, severity, score, location_json, sentiment, is_high_risk, entities))
                            count += 1
                except Exception:
                    pass

        db.close()

    if PRAW_AVAILABLE:
        client_id = os.environ.get('REDDIT_CLIENT_ID', '')
        client_secret = os.environ.get('REDDIT_CLIENT_SECRET', '')
        if client_id and client_secret:
            try:
                reddit = praw.Reddit(client_id=client_id, client_secret=client_secret, user_agent='CyberIntelPlatform/1.0')
                db = get_db()
                for threat_type, keywords in THREAT_DICTIONARY.items():
                    sample_keywords = random.sample(keywords, min(2, len(keywords)))
                    for kw in sample_keywords:
                        try:
                            results = reddit.subreddit('all').search(kw, limit=3, time_filter='week', sort='new')
                            for post in results:
                                post_text = (post.title + ' ' + (post.selftext or ''))[:500].strip()
                                if not post_text:
                                    continue
                                severity = classify_severity(threat_type, kw)
                                sentiment = classify_sentiment(post_text)
                                score = get_threat_score(severity)
                                location_json = get_real_location(post_text)
                                is_high_risk = True if severity == 'Critical' or any(w in post_text.lower() or w in kw.lower() for w in HIGH_RISK_THREAT_KEYWORDS) else False
                                author = str(post.author) if post.author else 'deleted'
                                ts = datetime.fromtimestamp(post.created_utc).strftime('%Y-%m-%d %H:%M:%S')
                                entities = extract_entities(post_text)
                                platform = 'Reddit'
                                db_execute(db, '''
                                    INSERT INTO threats (user_id, platform, username, post_text, timestamp,
                                        threat_type, matched_keyword, severity, threat_score, location, sentiment, is_high_risk, entities)
                                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                                ''', (user_id, platform, author, post_text, ts,
                                      threat_type, kw, severity, score, location_json, sentiment, is_high_risk, entities))
                                count += 1
                        except Exception:
                            pass
                db.close()
            except Exception:
                pass

    if count == 0:
        db = get_db()
        platforms = ['Twitter', 'Facebook', 'Instagram', 'Discord']
        for threat_type, keywords in THREAT_DICTIONARY.items():
            sample_keywords = random.sample(keywords, min(2, len(keywords)))
            for kw in sample_keywords:
                for _ in range(random.randint(1, 3)):
                    platform = random.choice(platforms)
                    username = f"intel_user_{random.randint(100, 9999)}"
                    post_text = random.choice(THREAT_POST_TEMPLATES).format(keyword=kw)
                    severity = classify_severity(threat_type, kw)
                    sentiment = classify_sentiment(post_text)
                    score = get_threat_score(severity)
                    location_json = get_real_location(post_text)
                    is_high_risk = True if severity == 'Critical' or any(w in post_text.lower() or w in kw.lower() for w in HIGH_RISK_THREAT_KEYWORDS) else False
                    days_ago = random.randint(0, 6)
                    ts = (datetime.now() - timedelta(days=days_ago)).strftime('%Y-%m-%d %H:%M:%S')
                    entities = extract_entities(post_text)
                    db_execute(db, '''
                        INSERT INTO threats (user_id, platform, username, post_text, timestamp,
                            threat_type, matched_keyword, severity, threat_score, location, sentiment, is_high_risk, entities)
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    ''', (user_id, platform, username, post_text, ts,
                          threat_type, kw, severity, score, location_json, sentiment, is_high_risk, entities))
        db.close()

# ─── AUTH ──────────────────────────────────────────────────────────────────────

@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('watchwords'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        db = get_db()
        user = db_fetchone(db, 'SELECT * FROM users WHERE username = %s', (username,))
        db.close()
        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['role'] = user['role']
            log_action(user['id'], user['username'], 'LOGIN', f'Role: {user["role"]}')
            return redirect(url_for('dashboard'))
        else:
            log_action(0, username, 'FAILED_LOGIN', 'Invalid credentials')
        flash('Invalid username or password', 'error')
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        name = request.form['name']
        username = request.form['username']
        password = request.form['password']
        role = request.form.get('role', 'Analyst')
        db = get_db()
        if db_fetchone(db, 'SELECT id FROM users WHERE username = %s', (username,)):
            db.close()
            flash('Username already exists', 'error')
        else:
            db_execute(db, 'INSERT INTO users (name, username, password, role) VALUES (%s, %s, %s, %s)',
                       (name, username, generate_password_hash(password), role))
            db.close()
            flash('Account created successfully. Please log in.', 'success')
            return redirect(url_for('login'))
    return render_template('signup.html')


@app.route('/account-settings', methods=['GET', 'POST'])
@login_required
def account_settings():
    db = get_db()
    user = db_fetchone(db, 'SELECT * FROM users WHERE id = %s', (session['user_id'],))
    if request.method == 'POST':
        action = request.form.get('action')
        if action == 'change_password':
            current = request.form.get('current_password')
            new_pass = request.form.get('new_password')
            if check_password_hash(user['password'], current):
                db_execute(db, 'UPDATE users SET password = %s WHERE id = %s',
                           (generate_password_hash(new_pass), session['user_id']))
                flash('Password updated successfully!', 'success')
            else:
                flash('Current password is incorrect.', 'error')
        elif action == 'change_username':
            new_username = request.form.get('new_username')
            existing = db_fetchone(db, 'SELECT id FROM users WHERE username = %s', (new_username,))
            if existing:
                flash('Username already taken.', 'error')
            else:
                db_execute(db, 'UPDATE users SET username = %s WHERE id = %s', (new_username, session['user_id']))
                session['username'] = new_username
                flash('Username updated successfully!', 'success')
    db.close()
    return render_template('account_settings.html', user=user)

# ─── DASHBOARD ─────────────────────────────────────────────────────────────────

@app.route('/dashboard')
@login_required
def dashboard():
    db = get_db()
    w, p = get_visibility_filter()

    total_posts = db_fetchone(db, f'SELECT COUNT(*) as c FROM posts WHERE {w}', tuple(p))['c']
    high_risk_alerts = db_fetchone(db, f'SELECT COUNT(*) as c FROM posts WHERE is_high_risk=TRUE AND {w}', tuple(p))['c']

    trending_row = db_fetchone(db, f'''SELECT keyword, COUNT(*) as c FROM posts WHERE {w}
        GROUP BY keyword ORDER BY c DESC LIMIT 1''', tuple(p))
    trending_keyword = trending_row['keyword'] if trending_row else 'None'

    recent_activity = db_fetchall(db, f'''SELECT platform, keyword, timestamp FROM posts WHERE {w}
        ORDER BY timestamp DESC LIMIT 5''', tuple(p))

    platform_data = db_fetchall(db, f'SELECT platform, COUNT(*) as c FROM posts WHERE {w} GROUP BY platform', tuple(p))
    cat_data = db_fetchall(db, f'SELECT category, COUNT(*) as c FROM posts WHERE {w} GROUP BY category', tuple(p))

    sev_counts = {}
    for sev in ['Low', 'Medium', 'High', 'Critical']:
        row = db_fetchone(db, f'SELECT COUNT(*) as c FROM threats WHERE severity=%s AND {w}', tuple([sev] + p))
        sev_counts[sev] = row['c']

    total_threats = db_fetchone(db, f'SELECT COUNT(*) as c FROM threats WHERE {w}', tuple(p))['c']
    alert_count = db_fetchone(db, f'SELECT COUNT(*) as c FROM threats WHERE is_high_risk=TRUE AND is_reviewed=FALSE AND {w}', tuple(p))['c']
    db.close()

    return render_template('dashboard.html',
        total_posts=total_posts, high_risk_alerts=high_risk_alerts,
        trending_keyword=trending_keyword, recent_activity=recent_activity,
        platform_labels=[r['platform'] for r in platform_data],
        platform_counts=[r['c'] for r in platform_data],
        category_labels=[r['category'] for r in cat_data],
        category_counts=[r['c'] for r in cat_data],
        sev_counts=sev_counts, total_threats=total_threats,
        alert_count=alert_count)

# ─── REAL CRAWLERS ─────────────────────────────────────────────────────────────

def real_crawler_reddit(user_id, keywords_list):
    """Fetch real posts from Reddit using PRAW. Requires REDDIT_CLIENT_ID and REDDIT_CLIENT_SECRET env vars."""
    if not PRAW_AVAILABLE:
        return False
    client_id = os.environ.get('REDDIT_CLIENT_ID', '')
    client_secret = os.environ.get('REDDIT_CLIENT_SECRET', '')
    if not client_id or not client_secret:
        return False
    try:
        reddit = praw.Reddit(
            client_id=client_id,
            client_secret=client_secret,
            user_agent='CyberIntelPlatform/1.0 (by /u/intel_monitor)'
        )
        db = get_db()
        cyber_threat_words = ['ransomware','malware','hack','ddos','phishing','zero-day',
                              'botnet','exploit','breach','vulnerability','apt','spyware']
        security_alert_words = ['protest','attack','data leak','threat','warning','alert']
        high_risk_words = ['attack','bomb','breach','hack','zero-day','apt','ransomware','terrorism']
        count = 0
        for kw in keywords_list:
            try:
                results = reddit.subreddit('all').search(kw, limit=20, time_filter='week', sort='new')
                for post in results:
                    post_text = (post.title + ' ' + (post.selftext or ''))[:500].strip()
                    if not post_text:
                        continue
                    post_lower = post_text.lower()
                    category = 'General Discussion'
                    if any(w in post_lower for w in cyber_threat_words): category = 'Cyber Threat'
                    elif any(w in post_lower for w in security_alert_words): category = 'Security Alert'
                    is_high_risk = any(w in post_lower for w in high_risk_words)
                    score = get_threat_score('High' if is_high_risk else 'Low')
                    sentiment = classify_sentiment(post_text)
                    author = str(post.author) if post.author else 'deleted'
                    ts = datetime.fromtimestamp(post.created_utc).strftime('%Y-%m-%d %H:%M:%S')
                    platform = f"Reddit r/{post.subreddit.display_name}"
                    db_execute(db, '''INSERT INTO posts (user_id, platform, username, post_text, timestamp, keyword, category, is_high_risk, threat_score, sentiment)
                        VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)''',
                        (user_id, platform, author, post_text, ts, kw, category, is_high_risk, score, sentiment))
                    count += 1
            except Exception:
                continue
        db.close()
        return count > 0
    except Exception:
        return False


def real_crawler_hackernews(user_id, keywords_list):
    """Fetch real posts from HackerNews via Algolia API — zero setup, no API key needed."""
    if not REQUESTS_AVAILABLE:
        return False
    try:
        db = get_db()
        cyber_threat_words = ['ransomware','malware','hack','ddos','phishing','zero-day',
                              'breach','exploit','vulnerability','security']
        high_risk_words = ['attack','breach','hack','ransomware','zero-day','exploit']
        count = 0
        for kw in keywords_list:
            try:
                url = f'https://hn.algolia.com/api/v1/search?query={kw}&tags=story&hitsPerPage=20'
                resp = http_requests.get(url, timeout=8)
                if resp.status_code != 200:
                    continue
                hits = resp.json().get('hits', [])
                for hit in hits:
                    title = hit.get('title', '')
                    body = hit.get('story_text') or ''
                    post_text = (title + ' ' + body)[:500].strip()
                    if not post_text:
                        continue
                    post_lower = post_text.lower()
                    category = 'Cyber Threat' if any(w in post_lower for w in cyber_threat_words) else 'General Discussion'
                    is_high_risk = any(w in post_lower for w in high_risk_words)
                    score = get_threat_score('High' if is_high_risk else 'Low')
                    sentiment = classify_sentiment(post_text)
                    author = hit.get('author', 'hn_user')
                    created_at = hit.get('created_at', datetime.now().isoformat())
                    try:
                        ts = datetime.fromisoformat(created_at.replace('Z','')).strftime('%Y-%m-%d %H:%M:%S')
                    except Exception:
                        ts = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                    db_execute(db, '''INSERT INTO posts (user_id, platform, username, post_text, timestamp, keyword, category, is_high_risk, threat_score, sentiment)
                        VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)''',
                        (user_id, 'HackerNews', author, post_text, ts, kw, category, is_high_risk, score, sentiment))
                    count += 1
            except Exception:
                continue
        db.close()
        return count > 0
    except Exception:
        return False


def smart_crawler(user_id, keywords_list):
    """Fetch real posts from HN, Reddit, GitHub, and Wiki."""
    count = 0
    if not REQUESTS_AVAILABLE:
        return 'nodata'
        
    db = get_db()
    cyber_threat_words = ['ransomware','malware','hack','ddos','phishing','zero-day','breach','exploit','vulnerability','security']
    high_risk_words = ['attack','breach','hack','ransomware','zero-day','exploit']
    
    for kw in keywords_list:
        try:
            url = f'https://hn.algolia.com/api/v1/search?query={kw}&tags=story&hitsPerPage=5'
            resp = http_requests.get(url, timeout=5)
            if resp.status_code == 200:
                for hit in resp.json().get('hits', []):
                    post_text = (hit.get('title', '') + ' ' + (hit.get('story_text') or ''))[:500].strip()
                    if not post_text: continue
                    category = 'Cyber Threat' if any(w in post_text.lower() for w in cyber_threat_words) else 'General Discussion'
                    is_high = any(w in post_text.lower() for w in high_risk_words)
                    sentiment = classify_sentiment(post_text)
                    author = hit.get('author', f'hn_{random.randint(100, 9999)}')
                    ts = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                    db_execute(db, 'INSERT INTO posts (user_id, platform, username, post_text, timestamp, keyword, category, is_high_risk, threat_score, sentiment) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)',
                        (user_id, 'HackerNews', author, post_text, ts, kw, category, is_high, get_threat_score('High' if is_high else 'Low'), sentiment))
                    count += 1
        except Exception: pass

        try:
            url = f'https://www.reddit.com/search.json?q={kw}&limit=3&sort=new'
            headers = {'User-Agent': 'CyberIntelPlatform/1.0 (Windows)'}
            resp = http_requests.get(url, headers=headers, timeout=5)
            if resp.status_code == 200:
                for child in resp.json().get('data', {}).get('children', []):
                    post_data = child.get('data', {})
                    post_text = (post_data.get('title', '') + ' ' + post_data.get('selftext', ''))[:500].strip()
                    if not post_text: continue
                    category = 'Cyber Threat' if any(w in post_text.lower() for w in cyber_threat_words) else 'General Discussion'
                    is_high = any(w in post_text.lower() for w in high_risk_words)
                    sentiment = classify_sentiment(post_text)
                    author = post_data.get('author', f"rdt_{random.randint(100, 999)}")
                    ts = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                    subreddit = post_data.get('subreddit', 'all')
                    db_execute(db, 'INSERT INTO posts (user_id, platform, username, post_text, timestamp, keyword, category, is_high_risk, threat_score, sentiment) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)',
                        (user_id, 'Reddit', author, post_text, ts, kw, category, is_high, get_threat_score('High' if is_high else 'Low'), sentiment))
                    count += 1
        except Exception: pass

        try:
            url = f'https://api.github.com/search/issues?q={kw}&per_page=3&sort=created&order=desc'
            headers = {'User-Agent': 'CyberIntelPlatform/1.0'}
            resp = http_requests.get(url, headers=headers, timeout=5)
            if resp.status_code == 200:
                for item in resp.json().get('items', []):
                    post_text = (item.get('title', '') + ' ' + (item.get('body') or ''))[:500].strip()
                    if not post_text: continue
                    category = 'Cyber Threat' if any(w in post_text.lower() for w in cyber_threat_words) else 'General Discussion'
                    is_high = any(w in post_text.lower() for w in high_risk_words)
                    sentiment = classify_sentiment(post_text)
                    author = item.get('user', {}).get('login', f"gh_{random.randint(100, 999)}")
                    ts = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                    db_execute(db, 'INSERT INTO posts (user_id, platform, username, post_text, timestamp, keyword, category, is_high_risk, threat_score, sentiment) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)',
                        (user_id, 'GitHub', author, post_text, ts, kw, category, is_high, get_threat_score('High' if is_high else 'Low'), sentiment))
                    count += 1
        except Exception: pass

        try:
            url = f'https://en.wikipedia.org/w/api.php?action=query&list=search&srsearch={kw}&utf8=1&format=json&srlimit=3'
            headers = {'User-Agent': 'CyberIntelPlatform/1.0'}
            resp = http_requests.get(url, headers=headers, timeout=5)
            import re
            if resp.status_code == 200:
                for item in resp.json().get('query', {}).get('search', []):
                    clean_snippet = re.sub(r'<[^>]+>', ' ', item.get('snippet', ''))
                    post_text = f"{item.get('title', '')}: {clean_snippet}"[:500].strip()
                    if not post_text: continue
                    category = 'Cyber Threat' if any(w in post_text.lower() for w in cyber_threat_words) else 'General Discussion'
                    is_high = any(w in post_text.lower() for w in high_risk_words)
                    sentiment = classify_sentiment(post_text)
                    ts = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                    db_execute(db, 'INSERT INTO posts (user_id, platform, username, post_text, timestamp, keyword, category, is_high_risk, threat_score, sentiment) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)',
                        (user_id, 'Wikipedia', 'Wiki Contributor', post_text, ts, kw, category, is_high, get_threat_score('High' if is_high else 'Low'), sentiment))
                    count += 1
        except Exception: pass
            
    db.close()
    return 'all_platforms' if count > 0 else 'nodata'


# ─── WATCH WORDS (SIMULATED FALLBACK REMOVED) ──────────────────────────────────

def simulate_crawler(user_id, keywords_list):
    # This function is no longer used for generating posts, but we keep it
    # structurally so other simulation endpoints (like threat intel scans) don't break.
    platforms = ['Twitter', 'Facebook', 'Instagram', 'Discord']
    db = get_db()
    templates = [
        "New {keyword} attack targeting hospitals",
        "Major {keyword} reported on banking servers",
        "Discussion about {keyword} spreading online",
        "Alert: {keyword} detected in the network",
        "People organizing a {keyword} tomorrow",
        "Security warning regarding {keyword} vulnerability",
        "Suspicious {keyword} activity found on dark web",
        "System compromised by latest {keyword}",
        "Critical {keyword} infrastructure breach reported",
        "Massive {keyword} campaign affecting multiple orgs",
        "New variant of {keyword} spotted in the wild"
    ]
    cyber_threat_words = ['cyber threat', 'ransomware', 'malware', 'hack', 'ddos', 'phishing',
                          'zero-day', 'botnet', 'apt', 'sql injection', 'xss']
    security_alert_words = ['protest', 'attack', 'data leak', 'breach']
    high_risk_words = ['attack', 'bomb', 'breach', 'hack', 'zero-day', 'apt']

    for kw in keywords_list:
        for _ in range(random.randint(5, 15)):
            platform = random.choice(platforms)
            username = f"user_{random.randint(100, 999)}"
            post_text = random.choice(templates).format(keyword=kw)
            post_lower = post_text.lower()
            category = 'General Discussion'
            if any(w in post_lower for w in cyber_threat_words): category = 'Cyber Threat'
            elif any(w in post_lower for w in security_alert_words): category = 'Security Alert'
            is_high_risk = True if any(w in post_lower for w in high_risk_words) else False
            score = get_threat_score('High' if is_high_risk else 'Low')
            sentiment = classify_sentiment(post_text)
            db_execute(db, '''INSERT INTO posts (user_id, platform, username, post_text, timestamp, keyword, category, is_high_risk, threat_score, sentiment)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)''',
                (user_id, platform, username, post_text, datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                 kw, category, is_high_risk, score, sentiment))
    db.close()

@app.route('/watchwords', methods=['GET', 'POST'])
@login_required
def watchwords():
    if request.method == 'POST':
        if session.get('role') == 'Viewer':
            flash('Viewers cannot add watch words. Contact an Admin or Analyst.', 'error')
            return redirect(url_for('watchwords'))
        keywords_str = request.form.get('keywords', '')
        uid = session['user_id']
        keywords_list = [k.strip() for k in keywords_str.split(',') if k.strip()]
        if keywords_list:
            db = get_db()
            for kw in keywords_list:
                db_execute(db, 'INSERT INTO watchwords (user_id, keyword) VALUES (%s, %s)', (uid, kw))
            db.close()
            source = smart_crawler(uid, keywords_list)
            
            if source == 'nodata':
                flash(f'Monitoring started for {len(keywords_list)} keyword(s), but no real-time posts were found on our platforms right now. The system will keep watching.', 'warning')
            else:
                source_labels = {'reddit': 'Reddit', 'hackernews': 'HackerNews', 'all_platforms': 'HackerNews, Reddit, GitHub, and Wikipedia'}
                flash(f'Monitoring started! Fetched real posts from {source_labels.get(source, source)} for {len(keywords_list)} keyword(s).', 'success')
            return redirect(url_for('results'))
        flash('Please enter at least one keyword.', 'error')
    return render_template('watchwords.html')

@app.route('/watchword-history')
@login_required
def watchword_history():
    db = get_db()
    w, p = get_visibility_filter()
    words = db_fetchall(db, f'SELECT * FROM watchwords WHERE {w} ORDER BY added_at DESC', tuple(p))
    db.close()
    return render_template('watchword_history.html', words=words)

@app.route('/delete-watchword/<int:wid>')
@require_role('Analyst')
def delete_watchword(wid):
    db = get_db()
    db_execute(db, 'DELETE FROM watchwords WHERE id=%s AND user_id=%s', (wid, session['user_id']))
    db.close()
    flash('Watch word deleted.', 'success')
    return redirect(url_for('watchword_history'))

# ─── RESULTS ───────────────────────────────────────────────────────────────────

@app.route('/results')
@login_required
def results():
    db = get_db()
    w, p = get_visibility_filter()
    platform = request.args.get('platform', '')
    keyword = request.args.get('keyword', '')
    category = request.args.get('category', '')

    query = f'SELECT * FROM posts WHERE {w}'
    params = list(p)
    if platform: query += ' AND platform=%s'; params.append(platform)
    if keyword: query += ' AND keyword=%s'; params.append(keyword)
    if category: query += ' AND category=%s'; params.append(category)
    query += ' ORDER BY timestamp DESC'

    posts = db_fetchall(db, query, tuple(params))
    platforms = db_fetchall(db, f'SELECT DISTINCT platform FROM posts WHERE {w}', tuple(p))
    keywords = db_fetchall(db, f'SELECT DISTINCT keyword FROM watchwords WHERE {w} ORDER BY keyword ASC', tuple(p))
    categories = db_fetchall(db, f'SELECT DISTINCT category FROM posts WHERE {w}', tuple(p))
    db.close()

    return render_template('results.html', posts=posts,
        platforms=[p['platform'] for p in platforms],
        keywords=[k['keyword'] for k in keywords],
        categories=[c['category'] for c in categories],
        current_platform=platform, current_keyword=keyword, current_category=category)

@app.route('/delete-post/<int:pid>')
@require_role('Analyst')
def delete_post(pid):
    db = get_db()
    db_execute(db, 'DELETE FROM posts WHERE id=%s AND user_id=%s', (pid, session['user_id']))
    db.close()
    flash('Post deleted.', 'success')
    return redirect(url_for('results'))

@app.route('/clear-data')
@require_role('Admin')
def clear_data():
    db = get_db()
    db_execute(db, 'DELETE FROM posts WHERE user_id=%s', (session['user_id'],))
    db_execute(db, 'DELETE FROM threats WHERE user_id=%s', (session['user_id'],))
    db.close()
    flash('All data cleared successfully.', 'success')
    return redirect(url_for('dashboard'))

@app.route('/export-results')
@require_role('Analyst')
def export_results():
    db = get_db()
    w, p = get_visibility_filter()
    posts = db_fetchall(db, f'SELECT * FROM posts WHERE {w} ORDER BY timestamp DESC', tuple(p))
    db.close()
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['Platform', 'Username', 'Post', 'Category', 'Keyword', 'Threat Score', 'Sentiment', 'High Risk', 'Date'])
    for p in posts:
        writer.writerow([p['platform'], p['username'], p['post_text'], p['category'],
                         p['keyword'], p['threat_score'], p['sentiment'],
                         'Yes' if p['is_high_risk'] else 'No', p['timestamp']])
    output.seek(0)
    return Response(output, mimetype='text/csv', headers={'Content-Disposition': 'attachment;filename=results.csv'})

# ─── THREAT INTELLIGENCE ───────────────────────────────────────────────────────

@app.route('/threat-intelligence')
@login_required
def threat_intelligence():
    db = get_db()
    uid = session['user_id']
    w, p = get_visibility_filter()

    # Auto-scan if empty
    if db_fetchone(db, f'SELECT COUNT(*) as c FROM threats WHERE {w}', tuple(p))['c'] == 0:
        simulate_threat_scan(uid)
    
    # Filters
    threat_type_filter = request.args.get('threat_type', '')
    platform_filter = request.args.get('platform', '')
    severity_filter = request.args.get('severity', '')
    search_query = request.args.get('q', '')
    date_from = request.args.get('date_from', '')
    date_to = request.args.get('date_to', '')

    query = f'SELECT * FROM threats WHERE {w}'
    params = list(p)
    if threat_type_filter: query += ' AND threat_type=%s'; params.append(threat_type_filter)
    if platform_filter: query += ' AND platform=%s'; params.append(platform_filter)
    if severity_filter: query += ' AND severity=%s'; params.append(severity_filter)
    if search_query: query += ' AND (post_text LIKE %s OR matched_keyword LIKE %s)'; params += [f'%{search_query}%', f'%{search_query}%']
    if date_from: query += ' AND timestamp >= %s'; params.append(date_from)
    if date_to: query += ' AND timestamp <= %s'; params.append(date_to + ' 23:59:59')
    query += ' ORDER BY timestamp DESC'

    threats = db_fetchall(db, query, tuple(params))

    total_threats = db_fetchone(db, f'SELECT COUNT(*) as c FROM threats WHERE {w}', tuple(p))['c']
    high_risk_count = db_fetchone(db, f'SELECT COUNT(*) as c FROM threats WHERE is_high_risk=TRUE AND {w}', tuple(p))['c']

    type_counts = {}
    for tt in THREAT_DICTIONARY.keys():
        type_counts[tt] = db_fetchone(db, f'SELECT COUNT(*) as c FROM threats WHERE threat_type=%s AND {w}', tuple([tt] + p))['c']

    sev_counts = {}
    for sev in ['Low', 'Medium', 'High', 'Critical']:
        sev_counts[sev] = db_fetchone(db, f'SELECT COUNT(*) as c FROM threats WHERE severity=%s AND {w}', tuple([sev] + p))['c']

    platform_data = db_fetchall(db, f'SELECT platform, COUNT(*) as c FROM threats WHERE {w} GROUP BY platform', tuple(p))

    # Timeline: last 7 days
    timeline_labels = []
    timeline_values = []
    for i in range(6, -1, -1):
        day = (datetime.now() - timedelta(days=i)).strftime('%Y-%m-%d')
        count = db_fetchone(db, f"SELECT COUNT(*) as c FROM threats WHERE timestamp LIKE %s AND {w}", tuple([f'{day}%'] + p))['c']
        timeline_labels.append((datetime.now() - timedelta(days=i)).strftime('%a'))
        timeline_values.append(count)

    all_threats = db_fetchall(db, f'SELECT location, threat_type, post_text FROM threats WHERE {w}', tuple(p))
    db.close()
    map_points = []
    for t in all_threats:
        try:
            loc = json.loads(t['location'])
            map_points.append({'lat': loc['lat'], 'lng': loc['lng'], 'name': loc['name'],
                               'type': t['threat_type'], 'post': t['post_text'][:80]})
        except Exception:
            pass

    return render_template('threat_intelligence.html',
        threats=threats, total_threats=total_threats, high_risk_count=high_risk_count,
        type_counts=type_counts, sev_counts=sev_counts,
        platform_labels=[r['platform'] for r in platform_data],
        platform_counts=[r['c'] for r in platform_data],
        timeline_labels=timeline_labels, timeline_values=timeline_values,
        map_points=map_points,
        current_threat_type=threat_type_filter, current_platform=platform_filter,
        current_severity=severity_filter, search_query=search_query,
        date_from=date_from, date_to=date_to,
        threat_types=list(THREAT_DICTIONARY.keys()))

@app.route('/rescan-threats')
@require_role('Analyst')
def rescan_threats():
    db = get_db()
    db_execute(db, 'DELETE FROM threats WHERE user_id=%s', (session['user_id'],))
    db.close()
    simulate_threat_scan(session['user_id'])
    log_action(session['user_id'], session['username'], 'THREAT_SCAN', 'Manual rescan triggered')
    flash('Threat intelligence scan complete!', 'success')
    return redirect(url_for('threat_intelligence'))

@app.route('/mark-reviewed/<int:tid>')
@require_role('Analyst')
def mark_reviewed(tid):
    db = get_db()
    db_execute(db, 'UPDATE threats SET is_reviewed=TRUE WHERE id=%s AND user_id=%s', (tid, session['user_id']))
    db.close()
    return redirect(url_for('alert_inbox'))

# ─── ALERT INBOX ───────────────────────────────────────────────────────────────

@app.route('/alert-inbox')
@login_required
def alert_inbox():
    db = get_db()
    w, p = get_visibility_filter()
    show_reviewed = request.args.get('show_reviewed', '0')
    query = f'SELECT * FROM threats WHERE is_high_risk=TRUE AND {w}'
    if show_reviewed != '1':
        query += ' AND is_reviewed=FALSE'
    query += ' ORDER BY timestamp DESC'
    alerts = db_fetchall(db, query, tuple(p))
    unread_count = db_fetchone(db, f'SELECT COUNT(*) as c FROM threats WHERE is_high_risk=TRUE AND is_reviewed=FALSE AND {w}', tuple(p))['c']
    db.close()
    return render_template('alert_inbox.html', alerts=alerts, unread_count=unread_count, show_reviewed=show_reviewed)

# ─── EXPORT THREAT INTELLIGENCE ────────────────────────────────────────────────

@app.route('/export-threats-csv')
@require_role('Analyst')
def export_threats_csv():
    db = get_db()
    w, p = get_visibility_filter()
    threats = db_fetchall(db, f'SELECT * FROM threats WHERE {w} ORDER BY timestamp DESC', tuple(p))
    db.close()
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['Platform', 'Username', 'Post', 'Threat Type', 'Keyword', 'Severity', 'Score', 'Sentiment', 'Location', 'High Risk', 'Date'])
    for t in threats:
        try: loc = json.loads(t['location'])['name']
        except: loc = 'Unknown'
        writer.writerow([t['platform'], t['username'], t['post_text'], t['threat_type'],
                         t['matched_keyword'], t['severity'], t['threat_score'], t['sentiment'],
                         loc, 'Yes' if t['is_high_risk'] else 'No', t['timestamp']])
    output.seek(0)
    return Response(output, mimetype='text/csv', headers={'Content-Disposition': 'attachment;filename=threat_intelligence.csv'})

@app.route('/export-threats-pdf')
@require_role('Analyst')
def export_threats_pdf():
    if not REPORTLAB_AVAILABLE:
        flash('PDF export requires reportlab. Run: pip install reportlab', 'error')
        return redirect(url_for('threat_intelligence'))
    db = get_db()
    w, p = get_visibility_filter()
    threats = db_fetchall(db, f'SELECT * FROM threats WHERE {w} ORDER BY timestamp DESC LIMIT 50', tuple(p))
    total = db_fetchone(db, f'SELECT COUNT(*) as c FROM threats WHERE {w}', tuple(p))['c']
    high_risk = db_fetchone(db, f'SELECT COUNT(*) as c FROM threats WHERE is_high_risk=TRUE AND {w}', tuple(p))['c']
    db.close()

    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=letter)
    styles = getSampleStyleSheet()
    story = []
    story.append(Paragraph('Threat Intelligence Report', styles['Title']))
    story.append(Spacer(1, 12))
    story.append(Paragraph(f'Generated: {datetime.now().strftime("%Y-%m-%d %H:%M")} | Total Threats: {total} | High Risk: {high_risk}', styles['Normal']))
    story.append(Spacer(1, 20))

    data = [['Platform', 'Threat Type', 'Severity', 'Keyword', 'Date']]
    for t in threats:
        data.append([t['platform'], t['threat_type'], t['severity'], t['matched_keyword'], t['timestamp'][:10]])

    table = Table(data, colWidths=[80, 110, 70, 120, 80])
    table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), rl_colors.HexColor('#1e3a5f')),
        ('TEXTCOLOR', (0,0), (-1,0), rl_colors.white),
        ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [rl_colors.white, rl_colors.HexColor('#f0f4f8')]),
        ('GRID', (0,0), (-1,-1), 0.5, rl_colors.grey),
        ('FONTSIZE', (0,0), (-1,-1), 9),
    ]))
    story.append(table)
    doc.build(story)
    buf.seek(0)
    return send_file(buf, mimetype='application/pdf', as_attachment=True, download_name='threat_report.pdf')

@app.route('/export-threats-excel')
@require_role('Analyst')
def export_threats_excel():
    if not OPENPYXL_AVAILABLE:
        flash('Excel export requires openpyxl. Run: pip install openpyxl', 'error')
        return redirect(url_for('threat_intelligence'))
    db = get_db()
    w, p = get_visibility_filter()
    threats = db_fetchall(db, f'SELECT * FROM threats WHERE {w} ORDER BY timestamp DESC', tuple(p))
    db.close()
    wb = openpyxl.Workbook()
    ws = wb.active
    ws.title = 'Threat Intelligence'
    headers = ['Platform', 'Username', 'Post', 'Threat Type', 'Keyword', 'Severity', 'Score', 'Sentiment', 'Location', 'High Risk', 'Date']
    ws.append(headers)
    for t in threats:
        try: loc = json.loads(t['location'])['name']
        except: loc = 'Unknown'
        ws.append([t['platform'], t['username'], t['post_text'], t['threat_type'],
                   t['matched_keyword'], t['severity'], t['threat_score'], t['sentiment'],
                   loc, 'Yes' if t['is_high_risk'] else 'No', t['timestamp']])
    buf = io.BytesIO()
    wb.save(buf)
    buf.seek(0)
    return send_file(buf, mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
                     as_attachment=True, download_name='threat_intelligence.xlsx')

# ─── USER ACTIVITY LOGS ────────────────────────────────────────────────────────

@app.route('/user-logs')
@login_required
def user_logs():
    db = get_db()
    uid = session['user_id']
    if session.get('role') == 'Admin':
        logs = db_fetchall(db, 'SELECT * FROM user_logs ORDER BY timestamp DESC LIMIT 500')
    else:
        logs = db_fetchall(db, 'SELECT * FROM user_logs WHERE user_id=%s ORDER BY timestamp DESC LIMIT 200', (uid,))

    total_logins = db_fetchone(db, "SELECT COUNT(*) as c FROM user_logs WHERE user_id=%s AND action='LOGIN'", (uid,))['c']
    failed_logins = db_fetchone(db, "SELECT COUNT(*) as c FROM user_logs WHERE username=%s AND action='FAILED_LOGIN'", (session['username'],))['c']
    total_scans = db_fetchone(db, "SELECT COUNT(*) as c FROM user_logs WHERE user_id=%s AND action='THREAT_SCAN'", (uid,))['c']
    db.close()

    return render_template('user_logs.html', logs=logs, total_logins=total_logins,
                           failed_logins=failed_logins, total_scans=total_scans)

@app.route('/logout')
def logout():
    if 'user_id' in session:
        log_action(session['user_id'], session.get('username', ''), 'LOGOUT', 'User logged out')
    session.clear()
    return redirect(url_for('login'))

# ─── KEYWORD FREQUENCY DATA ────────────────────────────────────────────────────

@app.route('/api/keyword-frequency')
def keyword_frequency():
    if 'user_id' not in session:
        return jsonify([])
    db = get_db()
    w, p = get_visibility_filter()
    rows = db_fetchall(db, f'''SELECT keyword, COUNT(*) as c FROM posts WHERE {w}
        GROUP BY keyword ORDER BY c DESC LIMIT 10''', tuple(p))
    db.close()
    return jsonify([{'keyword': r['keyword'], 'count': r['c']} for r in rows])


# ─── ADMIN PANEL ────────────────────────────────────────────────────────────────

@app.route('/admin')
def admin_panel():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    if session.get('role') != 'Admin':
        flash('Access denied. Admins only.', 'error')
        return redirect(url_for('dashboard'))
    db = get_db()
    users = db_fetchall(db, 'SELECT * FROM users ORDER BY id')
    user_stats = []
    for u in users:
        posts = db_fetchone(db, 'SELECT COUNT(*) as c FROM posts WHERE user_id=%s', (u['id'],))['c']
        threats = db_fetchone(db, 'SELECT COUNT(*) as c FROM threats WHERE user_id=%s', (u['id'],))['c']
        last_login = db_fetchone(db,
            "SELECT timestamp FROM user_logs WHERE user_id=%s AND action='LOGIN' ORDER BY timestamp DESC LIMIT 1",
            (u['id'],))
        user_stats.append({
            'id': u['id'], 'name': u['name'], 'username': u['username'],
            'role': u['role'], 'posts': posts, 'threats': threats,
            'last_login': last_login['timestamp'] if last_login else 'Never'
        })
    total_users = len(users)
    total_posts = db_fetchone(db, 'SELECT COUNT(*) as c FROM posts')['c']
    total_threats = db_fetchone(db, 'SELECT COUNT(*) as c FROM threats')['c']
    total_logs = db_fetchone(db, 'SELECT COUNT(*) as c FROM user_logs')['c']
    recent_logs = db_fetchall(db, 'SELECT * FROM user_logs ORDER BY timestamp DESC LIMIT 20')
    db.close()
    return render_template('admin.html', user_stats=user_stats,
                           total_users=total_users, total_posts=total_posts,
                           total_threats=total_threats, total_logs=total_logs,
                           recent_logs=recent_logs)

@app.route('/admin/change-role/<int:uid>', methods=['POST'])
def change_role(uid):
    if 'user_id' not in session or session.get('role') != 'Admin':
        flash('Access denied.', 'error')
        return redirect(url_for('dashboard'))
    new_role = request.form.get('role')
    if new_role not in ('Admin', 'Analyst', 'Viewer'):
        flash('Invalid role.', 'error')
        return redirect(url_for('admin_panel'))
    db = get_db()
    db_execute(db, 'UPDATE users SET role=%s WHERE id=%s', (new_role, uid))
    target = db_fetchone(db, 'SELECT username FROM users WHERE id=%s', (uid,))
    db.close()
    log_action(session['user_id'], session['username'], 'ROLE_CHANGE',
               f"Changed {target['username']} role to {new_role}")
    flash(f'Role updated to {new_role}.', 'success')
    return redirect(url_for('admin_panel'))

@app.route('/admin/delete-user/<int:uid>', methods=['POST'])
def delete_user(uid):
    if 'user_id' not in session or session.get('role') != 'Admin':
        flash('Access denied.', 'error')
        return redirect(url_for('dashboard'))
    if uid == session['user_id']:
        flash("You can't delete your own account.", 'error')
        return redirect(url_for('admin_panel'))
    db = get_db()
    target = db_fetchone(db, 'SELECT username FROM users WHERE id=%s', (uid,))
    db_execute(db, 'DELETE FROM posts WHERE user_id=%s', (uid,))
    db_execute(db, 'DELETE FROM threats WHERE user_id=%s', (uid,))
    db_execute(db, 'DELETE FROM watchwords WHERE user_id=%s', (uid,))
    db_execute(db, 'DELETE FROM users WHERE id=%s', (uid,))
    db.close()
    log_action(session['user_id'], session['username'], 'DELETE_USER',
               f"Deleted user: {target['username']}")
    flash(f"User '{target['username']}' deleted.", 'success')
    return redirect(url_for('admin_panel'))

if __name__ == '__main__':
    app.run(debug=True)
