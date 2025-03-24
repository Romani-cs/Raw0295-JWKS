from http.server import BaseHTTPRequestHandler, HTTPServer
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from urllib.parse import urlparse, parse_qs
import base64
import json
import jwt
import datetime
import sqlite3

hostName = "localhost"
serverPort = 8080

def init_db():
    """Initialize the SQLite database and create the keys table if it doesn't exist."""
    conn = sqlite3.connect('totally_not_my_privateKeys.db')
    cursor = conn.cursor()

    # Create the 'keys' table if it doesn't exist
    cursor.execute('''CREATE TABLE IF NOT EXISTS keys(
                        kid INTEGER PRIMARY KEY AUTOINCREMENT,
                        key BLOB NOT NULL,
                        exp INTEGER NOT NULL)''')
    conn.commit()
    conn.close()

def store_private_key(key, expiration_time):
    """Store the private key and its expiration time in the database."""
    conn = sqlite3.connect('totally_not_my_privateKeys.db')
    cursor = conn.cursor()

    # Serialize the private key to PEM format
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )

    # Insert the key into the database with its expiration time
    cursor.execute("INSERT INTO keys (key, exp) VALUES (?, ?)", (key_pem, expiration_time))
    conn.commit()
    conn.close()

def get_valid_keys():
    """Retrieve all valid (non-expired) keys from the database."""
    conn = sqlite3.connect('totally_not_my_privateKeys.db')
    cursor = conn.cursor()

    current_time = int(datetime.datetime.now(datetime.timezone.utc).timestamp())

    cursor.execute("SELECT key FROM keys WHERE exp > ?", (current_time,))
    rows = cursor.fetchall()

    valid_keys = []
    for row in rows:
        key_pem = row[0]
        key = serialization.load_pem_private_key(key_pem, password=None)
        valid_keys.append(key)

    conn.close()
    return valid_keys

# Your existing logic to generate private keys
private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
expired_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

# Initialize the database and store the keys (you can do this once on startup)
init_db()

# Store the keys in the database with their expiration times
current_time = int(datetime.datetime.utcnow().timestamp())
store_private_key(private_key, current_time + 3600)  # Valid for 1 hour
store_private_key(expired_key, current_time - 3600)  # Expired 1 hour ago

class MyServer(BaseHTTPRequestHandler):
    def do_PUT(self):
        self.send_response(405)
        self.end_headers()
        return

    def do_PATCH(self):
        self.send_response(405)
        self.end_headers()
        return

    def do_DELETE(self):
        self.send_response(405)
        self.end_headers()
        return

    def do_HEAD(self):
        self.send_response(405)
        self.end_headers()
        return

    def do_POST(self):
        parsed_path = urlparse(self.path)
        params = parse_qs(parsed_path.query)
        if parsed_path.path == "/auth":
            headers = {"kid": "goodKID"}
            token_payload = {
                "user": "username",
                "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1)
            }

            if 'expired' in params:
                headers["kid"] = "expiredKID"
                token_payload["exp"] = datetime.datetime.utcnow() - datetime.timedelta(hours=1)

            # Retrieve the appropriate key from the database
            valid_keys = get_valid_keys()
            if len(valid_keys) == 0:
                self.send_response(500)
                self.end_headers()
                self.wfile.write(bytes("No valid keys available", "utf-8"))
                return

            # Use the first valid key (you can improve this logic to handle multiple keys)
            selected_key = valid_keys[0]
            encoded_jwt = jwt.encode(token_payload, selected_key, algorithm="RS256", headers=headers)
            self.send_response(200)
            self.end_headers()
            self.wfile.write(bytes(encoded_jwt, "utf-8"))
            return

        self.send_response(405)
        self.end_headers()
        return

    def do_GET(self):
        if self.path == "/.well-known/jwks.json":
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()

            valid_keys = get_valid_keys()
            keys = {
                "keys": []
            }

            for key in valid_keys:
                numbers = key.public_key().public_numbers()
                keys["keys"].append({
                    "alg": "RS256",
                    "kty": "RSA",
                    "use": "sig",
                    "kid": "goodKID",  # You can modify this based on how you manage key IDs
                    "n": int_to_base64(numbers.n),
                    "e": int_to_base64(numbers.e),
                })

            self.wfile.write(bytes(json.dumps(keys), "utf-8"))
            return

        self.send_response(405)
        self.end_headers()
        return

# Helper function to convert integer to Base64URL-encoded string
def int_to_base64(value):
    value_hex = format(value, 'x')
    if len(value_hex) % 2 == 1:
        value_hex = '0' + value_hex
    value_bytes = bytes.fromhex(value_hex)
    encoded = base64.urlsafe_b64encode(value_bytes).rstrip(b'=') 
    return encoded.decode('utf-8')


if __name__ == "__main__":
    webServer = HTTPServer((hostName, serverPort), MyServer)
    try:
        webServer.serve_forever()
    except KeyboardInterrupt:
        pass

    webServer.server_close()

