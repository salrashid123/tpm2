from flask import Flask, request
import ssl

app = Flask(__name__)

context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain('certs/server.crt', 'certs/server.key')

context.verify_mode = ssl.CERT_REQUIRED
context.load_verify_locations('ca/root-ca.crt')

@app.route('/')
def index():
    client_cert = request.environ.get('SSL_CLIENT_CERT')
    if client_cert:
        # Validate the client certificate
        # ... 
        return 'Hello, authenticated client!'
    else:
        return 'Client certificate not found', 401

if __name__ == '__main__':
    app.run(ssl_context=context,host="127.0.0.1", port=8443, debug=True)
