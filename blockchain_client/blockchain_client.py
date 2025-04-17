from collections import OrderedDict
import binascii

from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15  # Updated from PKCS1_v1_5
from Crypto.Hash import SHA1  # Updated from deprecated SHA
from Crypto import Random

from flask import Flask, jsonify, request, render_template

# Transaction class
class Transaction:

    def __init__(self, sender_address, sender_private_key, recipient_address, value):
        self.sender_address = sender_address
        self.sender_private_key = sender_private_key
        self.recipient_address = recipient_address
        self.value = value

    def to_dict(self):
        return OrderedDict({
            'sender_address': self.sender_address,
            'recipient_address': self.recipient_address,
            'value': self.value
        })

    def sign_transaction(self):
        """
        Sign transaction with private key
        """
        try:
            private_key = RSA.import_key(binascii.unhexlify(self.sender_private_key))
            signer = pkcs1_15.new(private_key)
            h = SHA1.new(str(self.to_dict()).encode('utf-8'))
            signature = signer.sign(h)
            return binascii.hexlify(signature).decode('ascii')
        except (ValueError, TypeError) as e:
            return f"Error signing transaction: {str(e)}"


# Flask app setup
app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/make/transaction')
def make_transaction():
    return render_template('make_transaction.html')

@app.route('/view/transactions')
def view_transaction():
    return render_template('view_transactions.html')

@app.route('/wallet/new', methods=['GET'])
def new_wallet():
    random_gen = Random.new().read
    private_key = RSA.generate(1024, random_gen)
    public_key = private_key.publickey()

    response = {
        'private_key': binascii.hexlify(private_key.export_key(format='DER')).decode('ascii'),
        'public_key': binascii.hexlify(public_key.export_key(format='DER')).decode('ascii')
    }

    return jsonify(response), 200

@app.route('/generate/transaction', methods=['POST'])
def generate_transaction():
    # Can be request.form or request.json depending on client
    data = request.form if request.form else request.get_json()

    required = ['sender_address', 'sender_private_key', 'recipient_address', 'amount']
    if not all(k in data for k in required):
        return jsonify({'error': 'Missing transaction fields'}), 400

    transaction = Transaction(
        sender_address=data['sender_address'],
        sender_private_key=data['sender_private_key'],
        recipient_address=data['recipient_address'],
        value=data['amount']
    )

    response = {
        'transaction': transaction.to_dict(),
        'signature': transaction.sign_transaction()
    }

    return jsonify(response), 200

if __name__ == '__main__':
    from argparse import ArgumentParser

    parser = ArgumentParser()
    parser.add_argument('-p', '--port', default=8080, type=int, help='port to listen on')
    args = parser.parse_args()
    port = args.port

    app.run(host='127.0.0.1', port=port)
