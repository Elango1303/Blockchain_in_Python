from collections import OrderedDict
import binascii
from uuid import uuid4
from time import time
import hashlib
import json
from urllib.parse import urlparse

import requests
from flask import Flask, jsonify, request, render_template
from flask_cors import CORS

from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15  # Updated
from Crypto.Hash import SHA1  # Updated

# Constants
MINING_SENDER = "THE BLOCKCHAIN"
MINING_REWARD = 1
MINING_DIFFICULTY = 2

class Blockchain:
    def __init__(self):
        self.transactions = []
        self.chain = []
        self.nodes = set()
        self.node_id = str(uuid4()).replace('-', '')
        self.create_block(0, '00')

    def register_node(self, node_url):
        parsed_url = urlparse(node_url)
        if parsed_url.netloc:
            self.nodes.add(parsed_url.netloc)
        elif parsed_url.path:
            self.nodes.add(parsed_url.path)
        else:
            raise ValueError('Invalid URL')

    def verify_transaction_signature(self, sender_address, signature, transaction):
        try:
            public_key = RSA.import_key(binascii.unhexlify(sender_address))
            verifier = pkcs1_15.new(public_key)
            h = SHA1.new(str(transaction).encode('utf-8'))
            verifier.verify(h, binascii.unhexlify(signature))
            return True
        except (ValueError, TypeError):
            return False

    def submit_transaction(self, sender_address, recipient_address, value, signature):
        transaction = OrderedDict({
            'sender_address': sender_address,
            'recipient_address': recipient_address,
            'value': value
        })

        if sender_address == MINING_SENDER:
            self.transactions.append(transaction)
            return len(self.chain) + 1

        if self.verify_transaction_signature(sender_address, signature, transaction):
            self.transactions.append(transaction)
            return len(self.chain) + 1
        else:
            return False

    def create_block(self, nonce, previous_hash):
        block = {
            'block_number': len(self.chain) + 1,
            'timestamp': time(),
            'transactions': self.transactions,
            'nonce': nonce,
            'previous_hash': previous_hash
        }
        self.transactions = []
        self.chain.append(block)
        return block

    def hash(self, block):
        block_string = json.dumps(block, sort_keys=True).encode()
        return hashlib.sha256(block_string).hexdigest()

    def proof_of_work(self):
        last_block = self.chain[-1]
        last_hash = self.hash(last_block)
        nonce = 0
        while not self.valid_proof(self.transactions, last_hash, nonce):
            nonce += 1
        return nonce

    def valid_proof(self, transactions, last_hash, nonce, difficulty=MINING_DIFFICULTY):
        guess = f'{transactions}{last_hash}{nonce}'.encode()
        guess_hash = hashlib.sha256(guess).hexdigest()
        return guess_hash[:difficulty] == '0' * difficulty

    def valid_chain(self, chain):
        last_block = chain[0]
        current_index = 1

        while current_index < len(chain):
            block = chain[current_index]
            if block['previous_hash'] != self.hash(last_block):
                return False

            transactions = block['transactions'][:-1] if block['transactions'] else []
            transaction_elements = ['sender_address', 'recipient_address', 'value']
            transactions = [OrderedDict((k, transaction[k]) for k in transaction_elements) for transaction in transactions]

            if not self.valid_proof(transactions, block['previous_hash'], block['nonce'], MINING_DIFFICULTY):
                return False

            last_block = block
            current_index += 1

        return True

    def resolve_conflicts(self):
        neighbours = self.nodes
        new_chain = None
        max_length = len(self.chain)

        for node in neighbours:
            try:
                response = requests.get(f'http://{node}/chain')
                if response.status_code == 200:
                    length = response.json()['length']
                    chain = response.json()['chain']
                    if length > max_length and self.valid_chain(chain):
                        max_length = length
                        new_chain = chain
            except requests.exceptions.RequestException:
                continue

        if new_chain:
            self.chain = new_chain
            return True
        return False


# Flask app
app = Flask(__name__)
CORS(app)
blockchain = Blockchain()


@app.route('/')
def index():
    return render_template('./index.html')

@app.route('/configure')
def configure():
    return render_template('./configure.html')


@app.route('/transactions/new', methods=['POST'])
def new_transaction():
    values = request.get_json()

    required = ['sender_address', 'recipient_address', 'amount', 'signature']
    if not all(k in values for k in required):
        return 'Missing values', 400

    result = blockchain.submit_transaction(
        sender_address=values['sender_address'],
        recipient_address=values['recipient_address'],
        value=values['amount'],
        signature=values['signature']
    )

    if not result:
        return jsonify({'message': 'Invalid Transaction!'}), 406

    return jsonify({'message': f'Transaction will be added to Block {result}'}), 201


@app.route('/transactions/get', methods=['GET'])
def get_transactions():
    return jsonify({'transactions': blockchain.transactions}), 200


@app.route('/chain', methods=['GET'])
def full_chain():
    return jsonify({'chain': blockchain.chain, 'length': len(blockchain.chain)}), 200


@app.route('/mine', methods=['GET'])
def mine():
    last_block = blockchain.chain[-1]
    nonce = blockchain.proof_of_work()

    blockchain.submit_transaction(
        sender_address=MINING_SENDER,
        recipient_address=blockchain.node_id,
        value=MINING_REWARD,
        signature=""
    )

    previous_hash = blockchain.hash(last_block)
    block = blockchain.create_block(nonce, previous_hash)

    return jsonify({
        'message': "New Block Forged",
        'block_number': block['block_number'],
        'transactions': block['transactions'],
        'nonce': block['nonce'],
        'previous_hash': block['previous_hash']
    }), 200


@app.route('/nodes/register', methods=['POST'])
def register_nodes():
    values = request.get_json()
    nodes = values.get('nodes')

    if nodes is None:
        return "Error: Please supply a valid list of nodes", 400

    for node in nodes:
        blockchain.register_node(node)

    return jsonify({
        'message': 'New nodes have been added',
        'total_nodes': list(blockchain.nodes)
    }), 201


@app.route('/nodes/resolve', methods=['GET'])
def consensus():
    replaced = blockchain.resolve_conflicts()
    if replaced:
        return jsonify({'message': 'Our chain was replaced', 'new_chain': blockchain.chain}), 200
    return jsonify({'message': 'Our chain is authoritative', 'chain': blockchain.chain}), 200


@app.route('/nodes/get', methods=['GET'])
def get_nodes():
    return jsonify({'nodes': list(blockchain.nodes)}), 200


if __name__ == '__main__':
    from argparse import ArgumentParser

    parser = ArgumentParser()
    parser.add_argument('-p', '--port', default=5000, type=int, help='port to listen on')
    args = parser.parse_args()
    port = args.port

    app.run(host='127.0.0.1', port=port)
