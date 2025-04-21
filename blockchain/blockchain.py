from collections import OrderedDict
import binascii
from uuid import uuid4
from time import time
import hashlib
import json
from urllib.parse import urlparse
import logging

import requests
from flask import Flask, jsonify, request, render_template
from flask_cors import CORS

from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15  
from Crypto.Hash import SHA256  # Upgraded from SHA1

# Configure logging
logging.basicConfig(level=logging.INFO, 
                   format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

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
        """Add a new node to the list of nodes"""
        parsed_url = urlparse(node_url)
        if parsed_url.netloc:
            self.nodes.add(parsed_url.netloc)
        elif parsed_url.path:
            self.nodes.add(parsed_url.path)
        else:
            raise ValueError('Invalid URL')

    def verify_transaction_signature(self, sender_address, signature, transaction):
        """Verify the transaction signature using sender's public key"""
        try:
            public_key = RSA.import_key(binascii.unhexlify(sender_address))
            verifier = pkcs1_15.new(public_key)
            # Use SHA256 instead of SHA1 for better security
            h = SHA256.new(json.dumps(transaction, sort_keys=True).encode('utf-8'))
            verifier.verify(h, binascii.unhexlify(signature))
            return True
        except Exception as e:
            logger.error(f"Signature verification failed: {str(e)}")
            return False

    def submit_transaction(self, sender_address, recipient_address, value, signature):
        """Add a transaction to the transaction list"""
        transaction = OrderedDict({
            'sender_address': sender_address,
            'recipient_address': recipient_address,
            'value': value
        })

        # Mining reward transactions don't need verification
        if sender_address == MINING_SENDER:
            self.transactions.append(transaction)
            return len(self.chain) + 1

        # Verify transaction signature
        if self.verify_transaction_signature(sender_address, signature, transaction):
            self.transactions.append(transaction)
            return len(self.chain) + 1
        else:
            return False

    def create_block(self, nonce, previous_hash):
        """Create a new block in the blockchain"""
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
        """Create a SHA-256 hash of a block"""
        block_string = json.dumps(block, sort_keys=True).encode()
        return hashlib.sha256(block_string).hexdigest()

    def proof_of_work(self):
        """Proof of work algorithm"""
        last_block = self.chain[-1]
        last_hash = self.hash(last_block)
        nonce = 0
        while not self.valid_proof(self.transactions, last_hash, nonce):
            nonce += 1
        return nonce

    def valid_proof(self, transactions, last_hash, nonce, difficulty=MINING_DIFFICULTY):
        """Validate the proof: does hash(transactions+last_hash+nonce) start with zeros?"""
        guess = json.dumps({'transactions': transactions, 'last_hash': last_hash, 'nonce': nonce}, sort_keys=True).encode()
        guess_hash = hashlib.sha256(guess).hexdigest()
        return guess_hash[:difficulty] == '0' * difficulty

    def valid_chain(self, chain):
        """Verify if a blockchain is valid"""
        last_block = chain[0]
        current_index = 1

        while current_index < len(chain):
            block = chain[current_index]
            if block['previous_hash'] != self.hash(last_block):
                return False

            # Extract transactions from current block (excluding mining reward)
            transactions = block['transactions'][:-1] if block['transactions'] else []
            transaction_elements = ['sender_address', 'recipient_address', 'value']
            transactions = [OrderedDict((k, transaction[k]) for k in transaction_elements) for transaction in transactions]

            if not self.valid_proof(transactions, block['previous_hash'], block['nonce'], MINING_DIFFICULTY):
                return False

            last_block = block
            current_index += 1

        return True

    def resolve_conflicts(self):
        """Consensus algorithm: resolve conflicts by replacing our chain with the longest valid chain"""
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
            except requests.exceptions.RequestException as e:
                logger.warning(f"Error connecting to node {node}: {str(e)}")
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
    """Render home page"""
    return render_template('./index.html')

@app.route('/configure')
def configure():
    """Render configuration page"""
    return render_template('./configure.html')


@app.route('/transactions/new', methods=['POST'])
def new_transaction():
    """Submit a new transaction to the blockchain"""
    try:
        # Handle both JSON and form data
        values = None
        
        if request.is_json:
            values = request.get_json()
        elif request.form:
            # Process form data
            values = request.form.to_dict()
        elif request.data:
            # Try to parse raw data as JSON
            try:
                values = json.loads(request.data.decode('utf-8'))
            except json.JSONDecodeError:
                pass
        
        # If we still don't have values, check for URL-encoded content
        if values is None and request.content_type and 'application/x-www-form-urlencoded' in request.content_type:
            values = request.form.to_dict()
            
        # Last resort: try to parse the raw data
        if values is None and request.data:
            try:
                # Try to parse as JSON one more time with relaxed rules
                values = json.loads(request.data.decode('utf-8'))
            except:
                return jsonify({'error': 'Could not parse request data. Please send valid JSON or form data'}), 400
        
        if not values:
            return jsonify({'error': 'No data provided'}), 400

        required = ['sender_address', 'recipient_address', 'amount', 'signature']
        if not all(k in values for k in required):
            return jsonify({'error': 'Missing values'}), 400

        # Validate amount
        try:
            amount = float(values['amount'])
            if amount <= 0:
                return jsonify({'error': 'Amount must be positive'}), 400
        except ValueError:
            return jsonify({'error': 'Amount must be a valid number'}), 400

        result = blockchain.submit_transaction(
            sender_address=values['sender_address'],
            recipient_address=values['recipient_address'],
            value=amount,
            signature=values['signature']
        )

        if not result:
            return jsonify({'error': 'Invalid Transaction!'}), 406

        return jsonify({'message': f'Transaction will be added to Block {result}'}), 201
    
    except Exception as e:
        logger.error(f"Error processing transaction: {str(e)}")
        return jsonify({'error': f'Internal server error: {str(e)}'}), 500


@app.route('/transactions/get', methods=['GET'])
def get_transactions():
    """Get all pending transactions"""
    return jsonify({'transactions': blockchain.transactions}), 200


@app.route('/chain', methods=['GET'])
def full_chain():
    """Get the full blockchain"""
    return jsonify({'chain': blockchain.chain, 'length': len(blockchain.chain)}), 200


@app.route('/mine', methods=['GET'])
def mine():
    """Mine a new block"""
    try:
        # Find the proof of work
        last_block = blockchain.chain[-1]
        nonce = blockchain.proof_of_work()

        # Reward for mining
        blockchain.submit_transaction(
            sender_address=MINING_SENDER,
            recipient_address=blockchain.node_id,
            value=MINING_REWARD,
            signature=""
        )

        # Forge the new block
        previous_hash = blockchain.hash(last_block)
        block = blockchain.create_block(nonce, previous_hash)

        response = {
            'message': "New Block Forged",
            'block_number': block['block_number'],
            'transactions': block['transactions'],
            'nonce': block['nonce'],
            'previous_hash': block['previous_hash']
        }
        return jsonify(response), 200
    except Exception as e:
        logger.error(f"Error mining block: {str(e)}")
        return jsonify({'error': f'Error mining block: {str(e)}'}), 500


@app.route('/nodes/register', methods=['POST'])
def register_nodes():
    """Register a list of new nodes"""
    try:
        # Handle both JSON and form data similar to transactions/new
        values = None
        
        if request.is_json:
            values = request.get_json()
        elif request.form:
            values = request.form.to_dict()
        elif request.data:
            try:
                values = json.loads(request.data.decode('utf-8'))
            except json.JSONDecodeError:
                pass
        
        if not values:
            return jsonify({'error': 'No data provided'}), 400

        nodes = values.get('nodes')

        if nodes is None or not isinstance(nodes, list):
            return jsonify({'error': 'Please supply a valid list of nodes'}), 400

        for node in nodes:
            blockchain.register_node(node)

        return jsonify({
            'message': 'New nodes have been added',
            'total_nodes': list(blockchain.nodes)
        }), 201
    except Exception as e:
        logger.error(f"Error registering nodes: {str(e)}")
        return jsonify({'error': f'Error registering nodes: {str(e)}'}), 500


@app.route('/nodes/resolve', methods=['GET'])
def consensus():
    """Consensus algorithm to resolve conflicts between nodes"""
    try:
        replaced = blockchain.resolve_conflicts()
        if replaced:
            return jsonify({'message': 'Our chain was replaced', 'new_chain': blockchain.chain}), 200
        return jsonify({'message': 'Our chain is authoritative', 'chain': blockchain.chain}), 200
    except Exception as e:
        logger.error(f"Error resolving consensus: {str(e)}")
        return jsonify({'error': f'Error resolving consensus: {str(e)}'}), 500


@app.route('/nodes/get', methods=['GET'])
def get_nodes():
    """Get all registered nodes"""
    return jsonify({'nodes': list(blockchain.nodes)}), 200


@app.errorhandler(404)
def not_found(error):
    """Handle 404 errors"""
    return jsonify({'error': 'Resource not found'}), 404


@app.errorhandler(500)
def server_error(error):
    """Handle 500 errors"""
    return jsonify({'error': 'Internal server error'}), 500


if __name__ == '__main__':
    from argparse import ArgumentParser

    parser = ArgumentParser()
    parser.add_argument('-p', '--port', default=5000, type=int, help='port to listen on')
    parser.add_argument('--debug', action='store_true', help='run in debug mode')
    args = parser.parse_args()
    port = args.port

    logger.info(f"Starting blockchain node on port {port}")
    app.run(host='127.0.0.1', port=port, debug=args.debug)