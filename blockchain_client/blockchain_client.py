from collections import OrderedDict
import binascii
import json
import logging
from typing import Dict, Any, Union

from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256  # Upgraded from SHA1
from Crypto import Random
from flask import Flask, jsonify, request, render_template
from flask_cors import CORS

# Configure logging
logging.basicConfig(level=logging.INFO, 
                    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class Transaction:
    """Represents a cryptocurrency transaction with signing capabilities"""
    
    def __init__(self, sender_address: str, sender_private_key: str, 
                 recipient_address: str, value: float):
        """Initialize a new transaction"""
        self.sender_address = sender_address
        self.sender_private_key = sender_private_key
        self.recipient_address = recipient_address
        self.value = value
        
    def to_dict(self) -> OrderedDict:
        """Convert transaction to an ordered dictionary for consistent hashing"""
        return OrderedDict({
            'sender_address': self.sender_address,
            'recipient_address': self.recipient_address,
            'value': self.value
        })
    
    def sign_transaction(self) -> Union[str, None]:
        """Sign transaction with sender's private key using SHA256"""
        if not self.sender_private_key:
            logger.error("No private key provided for signing")
            return None
            
        try:
            # Import the private key
            private_key = RSA.import_key(binascii.unhexlify(self.sender_private_key))
            
            # Create the signature object
            signer = pkcs1_15.new(private_key)
            
            # Create hash of the transaction data
            transaction_hash = SHA256.new(json.dumps(self.to_dict(), sort_keys=True).encode('utf-8'))
            
            # Sign the hash
            signature = signer.sign(transaction_hash)
            
            # Return hex-encoded signature
            return binascii.hexlify(signature).decode('ascii')
        except Exception as e:
            logger.error(f"Error signing transaction: {str(e)}")
            return None


# Flask app
app = Flask(__name__)
CORS(app)  # Enable CORS for all routes

@app.route('/')
def index():
    """Render the main page"""
    return render_template('index.html')

@app.route('/make/transaction')
def make_transaction():
    """Render the transaction creation page"""
    return render_template('make_transaction.html')

@app.route('/view/transactions')
def view_transaction():
    """Render the transaction viewing page"""
    return render_template('view_transactions.html')

@app.route('/wallet/new', methods=['GET'])
def new_wallet():
    """Generate and return a new wallet (key pair)"""
    try:
        random_gen = Random.new().read
        # Increased key size from 1024 to 2048 bits for better security
        private_key = RSA.generate(2048, random_gen)
        public_key = private_key.publickey()
        
        response = {
            'private_key': binascii.hexlify(private_key.export_key(format='DER')).decode('ascii'),
            'public_key': binascii.hexlify(public_key.export_key(format='DER')).decode('ascii')
        }
        return jsonify(response), 200
    except Exception as e:
        logger.error(f"Error generating wallet: {str(e)}")
        return jsonify({'error': 'Failed to generate wallet'}), 500

@app.route('/generate/transaction', methods=['POST'])
def generate_transaction():
    """Create and sign a new transaction"""
    try:
        # Handle multiple content types
        data = None
        
        if request.is_json:
            data = request.get_json()
        elif request.form:
            data = request.form.to_dict()
        elif request.data:
            try:
                data = json.loads(request.data.decode('utf-8'))
            except json.JSONDecodeError:
                pass
                
        if data is None and request.content_type and 'application/x-www-form-urlencoded' in request.content_type:
            data = request.form.to_dict()
            
        if not data and request.data:
            try:
                # Last attempt to parse data
                data = json.loads(request.data.decode('utf-8'))
            except:
                return jsonify({'error': 'Could not parse request data. Please send valid JSON or form data'}), 400
        
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        # Validate required fields
        required = ['sender_address', 'sender_private_key', 'recipient_address', 'amount']
        if not all(k in data for k in required):
            missing = [k for k in required if k not in data]
            return jsonify({'error': f'Missing transaction fields: {", ".join(missing)}'}), 400
        
        # Validate amount
        try:
            amount = float(data['amount'])
            if amount <= 0:
                return jsonify({'error': 'Amount must be positive'}), 400
        except ValueError:
            return jsonify({'error': 'Amount must be a valid number'}), 400
        
        # Create and sign transaction
        transaction = Transaction(
            sender_address=data['sender_address'],
            sender_private_key=data['sender_private_key'],
            recipient_address=data['recipient_address'],
            value=amount
        )
        
        # Get transaction signature
        signature = transaction.sign_transaction()
        if not signature:
            return jsonify({'error': 'Failed to sign transaction'}), 500
        
        # Return transaction and signature
        response = {
            'transaction': transaction.to_dict(),
            'signature': signature
        }
        return jsonify(response), 200
    
    except Exception as e:
        logger.error(f"Error processing transaction: {str(e)}")
        return jsonify({'error': f'Internal server error: {str(e)}'}), 500

@app.route('/verify/transaction', methods=['POST'])
def verify_transaction():
    """Verify a transaction signature"""
    try:
        # Handle multiple content types
        data = None
        
        if request.is_json:
            data = request.get_json()
        elif request.form:
            data = request.form.to_dict()
        elif request.data:
            try:
                data = json.loads(request.data.decode('utf-8'))
            except json.JSONDecodeError:
                pass
                
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        required = ['transaction', 'signature', 'public_key']
        if not all(k in data for k in required):
            missing = [k for k in required if k not in data]
            return jsonify({'error': f'Missing verification fields: {", ".join(missing)}'}), 400
            
        transaction = data['transaction']
        if isinstance(transaction, str):
            try:
                transaction = json.loads(transaction)
            except json.JSONDecodeError:
                return jsonify({'error': 'Invalid transaction format'}), 400
        
        # Verify the signature
        try:
            public_key = RSA.import_key(binascii.unhexlify(data['public_key']))
            transaction_hash = SHA256.new(json.dumps(transaction, sort_keys=True).encode('utf-8'))
            verifier = pkcs1_15.new(public_key)
            verifier.verify(transaction_hash, binascii.unhexlify(data['signature']))
            return jsonify({'valid': True}), 200
        except Exception as e:
            logger.warning(f"Signature verification failed: {str(e)}")
            return jsonify({'valid': False}), 200
    
    except Exception as e:
        logger.error(f"Error verifying transaction: {str(e)}")
        return jsonify({'error': f'Internal server error: {str(e)}'}), 500

@app.route('/submit/transaction', methods=['POST'])
def submit_transaction():
    """
    Submit a signed transaction to the blockchain node
    This endpoint acts as a bridge between the wallet and blockchain node
    """
    try:
        # Handle multiple content types
        data = None
        
        if request.is_json:
            data = request.get_json()
        elif request.form:
            data = request.form.to_dict()
        elif request.data:
            try:
                data = json.loads(request.data.decode('utf-8'))
            except json.JSONDecodeError:
                pass
                
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        required = ['transaction', 'signature']
        if not all(k in data for k in required):
            missing = [k for k in required if k not in data]
            return jsonify({'error': f'Missing fields: {", ".join(missing)}'}), 400
        
        # Get the node URL from request or use default
        node_url = data.get('node_url', 'http://127.0.0.1:5000')
        
        # Format the transaction for the blockchain node
        transaction = data['transaction']
        if isinstance(transaction, str):
            try:
                transaction = json.loads(transaction)
            except json.JSONDecodeError:
                return jsonify({'error': 'Invalid transaction format'}), 400
        
        # Construct payload for blockchain node
        payload = {
            'sender_address': transaction['sender_address'],
            'recipient_address': transaction['recipient_address'],
            'amount': transaction['value'],
            'signature': data['signature']
        }
        
        # Send transaction to blockchain node
        headers = {'Content-Type': 'application/json'}
        
        response = requests.post(
            f"{node_url}/transactions/new", 
            json=payload,
            headers=headers
        )
        
        if response.status_code == 201:
            return jsonify(response.json()), 201
        else:
            error_msg = response.json().get('error', 'Unknown error from blockchain node')
            return jsonify({'error': error_msg}), response.status_code
    
    except requests.exceptions.RequestException as e:
        logger.error(f"Error connecting to blockchain node: {str(e)}")
        return jsonify({'error': 'Could not connect to blockchain node'}), 500
    except Exception as e:
        logger.error(f"Error submitting transaction to blockchain: {str(e)}")
        return jsonify({'error': f'Error: {str(e)}'}), 500

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
    import requests
    
    parser = ArgumentParser()
    parser.add_argument('-p', '--port', default=8080, type=int, help='port to listen on')
    parser.add_argument('--debug', action='store_true', help='run in debug mode')
    args = parser.parse_args()
    
    # Print startup information
    logger.info(f"Starting wallet server on port {args.port}")
    
    # Run the application
    app.run(host='127.0.0.1', port=args.port, debug=args.debug)