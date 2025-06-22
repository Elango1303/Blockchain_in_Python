# Blockchain Implementation

A complete blockchain implementation in Python with Flask web interface, featuring cryptocurrency transactions, digital signatures, proof-of-work mining, and a distributed network architecture.

## Features

- **Complete Blockchain**: Full blockchain implementation with blocks, transactions, and chain validation
- **Digital Signatures**: RSA-based transaction signing and verification using SHA-256
- **Proof of Work**: Mining algorithm with adjustable difficulty
- **Wallet System**: Generate wallets, create and sign transactions
- **Network Nodes**: Distributed network with consensus algorithm
- **REST API**: Complete REST API for blockchain operations
- **Web Interface**: User-friendly web interface for interaction
- **Security**: Enhanced security with 2048-bit RSA keys and SHA-256 hashing

## Architecture

The project consists of two main components:

### 1. Blockchain Node (`blockchain.py`)
- Core blockchain functionality
- Mining and proof-of-work
- Transaction validation
- Network consensus
- REST API endpoints

### 2. Blockchain Client (`blockchain_client.py`)
- Wallet generation and management
- Transaction creation and signing
- Transaction verification
- Client interface for interacting with blockchain nodes

## Installation

### Prerequisites
- Python 3.7+
- pip package manager

### Dependencies
```bash
pip install flask flask-cors pycryptodome requests
```

### Clone Repository
```bash
git clone <your-repository-url>
cd blockchain-project
```

## Usage

### Starting the Blockchain Node

```bash
# Start blockchain node on default port 5000
python blockchain.py

# Start on custom port
python blockchain.py -p 5001

# Start in debug mode
python blockchain.py --debug
```

### Starting the Client

```bash
# Start client on default port 8080
python blockchain_client.py

# Start on custom port
python blockchain_client.py -p 8081

# Start in debug mode
python blockchain_client.py --debug
```

## API Endpoints

### Blockchain Node (Port 5000)

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/` | Home page |
| GET | `/configure` | Configuration page |
| POST | `/transactions/new` | Submit new transaction |
| GET | `/transactions/get` | Get pending transactions |
| GET | `/chain` | Get full blockchain |
| GET | `/mine` | Mine a new block |
| POST | `/nodes/register` | Register network nodes |
| GET | `/nodes/resolve` | Consensus algorithm |
| GET | `/nodes/get` | Get registered nodes |

### Client (Port 8080)

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/` | Main page |
| GET | `/make/transaction` | Transaction creation page |
| GET | `/view/transactions` | View transactions page |
| GET | `/wallet/new` | Generate new wallet |
| POST | `/generate/transaction` | Create and sign transaction |
| POST | `/verify/transaction` | Verify transaction signature |
| POST | `/submit/transaction` | Submit transaction to blockchain |

## Example Usage

### 1. Generate a New Wallet
```bash
curl http://localhost:8080/wallet/new
```

### 2. Create a Transaction
```bash
curl -X POST http://localhost:8080/generate/transaction \
  -H "Content-Type: application/json" \
  -d '{
    "sender_address": "your_public_key",
    "sender_private_key": "your_private_key",
    "recipient_address": "recipient_public_key",
    "amount": 10
  }'
```

### 3. Submit Transaction to Blockchain
```bash
curl -X POST http://localhost:5000/transactions/new \
  -H "Content-Type: application/json" \
  -d '{
    "sender_address": "sender_public_key",
    "recipient_address": "recipient_public_key",
    "amount": 10,
    "signature": "transaction_signature"
  }'
```

### 4. Mine a Block
```bash
curl http://localhost:5000/mine
```

### 5. View Blockchain
```bash
curl http://localhost:5000/chain
```

## Configuration

### Mining Configuration
```python
MINING_SENDER = "THE BLOCKCHAIN"
MINING_REWARD = 1
MINING_DIFFICULTY = 2  # Number of leading zeros required
```

### Security Features
- **RSA-2048**: 2048-bit RSA keys for enhanced security
- **SHA-256**: Secure hashing algorithm for signatures and blocks
- **Input Validation**: Comprehensive input validation and error handling
- **Logging**: Detailed logging for debugging and monitoring

## Network Setup

### Running Multiple Nodes

1. **Start first node:**
```bash
python blockchain.py -p 5000
```

2. **Start second node:**
```bash
python blockchain.py -p 5001
```

3. **Register nodes with each other:**
```bash
# Register node 5001 with node 5000
curl -X POST http://localhost:5000/nodes/register \
  -H "Content-Type: application/json" \
  -d '{"nodes": ["127.0.0.1:5001"]}'

# Register node 5000 with node 5001
curl -X POST http://localhost:5001/nodes/register \
  -H "Content-Type: application/json" \
  -d '{"nodes": ["127.0.0.1:5000"]}'
```

4. **Resolve conflicts:**
```bash
curl http://localhost:5000/nodes/resolve
curl http://localhost:5001/nodes/resolve
```

## File Structure

```
blockchain-project/
├── blockchain.py           # Main blockchain node
├── blockchain_client.py    # Blockchain client/wallet
├── templates/             # HTML templates
│   ├── index.html
│   ├── configure.html
│   ├── make_transaction.html
│   └── view_transactions.html
└── README.md
```

## Security Considerations

- **Private Key Management**: Store private keys securely
- **Network Security**: Use HTTPS in production
- **Input Validation**: All inputs are validated and sanitized
- **Error Handling**: Comprehensive error handling prevents crashes
- **Signature Verification**: All transactions are cryptographically verified

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Troubleshooting

### Common Issues

1. **Port Already in Use**
   ```bash
   # Use different port
   python blockchain.py -p 5002
   ```

2. **Missing Dependencies**
   ```bash
   pip install flask flask-cors pycryptodome requests
   ```

3. **Connection Refused**
   - Ensure blockchain node is running before starting client
   - Check firewall settings
   - Verify correct ports are being used

### Logging

Both applications provide detailed logging. Check console output for debugging information.

## Performance Notes

- **Mining Difficulty**: Adjust `MINING_DIFFICULTY` based on desired block time
- **Key Size**: 2048-bit RSA keys provide good security vs performance balance
- **Network Latency**: Consider network delays when running distributed nodes

## Future Enhancements

- [ ] Database persistence
- [ ] Enhanced web interface
- [ ] Smart contracts
- [ ] Multi-signature transactions
- [ ] Transaction fees
- [ ] Block size limits
- [ ] Performance optimizations

## Support

For questions or issues, please open an issue on GitHub or contact the maintainers.

---

**Note**: This is an educational blockchain implementation. For production use, additional security measures and optimizations would be required.
