import pyaes
from encodings import utf_8
from flask import Flask, request, jsonify, render_template
from collections import OrderedDict
import requests
import Crypto
from Crypto.Hash import SHA
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


class Transaction:

    def __init__(self, sender_public_key, sender_private_key, recipient_public_key, message):
        self.sender_public_key = sender_public_key
        self.sender_private_key = sender_private_key
        self.recipient_public_key = recipient_public_key
        self.message = message

    def to_dict(self):
        return OrderedDict({
            'sender_public_key': self.sender_public_key,
            'recipient_public_key': self.recipient_public_key,
            'message': self.message,
        })

    def sign_transaction(self):
        private_key = serialization.load_der_private_key(
            bytes.fromhex(self.sender_private_key),
            password=None
        )
        h = SHA.new(str(self.to_dict()).encode('utf8'))
        return private_key.sign(
            bytes.fromhex(h.hexdigest()),
            ec.ECDSA(hashes.SHA256())
        )


app = Flask(__name__)


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/generate/transaction', methods=['POST'])
def generate_transaction():
    sender_public_key = request.form['sender_public_key']
    sender_private_key = request.form['sender_private_key']
    recipient_public_key = request.form['recipient_public_key']
    message = request.form['message']

    s_private_key = serialization.load_der_private_key(
        bytes.fromhex(sender_private_key),
        password=None
    )

    r_public_key = serialization.load_der_public_key(
        bytes.fromhex(recipient_public_key)
    )

    shared_key = s_private_key.exchange(ec.ECDH(), r_public_key)

    # Perform key derivation.
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'message exhange',
    ).derive(shared_key)

    cipher = pyaes.AESModeOfOperationCTR(derived_key)
    ct_message = cipher.encrypt(message).hex()

    transaction = Transaction(
        sender_public_key, sender_private_key, recipient_public_key, ct_message)

    response = {'transaction': transaction.to_dict(),
                'signature': transaction.sign_transaction().hex()
                }

    return jsonify(response), 200


@app.route('/make/transaction')
def make_transaction():
    return render_template('make_transaction.html')


@app.route('/view/transactions')
def view_transactions():
    return render_template('view_transactions.html')


@app.route('/view/transactions', methods=['POST'])
def decrypt_transactions():
    requests.get(request.form['node_url'] + "/nodes/resolve")
    recipient_private_key = request.form['recipient_private_key']
    recipient_public_key = request.form['recipient_public_key']
    response = requests.get(request.form['node_url'] + "/chain")
    transactions = [transaction
                    for transactions in response.json()["chain"]
                    for transaction in transactions['transactions']
                    ]
    recipientTransactions = [
        transaction for transaction in transactions if transaction['recipient_public_key'] == recipient_public_key]

    for singleTransaction in recipientTransactions:
        r_private_key = serialization.load_der_private_key(
            bytes.fromhex(recipient_private_key),
            password=None
        )

        s_public_key = serialization.load_der_public_key(
            bytes.fromhex(singleTransaction['sender_public_key'])
        )

        shared_key = r_private_key.exchange(ec.ECDH(), s_public_key)

        # Perform key derivation.
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'message exhange',
        ).derive(shared_key)

        cipher = pyaes.AESModeOfOperationCTR(derived_key)
        decrypted_message = cipher.decrypt(
            bytes.fromhex(singleTransaction['message']))
        singleTransaction['decrypted_message'] = str(
            decrypted_message, encoding='utf-8')

    return jsonify(recipientTransactions), 200


@app.route('/wallet/new')
def new_wallet():
    private_key = ec.generate_private_key(
        ec.SECP384R1()
    )

    public_key = private_key.public_key()

    response = {
        'private_key': private_key.private_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).hex(),
        'public_key': public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).hex()
    }

    return jsonify(response), 200


if __name__ == '__main__':
    from argparse import ArgumentParser

    parser = ArgumentParser()
    parser.add_argument('-p', '--port', default=8081,
                        type=int, help="port to listen to")
    args = parser.parse_args()
    port = args.port

    app.run(port=port, debug=True)
