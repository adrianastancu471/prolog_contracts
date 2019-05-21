from bigchaindb_driver import BigchainDB
from bigchaindb_driver.crypto import generate_keypair

from collections import OrderedDict
from pyswip import Prolog
import multiprocessing

import time
import json

import binascii

import Crypto
import Crypto.Random
from Crypto.Hash import SHA
from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5

import hashlib
import json
from time import time
from urllib.parse import urlparse
from uuid import uuid4

import requests
from flask import Flask, jsonify, request, render_template
from flask_cors import CORS
import datetime
import base64


MINING_SENDER = "THE BLOCKCHAIN"
MINING_REWARD = 1
MINING_DIFFICULTY = 2


class Blockchain:

    def __init__(self):
        
        self.transactions = []
        self.chain = []
        self.nodes = set()
        #Generate random number to be used as node_id
        self.node_id = str(uuid4()).replace('-', '')
        #Create genesis block
        self.create_block(0, '00')


    def register_node(self, node_url):
        """
        Add a new node to the list of nodes
        """
        #Checking node_url has valid format
        parsed_url = urlparse(node_url)
        if parsed_url.netloc:
            self.nodes.add(parsed_url.netloc)
        elif parsed_url.path:
            # Accepts an URL without scheme like '192.168.0.5:5000'.
            self.nodes.add(parsed_url.path)
        else:
            raise ValueError('Invalid URL')


    def verify_transaction_signature(self, sender_address, signature, transaction):
        """
        Check that the provided signature corresponds to transaction
        signed by the public key (sender_address)
        """
        public_key = RSA.importKey(binascii.unhexlify(sender_address))
        verifier = PKCS1_v1_5.new(public_key)
        h = SHA.new(str(transaction).encode('utf8'))
        return verifier.verify(h, binascii.unhexlify(signature))


    def submit_transaction(self, sender_address, recipient_address, value, signature):
        """
        Add a transaction to transactions array if the signature verified
        """
        transaction = OrderedDict({'sender_address': sender_address, 
                                    'recipient_address': recipient_address,
                                    'value': value})

        #Reward for mining a block
        if sender_address == MINING_SENDER:
            self.transactions.append(transaction)
            return len(self.chain) + 1
        #Manages transactions from wallet to another wallet
        else:
            transaction_verification = self.verify_transaction_signature(sender_address, signature, transaction)
            if transaction_verification:
                self.transactions.append(transaction)
                return len(self.chain) + 1
            else:
                return False


    def create_block(self, nonce, previous_hash):
        """
        Add a block of transactions to the blockchain
        """
        block = {'block_number': len(self.chain) + 1,
                'timestamp': time(),
                'transactions': self.transactions,
                'nonce': nonce,
                'previous_hash': previous_hash}

        # Reset the current list of transactions
        self.transactions = []

        self.chain.append(block)
        return block


    def hash(self, block):
        """
        Create a SHA-256 hash of a block
        """
        # We must make sure that the Dictionary is Ordered, or we'll have inconsistent hashes
        block_string = json.dumps(block, sort_keys=True).encode()
        
        return hashlib.sha256(block_string).hexdigest()


    def proof_of_work(self):
        """
        Proof of work algorithm
        """
        last_block = self.chain[-1]
        last_hash = self.hash(last_block)

        nonce = 0
        while self.valid_proof(self.transactions, last_hash, nonce) is False:
            nonce += 1

        return nonce


    def valid_proof(self, transactions, last_hash, nonce, difficulty=MINING_DIFFICULTY):
        """
        Check if a hash value satisfies the mining conditions. This function is used within the proof_of_work function.
        """
        guess = (str(transactions)+str(last_hash)+str(nonce)).encode()
        guess_hash = hashlib.sha256(guess).hexdigest()
        return guess_hash[:difficulty] == '0'*difficulty


    def valid_chain(self, chain):
        """
        check if a bockchain is valid
        """
        last_block = chain[0]
        current_index = 1

        while current_index < len(chain):
            block = chain[current_index]
            #print(last_block)
            #print(block)
            #print("\n-----------\n")
            # Check that the hash of the block is correct
            if block['previous_hash'] != self.hash(last_block):
                return False

            # Check that the Proof of Work is correct
            #Delete the reward transaction
            transactions = block['transactions'][:-1]
            # Need to make sure that the dictionary is ordered. Otherwise we'll get a different hash
            transaction_elements = ['sender_address', 'recipient_address', 'value']
            transactions = [OrderedDict((k, transaction[k]) for k in transaction_elements) for transaction in transactions]

            if not self.valid_proof(transactions, block['previous_hash'], block['nonce'], MINING_DIFFICULTY):
                return False

            last_block = block
            current_index += 1

        return True

    def resolve_conflicts(self):
        """
        Resolve conflicts between blockchain's nodes
        by replacing our chain with the longest one in the network.
        """
        neighbours = self.nodes
        new_chain = None

        # We're only looking for chains longer than ours
        max_length = len(self.chain)

        # Grab and verify the chains from all the nodes in our network
        for node in neighbours:
            print('http://' + node + '/chain')
            response = requests.get('http://' + node + '/chain')

            if response.status_code == 200:
                length = response.json()['length']
                chain = response.json()['chain']

                # Check if the length is longer and the chain is valid
                if length > max_length and self.valid_chain(chain):
                    max_length = length
                    new_chain = chain

        # Replace our chain if we discovered a new, valid chain longer than ours
        if new_chain:
            self.chain = new_chain
            return True

        return False

# Instantiate the Node
app = Flask(__name__)
CORS(app)
start_contract_event = multiprocessing.Event()
queue_in = multiprocessing.Queue()
queue_out = multiprocessing.Queue()

bdb_root_url = 'http://localhost:9984' 
bdb = BigchainDB(bdb_root_url)

# Instantiate the Blockchain
blockchain = Blockchain()

@app.route('/')
def index():
    return render_template('./index.html')

@app.route('/configure')
def configure():
    return render_template('./configure.html')

@app.route('/contract')
def contract():
    return render_template('./contract.html')


@app.route('/transactions/new', methods=['POST'])
def new_transaction():
    values = request.form

    # Check that the required fields are in the POST'ed data
    required = ['sender_address', 'recipient_address', 'amount', 'signature']
    if not all(k in values for k in required):
        return 'Missing values', 400
    # Create a new Transaction
    transaction_result = blockchain.submit_transaction(values['sender_address'], values['recipient_address'], values['amount'], values['signature'])

    if transaction_result == False:
        response = {'message': 'Invalid Transaction!'}
        return jsonify(response), 406
    else:
        response = {'message': 'Transaction will be added to Block '+ str(transaction_result)}
        return jsonify(response), 201

@app.route('/transactions/get', methods=['GET'])
def get_transactions():
    #Get transactions from transactions pool
    transactions = blockchain.transactions

    response = {'transactions': transactions}
    return jsonify(response), 200

@app.route('/chain', methods=['GET'])
def full_chain():
    response = {
        'chain': blockchain.chain,
        'length': len(blockchain.chain),
    }
    return jsonify(response), 200

@app.route('/mine', methods=['GET'])
def mine():
    # We run the proof of work algorithm to get the next proof...
    last_block = blockchain.chain[-1]
    nonce = blockchain.proof_of_work()

    # We must receive a reward for finding the proof.
    blockchain.submit_transaction(sender_address=MINING_SENDER, recipient_address=blockchain.node_id, value=MINING_REWARD, signature="")

    # Forge the new Block by adding it to the chain
    previous_hash = blockchain.hash(last_block)
    block = blockchain.create_block(nonce, previous_hash)

    response = {
        'message': "New Block Forged",
        'block_number': block['block_number'],
        'transactions': block['transactions'],
        'nonce': block['nonce'],
        'previous_hash': block['previous_hash'],
    }
    return jsonify(response), 200



@app.route('/nodes/register', methods=['POST'])
def register_nodes():
    values = request.form
    nodes = values.get('nodes').replace(" ", "").split(',')

    if nodes is None:
        return "Error: Please supply a valid list of nodes", 400

    for node in nodes:
        blockchain.register_node(node)

    response = {
        'message': 'New nodes have been added',
        'total_nodes': [node for node in blockchain.nodes],
    }
    return jsonify(response), 201


@app.route('/nodes/resolve', methods=['GET'])
def consensus():
    replaced = blockchain.resolve_conflicts()

    if replaced:
        response = {
            'message': 'Our chain was replaced',
            'new_chain': blockchain.chain
        }
    else:
        response = {
            'message': 'Our chain is authoritative',
            'chain': blockchain.chain
        }
    return jsonify(response), 200


@app.route('/nodes/get', methods=['GET'])
def get_nodes():
    nodes = list(blockchain.nodes)
    response = {'nodes': nodes}
    return jsonify(response), 200




@app.route('/generate/license', methods=['POST'])
def generate_license():
	
	password = request.form['password']
	username = request.form['username']
	product_name = request.form['product_name']
	duration = int(request.form['duration'])
	valid_countries = request.form['valid_countries']
	license_type = request.form['license_type']

	password_hash = SHA256.new(password.encode('utf-8')).hexdigest()
	key32 = "{: <32}".format(password).encode("utf-8")

	user_asset = bdb.assets.get(search=username)
	idx = -1
	user_transaction=[]
	user_idx = -1
	for i,user in enumerate(user_asset):
		user_transaction = bdb.transactions.get(asset_id=user["id"])
		transaction = user_transaction[len(user_transaction)-1]
		if transaction is None or 'metadata' not in transaction or transaction['metadata'] is None or 'account' not in transaction['metadata']:
			continue
		if transaction['metadata']['account'] == 'active' and transaction['metadata']['password']== password_hash:
			idx = len(user_transaction)-1
			user_idx = i

	if idx == -1:
		response = {'account':'invalid'}
		return jsonify(response), 200
	
	encrypted_private_key = user_transaction[idx]['metadata']['private_key']
	cipher = AES.new(key32,AES.MODE_ECB) 
	private_key = cipher.decrypt(base64.b64decode(encrypted_private_key))

	duration = datetime.datetime.now() + datetime.timedelta(days=duration)
	
	epoch = datetime.datetime.utcfromtimestamp(0)
	datetime_number = int((duration-epoch).total_seconds() *1000)
	contract = contract_form(license_type,valid_countries,datetime_number)
	print(contract)
	
	license_body = {'data':{'type':license_type,'product':product_name, 
			'valid_from': datetime.datetime.now().strftime("%Y-%m-%d %H:%M"), 
			'valid_to' : duration.strftime("%Y-%m-%d %H:%M"),
			'contract': contract}}

	owner_public_key = user_asset[user_idx]['data']['keypair']['public_key']

	prepared_creation_tx = bdb.transactions.prepare(
        operation='CREATE', 
        signers=owner_public_key, 
        asset=license_body, )

	fulfilled_creation_tx = bdb.transactions.fulfill(
        prepared_creation_tx, 
        private_keys=private_key.strip())

	bdb.transactions.send_commit(fulfilled_creation_tx)

	response = {'license_id': fulfilled_creation_tx['id'], 'contract':contract }

	return jsonify(response), 200

#User Register
@app.route('/register/user', methods=['POST'])
def register_user():
	
	email = request.form['email']
	username = request.form['username']
	password = request.form['password']
	country = request.form['country']

	#generez hash-ul parolei 
	password_hash = SHA256.new(password.encode('utf-8')).hexdigest()

	print("asset getbefore")
	#verificare daca mai exista acel user
	user_asset = bdb.assets.get(search=username)
	print("asset get")
	idx = -1
	print(len(user_asset))
	for i, user in enumerate(user_asset):
		print(user)
		if 'username' not in user['data']:
			continue
		if user['data']['username']== username :
			idx = i

	if idx != -1:
		response = {'username': '', 'account':'exists'}
		return jsonify(response), 200

	#criptare parola si cheie privata
	account_keypair = generate_keypair()
	private_key_original = account_keypair.private_key
	private_key_padded = account_keypair.private_key.encode("utf-8").rjust(48)
	print(len(private_key_padded))
	print(private_key_padded)
	print(len(account_keypair.private_key))
	print(account_keypair.private_key)

	key32 = "{: <32}".format(password).encode("utf-8")
	cipher = AES.new(key32,AES.MODE_ECB) 
	private_key_encoded = base64.b64encode(cipher.encrypt(private_key_padded))

	user = {'data':{'username':"",'email':"",'country':"",'keypair':{'public_key':''}}}
	user['data']['username']= username
	user['data']['email']= email
	user['data']['country']= country
	metadata = {'account': 'active','password':password_hash,'private_key':private_key_encoded}

	
	user['data']['keypair']['public_key'] = account_keypair.public_key

	print("prepare")
	prepared_creation_tx = bdb.transactions.prepare(
        operation='CREATE', 
        signers=account_keypair.public_key, 
        asset=user, 
		metadata=metadata,)
		
	print("fulfull")
	fulfilled_creation_tx = bdb.transactions.fulfill(
        prepared_creation_tx, 
        private_keys=private_key_original)

	print("commit")
	bdb.transactions.send_commit(fulfilled_creation_tx)

	response = {'username': username,'account':'created'}

	return jsonify(response), 200

@app.route('/login/user', methods=['POST'])
def login_user():
	
	username = request.form['username']
	password = request.form['password']

	password_hash = SHA256.new(password.encode('utf-8')).hexdigest()

	user_asset = bdb.assets.get(search=username)
	idx_asset = -1
	idx_transaction =-1

	for i, user in enumerate(user_asset):
		user_transaction = bdb.transactions.get(asset_id=user["id"])
		transaction = user_transaction[len(user_transaction)-1]
		if transaction is None:
			continue
		if 'metadata' not in transaction:
			continue
		if transaction['metadata'] is None or 'account' not in transaction['metadata']:
			continue
		if transaction['metadata']['account'] == 'active' and transaction['metadata']['password']== password_hash:
			idx_asset = i
			idx_transaction = len(user_transaction)-1

	if idx_asset == -1:
		response = {'account': 'invalid'}
		return jsonify(response), 200

	print(user_transaction[idx_transaction]['id'])

	response = {'account': user_transaction[idx_transaction]['id']}

	return jsonify(response), 200

#Resetare parola
@app.route('/reset_password/user', methods=['POST'])
def reset_password_user():
	
	current_password = request.form['current_password']
	username = request.form['password2']
	password = request.form['password']

	current_password_hash = SHA256.new(current_password.encode('utf-8')).hexdigest()
	password_hash = SHA256.new(password.encode('utf-8')).hexdigest()
	current_key32 = "{: <32}".format(current_password).encode("utf-8")
	key32 = "{: <32}".format(password).encode("utf-8")

	user_asset = bdb.assets.get(search=username)
	idx = -1
	user_transaction=[]
	asset_id = ""
	for user in user_asset:
		user_transaction = bdb.transactions.get(asset_id=user["id"])
		transaction = user_transaction[len(user_transaction)-1]
		if transaction['metadata']['account'] == 'active' and transaction['metadata']['password']== current_password_hash:
			idx = len(user_transaction)-1
			asset_id = user['id']
			break

	if idx == -1:
		response = {'username': '', 'account':'invalid'}
		return jsonify(response), 200
	
	#decriptare cheie privata pentru semnare tranzactie
	encrypted_private_key = user_transaction[idx]['metadata']['private_key']
	cipher_old = AES.new(current_key32,AES.MODE_ECB) 
	private_key_decoded = cipher_old.decrypt(base64.b64decode(encrypted_private_key))
	cipher_new = AES.new(key32,AES.MODE_ECB) 
	private_key_encoded = base64.b64encode(cipher_new.encrypt(private_key_decoded))

	txid = user_transaction[idx]["id"]
	creation_tx = bdb.transactions.retrieve(txid)

	transfer_asset = {
		'id': asset_id
	}
	metadata = {
		'account': 'active',
		'password':password_hash,
		'private_key':private_key_encoded
	}

	output = creation_tx['outputs'][0]

	transfer_input = {
		'fulfillment': output['condition']['details'],
		'fulfills': {
			'output_index': 0,
			'transaction_id': creation_tx['id'],
		},
		'owners_before': output['public_keys'],
	}

	prepared_transfer_tx = bdb.transactions.prepare(
		operation='TRANSFER',
		asset=transfer_asset,
		inputs=transfer_input,
		metadata=metadata,
		recipients=user['data']['keypair']['public_key'],
	)

	fulfilled_transfer_tx = bdb.transactions.fulfill(
		prepared_transfer_tx,
		private_keys=private_key_decoded.strip(),
	)
	bdb.transactions.send_commit(fulfilled_transfer_tx)
	
	response = {'username': username,'account':'active'}

	return jsonify(response), 200

#Printare chei
@app.route('/retrieve_private_key', methods=['POST'])
def retrieve_private_key():
	username = request.form['username']
	password = request.form['password']

	password_hash = SHA256.new(password.encode('utf-8')).hexdigest()

	user_asset = bdb.assets.get(search=username)
	idx_asset = -1
	idx_transaction = -1
	for i, user in enumerate(user_asset):
		user_transaction = bdb.transactions.get(asset_id=user["id"])
		transaction = user_transaction[len(user_transaction)-1]
		if transaction is None or transaction['metadata'] is None:
			break
		if transaction['metadata']['account'] == 'active' and transaction['metadata']['password']== password_hash:
			idx_asset = i
			idx_transaction = len(user_transaction)-1

	if idx_asset == -1:
		response = {'account': 'invalid'}
		return jsonify(response), 200

	public_key = user_asset[idx_asset]['data']['keypair']['public_key']

	key32 = "{: <32}".format(password).encode("utf-8")
	encrypted_private_key = user_transaction[idx_transaction]['metadata']['private_key']
	cipher_old = AES.new(key32,AES.MODE_ECB) 
	private_key = cipher_old.decrypt(base64.b64decode(encrypted_private_key)).strip()

	response = {'public_key': public_key ,'private_key':private_key}

	return jsonify(response), 200

#Printare chei
@app.route('/retrieve_public_key', methods=['POST'])
def retrieve_public_key():
	username = request.form['username']

	user_asset = bdb.assets.get(search=username)
	idx_asset = -1
	for i, user in enumerate(user_asset):
		user_transaction = bdb.transactions.get(asset_id=user["id"])
		transaction = user_transaction[len(user_transaction)-1]
		if transaction is None or transaction['metadata'] is None:
			break
		if transaction['metadata']['account'] == 'active':
			idx_asset = i

	if idx_asset == -1:
		response = {'account': 'invalid'}
		return jsonify(response), 200

	public_key = user_asset[idx_asset]['data']['keypair']['public_key']

	response = {'public_key': public_key }

	return jsonify(response), 200

#Printare licente
@app.route('/retrieve_licenses', methods=['POST'])
def retrieve_licenses():
	username = request.form['username']

	users_public_key = bdb.assets.get(search=username)[0]['data']['keypair']['public_key']
	print(users_public_key)

	full_license_assets = bdb.assets.get(search="full")
	evaluation_license_assets = bdb.assets.get(search="evaluation")
	full_licenses =[]
	evaluation_licenses =[]
	for license in full_license_assets:
		license_transactions = bdb.transactions.get(asset_id=license['id'])
		if license_transactions[-1]['outputs'][0]['condition']['details']['public_key'] == users_public_key :
			license_object = {
				'product': license['data']['product'],
				'valid_from': license['data']['valid_from'],
				'valid_to': license['data']['valid_to'],
				'contract': license['data']['contract'],
				'license_key' : license_transactions[0]['id'],
				'transfer_key': license_transactions[-1]['id']}
			full_licenses.append(license_object)
	for license in evaluation_license_assets:
		license_transactions = bdb.transactions.get(asset_id=license['id'])
		if license_transactions[-1]['outputs'][0]['condition']['details']['public_key'] == users_public_key :
			license_object = {
				'product': license['data']['product'],
				'valid_from': license['data']['valid_from'],
				'valid_to': license['data']['valid_to'],
				'contract': license['data']['contract'],
				'license_key' : license_transactions[0]['id'],
				'transfer_key': license_transactions[-1]['id']}
			evaluation_licenses.append(license_object)
		
	response = {'full_licenses': full_licenses, 'evaluation_licenses': evaluation_licenses}

	return jsonify(response), 200

@app.route('/transfer/license', methods=['POST'])
def transfer_license():
	
	password = request.form['transfer_password']
	username = request.form['transfer_username']
	license_id = request.form['transfer_license_id']
	recipient = request.form['transfer_recipient_address']
	transfer_transaction_id = request.form['transfer_transaction_id']

	password_hash = SHA256.new(password.encode('utf-8')).hexdigest()
	key32 = "{: <32}".format(password).encode("utf-8")

	user_asset = bdb.assets.get(search=username)
	idx = -1
	user_transaction=[]
	for user in user_asset:
		user_transaction = bdb.transactions.get(asset_id=user["id"])
		transaction = user_transaction[len(user_transaction)-1]
		if transaction['metadata']['account'] == 'active' and transaction['metadata']['password']== password_hash:
			idx = len(user_transaction)-1

	if idx == -1:
		response = {'account':'invalid'}
		return jsonify(response), 200
	
	encrypted_private_key = user_transaction[idx]['metadata']['private_key']
	cipher = AES.new(key32,AES.MODE_ECB) 
	private_key = cipher.decrypt(base64.b64decode(encrypted_private_key))

	#owner_public_key = user_asset[user_idx]['data']['keypair']['public_key']

	transfer_asset = {
		'id': license_id
	}

	transfer_tx = bdb.transactions.retrieve(transfer_transaction_id)
	creation_tx = bdb.transactions.retrieve(license_id)

	recipient_asset = bdb.assets.get(search=recipient)[0]
	print('RECIPIENT_ASSET')
	print(recipient_asset)
	print('ASSET')
	print(creation_tx)
	#TODO CATCH DACA NU E e gasit recipient

	verdict = verify_contract(
		creation_tx['asset']['data']['contract'],
		creation_tx['asset']['data']['type'].lower(),
		recipient_asset['data']['country'].lower(),
		datetime.datetime.now())

	print(verdict)

	output = transfer_tx['outputs'][0]

	transfer_input = {
		'fulfillment': output['condition']['details'],
		'fulfills': {
			'output_index': 0,
			'transaction_id': transfer_tx['id'],
		},
		'owners_before': output['public_keys'],
	}

	prepared_transfer_tx = bdb.transactions.prepare(
		operation='TRANSFER',
		asset=transfer_asset,
		inputs=transfer_input,
		recipients=recipient,
	)

	fulfilled_transfer_tx = bdb.transactions.fulfill(
		prepared_transfer_tx,
		private_keys=private_key.strip(),
	)

	bdb.transactions.send_commit(fulfilled_transfer_tx)

	response = {'license_id': fulfilled_transfer_tx['id'],
		'contract': creation_tx['asset']['data']['contract'], 
		'transfered_product_name': creation_tx['asset']['data']['product'] }

	return jsonify(response), 200

def create_contract_prolog(e,q_in,q_out):
	print('Process create contract: starting...')

	while(1):
		e.wait()
		
		guid, query, contract_body = q_in.get().split("\n",2)
		contract_clauses = contract_body.split("\n")

		prolog = Prolog()
		for clause in contract_clauses:
			if clause == "":
				continue
			clause_for_assert = "("+clause.split(".")[0]+")"
			print(clause_for_assert)
			prolog.assertz(clause_for_assert)
		
		raspuns = bool(list(prolog.query(query)))
		print(query)

		q_out.put(guid+"\n"+str(raspuns))

#return contract in Prolog syntax 
def contract_form(license_type, valid_countries, duration):
	contract = "transferlicenta(X,Y,T):-cantransfer(T),licentavalida(X),taravalida(Y).\n"
	valid_countries_list = valid_countries.split(',')
	for country in valid_countries_list:
		contract = contract + "taravalida("+country.strip().lower()+").\n"
	contract = contract + "licentavalida(X):- X < "+str(duration)+".\n"
	contract = contract + "cantransfer("+license_type+").\n"
	return contract

#send contract query and receive Prolog result
def verify_contract(contract, license_type, destination_country, current_date):
	epoch = datetime.datetime.utcfromtimestamp(0)
	datetime_number = int((current_date-epoch).total_seconds() *1000)

	guid = '1'

	queue_in.put(guid + "\ntransferlicenta("+str(datetime_number)+","+destination_country+","+license_type+").\n"+contract)
	start_contract_event.set()
	
	while(1):
		guid_retrieved, result  = queue_out.get().split("\n",1)
		if guid_retrieved == guid:
			return result
		else :
			queue_out.put(guid_retrieved+"\n"+result)

	return ""


if __name__ == '__main__':
    from argparse import ArgumentParser

    parser = ArgumentParser()
    parser.add_argument('-p', '--port', default=5000, type=int, help='port to listen on')
    args = parser.parse_args()
    port = args.port

    contract_processes = []
    for i in range(0,3):
        process_create_contract = multiprocessing.Process(name='create_contract', 
                    target=create_contract_prolog,
                    args=(start_contract_event,queue_in,queue_out))
        contract_processes.append(process_create_contract)
        process_create_contract.start()		
    
    app.run(host='127.0.0.1', port=port)

