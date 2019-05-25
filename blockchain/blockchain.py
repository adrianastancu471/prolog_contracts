from bigchaindb_driver import BigchainDB
from bigchaindb_driver.crypto import generate_keypair

from collections import OrderedDict
from pyswip import Prolog
import multiprocessing

import time
import json
import uuid

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

# Instantiate the Node
app = Flask(__name__)
CORS(app)
start_contract_event = multiprocessing.Event()
queue_in = multiprocessing.Queue()
queue_out = multiprocessing.Queue()

bdb_root_url = 'http://localhost:9984' 
bdb = BigchainDB(bdb_root_url)

@app.route('/')
def index():
    return render_template('./index.html')

@app.route('/transactions/get')
def get_transactions():
	full_license_assets = bdb.assets.get(search="full")
	evaluation_license_assets = bdb.assets.get(search="evaluation")
	full_licenses =[]
	evaluation_licenses =[]
	for license in full_license_assets:
		license_transactions = bdb.transactions.get(asset_id=license['id'])
		owner_public_key = license_transactions[-1]['outputs'][0]['public_keys'][0]
		owner = bdb.assets.get(search=owner_public_key)
		license_object = {
			'product': license['data']['product'],
			'valid_from': license['data']['valid_from'],
			'valid_to': license['data']['valid_to'],
			'contract': license['data']['contract'],
			'license_key' : license_transactions[0]['id'],
			'transfer_key': license_transactions[-1]['id'],
			'owner': owner[0]['data']['username']
			}
		full_licenses.append(license_object)
	for license in evaluation_license_assets:
		license_transactions = bdb.transactions.get(asset_id=license['id'])
		owner_public_key = license_transactions[-1]['outputs'][0]['public_keys'][0]
		owner = bdb.assets.get(search=owner_public_key)
		license_object = {
			'product': license['data']['product'],
			'valid_from': license['data']['valid_from'],
			'valid_to': license['data']['valid_to'],
			'contract': license['data']['contract'],
			'license_key' : license_transactions[0]['id'],
			'transfer_key': license_transactions[-1]['id'],
			'owner': owner[0]['data']['username']}
		evaluation_licenses.append(license_object)
		
	response = {'full_licenses': full_licenses, 'evaluation_licenses': evaluation_licenses}

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

	full_license_assets = bdb.assets.get(search="full -evaluation")
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

	verdict = verify_contract(
		creation_tx['asset']['data']['contract'],
		creation_tx['asset']['data']['type'].lower(),
		recipient_asset['data']['country'].lower(),
		datetime.datetime.now())

	print(verdict)
	if verdict != "True":
		response = {'license_id': "", 'contract': "", 'transfered_product_name': "", "validation":"false"}

		return jsonify(response), 200

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
		'transfered_product_name': creation_tx['asset']['data']['product'],"validation":"true" }

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
	contract = contract + "cantransfer(full).\n"
	return contract

#send contract query and receive Prolog result
def verify_contract(contract, license_type, destination_country, current_date):
	epoch = datetime.datetime.utcfromtimestamp(0)
	datetime_number = int((current_date-epoch).total_seconds() *1000)

	guid = str(uuid.uuid4().hex)

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
    parser.add_argument('-c', '--contracts', default=3, type=int, help='contract processes')
    args = parser.parse_args()
    port = args.port
    contracts = args.contracts

    contract_processes = []
    for i in range(0,contracts):
        process_create_contract = multiprocessing.Process(name='create_contract', 
                    target=create_contract_prolog,
                    args=(start_contract_event,queue_in,queue_out))
        contract_processes.append(process_create_contract)
        process_create_contract.start()		
    
    app.run(host='127.0.0.1', port=port)

