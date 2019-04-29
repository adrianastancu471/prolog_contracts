'''
title           : blockchain_client.py
description     : A blockchain client implemenation, with the following features
                  - Wallets generation using Public/Private key encryption (based on RSA algorithm)
                  - Generation of transactions with RSA encryption      
author          : Adil Moujahid
date_created    : 20180212
date_modified   : 20180309
version         : 0.3
usage           : python blockchain_client.py
                  python blockchain_client.py -p 8080
                  python blockchain_client.py --port 8080
python_version  : 3.6.1
Comments        : Wallet generation and transaction signature is based on [1]
References      : [1] https://github.com/julienr/ipynb_playground/blob/master/bitcoin/dumbcoin/dumbcoin.ipynb
'''

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
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5

import requests
from flask import Flask, jsonify, request, render_template

class Transaction:

    def __init__(self, sender_address, sender_private_key, recipient_address, value):
        self.sender_address = sender_address
        self.sender_private_key = sender_private_key
        self.recipient_address = recipient_address
        self.value = value

    def __getattr__(self, attr):
        return self.data[attr]

    def to_dict(self):
        return OrderedDict({'sender_address': self.sender_address,
                            'recipient_address': self.recipient_address,
                            'value': self.value})

    def sign_transaction(self):
        """
        Sign transaction with private key
        """
        private_key = RSA.importKey(binascii.unhexlify(self.sender_private_key))
        signer = PKCS1_v1_5.new(private_key)
        h = SHA.new(str(self.to_dict()).encode('utf8'))
        return binascii.hexlify(signer.sign(h)).decode('ascii')


app = Flask(__name__)
start_contract_event = multiprocessing.Event()
queue_in = multiprocessing.Queue()
queue_out = multiprocessing.Queue()

bdb_root_url = 'http://localhost:9984' 
bdb = BigchainDB(bdb_root_url)

@app.route('/')
def login():
	return render_template('./login.html')

@app.route('/index')
def index():
	return render_template('./index.html')

@app.route('/make/transaction')
def make_transaction():
    return render_template('./make_transaction.html')

@app.route('/view/transactions')
def view_transaction():
    return render_template('./view_transactions.html')

@app.route('/make/contract')
def make_contract():
    return render_template('./make_contract.html')

@app.route('/register')
def register():
    return render_template('./register.html')

@app.route('/reset_password')
def reset_password():
    return render_template('./reset_password.html')

@app.route('/wallet/new', methods=['GET'])
def new_wallet():
	random_gen = Crypto.Random.new().read
	private_key = RSA.generate(1024, random_gen)
	public_key = private_key.publickey()
	response = {
		'private_key': binascii.hexlify(private_key.exportKey(format='DER')).decode('ascii'),
		'public_key': binascii.hexlify(public_key.exportKey(format='DER')).decode('ascii')
	}

	return jsonify(response), 200

@app.route('/generate/transaction', methods=['POST'])
def generate_transaction():
	
	sender_address = request.form['sender_address']
	sender_private_key = request.form['sender_private_key']
	recipient_address = request.form['recipient_address']
	value = request.form['amount']

	transaction = Transaction(sender_address, sender_private_key, recipient_address, value)

	response = {'transaction': transaction.to_dict(), 'signature': transaction.sign_transaction()}

	return jsonify(response), 200

@app.route('/generate/contract', methods=['POST'])
def generate_contract():
	
	sender_address = request.form['sender_address']
	sender_private_key = request.form['sender_private_key']
	body = request.form['contract_body']
    #TODO parsare date contract + nume contract
    #contract_address = request.form['contract_address']
	#queue_in.put("Contract_name "+ body)
	
	body2 = "pereche_chei(pk_1,priv_1)."
	queue_in.put("Contract_name.pl "+body2)
	start_contract_event.set()
	
	print(queue_out.get())
	response = {'contract': {'sender_address':sender_address, 'private_key':sender_private_key,'body':body}, 'signature': 'semnatura'}
    
	return jsonify(response), 200


def create_contract_prolog(e,q_in,q_out):
    print('Process create contract: starting...')
    while(1):
        e.wait()
        contract_name, body = q_in.get().split(" ",1)
        time.sleep(10)
        with open(contract_name,"w") as fo:
            fo.write(body)
        prolog = Prolog()
        prolog.consult(contract_name)
        for soln in prolog.query("pereche_chei(Y,X)"):
            q_out.put(soln["X"] + " este cheia privata a" + soln["Y"])

#User Register
@app.route('/register/user', methods=['POST'])
def register_user():
	
	email = request.form['email']
	username = request.form['username']
	password = request.form['password']

	#verificare daca mai exista acel user
	user_asset = bdb.assets.get(search=username)
	idx = -1
	for i, user in enumerate(user_asset):
		if user['data']['username']== username :
			idx = i

	if idx != -1:
		response = {'username': '', 'account':'exists'}
		return jsonify(response), 200

	user = {'data':{'username':"",'email':"",'keypair':{'public_key':'','private_key':''}}}
	user['data']['username']= username
	user['data']['email']= email
	metadata = {'account': 'active','password':password}

	account_keypair = generate_keypair()
	user['data']['keypair']['public_key'] = account_keypair.public_key
	user['data']['keypair']['private_key'] = account_keypair.private_key

	prepared_creation_tx = bdb.transactions.prepare(
        operation='CREATE', 
        signers=account_keypair.public_key, 
        asset=user, 
		metadata=metadata,)

	fulfilled_creation_tx = bdb.transactions.fulfill(
        prepared_creation_tx, 
        private_keys=account_keypair.private_key)

	sent_creation_tx = bdb.transactions.send_commit(fulfilled_creation_tx)

	response = {'username': username,'account':'created'}

	return jsonify(response), 200

@app.route('/login/user', methods=['POST'])
def login_user():
	
	username = request.form['username']
	password = request.form['password']

	user_asset = bdb.assets.get(search=username)
	idx = -1
	for i, user in enumerate(user_asset):
		user_transaction = bdb.transactions.get(asset_id=user["id"])
		transaction = user_transaction[len(user_transaction)-1]
		if transaction['metadata']['account'] == 'active' and transaction['metadata']['password']== password:
			idx = i

	if idx == -1:
		response = {'account': 'invalid'}
		return jsonify(response), 200
	
	response = {'account': user_transaction[idx]['id']}

	return jsonify(response), 200

#Resetare parola
@app.route('/reset_password/user', methods=['POST'])
def reset_password_user():
	
	current_password = request.form['current_password']
	username = request.form['password2']
	password = request.form['password']

	user_asset = bdb.assets.get(search=username)
	idx = -1
	user_transaction=[]
	asset_id = ""
	for i, user in enumerate(user_asset):
		user_transaction = bdb.transactions.get(asset_id=user["id"])
		transaction = user_transaction[len(user_transaction)-1]
		if transaction['metadata']['account'] == 'active' and transaction['metadata']['password']== current_password:
			idx = len(user_transaction)-1
			asset_id = user['id']

	if idx == -1:
		response = {'username': '', 'account':'invalid'}
		return jsonify(response), 200

	txid = user_transaction[idx]["id"]
	creation_tx = bdb.transactions.retrieve(txid)

	transfer_asset = {
		'id': asset_id
	}
	metadata = {
		'account': 'active',
		'password':password
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
		private_keys=user['data']['keypair']['private_key'],
	)
	bdb.transactions.send_commit(fulfilled_transfer_tx)
	
	response = {'username': username,'account':'active'}

	return jsonify(response), 200

if __name__ == '__main__':
    from argparse import ArgumentParser

    parser = ArgumentParser()
    parser.add_argument('-p', '--port', default=8080, type=int, help='port to listen on')
    args = parser.parse_args()
    port = args.port
    
    process_create_contract = multiprocessing.Process(name='create_contract', 
                      target=create_contract_prolog,
                      args=(start_contract_event,queue_in,queue_out))
    process_create_contract.start()

    app.run(host='127.0.0.1', port=port)
