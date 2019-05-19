
from collections import OrderedDict

import requests
from flask import Flask, jsonify, request, render_template
import base64

app = Flask(__name__)

@app.route('/')
def login():
	return render_template('./login.html')

@app.route('/index')
def index():
	return render_template('./index.html')

@app.route('/make/transaction')
def make_transaction():
    return render_template('./make_transaction.html')

@app.route('/transfer/transaction')
def transfer_transaction():
    return render_template('./transfer_transaction.html')

@app.route('/view/licenses')
def view_licenses():
    return render_template('./view_licenses.html')

@app.route('/view/transactions')
def view_transaction():
    return render_template('./view_transactions.html')

@app.route('/register')
def register():
    return render_template('./register.html')

@app.route('/reset_password')
def reset_password():
    return render_template('./reset_password.html')

if __name__ == '__main__':
    from argparse import ArgumentParser

    parser = ArgumentParser()
    parser.add_argument('-p', '--port', default=8080, type=int, help='port to listen on')
    args = parser.parse_args()
    port = args.port

    app.run(host='127.0.0.1', port=port)
