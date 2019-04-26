from bigchaindb_driver import BigchainDB

from bigchaindb_driver.crypto import generate_keypair
import pymongo

"""mongo_client = pymongo.MongoClient('mongodb://127.0.0.1:9984')
bigchain_db = mongo_client["bigchaindb"]
print(bigchain_db)
"""

bdb_root_url = 'http://localhost:9984' 
bdb = BigchainDB(bdb_root_url)

user = {'data': {'username': 'adriana','pasword':'stancu','account':'active',},}
metadata = {'country': 'romania'}

account_creator = generate_keypair()

prepared_creation_tx = bdb.transactions.prepare(operation='CREATE', signers=account_creator.public_key, asset=user, metadata=metadata,)

fulfilled_creation_tx = bdb.transactions.fulfill(prepared_creation_tx, private_keys=account_creator.private_key)

sent_creation_tx = bdb.transactions.send_commit(fulfilled_creation_tx)

print(sent_creation_tx['id'])

"""block_height = bdb.blocks.get(txid=sent_creation_tx['id'])
print(block_height)
block = bdb.blocks.retrieve(str(block_height))
print(block)"""