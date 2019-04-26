from bigchaindb_driver import BigchainDB

from bigchaindb_driver.crypto import generate_keypair

import pymongo

username="adriana"
password="stancu"
mongo_client = pymongo.MongoClient('mongodb://%s:%s@127.0.0.1:9984' % (username, password))
bigchain_db = mongo_client["bigchaindb"]
print(bigchain_db)
cursor = bigchain_db.inventory.find({})
print(cursor)
"""
bdb = BigchainDB('http://127.0.0.1:9984')
alice = generate_keypair()
tx = bdb.transactions.prepare(
    operation='CREATE',
    signers=alice.public_key,
    asset={'data': {'message': ''}})
signed_tx = bdb.transactions.fulfill(
    tx,
    private_keys=alice.private_key)
bdb.transactions.send_commit(signed_tx)
"""