
service mongodb stop

sudo mongod --replSet=bigchain-rs

monit -d 1
