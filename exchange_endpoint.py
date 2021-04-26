#!/usr/bin/env python
# coding: utf-8

# In[10]:


#pip install progressbar
from flask import Flask, request, g
from flask_restful import Resource, Api
from sqlalchemy import create_engine
from flask import jsonify
import json
import eth_account
import algosdk
from sqlalchemy.orm import sessionmaker
from sqlalchemy.orm import scoped_session
from sqlalchemy.orm import load_only
from datetime import datetime
import math
import sys
import traceback
from web3 import Web3
import time

from algosdk import mnemonic
from algosdk.v2client import indexer


# In[2]:


# TODO: make sure you implement connect_to_algo, send_tokens_algo, and send_tokens_eth
from send_tokens import connect_to_algo, connect_to_eth, send_tokens_algo, send_tokens_eth

from models import Base, Order, TX
engine = create_engine('sqlite:///orders.db')
Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)

app = Flask(__name__)

""" Pre-defined methods (do not need to change) """

@app.before_request
def create_session():
    g.session = scoped_session(DBSession)

@app.teardown_appcontext
def shutdown_session(response_or_exc):
    sys.stdout.flush()
    g.session.commit()
    g.session.remove()

def connect_to_blockchains():
    try:
        # If g.acl has not been defined yet, then trying to query it fails
        acl_flag = False
        g.acl
    except AttributeError as ae:
        acl_flag = True
    
    try:
        if acl_flag or not g.acl.status():
            # Define Algorand client for the application
            g.acl = connect_to_algo()
    except Exception as e:
        print("Trying to connect to algorand client again")
        print(traceback.format_exc())
        g.acl = connect_to_algo()
    
    try:
        icl_flag = False
        g.icl
    except AttributeError as ae:
        icl_flag = True
    
    try:
        if icl_flag or not g.icl.health():
            # Define the index client
            g.icl = connect_to_algo(connection_type='indexer')
    except Exception as e:
        print("Trying to connect to algorand indexer client again")
        print(traceback.format_exc())
        g.icl = connect_to_algo(connection_type='indexer')

        
    try:
        w3_flag = False
        g.w3
    except AttributeError as ae:
        w3_flag = True
    
    try:
        if w3_flag or not g.w3.isConnected():
            g.w3 = connect_to_eth()
    except Exception as e:
        print("Trying to connect to web3 again")
        print(traceback.format_exc())
        g.w3 = connect_to_eth()
        
""" End of pre-defined methods """


# In[3]:


""" Helper Methods (skeleton code for you to implement) """
def check_sig(payload,sig):
    #1. Verifying an endpoint for verifying signatures for ethereum
    result_check_sig = False
    platform = payload['platform']
    sk = sig
    pk = payload['pk']
    message = json.dumps(payload)
    
    if platform == "Ethereum":
        eth_encoded_msg = eth_account.messages.encode_defunct(text=message)
        recovered_pk = eth_account.Account.recover_message(eth_encoded_msg,signature=sk)
        if(recovered_pk == pk):
            result_check_sig = True
            print( "Eth sig verifies!" )    
    
        #2. Verifying an endpoint for verifying signatures for Algorand
    elif platform == "Algorand":
        result_check_sig = algosdk.util.verify_bytes(message.encode('utf-8'),sk,pk)
        if(result_check_sig):
            print( "Algo sig verifies!" )
    
        #3. Check for invalid input
    else:
        print("invalid input")

    print(" this is jsonify(result_check_sig) = ",jsonify(result_check_sig))
    return jsonify(result_check_sig)


def log_message(message_dict):
    msg = json.dumps(message_dict)

    # TODO: Add message to the Log table
    g.session.add(log(message = msg))
    g.session.commit()
    
    return

def get_algo_keys():
    
    # TODO: Generate or read (using the mnemonic secret) 
    # the algorand public/private keys
    # mnemonic_secret = "YOUR MNEMONIC HERE"
    #sk, address = account.generate_account()
    mnemonic_secret = 'ship floor pattern transfer fiscal diamond maid raise never debate lemon brown siren upset gun sibling lend write cloth success glove shrug cattle ability ivory' 
    algo_sk = mnemonic.to_private_key(mnemonic_secret)
    algo_pk = mnemonic.to_public_key(mnemonic_secret)    
    return algo_sk, algo_pk


def get_eth_keys(filename = "eth_mnemonic.txt"):
    w3 = Web3()
    
    # TODO: Generate or read (using the mnemonic secret) 
    # the ethereum public/private keys
    w3.eth.account.enable_unaudited_hdwallet_features()
    acct,mnemonic_secret = w3.eth.account.create_with_mnemonic()
    acct = w3.eth.account.from_mnemonic(mnemonic_secret)
    eth_pk = acct._address
    eth_sk = acct._private_key
    return eth_sk, eth_pk
  
def fill_order(order, txes[]):
    # select record from DB
    sqlrs = session.query(Order)
    sqlrs = sqlrs.filter(Order.filled == None).filter(Order.buy_currency==current_order.sell_currency).filter(Order.sell_currency==current_order.buy_currency).filter(Order.sell_amount/Order.buy_amount >= current_order.buy_amount/current_order.sell_amount )
    sqlrs = sqlrs.order_by(Order.buy_amount/Order.sell_amount).first()
    # if it can't found
    if sqlrs is None:
        return
    # handle data
    sqlrs.filled = datetime.now()
    current_order.filled = datetime.now()
    current_order.counterparty_id = sqlrs.id
    sqlrs.counterparty_id = current_order.id
    new_tx_list = []

    amount = 0
    if current_order.sell_amount > sqlrs.buy_amount:
        amount = sqlrs.buy_amount
    else:
        amount = current_order.sell_amount
    tx1 = { "sender": "exchange", "receiver_pk": sqlrs.sender_pk, "amount": amount, "platform": sqlrs.buy_currency, "order_id": sqlrs.id }
   
    new_tx_list.append(tx1)
    if current_order.buy_amount > sqlrs.sell_amount:
        amount = sqlrs.buy_amount
    else:
        amount = current_order.sell_amount
    tx2 = { "sender": "exchange", "receiver_pk": current_order.sender_pk, "amount": amount, "platform": current_order.buy_currency, "order_id": current_order.id  }
    new_tx_list.append(tx2)
   
    if sqlrs.buy_amount > current_order.sell_amount:
        useRate = (float(current_order.sell_amount))/sqlrs.buy_amount;
        temp_order_dict = {}
        temp_order_dict['buy_currency'] = getattr(sqlrs,'buy_currency')
        temp_order_dict['sell_currency'] =  getattr(sqlrs,'sell_currency')
        temp_order_dict['buy_amount'] =  getattr(sqlrs,'buy_amount')
        temp_order_dict['sell_amount'] =  getattr(sqlrs,'sell_amount')
        temp_order_dict['sender_pk'] =  getattr(sqlrs,'sender_pk')
        temp_order_dict['receiver_pk'] =  getattr(sqlrs,'receiver_pk')
        new_order = Order(**temp_order_dict)
        new_order.creator_id= sqlrs.id
        new_order.sell_amount = (1-useRate)*sqlrs.sell_amount
        new_order.buy_amount = new_order.buy_amount - current_order.sell_amount
        g.session.add(new_order)
   
    if sqlrs.sell_amount < current_order.buy_amount:
        useRate = (float(sqlrs.sell_amount))/current_order.buy_amount;
        temp_order_dict = {}
        temp_order_dict['buy_currency'] = getattr(current_order,'buy_currency')
        temp_order_dict['sell_currency'] =  getattr(current_order,'sell_currency')
        temp_order_dict['buy_amount'] =  getattr(current_order,'buy_amount')
        temp_order_dict['sell_amount'] =  getattr(current_order,'sell_amount')
        temp_order_dict['sender_pk'] =  getattr(current_order,'sender_pk')
        temp_order_dict['receiver_pk'] =  getattr(current_order,'receiver_pk')
        new_order = Order(**temp_order_dict)
        new_order.creator_id= current_order.id
        new_order.buy_amount = new_order.buy_amount - sqlrs.sell_amount
        new_order.sell_amount = (1-useRate)*current_order.sell_amount
        g.session.add(new_order)
        g.session.commit()
        return update_orders( new_order, tx_list=tx_list+new_tx_list )
    else:
        g.session.commit()
        return tx_list + new_tx_list
    
def process_order(order):
    new_order = Order(**dict(order))
    g.session.add(new_order)
    g.session.commit()
    return fill_order(new_order)
  
def execute_txes(txes):
    if txes is None:
        return True
    if len(txes) == 0:
        return True
    print( f"Trying to execute {len(txes)} transactions" )
    print( f"IDs = {[tx['order_id'] for tx in txes]}" )

    eth_sk, eth_pk = get_eth_keys(filename = "eth_mnemonic.txt")
    algo_sk, algo_pk = get_algo_keys()
    
    if not all( tx['platform'] in ["Algorand","Ethereum"] for tx in txes ):
        print( "Error: execute_txes got an invalid platform!" )
        print( tx['platform'] for tx in txes )

    algo_txes = [tx for tx in txes if tx['platform'] == "Algorand" ]
    eth_txes = [tx for tx in txes if tx['platform'] == "Ethereum" ]

    # TODO: 
    #       1. Send tokens on the Algorand and eth testnets, appropriately
    #          We've provided the send_tokens_algo and send_tokens_eth skeleton methods in send_tokens.py
    #       2. Add all transactions to the TX table
    for algo_tx in algo_txes:
        acl = connect_to_algo()
        send_tokens_algo(acl, algo_pk , algo_tx)
        g.session.add(txes(platform = "Algorand",receiver_pk = algo_pk, tx_id = algo_tx))
        g.session.commit()
        
    for eth_tx in eth_txes:
        w3 = connect_to_eth()
        send_tokens_eth(w3, eth_sk, eth_tx) 
        g.session.add(txes(platform = "Ethereum",receiver_pk = eth_pk, tx_id = eth_tx))
        g.session.commit()
    
    pass

""" End of Helper methods"""


# In[ ]:


@app.route('/address', methods=['POST'])
def address():
    if request.method == "POST":
        content = request.get_json(silent=True)
        if 'platform' not in content.keys():
            print( f"Error: no platform provided" )
            return jsonify( "Error: no platform provided" )
        if not content['platform'] in ["Ethereum", "Algorand"]:
            print( f"Error: {content['platform']} is an invalid platform" )
            return jsonify( f"Error: invalid platform provided: {content['platform']}"  )
        
        if content['platform'] == "Ethereum":
            #Your code here
            eth_sk,eth_pk = get_eth_keys(filename = "eth_mnemonic.txt")
            return jsonify( eth_pk )
        if content['platform'] == "Algorand":
            #Your code here
            algo_sk,algo_pk = get_algo_keys()
            return jsonify( algo_pk )


# In[ ]:


@app.route('/trade', methods=['POST'])
def trade():
    print( "In trade", file=sys.stderr )
    connect_to_blockchains()
    #get_keys()
    if request.method == "POST":
        content = request.get_json(silent=True)
        columns = [ "buy_currency", "sell_currency", "buy_amount", "sell_amount", "platform", "tx_id", "receiver_pk"]
        fields = [ "sig", "payload" ]
        error = False
        for field in fields:
            if not field in content.keys():
                print( f"{field} not received by Trade" )
                error = True
        if error:
            print( json.dumps(content) )
            log_message(content)
            return jsonify( False )
        
        error = False
        for column in columns:
            if not column in content['payload'].keys():
                print( f"{column} not received by Trade" )
                error = True
        if error:
            print( json.dumps(content) )
            log_message(content)
            return jsonify( False )
        
        # Your code here
        
        # 1. Check the signature
        result_check = False
        payload = content['payload']
        sig = content['sig']
        result_check = check_sig(payload,sig)
        
        # 2. Add the order to the table
        if(result_check):
            order = {}
            order['sender_pk'] = payload['sender_pk']
            order['receiver_pk'] = payload['receiver_pk']
            order['buy_currency'] = payload['buy_currency']
            order['sell_currency'] = payload['sell_currency']
            order['buy_amount'] = payload['buy_amount']
            order['sell_amount'] = payload['sell_amount']
            order['signature'] = sig
            order['tx_id'] = payload['tx_id']
        
        # 3a. Check if the order is backed by a transaction equal to the sell_amount (this is new)


        # 3b. Fill the order (as in Exchange Server II) if the order is valid
        txes = process_order(order)        
        # 4. Execute the transactions
        execute_txes(txes)
        # If all goes well, return jsonify(True). else return jsonify(False)
        return jsonify(True)


# In[ ]:


@app.route('/order_book')
def order_book():
    fields = [ "buy_currency", "sell_currency", "buy_amount", "sell_amount", "signature", "tx_id", "receiver_pk" ,"sender_pk"]
        
    # Same as before
    temp = g.session.query(Order)
    mydict = []
    for myquery in temp.all():
        myorder = {}
        myorder['buy_currency'] = getattr(myquery,'buy_currency')
        myorder['sell_currency'] =  getattr(myquery,'sell_currency')
        myorder['buy_amount'] =  getattr(myquery,'buy_amount')
        myorder['sell_amount'] =  getattr(myquery,'sell_amount')
        myorder['sender_pk'] =  getattr(myquery,'sender_pk')
        myorder['receiver_pk'] =  getattr(myquery,'receiver_pk')
        myorder['signature'] =  getattr(myquery,'signature')
        myorder['tx_id'] =  getattr(myquery,'tx_id')
        mydict.append(myorder)
    result_order_book = { 'data': mydict } 
    #print(result_order_book) 
    #print(" this is jsonify(result_order_book) = ",jsonify(result_order_book))
    return jsonify(result_order_book)
    pass

if __name__ == '__main__':
    app.run(port='5002')


# In[12]:



