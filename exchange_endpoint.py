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
from algosdk.v2client import algod
from algosdk.v2client import indexer

from algosdk.v2client import algod
from algosdk import mnemonic
from algosdk import transaction
from algosdk import account
from web3 import Web3


# TODO: make sure you implement connect_to_algo, send_tokens_algo, and send_tokens_eth
from send_tokens import connect_to_algo, connect_to_eth, send_tokens_algo, send_tokens_eth

from models import Base, Order, TX, Log

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

""" Helper Methods (skeleton code for you to implement) """


def log_message(message_dict):
    msg = json.dumps(message_dict)

    # TODO: Add message to the Log table
    log_obj = Log(message=msg)
    g.session.add(log_obj)
    g.session.commit()

    return


def get_algo_keys():
    # TODO: Generate or read (using the mnemonic secret)
    # the algorand public/private keys
    #account_address = "JABZRKY732NUX6A64JNZK4JQ2MVIGMKCH37VVHD3AG5PG5RUCY2JWZOGAE"
    mnemonic_secret = "bar blue coral daughter add talk mammal busy cost dutch economy cigar imitate bean leader object found way grief trash wink grain volume above ill"
    algo_sk = mnemonic.to_private_key(mnemonic_secret)
    algo_pk = mnemonic.to_public_key(mnemonic_secret)
    return algo_sk, algo_pk


def get_eth_keys(filename="eth_mnemonic.txt"):
    w3 = Web3()

    # TODO: Generate or read (using the mnemonic secret)
    # the ethereum public/private keys
    w3.eth.account.enable_unaudited_hdwallet_features()
    mnemonic_secret = "butter case stone sun before large margin stereo april title catch much"
    acct = w3.eth.account.from_mnemonic(mnemonic_secret)
    eth_pk = acct._address
    eth_sk = acct._private_key
    return eth_sk, eth_pk


def fill_order(order, txes=[]):
    # TODO:
    # Match orders (same as Exchange Server II)
    # Validate the order has a payment to back it (make sure the counterparty also made a payment)
    # Make sure that you end up executing all resulting transactions!
    buy_currency = order['buy_currency']
    sell_currency = order['sell_currency']
    buy_amount = order['buy_amount']
    sell_amount = order['sell_amount']
    sender_pk = order['sender_pk']
    receiver_pk = order['receiver_pk']
    tx_id=order['tx_id']
    implied_exchange_rate = buy_amount / sell_amount
    new_order_sell_rate = sell_amount / buy_amount

    order_obj = Order(sender_pk=order['sender_pk'], receiver_pk=order['receiver_pk'],
                      buy_currency=order['buy_currency'], sell_currency=order['sell_currency'],
                      buy_amount=order['buy_amount'], sell_amount=order['sell_amount'], tx_id=order[tx_id])
    g.session.add(order_obj)
    g.session.commit()

    new_order_ID = order_obj.id

    query = g.session.query(Order).filter(
        Order.filled == None, Order.buy_currency == sell_currency, Order.sell_currency == buy_currency
    )
    result = g.session.execute(query)
    amount = 0
    id_order_matched = 0

    for order in result.scalars().all():
        existing_order_exchange_rate = order.sell_amount / order.buy_amount
        if existing_order_exchange_rate >= implied_exchange_rate:
            if order.sell_amount > amount:
                amount = sell_amount
                id_order_matched = order.id
    # pass

    if id_order_matched != 0:
        existing_order_sell_amount = 0
        existing_order_buy_amount = 0
        existing_order_sell_rate = 0
        existing_order_sender_pk = None
        existing_order_receiver_pk = None

        now = datetime.now()

        query1 = g.session.query(Order).filter(Order.id == id_order_matched)
        result1 = g.session.execute(query1)
        for order in result1.scalars().all():
            order.filled = now
            order.counterparty_id = new_order_ID
            existing_order_sell_amount = order.sell_amount
            existing_order_buy_amount = order.buy_amount
            existing_order_sender_pk = order.sender_pk
            existing_order_receiver_pk = order.receiver_pk
            existing_order_sell_rate = existing_order_sell_amount / existing_order_buy_amount
            g.session.commit()

        query2 = g.session.query(Order).filter(Order.id == new_order_ID)
        result2 = g.session.execute(query2)
        for order in result2.scalars().all():
            order.filled = now
            order.counterparty_id = id_order_matched
            g.session.commit()

        child_order_obj = None

        if existing_order_sell_amount < buy_amount:
            final_sell_amount = existing_order_sell_amount
            final_buy_amount = existing_order_buy_amount

            buy_amount = buy_amount - final_buy_amount
            sell_amount = buy_amount * new_order_sell_rate
            creator_id = new_order_ID

            child_order = {}
            child_order['sender_pk'] = sender_pk
            child_order['receiver_pk'] = receiver_pk
            child_order['buy_currency'] = buy_currency
            child_order['sell_currency'] = sell_currency
            child_order['buy_amount'] = buy_amount
            child_order['sell_amount'] = sell_amount
            child_order['creator_id'] = creator_id
            child_order['platform'] = sell_currency

            child_order_obj = Order(sender_pk=child_order['sender_pk'],
                                    receiver_pk=child_order['receiver_pk'],
                                    buy_currency=child_order['buy_currency'],
                                    sell_currency=child_order['sell_currency'],
                                    buy_amount=child_order['buy_amount'],
                                    sell_amount=child_order['sell_amount'],
                                    creator_id=child_order['creator_id'])
            g.session.add(child_order_obj)
            g.session.commit()


        elif existing_order_sell_amount > buy_amount:
            final_sell_amount = sell_amount
            final_buy_amount = buy_amount

            buy_currency_original = buy_currency
            sender_pk = existing_order_sender_pk
            receiver_pk = existing_order_receiver_pk
            buy_currency = sell_currency
            sell_currency = buy_currency_original
            buy_amount = existing_order_buy_amount - final_sell_amount
            sell_amount = buy_amount * existing_order_sell_rate
            creator_id = id_order_matched

            child_order = {}
            child_order['sender_pk'] = sender_pk
            child_order['receiver_pk'] = receiver_pk
            child_order['buy_currency'] = buy_currency
            child_order['sell_currency'] = sell_currency
            child_order['buy_amount'] = buy_amount
            child_order['sell_amount'] = sell_amount
            child_order['creator_id'] = creator_id
            child_order['platform'] = sell_currency

            child_order_obj = Order(sender_pk=child_order['sender_pk'],
                                    receiver_pk=child_order['receiver_pk'],
                                    buy_currency=child_order['buy_currency'],
                                    sell_currency=child_order['sell_currency'],
                                    buy_amount=child_order['buy_amount'],
                                    sell_amount=child_order['sell_amount'],
                                    creator_id=child_order['creator_id'])

            g.session.add(child_order_obj)
            g.session.commit()

        txes.append(order)
        txes.append(child_order)

def execute_txes(txes):
    if txes is None:
        return True
    if len(txes) == 0:
        return True
    print(f"Trying to execute {len(txes)} transactions")
    print(f"IDs = {[tx['order_id'] for tx in txes]}")
    eth_sk, eth_pk = get_eth_keys()
    algo_sk, algo_pk = get_algo_keys()

    if not all(tx['platform'] in ["Algorand", "Ethereum"] for tx in txes):
        print("Error: execute_txes got an invalid platform!")
        print(tx['platform'] for tx in txes)

    algo_txes = [tx for tx in txes if tx['platform'] == "Algorand"]
    eth_txes = [tx for tx in txes if tx['platform'] == "Ethereum"]

    # TODO:
    #       1. Send tokens on the Algorand and eth testnets, appropriately
    #          We've provided the send_tokens_algo and send_tokens_eth skeleton methods in send_tokens.py
    #       2. Add all transactions to the TX table
    w3=Web3()
    eth_tx_ids=send_tokens_eth(w3, eth_sk, eth_txes)

    acl=connect_to_algo()
    algo_tx_ids=send_tokens_algo(acl, algo_sk, algo_txes)

    for tx in eth_tx_ids:
        Tx = {}
        Tx['receiver_pk'] = tx['receiver_pk']
        Tx['platform'] = tx['platform']
        Tx['tx_id'] = tx['tx_id']
        tx_obj = Order(receiver_pk=Tx['receiver_pk'],
                                platform=Tx['platform'],
                                tx_id=Tx['tx_id'])
        g.session.add(tx_obj)
        g.session.commit()

    for tx in algo_tx_ids:
        Tx = {}
        Tx['receiver_pk'] = tx['receiver_pk']
        Tx['platform'] = tx['platform']
        Tx['tx_id'] = tx['tx_id']
        tx_obj = Order(receiver_pk=Tx['receiver_pk'],
                                platform=Tx['platform'],
                                tx_id=Tx['tx_id'])
        g.session.add(tx_obj)
        g.session.commit()


def check_sig(payload, sig):
    payload_dict = json.loads(payload)
    platform = payload_dict['platform']
    pk = payload_dict['sender_pk']

    verification_result = False

    if platform == 'Ethereum':
        eth_encoded_msg = eth_account.messages.encode_defunct(text=payload)
        if eth_account.Account.recover_message(eth_encoded_msg, signature=sig) == pk:
            verification_result = True

    elif platform == 'Algorand':
        if algosdk.util.verify_bytes(payload.encode('utf-8'), sig, pk):
            verification_result = True

    return verification_result


""" End of Helper methods"""


@app.route('/address', methods=['POST'])
def address():
    if request.method == "POST":
        content = request.get_json(silent=True)
        if 'platform' not in content.keys():
            print(f"Error: no platform provided")
            return jsonify("Error: no platform provided")
        if not content['platform'] in ["Ethereum", "Algorand"]:
            print(f"Error: {content['platform']} is an invalid platform")
            return jsonify(f"Error: invalid platform provided: {content['platform']}")

        if content['platform'] == "Ethereum":
            # Your code here
            eth_sk, eth_pk=get_eth_keys()
            return jsonify(eth_pk)
        if content['platform'] == "Algorand":
            # Your code here
            algo_sk, algo_pk = get_algo_keys()
            return jsonify(algo_pk)


@app.route('/trade', methods=['POST'])
def trade():
    print("In trade", file=sys.stderr)
    connect_to_blockchains()
    get_keys()
    if request.method == "POST":
        content = request.get_json(silent=True)
        columns = ["buy_currency", "sell_currency", "buy_amount", "sell_amount", "platform", "tx_id", "receiver_pk"]
        fields = ["sig", "payload"]
        error = False
        for field in fields:
            if not field in content.keys():
                print(f"{field} not received by Trade")
                error = True
        if error:
            print(json.dumps(content))
            return jsonify(False)

        error = False
        for column in columns:
            if not column in content['payload'].keys():
                print(f"{column} not received by Trade")
                error = True
        if error:
            print(json.dumps(content))
            return jsonify(False)

        # Your code here
        result=False
        # 1. Check the signature
        json_string = json.dumps(content)
        contentPyth = json.loads(json_string)
        signature = contentPyth['sig']
        payload = json.dumps(contentPyth['payload'])
        verification_result=check_sig(payload,signature)
        if verification_result:
        # 2. Add the order to the table
            sender_pk = contentPyth['payload']['sender_pk']
            receiver_pk = contentPyth['payload']['receiver_pk']
            buy_currency = contentPyth['payload']['buy_currency']
            sell_currency = contentPyth['payload']['sell_currency']
            buy_amount = contentPyth['payload']['buy_amount']
            sell_amount = contentPyth['payload']['sell_amount']
            tx_id= contentPyth['payload']['tx_id']
            platform=sell_currency
            order = {}
            order['sender_pk'] = sender_pk
            order['receiver_pk'] = receiver_pk
            order['buy_currency'] = buy_currency
            order['sell_currency'] = sell_currency
            order['buy_amount'] = buy_amount
            order['sell_amount'] = sell_amount
            order['tx_id'] = tx_id
            order['platform']=platform

        # 3a. Check if the order is backed by a transaction equal to the sell_amount (this is new)
            checkorderpayment=False
            w3=Web3()
            if sell_currency=='Ethereum':
                AttributeDict=w3.eth.get_transaction(tx_id)
                if AttributeDict['value']== sell_amount:
                    checkorderpayment=True
                else:
                    return jsonify(False)
            else:
                client = connect_to_algo("indexer")
                AlgodTransaction=client.search_transactions(txid=tx_id)
                if AlgodTransaction['value']== sell_amount:
                    checkorderpayment=True
                else:
                    return jsonify(False)
        # 3b. Fill the order (as in Exchange Server II) if the order is valid
            if checkorderpayment==True:
                txes = []
                fill_order(order, txes)
        # 4. Execute the transactions
                execute_txes(txes)
        # If all goes well, return jsonify(True). else return jsonify(False)
        return jsonify(result)


@app.route('/order_book')
def order_book():
    fields = ["buy_currency", "sell_currency", "buy_amount", "sell_amount", "signature", "tx_id", "receiver_pk",
              "sender_pk"]

    # Same as before
    query = g.session.query(Order)
    query_result = g.session.execute(query)
    initial_result = []
    for order in query_result.scalars().all():
        order_dict = dict.fromkeys(fields)
        order_dict['sender_pk'] = order.sender_pk
        order_dict['receiver_pk'] = order.receiver_pk
        order_dict['buy_currency'] = order.buy_currency
        order_dict['sell_currency'] = order.sell_currency
        order_dict['buy_amount'] = order.buy_amount
        order_dict['sell_amount'] = order.sell_amount
        order_dict['signature'] = order.signature
        order_dict['tx_id']=order.tx_id
        initial_result.append(order_dict)

    # Note that you can access the database session using g.session
    keyList2 = ['data']
    result = dict.fromkeys(keyList2)
    result['data'] = initial_result
    return jsonify(result)


if __name__ == '__main__':
    app.run(port='5002')
