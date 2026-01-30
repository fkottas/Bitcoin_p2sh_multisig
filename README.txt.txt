Assignment: P2SH 2-of-3 Multisig (Bitcoin Regtest)
Student: Ferdinantos Kottas
Network: regtest
Bitcoin Core: v28.1
Python: 3.12

================================================
REQUIREMENTS
================================================
- Windows 10
- Bitcoin Core installed and in PATH
- Python 3.12
- Local bitcoind running in regtest mode
- Fallback fee enabled
- Legacy wallet enabled

Node start command used:
bitcoind -regtest -deprecatedrpc=create_bdb -fallbackfee=0.0001


================================================
KEYS USED
================================================

WIF1: cQ2WquyqecYw8c9gFeYZgVdqCLTbZurQ1eqdAhtGxnifxCYx5ZjG
PUB1: 0289afcc6f7f5df5cc5cb0c708d38a7e68c50b695dfc3c26849e1b92b62c2d1803

WIF2: cRNYFKAxjw8KD7qCaxTnGWiKUybJDKCjSBi5c7CztGXbFkaBZvmd
PUB2: 03119212c9edb217ad47c761bb08285ffcdcd6dfd0a6bf82c6ba7c725be5f7aa5c

WIF3: cUYFedKAAnPwW3g5uyDQTKdfwBTrzjm347WZctJhcj2yaMgmhsnh
PUB3: 02204925015b63cd6ad08bc6ebdac4a5afd60f1e234eb0a6ecbf4dcc27e017b434


================================================
SCRIPT 1 – CREATE P2SH MULTISIG ADDRESS
================================================

Redeem script format:
OP_2 <PUB1> <PUB2> <PUB3> OP_3 OP_CHECKMULTISIG

Redeem Script (hex):
52210289afcc6f7f5df5cc5cb0c708d38a7e68c50b695dfc3c26849e1b92b62c2d1803
2103119212c9edb217ad47c761bb08285ffcdcd6dfd0a6bf82c6ba7c725be5f7aa5c
2102204925015b63cd6ad08bc6ebdac4a5afd60f1e234eb0a6ecbf4dcc27e017b434
53ae

P2SH Multisig Address:
2N9YHpze61T2ggDbUEvLDcqyrKsnfsBKw69


================================================
FUNDING
================================================

Miner address:
bcrt1qmuvemmfqmcsgk4r57y6zhr2ph9sapzzdm25xh4

Funding transactions:
TXID 1: 4408b283a02be845e155d7775d56ea8119f7f51c3c63074d2a7537cd23c0b056
TXID 2: ae860531430c0f7f56c640e876412d3530a52e75c83a5ffa2bcc4ef41075cd03

Total funded to P2SH: 2.0 BTC


================================================
SCRIPT 2 – SPEND P2SH MULTISIG
================================================

Destination P2PKH address:
mzoj1emDiV4RoGAhwojp1wdEh5doqa5UHY

Command used:
py spend_p2sh_multisig.py --network regtest --cookie "C:\Users\18252728\AppData\Local\Bitcoin\regtest\.cookie" --p2sh 2N9YHpze61T2ggDbUEvLDcqyrKsnfsBKw69 --to mzoj1emDiV4RoGAhwojp1wdEh5doqa5UHY --priv1 cQ2WquyqecYw8c9gFeYZgVdqCLTbZurQ1eqdAhtGxnifxCYx5ZjG --priv2 cRNYFKAxjw8KD7qCaxTnGWiKUybJDKCjSBi5c7CztGXbFkaBZvmd --pub3 02204925015b63cd6ad08bc6ebdac4a5afd60f1e234eb0a6ecbf4dcc27e017b434


================================================
RESULT
================================================

Unsigned raw tx: (printed by script)
Signed raw tx: (printed by script)

Transaction ID:
1bf70920c76aba9d2e78cd05b75ee1eece7e48d0dd2b23db8bdf23c7e049d2f1

testmempoolaccept result:
allowed: true

Broadcast result:
Broadcasted txid: 1bf70920c76aba9d2e78cd05b75ee1eece7e48d0dd2b23db8bdf23c7e049d2f1


================================================
NOTES
================================================

- Redeem script was manually constructed using OP codes:
  OP_2, OP_3, OP_CHECKMULTISIG
- scriptSig format:
  OP_0 <sig1> <sig2> <redeemScript>
- OP_0 is required due to the CHECKMULTISIG bug.
- Fee was calculated based on estimated transaction size and feerate.
- Transaction was verified using testmempoolaccept before broadcasting.
- Multiple inputs (2 UTXOs) were handled and both were signed.

================================================
FILES SUBMITTED
================================================

- create_p2sh_multisig.py
- spend_p2sh_multisig.py
- rpc.py
- requirements.txt
- README.txt
- verification.docx
