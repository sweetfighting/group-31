from tx_parser import *
from block_parser import *
txid=input(
"输入testnet交易ID:"
)
raw=requests.get(
f"https://blockstream.info/testnet/api/tx/{txid}/hex"
).text
parse_tx(raw)
block=input(
"\n输入block hash:"
)
parse_block(block)
