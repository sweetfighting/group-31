import requests
API="https://blockstream.info/testnet/api"
def parse_block(block_hash):
    url=f"{API}/block/{block_hash}"
    block=requests.get(url).json()
    print(
"""
========= BLOCK =========
"""
    )
    print(
        "Height:",
        block["height"]
    )
    print(
        "Version:",
        block["version"]
    )
    print(
        "Previous hash:",
        block["previousblockhash"]
    )
    print(
        "Merkle Root:",
        block["merkle_root"]
    )
    print(
        "Timestamp:",
        block["timestamp"]
    )
    print(
        "Nonce:",
        block["nonce"]
    )

    print(
        "Difficulty:",
        block["difficulty"]
    )
