import requests
from tx_parser import parse_tx
from block_parser import parse_block
from bit import PrivateKeyTestnet

print("=" * 50)
print("Bitcoin Testnet 完整工具")
print("=" * 50)

print("\n【1】初始化钱包")
WIF = "cUfrQQqtPc5GKpXgUmZP2YytA5kvoJdbV7jhxSkS6pHmjLgsB9vQ"  # 生成的WIF私钥
key = PrivateKeyTestnet(WIF)
print(f"当前钱包地址: {key.address}")


balance = int(key.get_balance())  
print(f"当前余额: {balance} Satoshi")

if balance == 0:
    print("\n⚠️ 余额为0! 请先去水龙头领取测试币:")
    print("   https://testnet-faucet.mempool.co/")
    print(f"   领取地址: {key.address}")
    exit()


print("\n【2】发送交易")
receiver = input("请输入接收方测试网地址: ")
amount = int(input("请输入发送金额(Satoshi): "))

if amount > balance:
    print(f"❌ 余额不足! 当前余额 {balance}, 需要 {amount}")
    exit()

print("正在创建交易...")
raw_tx = key.create_transaction([(receiver, amount, 'satoshi')])

print("正在广播交易...")
try:
    response = requests.post(
        "https://blockstream.info/testnet/api/tx",
        data=raw_tx,
        headers={"Content-Type": "text/plain"}
    )
    
    if response.status_code == 200:
        tx_id = response.text.strip()
        print(f"✅ 交易发送成功!")
        print(f"TxID: {tx_id}")
        print(f"查看: https://blockstream.info/testnet/tx/{tx_id}")
    else:
        print(f"❌ 广播失败: {response.status_code}")
        print(response.text)
        exit()
        
except Exception as e:
    print(f"❌ 网络错误: {e}")
    exit()


print("\n【3】解析交易数据")
print("-" * 50)
raw_tx_data = requests.get(
    f"https://blockstream.info/testnet/api/tx/{tx_id}/hex"
).text
parse_tx(raw_tx_data)


print("\n【4】解析区块数据")
print("-" * 50)
block_hash = input("请输入区块哈希 (或直接按Enter自动获取): ")

if block_hash == "":
    block_hash = requests.get(
        "https://blockstream.info/testnet/api/blocks/tip/hash"
    ).text.strip()
    print(f"自动获取最新区块: {block_hash}")

parse_block(block_hash)

print("\n" + "=" * 50)
print("✅ 全部完成!")

