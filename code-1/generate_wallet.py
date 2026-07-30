from bit import PrivateKeyTestnet

# 生成新钱包
key = PrivateKeyTestnet()

print("=" * 50)
print("请务必保存以下信息！")
print("=" * 50)
print(f"WIF 私钥: {key.to_wif()}")
print(f"测试网地址: {key.address}")
print("=" * 50)
print("⚠️ 丢失私钥 = 丢失资产，请妥善保存！")
