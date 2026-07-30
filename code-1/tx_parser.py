import struct
def read_varint(data,pos):
    x=data[pos]

    if x < 0xfd:
        return x,pos+1

    elif x==0xfd:

        return (
            int.from_bytes(
                data[pos+1:pos+3],
                "little"
            ),
            pos+3
        )
def byte_bit_show(data):

    print("\n===== BYTE / BIT =====")


    for i,b in enumerate(data):

        print(
            f"byte {i}: {hex(b)}  {b:08b}"
        )
def parse_tx(tx_hex):
    print("=========== TX ===========")
    data=bytes.fromhex(tx_hex)
    pos=0
    # version
    version=data[pos:pos+4]
    pos+=4
    print(
        "Version:",
        version.hex()
    )
    # input
    vin,pos=read_varint(
        data,
        pos
    )
    print(
        "Input:",
        vin
    )
    for i in range(vin):
        print("\nInput",i)
        txid=data[pos:pos+32]
        pos+=32
        print(
            "Previous hash:",
            txid[::-1].hex()
        )
        index=data[pos:pos+4]
        pos+=4
        print(
            "Index:",
            int.from_bytes(
                index,
                "little"
            )
        )
        script_len,pos=read_varint(
            data,
            pos
        )
        script=data[
            pos:
            pos+script_len
        ]
        pos+=script_len
        print(
            "Unlocking Script:",
            script.hex()
        )
        byte_bit_show(script)
        pos+=4   #sequence
    # output
    vout,pos=read_varint(
        data,
        pos
    )
    print(
        "\nOutput:",
        vout
    )
    for i in range(vout):
        print("\nOutput",i)
        value=data[pos:pos+8]
        pos+=8
        print(
            "Value:",
            int.from_bytes(
                value,
                "little"
            )
        )
        sl,pos=read_varint(
            data,
            pos
        )
        script=data[
            pos:
            pos+sl
        ]
        pos+=sl
        print(
            "Locking Script:",
            script.hex()
        )
        byte_bit_show(script)
    lock=data[pos:pos+4]
    print(
        "Locktime:",
        lock.hex()
    )
