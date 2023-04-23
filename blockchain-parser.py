import binascii
import struct
import datetime
import hashlib
import base58
import json


def log( string ):
    print(string)


def starts_with_op_ncode( pub ):
    try:
        intValue = int(pub[0:2] , 16)
        if 1 <= intValue <= 75:
            return True
    except:
        pass
    return False


def public_key_decode(pub):
    if pub.lower().startswith(b'76a914'):
        pub = pub[6:-4]
        result = b'\x00' + binascii.unhexlify(pub)
        h5 = hashlib.sha256(result)
        h6 = hashlib.sha256(h5.digest())
        result += h6.digest()[:4]
        return base58.b58encode(result)
    elif pub.lower().startswith(b'a9'):
        return pub
    elif starts_with_op_ncode(pub):
        pub = pub[2:-2]
        h3 = hashlib.sha256(binascii.unhexlify(pub))
        h4 = hashlib.new('ripemd160' , h3.digest())
        result = b'\x00' + h4.digest()
        h5 = hashlib.sha256(result)
        h6 = hashlib.sha256(h5.digest())
        result += h6.digest()[:4]
        return base58.b58encode(result)
    return pub


def string_little_endian_to_bigendian( string ):
    string = binascii.hexlify(string)
    n = len(string) / 2
    fmt = '%dh' % n
    return struct.pack(fmt , *reversed(struct.unpack(fmt , string)))


def read_short_little_endian(block_file):
    return struct.pack(">H" , struct.unpack("<H" , block_file.read(2))[0])


def read_long_little_endian(block_file):
    return struct.pack(">Q" , struct.unpack("<Q" , block_file.read(8))[0])


def read_int_little_endian(block_file):
    return struct.pack(">I" , struct.unpack("<I" , block_file.read(4))[0])


def hex_to_int(value):
    return int(binascii.hexlify(value) , 16)


def hex_to_str(value):
    return binascii.hexlify(value)


def read_var_int(block_file):
    varInt = ord(block_file.read(1))
    returnInt = 0
    if varInt < 0xfd:
        return varInt
    if varInt == 0xfd:
        returnInt = read_short_little_endian(block_file)
    if varInt == 0xfe:
        returnInt = read_int_little_endian(block_file)
    if varInt == 0xff:
        returnInt = read_long_little_endian(block_file)
    return int(binascii.hexlify(returnInt) , 16)


def read_input(block_file, version, input_count, std_out = False):
    previousHash = binascii.hexlify(block_file.read(32)[::-1])
    outId = binascii.hexlify(read_int_little_endian(block_file))
    scriptLength = read_var_int(block_file)
    scriptSignatureRaw = hex_to_str(block_file.read(scriptLength))
    scriptSignature = scriptSignatureRaw
    seqNo = binascii.hexlify(read_int_little_endian(block_file))

    if std_out:
        log("\n" + "Input")
        log("-" * 20)
        log("> Previous Hash: " + str(previousHash))
        log("> Out ID: " + str(outId))
        log("> Script length: " + str(scriptLength))
        log("> Script Signature (PubKey) Raw: " + str(scriptSignatureRaw))
        log("> Script Signature (PubKey): " + str(scriptSignature))
        log("> Seq No: " + str(seqNo))

    d = {'input_version' : str(version),
         'input_count' : str(input_count),
         'input_previous_hash': str(previousHash),
         'input_out_id': str(outId),
         'input_script_length': str(scriptLength),
         'input_script_signature_raw': str(scriptSignatureRaw),
         'input_script_signature': str(scriptSignature),
         'input_seq_no': str(seqNo)}

    return d


def read_output(block_file, version, output_count, std_out = False):
    value = hex_to_int(read_long_little_endian(block_file)) / 100000000.0
    scriptLength = read_var_int(block_file)
    scriptSignatureRaw = hex_to_str(block_file.read(scriptLength))
    scriptSignature = scriptSignatureRaw
    try:
        address = public_key_decode(scriptSignature)
    except Exception as e:
        address = e

    if std_out:
        log("\n" + "Output")
        log("-" * 20)
        log("> Value: " + str(value))
        log("> Script length: " + str(scriptLength))
        log("> Script Signature (PubKey) Raw: " + str(scriptSignatureRaw))
        log("> Script Signature (PubKey): " + str(scriptSignature))
        log("> Address: " + str(address))

    d = {'output_version' : str(version),
         'output_count': str(output_count) ,
         'output_value': str(value),
         'output_script_length': str(scriptLength),
         'output_script_signature_raw': str(scriptSignatureRaw),
         'output_script_signature': str(scriptSignature),
         'output_address': str(address)}

    return d


def read_transaction(block_file, std_out = False):
    extendedFormat = False
    beginByte = block_file.tell()
    inputIds = []
    outputIds = []
    version = hex_to_int(read_int_little_endian(block_file))
    cutStart1 = block_file.tell()
    cutEnd1 = 0
    dts = ''
    inputCount = read_var_int(block_file)
    if std_out:
        log("\n\n" + "Transaction")
        log("-" * 100)
        log("Version: " + str(version))
    flags_extended = 0
    if inputCount == 0:
        extendedFormat = True
        flags = ord(block_file.read(1))
        flags_extended = flags
        cutEnd1 = block_file.tell()
        if flags != 0:
            inputCount = read_var_int(block_file)
            if std_out:
                log("\nInput Count: " + str(inputCount))
            for inputIndex in range(0 , inputCount):
                d = read_input(block_file=block_file,
                               version=version,
                               input_count=inputCount)
                inputIds.append(d)
            outputCount = read_var_int(block_file)
            for outputIndex in range(0 , outputCount):
                d = read_output(block_file = block_file,
                                version=version,
                                output_count = outputCount)
                outputIds.append(d)
    else:
        cutStart1 = 0
        cutEnd1 = 0
        if std_out:
            log("\nInput Count: " + str(inputCount))
        for inputIndex in range(0 , inputCount):
            d = read_input(block_file=block_file ,
                           version=version ,
                           input_count=inputCount)
            inputIds.append(d)
        outputCount = read_var_int(block_file)
        if std_out:
            log("\nOutput Count: " + str(outputCount))
        for outputIndex in range(0 , outputCount):
            d = read_output(block_file=block_file ,
                            version=version ,
                            output_count=outputCount)
            outputIds.append(d)
    cutStart2 = 0
    cutEnd2 = 0
    witness = []
    if extendedFormat and flags_extended & 1:
        cutStart2 = block_file.tell()
        for inputIndex in range(0 , inputCount):
            countOfStackItems = read_var_int(block_file)
            for stackItemIndex in range(0 , countOfStackItems):
                stackLength = read_var_int(block_file)
                stackItem = block_file.read(stackLength)[::-1]
                if std_out:
                    log("Witness item: " + str(hex_to_str(stackItem)))
                witness.append(hex_to_str(stackItem))
        cutEnd2 = block_file.tell()
    lockTime = hex_to_int(read_int_little_endian(block_file))
    if lockTime < 500000000:
        if std_out:
            log("\nLock Time is Block Height: " + str(lockTime))
    else:
        dts = datetime.datetime.fromtimestamp(lockTime).strftime('%d.%m.%Y %H:%M')
        if std_out:
            log("\nLock Time is Timestamp: " + dts)
    endByte = block_file.tell()
    block_file.seek(beginByte)
    lengthToRead = endByte - beginByte
    dataToHashForTransactionId = block_file.read(lengthToRead)
    if extendedFormat and cutStart1 != 0 and cutEnd1 != 0 and cutStart2 != 0 and cutEnd2 != 0:
        dataToHashForTransactionId = dataToHashForTransactionId[:(cutStart1 - beginByte)] + \
                                     dataToHashForTransactionId[(cutEnd1 - beginByte):(cutStart2 - beginByte)] +\
                                     dataToHashForTransactionId[(cutEnd2 - beginByte):]
    elif extendedFormat:
        print(cutStart1 , cutEnd1 , cutStart2 , cutEnd2)
        quit()
    firstHash = hashlib.sha256(dataToHashForTransactionId)
    secondHash = hashlib.sha256(firstHash.digest())
    hashLittleEndian = secondHash.hexdigest()
    hashTransaction = string_little_endian_to_bigendian(binascii.unhexlify(hashLittleEndian))
    consolidate_inputs_outputs = []
    for e in inputIds:
        for o in outputIds:
            e.update(o)
            consolidate_inputs_outputs.append(e)
    if std_out:
        log("\nHash Transaction: " + str(hashTransaction))
    for v in consolidate_inputs_outputs:
        v.update({'lock_time_block_height' : str(lockTime)})
        v.update({'time_stamp' : str(dts)})
        for i in witness:
            v.update({"witness_item" : str(i)})
        if extendedFormat:
            v.update({'hash_transaction' : str(hashTransaction)})
        else:
            v.update({'hash_transaction' : str(hashTransaction)})
    if extendedFormat:
        if std_out:
            log("\nExtended Format: " + str(hashTransaction))
    return consolidate_inputs_outputs


def read_block(block_file,
               std_out = False,
               std_json = False,
               write_to_file = False,
               file_name = 'data/transactions.json'):
    magicNumber = binascii.hexlify(block_file.read(4))
    try:
        blockSize = hex_to_int(read_int_little_endian(block_file))
    except Exception as e:
        return False
    version = hex_to_int(read_int_little_endian(block_file))
    previousHash = binascii.hexlify(block_file.read(32))
    merkleHash = binascii.hexlify(block_file.read(32))
    creationTimeTimestamp = hex_to_int(read_int_little_endian(block_file))
    creationTime = datetime.datetime.fromtimestamp(creationTimeTimestamp).strftime('%d.%m.%Y %H:%M')
    bits = hex_to_int(read_int_little_endian(block_file))
    nonce = hex_to_int(read_int_little_endian(block_file))
    countOfTransactions = read_var_int(block_file)
    if std_out:
        log("Magic Number: " + str(magicNumber))
        log("Blocksize: " + str(blockSize))
        log("Version: " + str(version))
        log("Previous Hash: " + str(previousHash))
        log("Merkle Hash: " + str(merkleHash))
        log("Time: " + creationTime)
        log("Bits: " + str(bits))
        log("Nonce: " + str(nonce))
        log("Count of Transactions: " + str(countOfTransactions))

    for transactionIndex in range(0 , countOfTransactions):
        txs = read_transaction(block_file, std_out=std_out)
        if write_to_file:
            with open(file_name, 'a') as f:
                for v in txs:
                    v['version'] = str(version)
                    v['magic_number'] = str(magicNumber)
                    v['block_size'] = str(blockSize)
                    v['merkle_hash'] = str(merkleHash)
                    v['block_hash'] = str(previousHash)
                    v['block_time'] = str(creationTime)
                    v['block_timestamp'] = str(creationTimeTimestamp)
                    v['block_bits'] = str(bits)
                    v['block_nonce'] = str(nonce)
                    v['block_transactions_count'] = str(countOfTransactions)
                    json.dump(v, f)
                    f.write('\n')
        if std_json:
            for v in txs:
                v['version'] = str(version)
                v['magic_number'] = str(magicNumber)
                v['block_size'] = str(blockSize)
                v['merkle_hash'] = str(merkleHash)
                v['block_hash'] = str(previousHash)
                v['block_time'] = str(creationTime)
                v['block_timestamp'] = str(creationTimeTimestamp)
                v['block_bits'] = str(bits)
                v['block_nonce'] = str(nonce)
                v['block_transactions_count'] = str(countOfTransactions)
                return json.dumps(v)
    return True


def main():
    import os
    path = '/Bitcoin/blocks/'
    outfile = 'data/'
    files = [i for i in os.listdir(path) if i.startswith('blk')]
    for i in files:
        with open(path + i, "rb") as block_file:
            try:
                while True:
                    if not read_block(block_file,
                                      std_out=False,
                                      std_json=False,
                                      file_name=outfile + i.split('/')[-1].split('.')[0] + '.json',
                                      write_to_file=True):
                        break
            except Exception as e:
                pass
        print("DONE:", i)


if __name__ == "__main__":
    main()