from bsddb3.db import *
from fastecdsa.keys import get_public_key
from fastecdsa.curve import secp256k1
from bc4py_extension import PyAddress
from Cryptodome.Cipher import AES
from binascii import b2a_hex
from collections import defaultdict
import hashlib
import requests


__version__ = "0.1.0"
task_working = False


class Pycrypto(object):
    def __init__(self, key, iv):
        self.ch_key = key
        self.ch_iv = iv

    @classmethod
    def set_key_from_passphrase(cls, key, salt, derivation):
        assert len(salt) == 8
        data = key + salt
        for i in range(derivation):
            data = hashlib.sha512(data).digest()
        return cls(data[0:32], data[32:32 + 16])

    def set_key(self, key):
        self.ch_key = key[0:32]

    def set_iv(self, iv):
        self.ch_iv = iv[0:16]

    def encrypt(self, data):
        return AES.new(self.ch_key, AES.MODE_CBC, self.ch_iv).encrypt(data)[0:32]

    def decrypt(self, data):
        return AES.new(self.ch_key, AES.MODE_CBC, self.ch_iv).decrypt(data)[0:32]


def double_hash(data):
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def sk2pk(sk):
    """secretKey to publicKey"""
    point = get_public_key(int.from_bytes(sk, 'big'), secp256k1)
    x = point.x.to_bytes(32, 'big')
    if point.y & 1:
        return b'\3' + x
    else:
        return b'\2' + x


def decode_encrypted_wallet(password: str, path="wallet.dat"):
    """get keypair data from encrypted wallet"""
    db = DB()
    db.open(path, "main", DB_BTREE, DB_THREAD | DB_RDONLY)
    data = defaultdict(list)

    # iterate database
    for k, v in db.items():
        key_name = k[1:1+k[0]].decode()
        if key_name == 'ckey':
            # encryptedKey: [(py, encrypted_sk), ]
            data[key_name].append((k[6:6+33], v[1:1+96]))
        elif key_name == 'mkey':
            # masterKey: encrypted_key, salt, DerivationIterations
            data[key_name] = [v[1:1+48], v[50:50+8], int.from_bytes(v[4+58:4+58+8], 'little')]
        elif key_name == 'key':
            # normalKey:
            raise Exception('this wallet is not encrypted!')
    db.close()

    # decrypt
    cp = Pycrypto.set_key_from_passphrase(
        password.encode(), data['mkey'][1], data['mkey'][2])
    mk = cp.decrypt(data['mkey'][0])  # import masterKey as key
    cp.set_key(mk)
    for pk, encrypted_sk in data['ckey']:
        cp.set_iv(double_hash(pk))  # import doubleHashed pk as IV
        sk = cp.decrypt(encrypted_sk)
        if sk2pk(sk) != pk:
            raise Exception('wrong password! {} {}'.format(sk2pk(sk).hex(), pk.hex()))
        ck = hashlib.new('ripemd160', hashlib.sha256(pk).digest()).digest()
        yield sk, pk, ck


def decode_normal_wallet(path="wallet.dat"):
    """get keypair data from un-encrypted wallet"""
    db = DB()
    db.open(path, "main", DB_BTREE, DB_THREAD | DB_RDONLY)
    for k, v in db.items():
        key_name = k[1:1 + k[0]].decode()
        if key_name == 'key':
            for i in range(len(v) - 32):
                sk = v[i:i+32]
                pk = sk2pk(sk)
                if pk not in k:
                    continue
                ck = hashlib.new('ripemd160', hashlib.sha256(pk).digest()).digest()
                yield sk, pk, ck
        elif key_name == 'ckey':
            raise Exception('wallet is encrypted!')
    db.close()


def write_down(path="wallet.dat", output='dump.txt', only_key=False):
    """write down all key->value"""
    db = DB()
    db.open(path, "main", DB_BTREE, DB_THREAD | DB_RDONLY)
    with open(output, mode="w") as fp:
        for k, v in db.items():
            if only_key:
                if 32 < len(k) and (k[-33] == 2 or k[-33] == 3):
                    fp.write(b2a_hex(k).decode() + " -> " + b2a_hex(v).decode() + "\n")
            else:
                fp.write(b2a_hex(k).decode() + " -> " + b2a_hex(v).decode() + "\n")
    db.close()


def push_keypair(url, jsn):
    try:
        r = requests.post(url, json=jsn)
        if r.status_code == 200:
            return None
        return r.text
    except Exception:
        return "connection refused by node"


def task(password, wallet_path, hrp, url, system_msg, ok_button):
    global task_working
    if task_working:
        system_msg.update("error: already task working!\n", append=True)
        return
    try:
        # search
        success = 0
        failed = 0
        task_working = True
        for sk, pk, ck in \
                decode_encrypted_wallet(password, wallet_path) \
                if password else decode_normal_wallet(wallet_path):
            addr: PyAddress = PyAddress.from_param(hrp, 0, ck)
            system_msg.update("msg: try to import `%s`\n" % addr.string, append=True)
            result = push_keypair(url, {"private_key": sk.hex(), "address": addr.string})
            if result:
                failed += 1
                system_msg.update("warning: failed by `%s`\n" % result, append=True)
            else:
                success += 1
                system_msg.update("msg: success import\n", append=True)

        # end of process
        system_msg.update("msg: finish all imports (success %d, failed %d)\n"
                          % (success, failed), append=True)
        system_msg.update("msg: you must resync after\n", append=True)
        ok_button.update(disabled=True)
    except Exception as e:
        system_msg.update("error: %s \n" % str(e), append=True)
    task_working = False


__all__ = [
    "__version__",
    "Pycrypto",
    "double_hash",
    "sk2pk",
    "decode_encrypted_wallet",
    "decode_normal_wallet",
    "write_down",
    "push_keypair",
    "task",
]
