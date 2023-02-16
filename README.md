# tongsuo-python-sdk

Tongsuo-Python-SDK基于[Tongsuo密码库](https://github.com/Tongsuo-Project/Tongsuo), 为Python应用提供密码学原语和安全传输协议的支持，目前以支持中国商用密码算法和安全协议为主。

SM2签名和验签，详见[sm2_sign_verify.py](https://github.com/Tongsuo-Project/tongsuo-python-sdk/blob/main/demos/sm2_sign_verify.py)
```python
from tongsuopy.crypto import hashes, serialization
from tongsuopy.crypto.asymciphers import ec

msg = b"hello"
key = ec.generate_private_key(ec.SM2())

pem = key.public_key().public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo,
)
pubkey = serialization.load_pem_public_key(pem)

signature = key.sign(msg, ec.ECDSA(hashes.SM3()))
pubkey.verify(signature, msg, ec.ECDSA(hashes.SM3()))
```

SM3杂凑，详见[sm3.py](https://github.com/Tongsuo-Project/tongsuo-python-sdk/blob/main/demos/sm3.py)
```python
from tongsuopy.crypto import hashes

h = hashes.Hash(hashes.SM3())
h.update(b"abc")
res = h.finalize()
```

SM4-CBC加密，详见[sm4_cbc.py](https://github.com/Tongsuo-Project/tongsuo-python-sdk/blob/main/demos/sm4_cbc.py)
```python
from tongsuopy.crypto.ciphers import Cipher, algorithms, modes

c = Cipher(algorithms.SM4(key), modes.CBC(iv))
enc = c.encryptor()
ciphertext = enc.update(plaintext)
ciphertext += enc.finalize()
```

SM4-GCM加密，详见[sm4_gcm.py](https://github.com/Tongsuo-Project/tongsuo-python-sdk/blob/main/demos/sm4_gcm.py)
```python
from tongsuopy.crypto.ciphers import Cipher, algorithms, modes

c = Cipher(algorithms.SM4(key), modes.GCM(iv))

enc = c.encryptor()
enc.authenticate_additional_data(aad)
ciphertext = enc.update(plaintext)
ciphertext += enc.finalize()
```

## 安装

```bash
pip install tongsuopy
```
要求Python >= 3.6。

## 功能特性

- 支持SM2签名和验签
- 支持SM3杂凑算法
- 支持SM4加解密，包括ECB、CBC、OFB、CFB、CTR模式
- 支持SM4-GCM和SM4-CCM
- [TODO] TLCP协议支持


## 交流群

欢迎加入铜锁社区交流群，使用钉钉扫描二维码或者钉钉内搜索群号44810299。

![铜锁社区交流群](https://mdn.alipayobjects.com/huamei_uwixg7/afts/img/A*4ag7R5ZF6HAAAAAAAAAAAAAADnyFAQ/original)
