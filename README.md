# tongsuo-python-sdk

铜锁Python开发套件基于[Tongsuo密码库](https://github.com/Tongsuo-Project/Tongsuo), 为Python应用提供密码学原语和安全传输协议的支持，目前以支持中国商用密码算法和安全协议为主。

## 功能特性

- 支持SM2签名和验签
- 支持SM3杂凑算法
- 支持SM4加解密，包括ECB、CBC、OFB、CFB、CTR模式
- 支持SM4-GCM和SM4-CCM
- [TODO] TLCP协议支持

## 安装

Linux、MacOS安装示例：
```bash
# 先安装铜锁，下载源码包或者使用git仓库代码
wget https://github.com/Tongsuo-Project/Tongsuo/archive/refs/tags/8.3.2.tar.gz
tar xzvf 8.3.2.tar.gz
pushd Tongsuo-8.3.2
./config enable-ntls --prefix=/usr/local/tongsuo -Wl,-rpath=/usr/local/tongsuo/lib
make -j
make install
popd

# 设置TONGSUO_HOME环境变量：
export TONGSUO_HOME=/usr/local/tongsuo

pip install tongsuopy
```

## 文档

## 交流群

欢迎加入铜锁社区交流群，使用钉钉扫描二维码或者钉钉内搜索群号44810299。

![铜锁社区交流群](https://mdn.alipayobjects.com/huamei_uwixg7/afts/img/A*4ag7R5ZF6HAAAAAAAAAAAAAADnyFAQ/original)
