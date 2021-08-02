# EasyRootCA

~~my first python project~~

~~openssl 命令行太烦了啊啊啊啊啊~~

自己做 Root CA, 简单给测试环境签发证书

## 使用方法:

直接使用打包好的 exe 文件: https://github.com/NimaQu/EasyRootCA/releases

直接运行源代码：

环境: Python 3.9

```
git clone https://github.com/NimaQu/EasyRootCA.git
pip3 install cryptography
cp config.ini.example config.ini
nano config.py #修改成你需要的值
python3 main.py
```

第一次使用会提示创建 CA 证书，将创建好的 root_cert.crt 安装进系统受信任的根证书即可

IPv4 证书和域名证书均可创建，如果为 [IDN 域名 ](https://zh.wikipedia.org/wiki/%E5%9B%BD%E9%99%85%E5%8C%96%E5%9F%9F%E5%90%8D)需要先进行转义

### Todo:

- [ ] IPv6 支持

- [x] 使用 Github Action 自动编译成~~各平台~~ Windows 可执行文件

