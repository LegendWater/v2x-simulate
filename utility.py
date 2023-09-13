from datetime import datetime, timedelta, timezone
import uuid
import requests
import hashlib
from cryptography import x509
from cryptography.x509 import Name
from cryptography.x509.oid import NameOID
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding, ec
from cryptography.hazmat.primitives import serialization
from cryptography.x509 import Version
import configs.config as config
from entity.Certificate import Certificate

def gen_id() -> str:
    '''
    生成一串唯一id
    '''
    return uuid.uuid1().hex

def get_time_IEEE1609_2_Time32() -> str:
    return str(datetime.now(timezone.utc)) #2023-09-04 13:20:43.267223+00:00

def req(url: str, data) -> (str | None):
    '''
    http请求工具, data=None是get请求, 否则是post请求
    '''

    if data is None: #get请求
        req = requests.get(url)
        if req.status_code == 200: #成功
            res = req.json()
            print(type(res))
            return res
        else:
            return None
    else: #post请求
        req = requests.post(url, json=data)
        if req.status_code == 201: #成功
            res = req.json()
            return res
        else:
            return None
        
def gen_key_pair():
    '''
    生成一对公私钥对, 返回RSAPublicKey, RSAPrivateKey
    '''
    # private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    return private_key.public_key(), private_key

def key_2_bytes(pubkey: ec.EllipticCurvePublicKey | None, prikey: ec.EllipticCurvePrivateKey | None):
    '''
    得到Key对象的二进制表示
    '''
    pubres = b''
    prires = b''

    if pubkey is not None:
        pubres = pubkey.public_bytes(
            encoding=serialization.Encoding.DER, 
            format=serialization.PublicFormat.SubjectPublicKeyInfo)
    if prikey is not None:
        prires = prikey.private_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption())
    
    return (pubres, prires)

def bytes_2_key(pubytes: bytes | None, pribytes: bytes | None):
    '''
    从二进制得到Key对象
    '''
    pubkey = None
    prikey = None

    if pubytes is not None:
        pubkey = serialization.load_der_public_key(pubytes)
    if pribytes is not None:
        prikey = serialization.load_der_private_key(pribytes, None)
    return (pubkey, prikey)

def abstract(content: str|bytes) -> bytes:
    '''
    生成内容的摘要, 即内容的md5值
    '''
    if isinstance(content, str):
        content = content.encode('latin1')
    md5 = hashlib.md5()
    md5.update(content)
    return md5.hexdigest().encode('latin1')

def gen_self_signed_cert(private_key: ec.EllipticCurvePrivateKey):
    '''
    生成符合X.509标准的自签名证书, 给RootCA自己用, 证书文件格式DER, 内容包括: \n
    证书序列号:    表示证书的唯一标识符, 由颁发者分配。\n
    签名算法标识符: 表示用于对证书进行数字签名的算法和参数, 如SHA-256、RSA等。\n
    颁发者名称:    表示颁发者的身份信息, 如国家/地区、组织、组织单位、通用名称等。\n
    有效期:        表示证书的有效时间范围, 包括起始时间和结束时间。\n
    主题名称:      表示主题（即持有者）的身份信息, 如国家/地区、组织、组织单位、通用名称等。\n
    主题公钥信息:   表示主题的公钥和相关参数, 如算法、长度、指数等。\n
    证书签名:      表示对上述信息进行哈希运算后, 再用颁发者的私钥加密得到的数字签名。\n
    return: x509 cert
    '''

    # if not isinstance(private_key, rsa.RSAPrivateKey):
    #     print('parameter is invalid')
    #     return None
 
    # # subject：使用者
    # subject = x509.Name(
    #     [
    #         x509.NameAttribute(NameOID.ORGANIZATION_NAME, "www.jmzv2x.com"),
    #         x509.NameAttribute(NameOID.COMMON_NAME, 'RootCA'),
    #         x509.NameAttribute(NameOID.COUNTRY_NAME, 'cn'),
    #     ]
    # )
 
    # # issuer：颁发者
    # issuer = x509.Name(
    #     [
    #         x509.NameAttribute(NameOID.ORGANIZATION_NAME, "www.jmzv2x.com"),
    #         x509.NameAttribute(NameOID.COMMON_NAME, 'RootCA'),
    #         x509.NameAttribute(NameOID.COUNTRY_NAME, 'cn'),
    #     ]
    # )
 
    # # cert使用私钥签名（.sign(私钥，摘要生成算法，填充方式)），使用x509.CertificateBuilder()方法生成证书，证书属性使用下列函数叠加补充
    # cert = (
    #     x509.CertificateBuilder()
    #     .subject_name(subject)
    #     .issuer_name(issuer)
    #     .public_key(private_key.public_key())
    #     .serial_number(x509.random_serial_number())
    #     .not_valid_before(datetime.utcnow() + timedelta())
    #     .not_valid_after(datetime.utcnow() + config.cert_lifespan['RootCA'])
    #     .sign(private_key, hashes.SHA256(), default_backend())
    # )

    cert = gen_X509_cert('RootCA,www.jmzv2x.com,cn', 'RootCA,www.jmzv2x.com,cn', private_key.public_key(), private_key, config.cert_lifespan['RootCA'])
    
    return cert

def gen_X509_cert(issuer_cn_o_c: str, subject_cn_o_c: str, public_key: ec.EllipticCurvePublicKey, private_key: ec.EllipticCurvePrivateKey, lifespan: timedelta):
    '''
    生成符合X.509标准的 未签名 证书, 给除了RootCA以外的实体使用, 证书文件格式DER, 内容包括: \n
    证书序列号:    表示证书的唯一标识符, 由颁发者分配。\n
    签名算法标识符: 表示用于对证书进行数字签名的算法和参数, 如SHA-256、RSA等。\n
    颁发者名称:    表示颁发者的身份信息, 如国家/地区、组织、组织单位、通用名称等。\n
    有效期:        表示证书的有效时间范围, 包括起始时间和结束时间。\n
    主题名称:      表示主题（即持有者）的身份信息, 如国家/地区、组织、组织单位、通用名称等。\n
    主题公钥信息:   表示主题的公钥和相关参数, 如算法、长度、指数等。\n
    证书签名:      表示对上述信息进行哈希运算后, 再用颁发者的私钥加密得到的数字签名。\n
    @param issuer_cn_o_c:  issuer's common name, organization, country\n
    @param subject_cn_o_c: subject's common name, organization, country'\n
    @param public_key:  需要签名的公钥\n
    @param private_key: 用于签名的私钥\n
    @param lifespan: 证书有效期\n
    return: x509 cert
    '''
 
    subject_cn, subject_o, subject_c = subject_cn_o_c.split(',')
    # subject：使用者
    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, subject_o),
            x509.NameAttribute(NameOID.COMMON_NAME, subject_cn),
            x509.NameAttribute(NameOID.COUNTRY_NAME, subject_c),
        ]
    )
 
    issuer_cn, issuer_o, issuer_c = issuer_cn_o_c.split(',')
    # issuer：颁发者
    issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, issuer_o),
            x509.NameAttribute(NameOID.COMMON_NAME, issuer_cn),
            x509.NameAttribute(NameOID.COUNTRY_NAME, issuer_c),
        ]
    )
 
    # cert使用私钥签名（.sign(私钥，摘要生成算法，填充方式)），使用x509.CertificateBuilder()方法生成证书，证书属性使用下列函数叠加补充
    cert = (x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow() + timedelta())
        .not_valid_after(datetime.utcnow() + lifespan)
        .sign(private_key, hashes.SHA256(), default_backend()) #不准不签名
    )

    '''
    # 最终生成的证书与密钥对为类对象，要保存在文件中还需要进一步转换成字节格式
    cert_text = cert.public_bytes(serialization.Encoding.DER)
    print('cert text:\n', cert_text)

    private_text = private_key.private_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )
    print('\nprivate key:\n', private_text)
    #重新读取二进制流中的证书
    #保存到文件的private_key怎么重新读取出来?
    X509Cert = crypto.load_certificate(crypto.FILETYPE_DER, cert_text)
    print('\nissuer\n', X509Cert.get_issuer().commonName)
    '''
    return cert

def get_X509_info(cert: x509.Certificate):
    '''
    获取x509证书中的各种信息
    '''

    if not isinstance(cert, x509.Certificate):
        return
    
    res = {'serial_num': str(cert.serial_number), 
           'version': '', 
           'issuer': {'common name': '', 'organization': '', 'country': ''}, 
           'subject': {'common name': '', 'organization': '', 'country': ''}, 
           'valid from': cert.not_valid_before, 
           'valid until': cert.not_valid_after, 
           'public key': cert.public_key().public_bytes(encoding=serialization.Encoding.DER,
                                                        format=serialization.PublicFormat.SubjectPublicKeyInfo), 
           'signature algorithm': '', 
           'signature': cert.signature, 
           'whole content': cert.public_bytes(serialization.Encoding.DER)
           }

    #获取证书版本
    v = ''
    if cert.version == Version.v1:
        v = 'v1'
    elif cert.version == Version.v3:
        v = 'v3'
    res['version'] = v

    #获取issuer和subject的信息
    names = ['issuer', 'subject']
    for name in names:
        if name == 'issuer':
            info = cert.issuer.rfc4514_string() #C=cn,CN=RootCA,O=www.jmzv2x.com
        else:
            info = cert.issuer.rfc4514_string()
        
        info_split = info.split(',')
        cn = ''
        organ = ''
        country = ''
        for fo in info_split:
            if fo.startswith('CN'):
                cn = fo[3:]
            elif fo.startswith('C'):
                country = fo[2:]
            elif fo.startswith('O'):
                organ = fo[2:]
            
        res_name = res[name]
        res_name.update({'common name': cn, 'organization': organ, 'country': country})

    #获得签名算法信息
    sign_algorithm = cert.signature_hash_algorithm.name if cert.signature_hash_algorithm is not None else 'None'
    res['signature algorithm'] = sign_algorithm

    return res

def signature(cert: Certificate, private_key: ec.EllipticCurvePrivateKey) -> bytes:
    '''
    根据private key生成我们定义的Certificate对象的签名, 返回签名后的证书内容\n
    AI说应该用CSR申请证书, 等申请到签名之后再生成证书但是我觉得麻烦
    '''

    if cert.has_signed: #已经签名过了
        return cert.content

    issuer_cn, issuer_o, issuer_c = cert.issued_by.split(',') #'common name,organization,country'
    issuer_name = x509.Name([
                    x509.NameAttribute(NameOID.ORGANIZATION_NAME, issuer_o),
                    x509.NameAttribute(NameOID.COMMON_NAME, issuer_cn),
                    x509.NameAttribute(NameOID.COUNTRY_NAME, issuer_c),
                ])
    subject_cn, subject_o, subject_c = cert.owner.split(',')
    subject_name = x509.Name([
                    x509.NameAttribute(NameOID.ORGANIZATION_NAME, subject_o),
                    x509.NameAttribute(NameOID.COMMON_NAME, subject_cn),
                    x509.NameAttribute(NameOID.COUNTRY_NAME, subject_c),
                ])

    #拿到RSAPublicKey对象
    pubkey, _ = bytes_2_key(cert.public_key, None)
    #用x509.CertificateBuilder构建一个x509.Certificate
    builder = (x509.CertificateBuilder()
                .issuer_name(issuer_name)
                .subject_name(subject_name)
                .public_key(pubkey)
                .serial_number(x509.random_serial_number()) #自定义的Certificate没有序列号信息, 随机生成一个问题应该也不大
                .not_valid_before(cert.valid_from)
                .not_valid_after(cert.valid_ntil))

    mcert = builder.sign(private_key, hashes.SHA256())
    content = mcert.public_bytes(serialization.Encoding.DER)
    return content

def bytes_2_x509Cert(cert_data: bytes):
    '''
    从DER格式的x509证书二进制中解析出证书类数据
    '''
    x509_cert = x509.load_der_x509_certificate(cert_data, default_backend())
    return x509_cert
