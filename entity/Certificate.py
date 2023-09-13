from datetime import datetime, timedelta
import json

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa, ec

from configs.typedef import CertType
import utility

class Certificate:
    '''
    证书类
    '''
    #下面这些成员是Certificate类的静态属性, 没有使用, 列在这只是为了方便查阅
    id: str #证书id
    type: CertType #证书类型
    issued_by: str #证书发行方, rfc4514格式, 'common name,organization,country'
    owner: str     #证书所有方, rfc4514格式
    create_time: datetime #证书创建时间
    valid_from: datetime  #证书有效时间
    valid_ntil: datetime  #证书过期时间
    has_expired: bool     #证书是否过期
    public_key: bytes                #证书内包含的公钥
    # public_key_obj: rsa.RSAPublicKey #可以从bytes中复原RSAPublicKey对象所以以后会删除这行代码
    has_signed: bool #证书是否签名了
    content: bytes #证书实际内容

    # def __init__(self, cert_type: CertType, issuer: str, owner: str, lifespan: timedelta) -> None:
    #     self.id = utility.gen_id()
    #     self.type = cert_type
    #     self.issued_by = issuer
    #     self.owner = owner
    #     self.create_time = datetime.now()
    #     self.expiration_time = self.create_time + lifespan
    #     self.content = Certificate.genCertContent(cert_type, lifespan, 1)[0]
    #     self.has_expired = False

    def __init__(
            self, 
            cert_type: CertType, 
            issued_by: str, owner: str, 
            valid_from: datetime, lifespan: timedelta, 
            pubkey: bytes):
        '''
        根据传入的参数构造证书信息, 证书需要经过签名才能使用部分功能(也就是需要调用sign()方法), 
        而Certificate.from_X509Cert()方法得到的证书是有签名的, 无需调用sign()就能使用所有功能

        @param issued_by: 格式'common name,organization,country'
        @param owner:     格式和issued_by一样
        '''
        self.id = utility.gen_id()
        self.type = cert_type

        self.issued_by = issued_by
        self.owner = owner
        self.create_time = datetime.now()
        self.valid_from = valid_from
        self.valid_ntil = self.create_time + lifespan
        self.has_expired = self.create_time > self.valid_ntil
        self.public_key = pubkey
        # self.public_key_obj = pubkey
        self.has_signed = False
        self.content = b''

    def sign(self, private_key: ec.EllipticCurvePrivateKey):
        '''
        用private key对自身内容签名
        '''

        if self.has_signed:
            return

        self.content = utility.signature(self, private_key)
        self.has_signed = True

    @staticmethod
    def from_X509Cert(x509_cert: x509.Certificate, cert_type: CertType):
        '''
        从x509的证书类信息中构造我们自己的证书类对象, 此时证书是经过签名的
        '''
        cert_info = utility.get_X509_info(x509_cert)
        if cert_info is None:
            print('证书对象创建失败, 无法获取X509证书信息')
            return None

        issued_by      = '{},{},{}'.format(cert_info['issuer']['common name'], cert_info['issuer']['organization'], cert_info['issuer']['country'])
        owner          = '{},{},{}'.format(cert_info['subject']['common name'], cert_info['subject']['organization'], cert_info['subject']['country'])
        valid_from     = cert_info['valid from']
        valid_ntil     = cert_info['valid until']
        public_key     = cert_info['public key']
        # public_key_obj = x509_cert.public_key()
        content        = cert_info['whole content']

        has_expired = datetime.now() > valid_ntil
        has_signed = True

        mcert = Certificate(cert_type, issued_by, owner, valid_from, valid_ntil - valid_from, public_key)
        mcert.public_key = public_key
        mcert.content = content
        mcert.has_expired = has_expired
        mcert.has_signed = has_signed
        return mcert

    def if_expire(self) -> bool:
        '''
        检查本证书是否过期
        '''
        self.has_expired = datetime.now() > self.valid_ntil
        return self.has_expired
    
    def to_dict(self):
        '''
        留给to_json()使用
        '''
        return {'type': int(self.type), 'issued_by': self.issued_by, 'owner': self.owner, 
                'valid_from': self.valid_from.strftime('%Y-%m-%d %H:%M:%S'), 'valid_ntil': self.valid_ntil.strftime('%Y-%m-%d %H:%M:%S'), 
                'public_key': self.public_key.decode('latin1'), 'has_signed': self.has_signed}
    
    def to_json(self):
        '''
        把自身信息转换为json格式字符串
        '''
        jsonstr = json.dumps(self, default=lambda obj: obj.to_dict())
        return jsonstr
    
    def content_from_json(self, jsonstr: str):
        '''
        从json字符串中得到自身content信息

        @param jsonstr: "{'content': b'xxx'}"
        '''
        #这个函数的功能不应该由Certificate来做, 应该换成V2XBase来做, TODO 移植到V2XBase类中
        obj = json.loads(jsonstr) #obj is a dict
        content = obj['content'] #bytes
        self.content = content

    # @staticmethod
    # def genCertContent(cert_type: CertType, lifespan: timedelta, cert_num: int) -> list[str]:
    #     '''
    #     生成证书的内容, 根据传入的证书类型和有效期, 可以提供给外部使用
    #     :param cert_type: 证书类型
    #     :param cert_num:  需要生成的证书数量
    #     :param duration:  证书有效期

    #     :return 返回生成的证书列表
    #     '''
    #     return list('')