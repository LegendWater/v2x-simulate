from datetime import datetime, timedelta
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa

from configs.typedef import CertType
import utility

class Certificate:
    '''
    证书类
    '''
    #下面这些成员是Certificate类的静态属性, 没有使用, 列在这只是为了方便查阅
    id: str #证书id
    type: CertType #证书类型
    issued_by: str #证书发行方
    owner: str     #证书所有方
    create_time: datetime     #证书创建时间
    expiration_time: datetime #证书过期时间
    has_expired: bool         #证书是否过期
    public_key: bytes                #证书内包含的公钥
    public_key_obj: rsa.RSAPublicKey #由于无法从bytes中复原RSAPublicKey对象所以额外保存这个信息
    content: bytes #证书实际内容

    def __init__(self, cert_type: CertType, issuer: str, owner: str, lifespan: timedelta) -> None:
        self.id = utility.gen_id()
        self.type = cert_type
        self.issued_by = issuer
        self.owner = owner
        self.create_time = datetime.now()
        self.expiration_time = self.create_time + lifespan
        self.content = Certificate.genCertContent(cert_type, lifespan, 1)[0]
        self.has_expired = False


    def __init__(self, cert_type: CertType, cert: x509.Certificate):
        '''
        从x509.Certificate中构造证书信息
        '''
        self.id = utility.gen_id()
        self.type = cert_type

        cert_info = utility.get_X509_info(cert)
        if cert_info is None:
            raise RuntimeError('证书创建失败, 无法获取证书信息')

        self.issued_by       = cert_info['issuer']['common name']
        self.owner           = cert_info['subject']['common name']
        self.create_time     = cert_info['valid from']
        self.expiration_time = cert_info['valid until']
        self.public_key      = cert_info['public key']
        self.public_key_obj  = cert.public_key()
        self.content         = cert_info['whole content']

        self.has_expired = datetime.now() > self.expiration_time

    def if_expire(self) -> bool:
        '''
        检查本证书是否过期
        '''
        self.has_expired = datetime.now() > self.expiration_time
        return self.has_expired

    @staticmethod
    def genCertContent(cert_type: CertType, lifespan: timedelta, cert_num: int) -> list[str]:
        '''
        生成证书的内容, 根据传入的证书类型和有效期, 可以提供给外部使用
        :param cert_type: 证书类型
        :param cert_num:  需要生成的证书数量
        :param duration:  证书有效期

        :return 返回生成的证书列表
        '''
        return list('')