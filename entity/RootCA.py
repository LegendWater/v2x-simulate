from configs.typedef import SCMSComponent, CertType
import utility
from entity.Certificate import Certificate

class RootCA(SCMSComponent):
    components: list[str] #在Root CA注册在案的所有SCMS组件, 保存它们的id
    
    #这个静态属性放在这, 是为了模拟其他组件出厂自带RootCA的证书
    self_signed_cert = None #自签名证书, v2x的Certificate类型

    def __init__(self) -> None:
        super().__init__()

        #生成自签名证书
        public_key, private_key = utility.gen_key_pair()
        cert = utility.gen_self_signed_cert(private_key)
        if cert is None:
            raise RuntimeError('private key type error')
        
        v2x_cert = Certificate(CertType.RootCA, cert)

        RootCA.self_signed_cert = v2x_cert #静态属性赋值

        self.certs[CertType.RootCA] = [v2x_cert] #保存证书
        self.public_key[CertType.RootCA] = [{v2x_cert.id: public_key}] #保存公钥, TODO 验证public_key.public_bytes()和v2x_cert.public_key是一样的二进制串
        self.private_key[CertType.RootCA] = [{v2x_cert.id: private_key}] #保存私钥
    
    @staticmethod
    def get_root_cert() -> Certificate | None:
        '''
        返回RootCA的自签名证书, 给EE做出厂设置
        '''
        return RootCA.self_signed_cert

    def signature(self, content: bytes) -> bytes | None:
        '''
        给接收到的消息签名, 返回值仅包含生成的签名本身
        '''
        which_cert = self.certs[CertType.RootCA][0]
        return super().signature(which_cert, content)