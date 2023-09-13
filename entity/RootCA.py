from datetime import datetime
import json
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
        x509_cert = utility.gen_self_signed_cert(private_key)
        
        v2x_cert = Certificate.from_X509Cert(x509_cert, cert_type=CertType.RootCA)
        if v2x_cert is None:
            raise RuntimeError('root ca init failed')

        RootCA.self_signed_cert = v2x_cert #静态属性赋值

        self.certs[CertType.RootCA] = [v2x_cert] #保存证书

        if CertType.RootCA not in self.public_key.keys(): #尚未添加root ca的public key
            self.public_key[CertType.RootCA] = [{v2x_cert.id: public_key}] #保存公钥, TODO 验证public_key.public_bytes()和v2x_cert.public_key是一样的二进制串
        else:
            self.public_key[CertType.RootCA].append({v2x_cert.id: public_key})

        if CertType.RootCA not in self.private_key.keys(): #尚未添加root ca的private key
            self.private_key[CertType.RootCA] = [{v2x_cert.id: private_key}] #保存私钥
        else:
            self.private_key[CertType.RootCA].appen({v2x_cert.id: public_key})
    
    @staticmethod
    def get_root_cert() -> Certificate | None:
        '''
        返回RootCA的自签名证书, 给EE做出厂设置
        '''
        return RootCA.self_signed_cert

    def signature(self, cert_data: str) -> bytes:
        '''
        给接收到的消息签名, 返回签名之后证书的二进制

        @param cert_data: cert_data是json格式的, 从Certificate.to_json()生成而来, 表示Certificate的信息, 
        之所以用str是因为cert_data是从http请求得到的, str比较方便传递
        '''
        which_cert = self.certs[CertType.RootCA][0]

        #解析得到Certificate
        d = json.loads(cert_data) #d is a dict
        typestr = d['type']
        issued_by = d['issued_by']
        owner = d['owner']
        valid_from_str = d['valid_from']
        valid_ntil_str = d['valid_ntil']
        public_key_str = d['public_key']
        has_signed_str = d['has_signed']

        type = CertType(int(typestr))
        valid_from = datetime.strptime(valid_from_str, '%Y-%m-%d %H:%M:%S')
        valid_ntil = datetime.strptime(valid_ntil_str, '%Y-%m-%d %H:%M:%S')
        public_key = public_key_str.encode('latin1')
        has_signed = bool(has_signed_str)
        cert = Certificate(type, issued_by, owner, valid_from, valid_ntil - valid_from, public_key)
        cert.has_signed = has_signed

        return super().signature(which_cert, cert)