from configs.typedef import *
import configs.config as config

class ECA(SCMSComponent):
    #所有有效的RSE和OBE的注册证书保存在RA

    def __init__(self) -> None:
        super().__init__()
        self.enroll_cert_list = list()

    def __boost(self):
    '''
    初始化工作
    '''

    #1.首先获取RootCA证书
    root_cert = self.get_rootca_cert()
    self.SCMS_certs['RootCA'] = root_cert
    #2.此时RootCA还在线, 申请给自己(指ECA自己)签发证书
    #2.1 申请公私钥对
    pubkey, prikey = utility.gen_key_pair()
    pubytes, _ = utility.key_2_bytes(pubkey, prikey)
    #2.2 创建一个ECA证书
    cert = Certificate(CertType.ECA, 'RootCA,www.jmzv2x.com,cn', 'ECA,www.jmzv2x.com,cn', datetime.now(), cert_lifespan['ECA'], pubytes)
    #2.3 向RootCA申请签名, TODO root ca的server和url
    res_json = utility.req('root ca url', cert.to_json())
    if res_json is None:
        raise RuntimeError('请求ECA证书失败')
    res_dict = json.loads(res_json)
    #2.4 取出Certificate数据(是签名后的证书二进制)
    content = res_dict['data']
    #2.5 保存签名后的证书内容
    cert.content = content

    def _sign_cert(self, cert: Certificate) -> bytes:
    '''签名证书的函数。此处是一个占位函数，实际上应使用ECA的私钥进行签名。'''
    return utility.sign_data_with_key(self.private_key, cert.to_json())

    def gen_enroll_cert(self, target: V2XBase) -> Certificate:
        '''
        为一个RSE或者OBE生成一份注册证书
        '''
        # 生成公私钥对
        pubkey, prikey = utility.gen_key_pair()
        pubytes, _ = utility.key_2_bytes(pubkey, prikey)
        
        # 创建证书对象
        cert = Certificate(CertType.enrollment, target.id, datetime.now(), config.cert_lifespan[CertType.enrollment], pubytes)
        
        # 使用ECA的私钥签名该证书
        cert.content = self._sign_cert(cert)
        
        # 将新证书添加到列表中
        self.enroll_cert_list.append(cert)

        return cert
