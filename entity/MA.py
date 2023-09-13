from datetime import datetime
import json
from configs.filter import V2XFilter
from configs.typedef import CertType, SCMSComponent
from entity.Certificate import Certificate
from entity.RootCA import RootCA

from configs.config import cert_lifespan
import utility


class MA(SCMSComponent):
    CRL_seed: list[str] #链接种子CRL列表
    CRL_link: list[str] #链接值CRL列表
    filter: V2XFilter

    def __init__(self, filter: V2XFilter) -> None:
        '''
        可以传入不同的过滤器实现，来实验验证各种过滤器的性能
        '''
        super().__init__()
        self.CRL_seed = list()
        self.CRL_link = list()
        self.filter = filter

        self.__boost()

    def __boost(self):
        '''
        初始化工作
        '''

        #1.首先获取RootCA证书
        root_cert = self.get_rootca_cert()
        self.SCMS_certs['RootCA'] = root_cert
        #2.此时RootCA还在线, 申请给自己(指MA自己)签发证书
        #2.1 申请公私钥对
        pubkey, prikey = utility.gen_key_pair()
        pubytes, _ = utility.key_2_bytes(pubkey, prikey)
        #2.2 创建一个MA证书
        cert = Certificate(CertType.MA, 'RootCA,www.jmzv2x.com,cn', 'MA,www.jmzv2x.com,cn', datetime.now(), cert_lifespan['MA'], pubytes)
        #2.3 向RootCA申请签名, TODO root ca的server和url
        res_json = utility.req('root ca url', cert.to_json())
        if res_json is None:
            raise RuntimeError('请求MA证书失败')
        res_dict = json.loads(res_json)
        #2.4 取出Certificate数据(是签名后的证书二进制)
        content = res_dict['data']
        #2.5 保存签名后的证书内容
        cert.content = content

    def broadcast_CRL(self) -> None:
        '''
        发布CRL
        '''
        #TODO 待实现