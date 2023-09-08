from configs.typedef import *
import configs.config as config

class ECA(SCMSComponent):
    #所有有效的RSE和OBE的注册证书保存在RA

    def __init__(self) -> None:
        super().__init__()
        self.enroll_cert_list = list()

    def gen_enroll_cert(self, target: V2XBase) -> Certificate:
        '''
        为一个RSE或者OBE生成一份注册证书
        '''
        return Certificate(CertType.enrollment, target.id, config.cert_lifespan[CertType.enrollment])