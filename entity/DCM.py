from configs.typedef import *
import utility

class DCM(V2XBase):

    eca_address: str #ECA的http请求url

    def __init__(self, eca_address) -> None:
        super().__init__(cert_type=CertType.component)
        self.eca_address = eca_address

    def __check_if_valid(self, target: V2XBase) -> bool:
        '''
        验证一个OBE或者RSE有资格获取注册证书
        '''
        #TODO 待实现
        return True
    
    def request_enroll_cert(self, target: V2XBase) -> (Certificate | None):
        '''
        向ECA请求一个对于RSE或者OBE的注册证书

        return: 注册证书或者在OBE或RSE没有资格时返回None
        '''
        if self.__check_if_valid(target):
            utility.req()
            return ECA.gen_enroll_cert(target)
        else:
            return None