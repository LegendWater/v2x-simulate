'''
定义了SCMS系统中使用的类型
'''

from enum import IntEnum
from datetime import datetime, timedelta
from configs.filter import V2XFilter, BloomFilter, CuckooFilter
from hashlib import sha256
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa
from entity.Certificate import Certificate

import utility
import configs.config as config
from entity.RootCA import RootCA

class CertType(IntEnum):
    '''
    定义了所有的证书类型
    '''
    RootCA = 1
    ECA = 2
    PCA = 3
    RA = 4
    MA = 5
    OBE_enroll = 6
    OBE_pseudonym = 7
    OBE_identification = 8
    RSE_enroll = 9
    RSE_application = 10

class V2XBase:
    '''
    v2x 系统中所有实体的基类
    '''

    def __init__(self) -> None:
        self.id = utility.gen_id() #每个v2x实体的唯一标识符
        self.certs = dict()       #持有的自己的证书, 格式如{enroll:[Cert], pseudonym:[Cert, Cert, ...]}
        self.public_key = dict()  #持有的自己的公钥, 格式{证书类型: [{证书id: 公钥}]}, 如{enroll:[{id:RSAPublicKey}], pseudonym:[{id:RSAPublicKey}, ...]}
        self.private_key = dict() #持有的自己的私钥, 格式同public_key, 但是存的是rsa.RSAPrivateKey
        self.SCMS_certs = dict()  #持有的SCMS组件的证书, 用于信任SCMS组件, 格式如{'ECA': Cert, 'RootCA': Cert, ...}, 这些证书都是RootCA签发给SCMS组件的
        self.EE_certs = dict()    #持有的EE的证书, 格式如{'RSE': {id1: [Cert, Cert, ...], id2: [Cert, ]}, 'OBE': {id1: [Cert, ], id2: [Cert, ]}}

    def __get_private_key(self, cert_type: CertType, cert_id: str) -> rsa.RSAPrivateKey | None:
        '''
        拿到证书对应的私钥
        '''
        ids = self.private_key[cert_type]
        for d in ids:
            for id, key in d.items():
                if id == cert_id:
                    return key

        return None

    def get_public_key(self, cert_type: CertType, cert_id: str) -> rsa.RSAPublicKey | None:
        '''
        拿到证书对应的公钥
        '''
        ids = self.public_key[cert_type]
        for d in ids:
            for id, key in d.items():
                if id == cert_id:
                    return key
        return None

    def get_rootca_cert(self):
        '''
        获取RootCA的自签名证书
        '''
        if RootCA.self_signed_cert is None:
            raise RuntimeError('Root CA还未启动')
        return RootCA.self_signed_cert

    def signature(self, which_cert: Certificate, cert: Certificate) -> bytes:
        '''
        生成自己的数字签名, 返回数字签名之后证书的内容
        @param which_cert: 选择要用哪一本证书对应的私钥生成签名
        @param cert: 待签名的证书
        '''
        #判断证书是否已经签名过了
        if not cert.has_signed:
            key = self.__get_private_key(which_cert.type, which_cert.id)
            if key is None:
                return b''

            cert.sign(key)

        return cert.content


class SCMSComponent(V2XBase):
    '''
    所有SCMS组件的基类(也就是排除RSE和OBE)
    '''

    def __init__(self) -> None:
        super().__init__()

class EndEntity(V2XBase):
    '''
    RSE和OBE的基类
    '''

    def __init__(self) -> None:
        super().__init__()

        self.__boost()

    def __boost(self):
        '''
        EE的启动流程

        启动完成后, EE需持有: Root CA证书、最新的CRL、MA证书、ECA证书、注册证书、PCA证书、RA证书
        '''
        #TODO 待完成
        #首先生成最终持有的证书的公私钥, 共4(MA ECA PCA RA)+1(注册证书)=5组
        keys_list = [utility.gen_key_pair()] * 5
        #RootCA的自签名证书出厂就内置了
        root_cert = RootCA.self_signed_cert
        if root_cert is None: #系统中还没有RootCA
            raise RuntimeError('Root CA还未启动')
        
        self.SCMS_certs['RootCA'] = root_cert
        #MA证书
        ...
        #ECA证书
        ...
        #PCA证书
        ...
        #RA证书
        ...
        #注册证书
        ...
        

    def __get_enroll_cert(self) -> Certificate | None:
        '''
        每个RSE和OBE在启动之后都有一本注册证书
        '''
        type_name = type(self).__name__ #此时还没定义OBE类和RSE类, 只能用类型名字判断了
        if type_name == 'RSE' or type_name == 'OBE':
            if type_name == 'RSE':
                enroll_cert = self.certs[CertType.RSE_enroll][0].values()[0]
                return enroll_cert
            elif type_name == 'OBE':
                enroll_cert = self.certs[CertType.OBE_enroll][0].values()[0]
                return enroll_cert
        return None

    def __req_RootCA(self):
        ...

    def request_to_RA(self, req_content) -> str | None:
        '''
        与RA通信的流程:
        1、对当前时间签名;
        2、提交自己的注册证书、当前时间、当前时间的签名给RA;
        3、从RA获取请求的数据。
        '''
        enroll_cert = self.__get_enroll_cert()
        if enroll_cert == None:
            return None

        time = utility.get_time_IEEE1609_2_Time32().encode('latin1')
        signed_time = self.signature(which_cert=enroll_cert, content=time)

        info = {'enroll cert': enroll_cert, 'time': time, 'time sign': signed_time, 'data': req_content}
        res = utility.req('RA url', info)
        return res
    

        
class PCA(V2XBase):
    def __init__(self) -> None:
        super().__init__()

    def gen_pseudonym_cert(self, target: V2XBase, num: int) -> (list[Certificate] | None):
        '''
        为一个RSE或者OBE生成若干份假名证书
        '''
        res = list()
        for _ in range(num):
            res.append(Certificate(CertType.pseudonym, target.id, config.cert_lifespan[CertType.pseudonym]))

        return res

class RA(V2XBase):
    def __init__(self) -> None:
        super().__init__(cert_type=CertType.component)

    def __check_if_valid(self, target: V2XBase) -> bool:
        '''
        验证一个OBE或者RSE有资格获取假名证书
        '''
        #TODO 待实现
        return True

    def request_pseudonym_cert(self, PCA: PCA, target: V2XBase) -> list[Certificate]:
        '''
        向PCA请求若干个对于RSE或者OBE的假名证书

        return: 假名证书list或者在OBE或RSE没有资格时返回None
        '''
        #TODO 乱序各个OBE的假名证书请求
        if self.__check_if_valid(target):
            return PCA.gen_pseudonym_cert(target, config.pseudonym_cert_req_num)
        else:
            return None
        


class LA(V2XBase):
    def __init__(self) -> None:
        super().__init__(cert_type=CertType.component)

    def gen_pre_link(self) -> str:
        '''
        生成预链接值
        '''
        #TODO 待实现
        return ''
    
class SCMS:
    '''
    代表了SCMS所有组件的集合的抽象概念
    '''

    def __init__(self) -> None:
        self.RootCA = RootCA()
        self.ECA = ECA()
        self.PCA = PCA()
        self.DCM = DCM()
        self.RA = RA()
        self.MA_bloom = MA(BloomFilter())
        self.MA_cuckoo = MA(CuckooFilter())
        self.LA1 = LA()
        self.LA2 = LA()

        self.RootCA.authenticate(self.ECA)
        self.RootCA.authenticate(self.PCA)
        self.RootCA.authenticate(self.DCM)
        self.RootCA.authenticate(self.RA)
        self.RootCA.authenticate(self.MA_bloom)
        self.RootCA.authenticate(self.MA_cuckoo)
        self.RootCA.authenticate(self.LA1)
        self.RootCA.authenticate(self.LA2)

    def request_enroll_cert(self, target: V2XBase) -> (Certificate | None):
        return self.DCM.request_enroll_cert(self.ECA, target)
    
    def request_pseudonym_cert(self, target: V2XBase) -> (list[Certificate] | None):
        return self.RA.request_pseudonym_cert(self.PCA, target)
    
class RSE(V2XBase):
    pseudonym_cert: list[Certificate] #持有的假名证书列表
    CRL_seed: list[str] #下载的CRL链接种子列表

    def __init__(self) -> None:
        super().__init__(cert_type=CertType.enrollment)
        self.pseudonym_cert = list()
        self.CRL_seed = list()

    def request_enroll_cert(self) -> bool:
        '''
        使用http请求的方式向SCMS请求一张注册证书
        '''
        #TODO 待实现
        pass