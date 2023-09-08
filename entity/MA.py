from configs.filter import V2XFilter
from configs.typedef import CertType, SCMSComponent
from entity.RootCA import RootCA


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

        self.__init()

    def __init(self):
        '''
        初始化工作
        '''

        #首先获取RootCA证书
        root_cert = self.get_rootca_cert()
        self.SCMS_certs['RootCA'] = root_cert
        #此时RootCA还在线, 申请给自己签发证书
        ...

    def broadcast_CRL(self) -> None:
        '''
        发布CRL
        '''
        #TODO 待实现