'''
用于保存系统中使用的各个参数值和各种配置值
'''

from datetime import timedelta

http_ip = '127.0.0.1' #SCMS组件的ip
http_port = 8000 #SCMS组件监听的端口号

url_rootca_authen = '/rootca/authen'

#证书的有效时间
cert_lifespan = {'RootCA': timedelta(days=365*10),
                 'MA': timedelta(days=365)
                 }

pseudonym_cert_req_num = 20 #单次请求的假名证书数量

bloom_filter_cap = 300 #布隆过滤器容量
cuckoo_filter_cap = 300 #布谷鸟过滤器容量
cuckoo_bucket = 4 #布谷鸟过滤器的桶大小