from abc import ABC, abstractmethod

import configs.config as config

class V2XFilter(ABC):
    '''
    v2x系统中的过滤器基类
    '''

    capacity: int #过滤器的容量
    load_factor: float #过滤器的装填因子(0~1), 达到之后过滤器需要扩容
    hash_func: list #使用的所有哈希函数
    hash_table: list[list] #实际保存的哈希表, 布隆和布谷鸟都是两张哈希表

    def __init__(self, capacity, hash_func_list: list = None) -> None:
        self.capacity = capacity
        self.load_factor = 0.95
        if hash_func_list is not None:
            self.hash_func = hash_func_list.copy()

    @abstractmethod #abstractmethod注解的意思是子类必须实现这个方法
    def add(self, item) -> None:
        '''
        新项的插入
        '''
        pass #交给子类来实现

    @abstractmethod
    def contains(self, item) -> bool:
        '''
        检查元素是否存在
        '''
        pass

class BloomFilter(V2XFilter):
    '''
    布隆过滤器
    '''

    def __init__(self, hash_func_list: list = None) -> None:
        super().__init__(config.bloom_filter_cap, hash_func_list)

    def add(self, item) -> None:
        #TODO 待实现
        pass

    def contains(self, item) -> bool:
        #TODO 待实现
        pass

class CuckooFilter(V2XFilter):
    '''
    布谷鸟过滤器
    '''
    bucket: int #桶的大小

    def __init__(self, hash_func_list: list = None) -> None:
        super().__init__(config.cuckoo_filter_cap, hash_func_list)
        self.bucket = config.cuckoo_bucket

    def finger_print(self, item) -> str:
        '''
        生成指纹
        '''
        #TODO 待实现
        return ''

    def add(self, item) -> None:
        #TODO 待实现
        pass

    def contains(self, item) -> bool:
        #TODO 待实现
        pass