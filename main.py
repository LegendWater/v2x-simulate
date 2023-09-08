from configs.typedef import CertType
from entity.RootCA import RootCA

if __name__ == '__main__':
    rca = RootCA()
    print(rca.certs[CertType.RootCA][0].public_key)
    print('\n', rca.public_key[CertType.RootCA][0])
    print('\n', rca.private_key[CertType.RootCA][0])