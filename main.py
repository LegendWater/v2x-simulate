from configs.typedef import CertType
from configs import config
from entity.RootCA import RootCA
from cryptography.hazmat.primitives import serialization
import utility

if __name__ == '__main__':
    pubkey, prikey = utility.gen_key_pair()
    cert = utility.gen_self_signed_cert(prikey)
    print('cert')
    print(cert.public_bytes(serialization.Encoding.DER))

    issuer = 'RootCA,www.jmzv2x.com,cn'
    cert_nosign = utility.gen_X509_cert(issuer, issuer, pubkey, config.cert_lifespan['RootCA'])
    utility.signature(prikey, cert_nosign)