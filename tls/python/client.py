# First create openssl.cnf and with content:

# openssl_conf = openssl_init

# [openssl_init]
# providers = provider_sect

# [provider_sect]
# default = default_sect
# tpm2 = tpm2_sect

# [default_sect]
# activate = 1

# [tpm2_sect]
# activate = 1

# Then

# export OPENSSL_CONF=`pwd`/openssl.cnf
# python3 client.py


import requests

response = requests.get('https://localhost:8443/', verify='ca/root-ca.crt', cert=('certs/tpmc.crt', 'certs/tpmc.key'))

print("Status Code: %s" % response.status_code)
print(response.text)

