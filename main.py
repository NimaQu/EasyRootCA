import datetime
import os
import re

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from ipaddress import IPv4Address, IPv6Address
import config


def load_ca_file(file_type):
    try:
        if file_type == 'cert':
            with open("rootCA_cert.crt", "rb") as f:
                return x509.load_pem_x509_certificate(f.read())
    except FileNotFoundError:
        print("Can't find root cert File")
        exit(114514)
    try:
        if file_type == 'key':
            with open("rootCA_key.pem", "rb") as f:
                return serialization.load_pem_private_key(f.read(), None)
    except FileNotFoundError:
        print("Can't find root key file")
        exit(114514)


def generate_csr(common_name):
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    with open("key.pem", "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ))

    csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
        # Provide various details about who we are.
        x509.NameAttribute(NameOID.COUNTRY_NAME, config.COUNTRY_NAME),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, config.STATE_OR_PROVINCE_NAME),
        x509.NameAttribute(NameOID.LOCALITY_NAME, config.LOCALITY_NAME),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, config.ORGANIZATION_NAME),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])).sign(key, hashes.SHA256())
    return csr


def sign_certificate_request(csr_cert, ca_cert, private_ca_key, ext_data):
    cert = x509.CertificateBuilder().subject_name(
        csr_cert.subject
    ).issuer_name(
        ca_cert.issuer
    ).public_key(
        csr_cert.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        # Our certificate will be valid for 10 days
        datetime.datetime.utcnow() + datetime.timedelta(days=10)
        # Sign our certificate with our private key
    ).add_extension(
        x509.SubjectAlternativeName(ext_data),
        critical=False,
        # Sign the CSR with our private key.
    ).sign(private_ca_key, hashes.SHA256())

    # return DER certificate
    with open("cert.crt", "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))


def check_is_ip(data):
    p = re.compile('^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$')
    if p.match(data):
        return True
    else:
        return False


def user_input_alt_name():
    data = []
    count = 0
    common_name = ""
    print("Please enter the domain or ip address you want to create in the cert")
    print("Enter 1 domain or IP address each time, press ENTER to end")

    while True:
        input_data = ""
        input_data = input()

        if count == 0:
            common_name = input_data
            count = count + 1
        if input_data == "":
            break
        if check_is_ip(input_data):
            try:
                data.append(x509.IPAddress(IPv4Address(input_data)))
            except ValueError:
                print("Illegal IP address! Please try again")
        else:
            data.append(x509.DNSName(input_data))
        print("current domain or ipaddress:", end="")
        print(data)
    return common_name, data


def main():
    common_name, ext_data = user_input_alt_name()
    local_csr_cert = generate_csr(common_name)
    local_ca_cert = load_ca_file("cert")
    local_ca_key = load_ca_file("key")
    sign_certificate_request(local_csr_cert, local_ca_cert, local_ca_key, ext_data)


if __name__ == "__main__":
    main()
