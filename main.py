import datetime
import re
import configparser
import os

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from ipaddress import IPv4Address, IPv6Address

config = configparser.ConfigParser()
try:
    with open('config.ini', encoding="utf-8") as f:
        config.read_file(f)
except FileNotFoundError:
    print(
        "config file is missing, please download from "
        "https://raw.githubusercontent.com/NimaQu/EasyRootCA/main/config.ini.example and rename to config.ini")
    exit(114514)


def load_ca_file(file_type):
    try:
        if file_type == 'cert':
            with open(config["general"]["ROOT_CERT_FILE"], "rb") as f:
                return x509.load_pem_x509_certificate(f.read())
    except FileNotFoundError:
        print("Can't find root cert File, it should be called root_cert.crt in the same directory.")
        select = input("Do you want to create root certificate? (y/N)")
        if select == "y" or select == "Y":
            create_root_certificate()
            exit(114514)
        else:
            exit(114514)
    try:
        if file_type == 'key':
            with open(config["general"]["ROOT_KEY_FILE"], "rb") as f:
                return serialization.load_pem_private_key(f.read(), None)
    except FileNotFoundError:
        print("Can't find root key file, it should be called root_cert.cert in the same directory.")
        select = input("Do you want to create root certificate? (y/N)")
        if select == "y" or select == "Y":
            create_root_certificate()
        else:
            exit(114514)


def generate_csr(common_name):
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    try:
        key_path = config["general"]["OUTPUT_PATH"] + "/" + common_name + "/" + common_name + ".pem"
        os.makedirs(os.path.dirname(key_path), exist_ok=True)
        with open(key_path, "wb") as f:
            f.write(key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            ))
    except IOError:
        print("Unable write to file!")
        exit(114514)

    csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
        # Provide various details about who we are.
        x509.NameAttribute(NameOID.COUNTRY_NAME, config["CertInfo"]["COUNTRY_NAME"]),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, config["CertInfo"]["STATE_OR_PROVINCE_NAME"]),
        x509.NameAttribute(NameOID.LOCALITY_NAME, config["CertInfo"]["LOCALITY_NAME"]),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, config["CertInfo"]["ORGANIZATION_NAME"]),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])).sign(key, hashes.SHA256())
    return csr


def sign_certificate_request(ca_cert, private_ca_key, common_name, ext_data):
    csr_cert = generate_csr(common_name)
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
        datetime.datetime.utcnow() + datetime.timedelta(days=int(config["general"]["VALID_DAYS"]))
        # Sign our certificate with our private key
    ).add_extension(
        x509.SubjectAlternativeName(ext_data),
        critical=False,
        # Sign the CSR with our private key.
    ).sign(private_ca_key, hashes.SHA256())

    # return DER certificate
    try:
        cert_path = config["general"]["OUTPUT_PATH"] + "/" + common_name + "/" + common_name + ".crt"
        os.makedirs(os.path.dirname(cert_path), exist_ok=True)
        with open(cert_path, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
    except IOError:
        print("Unable write to file!")
        exit(114514)
    print("Success create new certificate")


def check_is_ip(data):
    p = re.compile(r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$')
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
        input_data = input()
        if count == 0:
            common_name = input_data  # use first domain or ip address as cert CN
            count = count + 1
        if input_data == "":
            break
        if check_is_ip(input_data):
            try:
                data.append(x509.IPAddress(IPv4Address(input_data)))
            except ValueError:
                print("Illegal IP address! Please try again")
        else:
            try:
                data.append(x509.DNSName(input_data))
            except ValueError:
                print("IDN current not supported!, please convert to punycode first")
        print("current domain or ipaddress:", end="")
        print(data)
    common_name = common_name.replace("*", "_")
    return common_name, data


def create_root_certificate():
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    print("You are about to be asked to enter information that will be incorporated\ninto your certificate "
          "request.\nWhat you are about to enter is what is called a Distinguished Name or a DN.\nThere are quite a "
          "few fields but you can leave some blank\nFor some fields there will be a default value,\nIf you enter '.', "
          "the field will be left blank.\n-----")
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, input("Country Name (2 letter code) [AU]:") or "AU"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME,
                           input("State or Province Name (full name) [Some-State]:") or "Some-State"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, input("Locality Name (eg, city):")),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, input(
            "Organization Name (eg, company) [Internet Widgits Pty Ltd]:") or "Internet Widgits Pty Ltd"),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, input("Organizational Unit Name (eg, section):")),
        x509.NameAttribute(NameOID.COMMON_NAME, input("Common Name (e.g. server FQDN or YOUR name):")),
        x509.NameAttribute(NameOID.EMAIL_ADDRESS, input("Email Address:")),
    ])
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        datetime.datetime.utcnow() + datetime.timedelta(days=int(config["general"]["VALID_DAYS"]))
    ).sign(key, hashes.SHA256())
    # Write our certificate out to disk.
    try:
        with open("root_key.pem", "wb") as f:
            f.write(key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            ))

        with open("root_cert.crt", "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
    except IOError:
        print("Unable write to file!")
        exit(114514)
    print("Success create root certificate, now you can run this program again to create user certificates")


def generate_fullchain(common_name):
    with open(config["general"]["OUTPUT_PATH"] + "/" + common_name + "/" + common_name + ".crt", 'r') as f:
        new_cert = f.read()
    with open(config["general"]["ROOT_CERT_FILE"], "r") as f:
        ca_cert = f.read()

    fullchain = new_cert
    fullchain += ca_cert

    with open(config["general"]["OUTPUT_PATH"] + "/" + common_name + "/" + common_name + "_fullchain" + ".crt",
              'w') as f:
        f.write(fullchain)


def main():
    common_name, ext_data = user_input_alt_name()
    sign_certificate_request(load_ca_file("cert"), load_ca_file("key"), common_name, ext_data)
    generate_fullchain(common_name)


if __name__ == "__main__":
    main()
