#!/bin/env python
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/
from __future__ import division, absolute_import, print_function#, unicode_literals
import OpenSSL
import uuid
import random
import os
import json

def create_ca(size=2048, valid=315360000, CN=None):
    """
    Creates a CA key and cert

    size - The RSA key size to be used
    valid - The time is seconds the key should be valid for
    CN - The CN to be used for the cert
    """
    if CN is None:
        CN = str(uuid.uuid4())
    key = OpenSSL.crypto.PKey()
    key.generate_key(OpenSSL.crypto.TYPE_RSA, size)

    ca = OpenSSL.crypto.X509()
    ca.set_version(2)
    #ca.set_serial_number(1)
    ca.get_subject().CN = CN
    ca.gmtime_adj_notBefore(0)
    ca.gmtime_adj_notAfter(valid)
    ca.set_issuer(ca.get_subject())
    ca.set_pubkey(key)
    ca.add_extensions([
        OpenSSL.crypto.X509Extension("basicConstraints", False, "CA:TRUE"),
        OpenSSL.crypto.X509Extension("keyUsage", False, "keyCertSign, cRLSign"),
        OpenSSL.crypto.X509Extension("subjectKeyIdentifier", False, "hash", subject=ca)
    ])
    ca.add_extensions([
        OpenSSL.crypto.X509Extension("authorityKeyIdentifier", False, "keyid:always",issuer=ca)
    ])
    ca.sign(key, "sha256")
    return ca, key


def create_cert(is_server, cacert, cakey, size=2048, valid=315360000, CN=None):
    """
    Creates a client/server key and cert

    is_server - Must be True for a server, False for a client
    cacert - The OpenSSL.crypto.X509 object of the CA
    cakey - The OpenSSL.crypto.PKey object of the CA

    Optional:
    size - The RSA key size to be used
    valid - The time is seconds the key should be valid for
    CN - The CN to be used for the cert
    """
    if CN is None:
        CN = str(uuid.uuid4())
    key = OpenSSL.crypto.PKey()
    key.generate_key(OpenSSL.crypto.TYPE_RSA, size)

    cert = OpenSSL.crypto.X509()
    cert.set_version(2)
    cert.set_serial_number(random.randint(1, 99999999))
    cert.get_subject().CN = CN
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(valid)
    cert.set_issuer(cacert.get_subject())
    cert.set_pubkey(key)
    if is_server:
        cert.add_extensions([
            OpenSSL.crypto.X509Extension("basicConstraints", False, "CA:FALSE"),
            OpenSSL.crypto.X509Extension("keyUsage", False, "digitalSignature, keyEncipherment"),
            OpenSSL.crypto.X509Extension("extendedKeyUsage", False, "serverAuth"),
            OpenSSL.crypto.X509Extension("subjectKeyIdentifier", False, "hash", subject=cert),
            OpenSSL.crypto.X509Extension("authorityKeyIdentifier", False, "keyid:always",issuer=cacert)
        ])
    else:
        cert.add_extensions([
            OpenSSL.crypto.X509Extension("basicConstraints", False, "CA:FALSE"),
            OpenSSL.crypto.X509Extension("keyUsage", False, "digitalSignature"),
            OpenSSL.crypto.X509Extension("extendedKeyUsage", False, "clientAuth"),
            OpenSSL.crypto.X509Extension("subjectKeyIdentifier", False, "hash", subject=cert),
            OpenSSL.crypto.X509Extension("authorityKeyIdentifier", False, "keyid:always",issuer=cacert)
        ])
    cert.sign(cakey, "sha256")
    return cert, key


def create_conf(json_config, cacert, cert, key, path):
    fhandle = open(path, 'w')
    for key, value in json_config.items():
        if value is False:
            continue
        elif value is True:
            fhandle.write(key + '\n')
        else:
            fhandle.write(key + ' ' + value + '\n')

def basic_pki(path):
    if not os.path.isdir(path):
        os.mkdir(path)
    cacert, cakey = create_ca()
    with open(os.path.join(path, "ca.crt"), "w") as fhandle:
        fhandle.write(OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, cacert))
    clientcert, clientkey = create_cert(False, cacert, cakey)
    with open(os.path.join(path, "client.crt"), "w") as fhandle:
        fhandle.write(OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, clientcert))
    with open(os.path.join(path, "client.key"), "w") as fhandle:
        fhandle.write(OpenSSL.crypto.dump_privatekey(OpenSSL.crypto.FILETYPE_PEM, clientkey))

if __name__ == "__main__":
    basic_pki("keys")

