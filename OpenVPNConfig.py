#!/bin/env python
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/
from __future__ import division, absolute_import, print_function, unicode_literals
import OpenSSL
import uuid
import random
import os
import json
import subprocess
import sys
if sys.version_info[:1] == (2,):
    input = raw_input

def create_ca(size=2048, valid=315360000, CN=None):
    """
    Creates a CA key and cert

    size - The RSA key size to be used
    valid - The time is seconds the key should be valid for
    CN - The CN to be used for the cert. None will create a UUID
    """
    if CN is None:
        CN = 'CA-'+str(uuid.uuid4())
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
        OpenSSL.crypto.X509Extension(b"basicConstraints", False, b"CA:TRUE"),
        OpenSSL.crypto.X509Extension(b"keyUsage", False, b"keyCertSign, cRLSign"),
        OpenSSL.crypto.X509Extension(b"subjectKeyIdentifier", False, b"hash", subject=ca)
    ])
    ca.add_extensions([
        OpenSSL.crypto.X509Extension(b"authorityKeyIdentifier", False, b"keyid:always",issuer=ca)
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
    CN - The CN to be used for the cert. None will create a UUID
    """
    if CN is None:
        if is_server:
            CN='server-'+str(uuid.uuid4())
        else:
            CN = 'client-'+str(uuid.uuid4())
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
            OpenSSL.crypto.X509Extension(b"basicConstraints", False, b"CA:FALSE"),
            OpenSSL.crypto.X509Extension(b"keyUsage", False, b"digitalSignature,keyEncipherment"),
            OpenSSL.crypto.X509Extension(b"extendedKeyUsage", False, b"serverAuth"),
            OpenSSL.crypto.X509Extension(b"subjectKeyIdentifier", False, b"hash", subject=cert),
            OpenSSL.crypto.X509Extension(b"authorityKeyIdentifier", False, b"keyid:always",issuer=cacert),
            OpenSSL.crypto.X509Extension(b"nsCertType", False, b"server")
        ])
    else:
        cert.add_extensions([
            OpenSSL.crypto.X509Extension(b"basicConstraints", False, b"CA:FALSE"),
            OpenSSL.crypto.X509Extension(b"keyUsage", False, b"digitalSignature"),
            OpenSSL.crypto.X509Extension(b"extendedKeyUsage", False, b"clientAuth"),
            OpenSSL.crypto.X509Extension(b"subjectKeyIdentifier", False, b"hash", subject=cert),
            OpenSSL.crypto.X509Extension(b"authorityKeyIdentifier", False, b"keyid:always",issuer=cacert),
            OpenSSL.crypto.X509Extension(b"nsCertType", False, b"client")
        ])
    cert.sign(cakey, "sha256")
    return cert, key

def gen_dhparams(size=1024):
    """
    Generate Diffie Hellman parameters by calling openssl. Returns a string.

    I don't like doing it like this but pyopenssl doesn't seem to
    have a way to do this natively.

    size - The size of the prime to generate.
    """
    cmd = ['openssl', 'dhparam', '-out', 'dh.tmp', str(size)]
    ret = subprocess.check_call(cmd)
    with open('dh.tmp') as dh:
        params = dh.read()
    os.remove('dh.tmp')
    return params

def gen_tlsauth_key():
    """Generate an openvpn secret key by calling openvpn. Returns a string."""
    cmd = ['openvpn', '--genkey', '--secret', 'ta.tmp']
    ret = subprocess.check_call(cmd)
    with open('ta.tmp') as key:
        key = key.read()
    os.remove('ta.tmp')
    return key

def create_confs(name, confdict, path='.'):
    """
    Creates the client and server configs.

    name - The name of the run which is prepended to the config file names
    confdict - A dictionary representing the config parameters.
    """
    clientfile = open(os.path.join(path, name+'_client.ovpn'), 'w')
    serverfile = open(os.path.join(path, name+'_server.ovpn'), 'w')

    clientfile.write('client\n')
    for key, value in confdict['both'].items():
        if value is False:
            continue
        elif value is True:
            clientfile.write(key + '\n')
            serverfile.write(key + '\n')
        elif isinstance(value, list):
            for v in value:
                clientfile.write(key + ' ' + v + '\n')
                serverfile.write(key + ' ' + v + '\n')
        else:
            clientfile.write(key + ' ' + value + '\n')
            serverfile.write(key + ' ' + value + '\n')

    for key, value in confdict['client'].items():
        if value is False:
            continue
        elif value is True:
            clientfile.write(key + '\n')
        elif isinstance(value, list):
            for v in value:
                clientfile.write(key + ' ' + v + '\n')
        else:
            clientfile.write(key + ' ' + value + '\n')

    for key, value in confdict['server'].items():
        if value is False:
            continue
        elif value is True:
            serverfile.write(key + '\n')
        elif isinstance(value, list):
            for v in value:
                serverfile.write(key + ' ' + v + '\n')
        else:
            serverfile.write(key + ' ' + value + '\n')

    host = str(input("Enter Hostname/IP: ")).rstrip()
    port = str(input("Enter port number: ")).rstrip()
    clientfile.write('remote ' + host + ' ' + port + '\n')
    serverfile.write('port ' + port + '\n')

    cacert, cakey = create_ca()
    servercert, serverkey = create_cert(True, cacert, cakey)
    clientcert, clientkey = create_cert(False, cacert, cakey)

    cacert = OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, cacert).decode('ascii')
    cakey = OpenSSL.crypto.dump_privatekey(OpenSSL.crypto.FILETYPE_PEM, cakey).decode('ascii')
    clientkey = OpenSSL.crypto.dump_privatekey(OpenSSL.crypto.FILETYPE_PEM, clientkey).decode('ascii')
    clientcert = OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, clientcert).decode('ascii')
    serverkey = OpenSSL.crypto.dump_privatekey(OpenSSL.crypto.FILETYPE_PEM, serverkey).decode('ascii')
    servercert = OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, servercert).decode('ascii')

    if 'meta' in confdict:
        if confdict['meta'].get('embedkeys', False):
            clientfile.write('<ca>\n'+cacert+'</ca>\n')
            serverfile.write('<ca>\n'+cacert+'</ca>\n')
            clientfile.write('<key>\n'+clientkey+'</key>\n')
            clientfile.write('<cert>\n'+clientcert+'</cert>\n')
            serverfile.write('<key>\n'+serverkey+'</key>\n')
            serverfile.write('<cert>\n'+servercert+'</cert>\n')
            serverfile.write('<dh>\n'+gen_dhparams()+'</dh>\n')
        if confdict['meta'].get('tls-auth', False):
            serverfile.write('key-direction 0\n')
            clientfile.write('key-direction 1\n')
            auth = gen_tlsauth_key()
            clientfile.write('<tls-auth>\n'+auth+'</tls-auth>\n')
            serverfile.write('<tls-auth>\n'+auth+'</tls-auth>\n')
        if confdict['meta'].get('savecerts', False):
            try:
                with open(name+'_client.cer', 'w') as fileout:
                    fileout.write(clientcert)
            except Exception as e:
                print('Unable to write', name+'_client.cer')
                print(e)
            try:
                with open(name+'_client.key', 'w') as fileout:
                    fileout.write(clientkey)
            except Exception as e:
                print('Unable to write', name+'_client.key')
                print(e)
            try:
                with open(name+'_server.cer', 'w') as fileout:
                    fileout.write(servercert)
            except Exception as e:
                print('Unable to write', name+'_server.cer')
                print(e)
            try:
                with open(name+'_server.key', 'w') as fileout:
                    fileout.write(serverkey)
            except Exception as e:
                print('Unable to write', name+'_server.key')
                print(e)
            try:
                with open(name+'_ca.cer', 'w') as fileout:
                    fileout.write(cacert)
            except Exception as e:
                print('Unable to write', name+'_ca.cer')
                print(e)
            try:
                with open(name+'_ca.key', 'w') as fileout:
                    fileout.write(cakey)
            except Exception as e:
                print('Unable to write', name+'_ca.key')
                print(e)

def _parse_args():
    """Parse command line args"""
    import argparse
    parser = argparse.ArgumentParser(description='Create OpenVPN client/server configs.')
    parser.add_argument('-i', '--interactive', action='store_true', help='Interactively configure templates')
    parser.add_argument('-t', '--template', help='The config file/directory to use', default=os.path.join(os.path.dirname(__file__), 'templates'))

    return parser.parse_args()

def _testing_main():
    """Temporary while testing key creation"""
    args = _parse_args()
    with open(os.path.join(args.template,'basic.json')) as fh:
        conf = json.load(fh)
    create_confs("test", conf)
    #basic_pki("keys")

def _ask_template(templates):
    """Prompts user for the template to use"""
    i = 1
    print('Which template would you like to use?')
    for template in templates:
        print(i, ') ', template['meta']['name'], ': ', template['meta']['description'],sep='')
        i += 1
    ret = int(input('Enter selection: '))
    while ret <= 0 or ret > i-1:
        ret = int(input('Enter selection: '))
    return templates[ret-1]

def _ask_interactive():
    conf_changes = {'meta': {}, 'client': {}, 'server': {}}
    ret = input('Would you like to allow more then one client to connect with the same config at the same time? [Y/n]: ').lower()
    if ret == 'n':
        conf_changes['server']['duplicate-cn'] = False
    else:
        conf_changes['server']['duplicate-cn'] = True

    return conf_changes

def main():
    args = _parse_args()

    # Read in configs
    confs = []
    if os.path.isdir(args.template):
        list = os.listdir(args.template)
        for f in list:
            f = os.path.join(args.template, f)
            if os.path.isfile(f):
                with open(f, 'r') as fh:
                    try:
                        data = json.loads(fh.read())
                    except Exception as e:
                        print('WARNING:', f, 'is not valid json.', e, file=sys.stderr)
                        continue
                if 'meta' in data:
                    if 'name' not in data['meta']:
                        data['meta']['name'] = f
                    if 'description' not in data['meta']:
                        data['meta']['description'] = ''
                confs.append(data)

    else:
        with open(args.template, 'r') as fh:
            try:
                confs.append(json.loads(fh.readall()))
            except Exception as e:
                print('WARNING:', args.template, 'is not valid json.', e, file=sys.stderr)

    if len(confs) == 0:
        print('ERROR: No valid templates to use', file=sys.stderr)
        exit(-1)
    elif len(confs) == 1:
        template = confs[0]
    else:
        template = _ask_template(confs)

    name = input('Enter a name for the configs: ')
    if args.interactive:
        updates = _ask_interactive()
        for key in updates:
            template[key].update(updates[key])
    create_confs(name, template)

if __name__ == "__main__":
    main()
