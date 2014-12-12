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

def gen_dhparams(size=1024):
	cmd = ['openssl', 'dhparam', '-out', 'dh.tmp', str(size)]
	ret = subprocess.check_call(cmd)
	if ret != 0:
		raise SystemError("OpenSSL failed...")
	with open('dh.tmp') as dh:
		params = dh.read()
	os.remove('dh.tmp')
	return params

def gen_tlsauth_key():
	cmd = ['openvpn', '--genkey', '--secret', 'ta.tmp']
	ret = subprocess.check_call(cmd)
	if ret != 0:
		raise SystemError("OpenVPN failed...")
	with open('ta.tmp') as key:
		key = key.read()
	os.remove('ta.tmp')
	return key

def create_confs(name, confdict, path='.'):
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

	host = raw_input("Enter Hostname/IP: ").rstrip()
	port = raw_input("Enter port number: ").rstrip()
	clientfile.write('remote ' + host + ' ' + port + '\n')
	serverfile.write('port ' + port + '\n')

	cacert, cakey = create_ca()
	servercert, serverkey = create_cert(True, cacert, cakey)
	clientcert, clientkey = create_cert(False, cacert, cakey)

	cacert = OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, cacert)
	clientkey = OpenSSL.crypto.dump_privatekey(OpenSSL.crypto.FILETYPE_PEM, clientkey)
	clientcert = OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, clientcert)
	serverkey = OpenSSL.crypto.dump_privatekey(OpenSSL.crypto.FILETYPE_PEM, serverkey)
	servercert = OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, servercert)

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

def _parse_args():
	"""Parse command line args"""
	import argparse
	parser = argparse.ArgumentParser(description='Create OpenVPN client/server configs.')
	parser.add_argument('-i', '--interactive', action='store_true', help='Interactively configure templates')
	parser.add_argument('-t', '--templates', help='The config file/directory to use', default=os.path.join(os.path.dirname(__file__), 'templates'))

	return parser.parse_args()

if __name__ == "__main__":
	args = _parse_args()
	with open(os.path.join(args.templates,'basic.json')) as fh:
		conf = json.load(fh)
	create_confs("test", conf)
	#basic_pki("keys")
