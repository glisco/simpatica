# -*- coding: utf-8 -*-
#
# simpatiCA - a simple PKI
#
# Copyright (C) 2011 by Michele Comitini <michele.comitini _at_ glisco.it>
# Copyright (C) 2011 by Glisco s.r.l. <info _at_ glisco.it>
#
#     This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
# see LICENSE for licensing info.

import os
import sys

# only local request can access the ca
if request.controller=='ca' and not request.is_local:
    redirect(URL(r=request,c='default',f='index.html'))

# location of CA certificates and secrets (must be well protected)    
ca_base_path=os.path.join(request.folder,'private', 'ssl')

# certificate and key of the ca
ca_certificate_path=os.path.join(ca_base_path,"ca","cacert.pem")
ca_key_path=os.path.join(ca_base_path,"ca-private/cacert.key")
ca_csr_path=os.path.join(ca_base_path,"ca","cacsr.pem")
ca_crt_path=os.path.join(ca_base_path,"ca","cacrt.pem")


# certificate dir (for user certs or server certs)
ca_certs_dir=os.path.join(ca_base_path,"certs")
# encrypted private keys
ca_priv_keys=os.path.join(ca_base_path,"private_keys")


# durata in secondi

def ca_cert_durata():
    return 10*365*24*60*60

# test if dir exists else create

def create_if_not_exists_dir(path):
    if not os.path.exists(path):
        os.makedirs(path, mode=0700)

create_if_not_exists_dir(os.path.dirname(ca_certificate_path))
create_if_not_exists_dir(os.path.dirname(ca_key_path))
create_if_not_exists_dir(ca_certs_dir)
create_if_not_exists_dir(ca_priv_keys)

sys.path.insert(0,os.path.join(request.folder, 'private'))

try:
    from ca_defaults import CA_SUBJECT
except ImportError:
    CA_SUBJECT=dict(C="ZZ",
                ST="XXXXX",
                L="YYYYY",
                O="ACME",
                OU="Certification Authority",
                CN="ACME CA",
                emailAddress="ca@acme.biz")

try:
    from ca_defaults import PKCS12_DOWNLOAD_URL
except ImportError:
    PKCS12_DOWNLOAD_URL = URL(r=request,c='public', f='pkcs12_export', scheme=True)


class IS_RSA_PASS(object):
    def __init__(self, pkey_pem_string=None, pkey_pem_file=None, error_message=T('Password errata')):
        self.pkey_pem_string = None
        self.pkey_pem_file = None
        
        if pkey_pem_string:
            self.pkey_pem_string = pkey_pem_string
        elif not pkey_pem_file:
            raise Exception('Need pkey_pem_string  or pkey_pem_file')
        else:
            self.pkey_pem_file = pkey_pem_file
        self.e = error_message

    def __call__(self, passwd):
        try:
            if self.pkey_pem_string:
                RSA.load_key_string(self.pkey_pem_string, callback=lambda v: passwd)
            else:
                RSA.load_key(self.pkey_pem_file, callback=lambda v: passwd)
        except RSA.RSAError:
            return (passwd, self.e)

        return (passwd, None)




class IS_CA_KEY_PASS(IS_RSA_PASS):
    def __init__(self, error_message=T('Password errata')):
        IS_RSA_PASS.__init__(self, pkey_pem_file=ca_key_path, error_message=error_message)


def ca_key_file_exists():
    return os.path.exists(ca_key_path)

def ca_crt_file_exists():
    return os.path.exists(ca_crt_path)

def ca_csr_file_exists():
    return os.path.exists(ca_csr_path)


CA_KEY_FILE_EXISTS_MSG=T('Key is already present!<br>You must delete it manually.')
CA_CSR_FILE_EXISTS_MSG=T('Certificate request is already present!<br>You must delete it manually.')
CA_CRT_FILE_EXISTS_MSG=T('Certificate is already present!<br>You must delete it manually.')
