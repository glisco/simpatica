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

from gluon.utils import uuid

db.define_table('ca_user_data',
                Field('uuid', length=64, default=lambda:str(uuid.uuid4()), readable=False, writable=False),
                Field('modified_on', 'datetime', default=request.now, writable=False, readable=False),
                Field('key_pem', 'text', readable=False, writable=False), #user private key pem encoded and ciphered with user supplied password
                Field('key_ca_encrypted_pem', 'text', readable=False, writable=False), #user private key encrypted with 256 bit shared secret.
                Field('ca_rsa_encrypted_secret', readable=False, writable=False), # the shared secret used for encrypting the user private key is encrypted in turn using RSA public key from CA certificate. This way the CA can recover private keys yet keeping security high.
                Field('ST', 'string', label=T('State')),
                Field('L', 'string', label=T('City')),
                Field('O', 'string', label=T('Organization'), writable=False),
                Field('OU', 'string', label=T('Organizational Unit')),
                Field('CN', 'string', label=T('Common Name'), requires=IS_NOT_IN_DB(db, 'ca_user_data.CN'), unique=True, notnull=True, required=True),
                Field('GN', 'string', label=T('Given Name'), requires=IS_NOT_IN_DB(db, 'ca_user_data.CN')),
                Field('SN', 'string', label=T('Surname'), requires=IS_NOT_IN_DB(db, 'ca_user_data.CN')),
                Field('emailAddress', 'string',
                      label=T('Email Address'),
                      unique=True,
                      required=True,
                      requires=[IS_NOT_IN_DB(db,'ca_user_data.emailAddress'),IS_EMAIL(error_message=T('Invalid Email Address!'))],
                      default=''),)


# assign default values from ca data
ca_user_fields = list(db.ca_user_data.fields)
# but do not touch CN
try:
    ca_user_fields.remove('CN')
    ca_user_fields.remove('emailAddress')
except ValueError:
    pass

for k,v in CA_SUBJECT.items():
     if k in ca_user_fields:
        db.ca_user_data[k].default=v


db.define_table('ca_user_cert',
                Field('uuid', length=64, default=lambda:str(uuid.uuid4()), readable=False, writable=False),
                Field('modified_on', 'datetime', default=request.now, writable=False, readable=False),
                Field('ca_user_data_id',db.ca_user_data),
                Field('certificate', 'text',
                      label=T('Certificato firmato dalla CA'),
                      writable=False),
                Field('certificate_request', 'text',
                      label=T('Certificate Request'),
                      writable=False),
                Field('revoked', 'boolean', default=False))



###
# Helper function to create a server side key + csr
###

def create_key_csr(csr_data):
    data_id = db.ca_user_data.insert(
        **db.ca_user_data._filter_fields(csr_data))
    pkey = createKeyPair(int(csr_data['bitnum']))

    # user private key encrypted with user secret
    key_pem = pkey.as_pem(callback=lambda x: str(csr_data['password']))
    db.ca_user_data[data_id].update_record(key_pem = key_pem)
    
    # generate a random shared secret 32 bytes log
    rnd_key=Rand.rand_bytes(32)
    # encrypt the user's private key with the random secret
    enc_pem_key = pkey.as_pem(callback=lambda x: rnd_key)
    db.ca_user_data[data_id].update_record(key_ca_encrypted_pem =  enc_pem_key)
    # encrypt the shared secret with RSA using CA public key
    # this will allow the recovery of the private key using CA private key
    ca_cert = X509.load_cert(ca_crt_path)
    ca_pub_key = ca_cert.get_pubkey().get_rsa()
    # save in db the encrypted random key in base64 encoding
    db.ca_user_data[data_id].update_record(ca_rsa_encrypted_secret = base64.b64encode(ca_pub_key.public_encrypt(rnd_key, RSA.pkcs1_oaep_padding)))

    # filter the subject components

    name_entries = CA_SUBJECT.copy()

    name_entries.update(dict(filter(lambda x: X509.X509_Name.nid.has_key(x[0]), map(lambda y: (str(y[0]),str(y[1])),csr_data.iteritems()))))
        

        
    # now generate the certificate request
    req = createCertRequest(pkey, **name_entries)
    
    cert_id=db.ca_user_cert.insert(ca_user_data_id=data_id, certificate_request = req.as_pem())
    
    # send mail to administrator
    
    mail.settings.sender=cert_administrator
    mail_text = mail_message % {'cn': csr_data['CN']}
    mail.send(cert_administrator,
              subject=T('New certificate request'),
              message=mail_text)


    return cert_id
