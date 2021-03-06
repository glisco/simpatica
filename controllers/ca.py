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

#
# Action related to the CA part of the PKI
#

from M2Crypto import X509, RSA, EVP
from certgen import *

def index():
    return dict()


def create_ca_key():
    if ca_key_file_exists():
        session.flash=CA_KEY_FILE_EXISTS_MSG
        redirect(URL('index.html'))
    form = SQLFORM.factory(
        Field('bitnum','integer',
              requires=IS_IN_SET([2048,4096,8192]),
              notnull=True,
              label=T('Key length in bits')),
        Field('password','password',
              requires=IS_NOT_EMPTY(),
              label=T('Password')),
        Field('password_again','password',
              requires=IS_EQUAL_TO(request.vars.password),
              label=T('Password verification')))

    if form.process().accepted:
        pkey = createKeyPair(form.vars.bitnum)
        pkey.save_key(ca_key_path, callback=lambda x: form.vars.password)
        redirect(URL(f='display',args=['key']))
    return dict(form=form)

def display():
    """
    Display ca items
    args can be:
    - key
    - cert
    - csr
    - crt
    """

    item = request.args and request.args[0]


    if item == 'key':
        ca_key_file = None
        title = T('Chiave Privata della CA')
        try:
            ca_key_file = open(ca_key_path, 'r')
            content = ca_key_file.read()
        except IOError, e:
            content = T('File %s cannot be opened.', ca_key_file)
            response.flash = T('Error reading key.')
        finally:
            if ca_key_file:
                ca_key_file.close()
                
    elif item == 'csr':
        ca_csr_file = None
        title = T('CA Certificate Request')
        try:
            ca_csr_file = open(ca_csr_path, 'r')
            content = ca_csr_file.read()
        except IOError, e:
            content = T('File %s cannot be opened.', ca_csr_path)
            response.flash = T('Error reading request.')
        finally:
            if ca_csr_file:
                ca_csr_file.close()

    elif item == 'crt':
        ca_crt_file = None
        title = T('CA certificate (self signed cert)')
        try:
            ca_crt_file = open(ca_crt_path, 'r')
            content = ca_crt_file.read()
        except IOError, e:
            content = T('File %s cannot be opened.', ca_crt_path)
            response.flash = T('Error reading certificate.')
        finally:
            if ca_crt_file:
                ca_crt_file.close()

    return dict(content=content, title=title)
            

def create_ca_csr():
    """
    Create a certificate singing request with the ca key.
    """


    errmsg=None
    form = SQLFORM.factory(
        Field('password', 'password', label=T('Private key password')))

    if form.process().accepted:
        try:
            ca_key_file = open(ca_key_path, 'r')
            key = ca_key_file.read()
        except IOError, e:
            errmsg = T('File %s cannot be opened.', ca_key_file)
            response.flash = T('Error reading key.')
            return dict(form=None, errmsg=errmsg)
        finally:
            if ca_key_file:
                ca_key_file.close()

        pkey=RSA.load_key_string(key, lambda x: form.vars.password)
        csr = createCertRequest(pkey, **CA_SUBJECT)

        try:
            csr.save(ca_csr_path)
        except IOError, e:
            errmsg = T('File %s cannot be opened.', csr_file)
            response.flash = T('Error writing certificate request')
            return dict(form=None, errmsg=errmsg)


        redirect(URL('display', args=['csr']))
        
        
    return dict(form=form,errmsg=errmsg)
    

def create_self_signed_cert():
    """
    Create a self signed certificate  with the ca key from the ca csr.
    """


    errmsg=None
    form = SQLFORM.factory(
        Field('password', 'password', label=T('Private key password')))

    if form.process().accepted:
        try:
            ca_key_file = open(ca_key_path, 'r')
            key = ca_key_file.read()
        except IOError, e:
            errmsg = T('File %s cannot be opened.', ca_key_file)
            response.flash = T('Error reading key.')
            return dict(form=None, errmsg=errmsg)
        finally:
            if ca_key_file:
                ca_key_file.close()

        pkey=RSA.load_key_string(key, lambda x: form.vars.password)

        try:
            csr_file=open(ca_csr_path, 'r')

            csr = csr_file.read()
        except IOError, e:
            errmsg = T('File %s cannot be opened.', csr_file)
            response.flash = T('Error reading request.')
            return dict(form=None, errmsg=errmsg)

        finally:
            if csr_file:
                csr_file.close()

        req = X509.load_request_string(csr)

        extensions=[]
        # Set type of cert
        extensions.append(X509.new_extension('basicConstraints','CA:true,pathlen:1',critical=True))
        extensions.append(X509.new_extension('keyUsage','keyCertSign',critical=True))

        crt = createCertificate(req, (req, pkey), 0, (0,ca_cert_durata()), extensions=extensions)

        try:
            crt.save(ca_crt_path)
        except IOError, e:
            errmsg = T('File %s cannot be opened.', crt_file)
            response.flash = T('Error writing certificate request')
            return dict(form=None, errmsg=errmsg)


        redirect(URL('display', args=['crt']))
        
        
    return dict(form=form,errmsg=errmsg)



def list_requests():
    import base64
    
    db.ca_user_data.id.represent = lambda x: base64.urlsafe_b64encode('00%s' % x)
    db.ca_user_data.modified_on.represent = prettydate
    rows = db((db.ca_user_data.id > 0) &
              (db.ca_user_data.id==db.ca_user_cert.ca_user_data_id) &
              (db.ca_user_cert.certificate==None) &
              (db.ca_user_cert.revoked==False))\
              .select(db.ca_user_cert.id,
                      db.ca_user_data.CN,
                      db.ca_user_data.emailAddress,
                      db.ca_user_cert.modified_on)
                      
    return dict(rows=rows)


def list_certs():
    import base64

    db.ca_user_cert.revoked.represent = lambda revoked, row:\
                                        IMG(_src=URL('static', 'images/error.png' if revoked else 'images/ok.png'))
    db.ca_user_cert.revoked.label = T('Valid')

    db.ca_user_data.modified_on.represent = prettydate
    rows = db((db.ca_user_data.id > 0) &
              (db.ca_user_data.id==db.ca_user_cert.ca_user_data_id) &
              (db.ca_user_cert.certificate!=None))\
              .select(db.ca_user_cert.id,
                      db.ca_user_cert.revoked,
                      db.ca_user_data.CN,
                      db.ca_user_data.emailAddress,
                      db.ca_user_cert.modified_on)
    return dict(rows=rows)

def sign_user_cert():
    id = int(request.args[0])

    form = SQLFORM.factory(
        Field('password','password', label=T('Password CA private key'), requires=IS_CA_KEY_PASS()),
        Field('duration_years', 'integer', label=T('Duration in years'), default=3, requires=IS_INT_IN_RANGE(1, 100), required=True),
        Field('key_usage', 'string', requires=IS_IN_SET(['clientAuth', 'serverAuth']), required=True, notnull=True))

    if form.process().accepted:
        ca_user_cert = db.ca_user_cert[id]
        req = X509.load_request_string(ca_user_cert.certificate_request)
        ca_pkey = RSA.load_key(ca_key_path, lambda x: form.vars.password)
        ca_x509 = X509.load_cert(ca_crt_path)

        extensions = list()
        extensions.append(X509.new_extension('keyUsage',form.vars.key_usage))

        #cert_id=db.ca_user_cert.insert(ca_user_data_id=id)
        cert = createCertificate(req, (ca_x509, ca_pkey), id, (0, (365*24*60*60)*form.vars.duration_years), extensions=extensions)

        ca_user_cert.update_record(certificate=cert.as_pem())

        ca_user_data=db.ca_user_data[ca_user_cert.ca_user_data_id]
        mail_dest=ca_user_data.emailAddress
        mail.settings.sender=cert_administrator
        mail_text = mail_message_accepted % {'cn': ca_user_data['CN'],
                                             'ca_mail': cert_administrator,
                                             'pkcs12_url': "%s/%s" % (PKCS12_DOWNLOAD_URL, id)}
        mail.send(mail_dest,
                  subject=T('Certificate available'),
                  message=mail_text)


        session.flash=T('Certificate issued')
        redirect(URL(c='public', f='display', args=['crt',id]))
        
    return dict(form=form)


def revoke_cert():
    id = request.args(0)

    if id:
        cert_row=db.ca_user_cert(int(id))
        cert_row.update_record(revoked=True)

    session.flash=T('Certificate has been revoked!')

    return redirect(URL('public', 'display', args=['crt', id]))
