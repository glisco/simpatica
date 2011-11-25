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
# Action related to the public part of the PKI
#

import OpenSSL
from certgen import *
from M2Crypto import X509, ASN1, Rand, EVP, RSA
import base64
from gluon.streamer import streamer

def index():
    return dict()

def create_csr():
    """
    Create a private key and a signed csr.
    There are 2 ways to create keys:
    - server side.
    - browser side.

    At the moment only server side is implemented.
    """
    

    db.ca_user_cert.certificate_request.readable=False
    form = SQLFORM.factory(db.ca_user_data,
        Field('bitnum','integer',
              requires=IS_IN_SET([2048,4096,8192]),
              notnull=True,
              label=T('Key length in bits')),
        Field('password','password',
              requires=IS_STRONG(min=8, upper=1, special=1),
              label=T('Password')),
        Field('password_again','password',
              requires=IS_EQUAL_TO(request.vars.password),
              label=T('Password verification')))

    csr_data = form.vars
    
    if form.process().accepted:
        data_id = create_key_csr(csr_data)
        redirect(URL(f='display', args=['csr',data_id]))

    return dict(form=form)

def display():
    item=request.args[0]
    record_id = request.args[1]
    if item == 'csr' and record_id:
        rec = db.ca_user_cert[record_id]
        content = rec.certificate_request
        req = X509.load_request_string(content)
        title=XML(T('Certificate Request for  %s',  PRE(req.get_subject())))

    elif item=='crt' and record_id:
        rec = db.ca_user_cert[record_id]
        content = rec.certificate
        cert = X509.load_cert_string(content)
        title=XML(T('Certificate owned by %s',  PRE(cert.get_subject())))
    return dict(content=content, title=title)


def pkcs12_export():
    '''
    Download a pkcs12 armored x509cert and relative private key.
    TODO: Handle browsers with crypto library like firefox.
    '''
    from OpenSSL import crypto
    from StringIO import StringIO
    from gluon.streamer import streamer
    
    id = request.args(0)

    r = db(db.ca_user_cert.id==id).select(db.ca_user_data.key_pem, db.ca_user_cert.certificate,join=[db.ca_user_cert.on(db.ca_user_data.id==db.ca_user_cert.ca_user_data_id)]).first()
    cert_pem = r.ca_user_cert.certificate
    pkey_pem = r.ca_user_data.key_pem
    ca_cert_pem = open(ca_crt_path, 'r').read()
    
    form = SQLFORM.factory(Field('password','password', label=T('Private key password'), requires=IS_RSA_PASS(pkey_pem_string=pkey_pem)),)

    if form.process().accepted:
        pkey = crypto.load_privatekey(crypto.FILETYPE_PEM, pkey_pem, form.vars.password)
        cert = crypto.load_certificate(crypto.FILETYPE_PEM, cert_pem)
        ca_cert = crypto.load_certificate(crypto.FILETYPE_PEM, ca_cert_pem)

        pkcs12 = crypto.PKCS12()

        pkcs12.set_ca_certificates([ca_cert])
        pkcs12.set_certificate(cert)
        pkcs12.set_privatekey(pkey)


        response.headers['Content-Type'] = 'application/pkcs-12'
        response.headers['Content-Disposition'] = 'attachment; filename=cert.p12'

        data = pkcs12.export(passphrase=form.vars.password)
        stream = StringIO(data)

        return streamer(stream, len(data))


    return dict(form=form)

def call():
    """
    exposes services. for example:
    http://..../[app]/default/call/jsonrpc
    decorate with @services.jsonrpc the functions to expose
    supports xml, json, xmlrpc, jsonrpc, amfrpc, rss, csv
    """
    return service()


@service.jsonrpc
def csr_remote_service(data):
    # check that the channel is secure!! [copied from admin app]
    if request.env.http_x_forwarded_for or request.is_https:
        session.secure()
    elif not request.is_local:
        raise HTTP(200, T('Disabled because insecure channel'))

    data_id=create_key_csr(data)

    #return the URL where the data can be displayed
    return dict(url=URL(f='display', args=['csr',data_id]))

    
def get_ca_cert():
    """
    Return the CA certificate
    """


    response.headers['Content-Type'] = 'application/x-x509-ca-cert'
    response.headers['Content-Disposition'] = 'attachment; filename=cacert.pem'


    try:
        stream = open(ca_crt_path, 'r')
    except IOError:
        session.flash=T('CA needs setup')
        redirect(URL('index.html'))
    return streamer(stream)



def get_ca_crl():
    """
    Select all certificates that are not valid and make a big pem
    """
    ###TODO
    
    return
