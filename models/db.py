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




db = DAL('sqlite://storage.sqlite')

# by default give a view/generic.extension to all actions from localhost
# none otherwise. a pattern can be 'controller/function.extension'
response.generic_patterns = ['*'] if request.is_local else []


from gluon.tools import Mail, Auth, Crud, Service, PluginManager, prettydate
mail = Mail()                                  # mailer
auth = Auth(db)                                # authentication/authorization
crud = Crud(db)                                # for CRUD helpers using auth
service = Service()                            # for json, xml, jsonrpc, xmlrpc, amfrpc
plugins = PluginManager()                      # for configuring plugins

mail.settings.server = 'logging' or 'smtp.gmail.com:587'  # your SMTP server
mail.settings.sender = 'you@gmail.com'         # your email
mail.settings.login = 'username:password'      # your credentials or None

auth.settings.hmac_key = 'sha512:6ac5e63e-3a93-42d4-9b6e-661882692a33'   # before define_tables()
auth.define_tables()                           # creates all needed tables
auth.settings.mailer = mail                    # for user email verification
auth.settings.registration_requires_verification = False
auth.settings.registration_requires_approval = False
auth.messages.verify_email = 'Click on the link http://'+request.env.http_host+URL('default','user',args=['verify_email'])+'/%(key)s to verify your email'
auth.settings.reset_password_requires_verification = True
auth.messages.reset_password = 'Click on the link http://'+request.env.http_host+URL('default','user',args=['reset_password'])+'/%(key)s to reset your password'


mail_message="""E' arrivata una richiesta per un certificato X509 da parte dell'utente: %(cn)s"""

mail_message_accepted="""
La Certification Authority di Mediofimaa ha approvato la richiesta di certificazione x509 effettuata dall'utente: %(cn)s

È possibile scaricare il certificato al seguente indirizzo:

%(pkcs12_url)s

Che andrà installato come certificato personale nel browser web, la password richiesta è la stessa utilizzata al momento della richiesta di registrazione.

Per eventuali problemi contattare la Certification Authority di Mediofimaa %(ca_mail)s

Cordiali Saluti,
Mediofimaa Certification Authority

----

Mediofimaa Certification Authority
email: %(ca_mail)s

"""

cert_administrator=r"ca@mediofimaa.com"

