# -*- coding: latin-1 -*-
#
# Copyright (C) AB Strakt
# Copyright (C) Jean-Paul Calderone
# See LICENSE for details.
#
# Changes:
# - Michele Comitini (michele_dot_comitini_at_gmail_dot_com): ported to M2Crypto

"""
Certificate generation module.
"""

from M2Crypto import X509, RSA, ASN1, EVP
from datetime import datetime, timedelta

def createKeyPair(bits):
    """
    Create a public/private key pair.

    Arguments: type - Key type, must be one of TYPE_RSA and TYPE_DSA
               bits - Number of bits to use in the key
    Returns:   The public/private key pair in a PKey object
    """
    pkey = RSA.gen_key(int(bits), 65537, lambda x: None)
    return pkey

def createCertRequest(pkey, digest="md5", **name):
    """
    Create a certificate request.

    Arguments: pkey   - The key to associate with the request
               digest - Digestion method to use for signing, default is md5
               **name - The name of the subject of the request, possible
                        arguments are:
                          C     - Country name
                          ST    - State or province name
                          L     - Locality name
                          O     - Organization name
                          OU    - Organizational unit name
                          CN    - Common name
                          emailAddress - E-mail address
    Returns:   The certificate request in an X509Req object
    """
    req = X509.Request()
    subj = X509.X509_Name()
    
    for (key,value) in name.items():
        subj.add_entry_by_txt(key, ASN1.MBSTRING_ASC, entry=value, len=-1, loc=-1,set=0)

    req.set_subject(subj)
    evp_key = EVP.PKey(md=digest)
    evp_key.assign_rsa(pkey)
    req.set_pubkey(evp_key)
    req.sign(evp_key, md=digest)
    return req

def createCertificate(req, (issuerCert, issuerKey), serial, (notBefore, notAfter), digest="md5", extensions=[]):
    """
    Generate a certificate given a certificate request.

    Arguments: req        - Certificate reqeust to use
               issuerCert - The certificate of the issuer
               issuerKey  - The private key of the issuer
               serial     - Serial number for the certificate
               notBefore  - Timestamp (relative to now) when the certificate
                            starts being valid
               notAfter   - Timestamp (relative to now) when the certificate
                            stops being valid
               digest     - Digest method to use for signing, default is md5
               extensions - a list of X509Extension instances
    Returns:   The signed certificate in an X509 object
    """
    cert = X509.X509()
    cert.set_serial_number(serial)
    asn1_time_before = ASN1.ASN1_UTCTIME()
    asn1_time_before.set_datetime(datetime.utcnow() + timedelta(seconds=notBefore))
    cert.set_not_before(asn1_time_before)
    asn1_time_after = ASN1.ASN1_UTCTIME()
    asn1_time_after.set_datetime(datetime.utcnow() + timedelta(seconds=notAfter))
    cert.set_not_after(asn1_time_after)
    cert.set_issuer(issuerCert.get_subject())
    cert.set_subject(req.get_subject())
    for ext in extensions:
        cert.add_ext(ext)
    evp_key = EVP.PKey(md=digest)
    evp_key.assign_rsa(issuerKey)
    cert.set_pubkey(req.get_pubkey())
    cert.sign(evp_key, md=digest)
    return cert

