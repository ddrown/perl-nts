#define PERL_NO_GET_CONTEXT
#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

#include <aes_siv.h>

MODULE = NTP::NTSKE    PACKAGE = NTP::NTSKE::AES_SIV   PREFIX = AES_SIV

PROTOTYPES: ENABLE

int
AES_SIVVersion()
    CODE:
    RETVAL = LIBAES_SIV_VERSION;
    OUTPUT:
    RETVAL

AES_SIV_CTX *
AES_SIV_CTX_new()
    CODE:
    RETVAL = AES_SIV_CTX_new();
    if(!RETVAL) croak("out of memory");
    OUTPUT:
    RETVAL

void
AES_SIV_CTX_copy(dst, src)
    AES_SIV_CTX *dst
    AES_SIV_CTX const *src

void
AES_SIV_CTX_cleanup(ctx)
    AES_SIV_CTX *ctx

void
AES_SIV_CTX_free(ctx)
    AES_SIV_CTX *ctx

int
AES_SIV_Init(ctx, key)
    AES_SIV_CTX *ctx
    PREINIT:
    STRLEN keylen;
    INPUT:
    unsigned char *key = (unsigned char *)SvPV(ST(1), keylen);
    CODE:
    RETVAL = AES_SIV_Init(ctx, key, keylen);
    OUTPUT:
    RETVAL

int
AES_SIV_AssociateData(ctx, data)
    AES_SIV_CTX *ctx
    PREINIT:
    STRLEN datalen;
    INPUT:
    unsigned char *data = (unsigned char *)SvPV(ST(1), datalen);
    CODE:
    RETVAL = AES_SIV_AssociateData(ctx, data, datalen);
    OUTPUT:
    RETVAL

void
AES_SIV_Encrypt(ctx, key, nonce, plaintext, ad)
    AES_SIV_CTX *ctx
    PREINIT:
    STRLEN keylen = 0, noncelen = 0, plaintextlen = 0, adlen = 0, outlen = 0;
    unsigned char *out;
    int status;
    INPUT:
    unsigned char *key = NULL;
    unsigned char *nonce = NULL;
    unsigned char *plaintext = NULL;
    unsigned char *ad = NULL; 
    PPCODE:
    if(SvOK(ST(1)))
      key = (unsigned char *)SvPV(ST(1), keylen);
    if(SvOK(ST(2)))
      nonce = (unsigned char *)SvPV(ST(2), noncelen);
    if(SvOK(ST(3)))
      plaintext = (unsigned char *)SvPV(ST(3), plaintextlen);
    if(SvOK(ST(4)))
      ad = (unsigned char *)SvPV(ST(4), adlen);

    outlen = plaintextlen + 16;
    Newx(out,outlen,unsigned char);
    if(!out) croak("out of memory");

    status = AES_SIV_Encrypt(ctx, out, &outlen, key, keylen, nonce, noncelen, plaintext, plaintextlen, ad, adlen);
    XPUSHs(sv_2mortal(newSViv(status)));
    XPUSHs(sv_2mortal(newSVpv((char *)out, outlen)));

void
AES_SIV_Decrypt(ctx, key, nonce, ciphertext, ad)
    AES_SIV_CTX *ctx
    PREINIT:
    STRLEN keylen = 0, noncelen = 0, ciphertextlen = 0, adlen = 0, outlen = 0;
    unsigned char *out;
    int status;
    INPUT:
    unsigned char *key = NULL;
    unsigned char *nonce = NULL;
    unsigned char *ciphertext = NULL;
    unsigned char *ad = NULL;
    PPCODE:

    if(SvOK(ST(1)))
      key = (unsigned char *)SvPV(ST(1), keylen);
    if(SvOK(ST(2)))
      nonce = (unsigned char *)SvPV(ST(2), noncelen);
    if(SvOK(ST(3)))
      ciphertext = (unsigned char *)SvPV(ST(3), ciphertextlen);
    if(SvOK(ST(4)))
      ad = (unsigned char *)SvPV(ST(4), adlen);

    outlen = ciphertextlen + 16;
    Newx(out,outlen,unsigned char);
    if(!out) croak("out of memory");

    status = AES_SIV_Decrypt(ctx, out, &outlen, key, keylen, nonce, noncelen, ciphertext, ciphertextlen, ad, adlen);
    XPUSHs(sv_2mortal(newSViv(status)));
    XPUSHs(sv_2mortal(newSVpv((char *)out, outlen)));

void
AES_SIV_EncryptFinal(ctx, plaintext)
    AES_SIV_CTX *ctx
    PREINIT:
    STRLEN plaintextlen = 0, enc_outlen = 0, iv_outlen = 0;
    unsigned char *enc_out, *iv_out;
    int status;
    INPUT:
    unsigned char *plaintext = NULL;
    PPCODE:
    if(SvOK(ST(1)))
      plaintext = (unsigned char *)SvPV(ST(1), plaintextlen);

    enc_outlen = plaintextlen;
    Newx(enc_out,enc_outlen,unsigned char);
    if(!enc_out) croak("out of memory");
    iv_outlen = 16;
    Newx(iv_out,iv_outlen,unsigned char);
    if(!iv_out) croak("out of memory");

    status = AES_SIV_EncryptFinal(ctx, iv_out, enc_out, plaintext, plaintextlen);
    XPUSHs(sv_2mortal(newSViv(status)));
    XPUSHs(sv_2mortal(newSVpv((char *)iv_out, iv_outlen)));
    XPUSHs(sv_2mortal(newSVpv((char *)enc_out, enc_outlen)));

void
AES_SIV_DecryptFinal(ctx, iv, ciphertext)
    AES_SIV_CTX *ctx
    PREINIT:
    STRLEN ciphertextlen = 0, ivlen = 0, outlen = 0;
    unsigned char *out;
    int status;
    INPUT:
    unsigned char *iv = NULL;
    unsigned char *ciphertext = NULL;
    PPCODE:

    if(SvOK(ST(1)))
      iv = (unsigned char *)SvPV(ST(1), ivlen);
    if(SvOK(ST(2)))
      ciphertext = (unsigned char *)SvPV(ST(2), ciphertextlen);

    outlen = ciphertextlen;
    Newx(out,outlen,unsigned char);
    if(!out) croak("out of memory");

    status = AES_SIV_DecryptFinal(ctx, out, iv, ciphertext, ciphertextlen);
    XPUSHs(sv_2mortal(newSViv(status)));
    XPUSHs(sv_2mortal(newSVpv((char *)out, outlen)));
