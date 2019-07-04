package NTP::NTSKE::Constants;

use strict;
use base qw(Exporter);
our @EXPORT_OK = qw(NEXTPROTO_NTP AES_SIV_256_IETF_ID AES_SIV_256_KEYLEN EXT_UniqueIdentifier EXT_NTSCookie EXT_NTSCookiePlaceholder EXT_NTSAuthenticatorAndEncryptedExtension);

use constant {
  NEXTPROTO_NTP => 0,
  AES_SIV_256_IETF_ID => 15, # AEAD_AES_SIV_CMAC_256
  AES_SIV_256_KEYLEN => 32,  # true for AEAD_AES_SIV_CMAC_256
  EXT_UniqueIdentifier => 0x104,
  EXT_NTSCookie => 0x0204,
  EXT_NTSCookiePlaceholder => 0x0304,
  EXT_NTSAuthenticatorAndEncryptedExtension => 0x0404
};

1;
