package NTP::NTSKE::Constants;

use strict;
use base qw(Exporter);
our @EXPORT_OK = qw(NEXTPROTO_NTP AES_SIV_256_IETF_ID AES_SIV_256_KEYLEN);

use constant {
  NEXTPROTO_NTP => 0,
  AES_SIV_256_IETF_ID => 15, # AEAD_AES_SIV_CMAC_256
  AES_SIV_256_KEYLEN => 32   # true for AEAD_AES_SIV_CMAC_256
};

1;
