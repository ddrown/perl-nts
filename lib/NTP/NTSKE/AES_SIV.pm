package NTP::NTSKE::AES_SIV;

use strict;
use NTP::NTSKE;
use XSLoader;

XSLoader::load("NTP::NTSKE", $NTP::NTSKE::VERSION);

sub new {
  my($class) = @_;
  my $self = {};
  $self->{ctx} = _CTX_new();
  return bless $self,$class;
}

sub DESTROY {
  my($self) = @_;
  if(defined($self->{ctx})) {
    _CTX_cleanup($self->{ctx});
    _CTX_free($self->{ctx});
  }
  $self->{ctx} = undef;
}

sub Encrypt {
  my($self,$key,$nonce,$plaintext,$ad) = @_;

  die("ctx undefined") if not defined($self->{ctx});
  return _Encrypt($self->{ctx}, $key, $nonce, $plaintext, $ad);
}

sub Decrypt {
  my($self,$key,$nonce,$ciphertext,$ad) = @_;

  die("ctx undefined") if not defined($self->{ctx});
  return _Decrypt($self->{ctx}, $key, $nonce, $ciphertext, $ad);
}

sub Init {
  my($self,$key) = @_;

  die("ctx undefined") if not defined($self->{ctx});
  return _Init($self->{ctx}, $key);
}

sub AssociateData {
  my($self,$ad) = @_;

  die("ctx undefined") if not defined($self->{ctx});
  return _AssociateData($self->{ctx}, $ad);
}

sub EncryptFinal {
  my($self,$plaintext) = @_;

  die("ctx undefined") if not defined($self->{ctx});
  return _EncryptFinal($self->{ctx}, $plaintext);
}

sub DecryptFinal {
  my($self,$iv,$ciphertext) = @_;

  die("ctx undefined") if not defined($self->{ctx});
  return _DecryptFinal($self->{ctx}, $iv, $ciphertext);
}

1;
