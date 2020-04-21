package NTP::NTSKE::TLS;

use strict;
use constant DEFAULT_CERTFILE => "/etc/pki/tls/certs/ca-bundle.crt";
use NTP::NTSKE::Constants qw(NEXTPROTO_NTP);
use Net::SSLeay 1.88 qw(die_now); # 1.88 adds export_keying_material
use IO::Socket::INET;

Net::SSLeay::initialize();

sub new {
  my($class) = shift;
  my(%args) = @_;
  my(%defaults) = (
    hostname => undef,
    port => 4460,
    certfile => DEFAULT_CERTFILE,
    mintls => "1.2",
    exportConst => "EXPORTER-network-time-security"
      );
  my($self) = {
    %defaults,
    %args
  };
  die("no hostname") if not defined($self->{hostname});
  return bless $self, $class;
}

sub connect {
  my($self) = @_;

  $self->_new_tls();

  $self->_set_verify_hostname();

  # send application negotiation (RFC7301)
  Net::SSLeay::set_alpn_protos($self->{ssl}, ["ntske/1"]);

  $self->_connect_and_verify();
}

sub _tls_minver {
  my($self) = @_;

  if($self->{mintls} eq "1.3" or not defined($self->{mintls})) {
    return Net::SSLeay::TLS1_3_VERSION();
  } elsif($self->{mintls} eq "1.2") {
    return Net::SSLeay::TLS1_2_VERSION();
  } elsif($self->{mintls} eq "1.1") {
    return Net::SSLeay::TLS1_1_VERSION();
  }
  die("unknown default minimum tls ".$self->{mintls});
}

sub _tls_min_method {
  my($self) = @_;

  if($self->{mintls} eq "1.3") {
    die("openssl version does not support TLS 1.3");
  } elsif($self->{mintls} eq "1.2" or not defined($self->{mintls})) {
    return Net::SSLeay::TLSv1_2_method();
  } elsif($self->{mintls} eq "1.1") {
    return Net::SSLeay::TLSv1_1_method();
  }
  die("unknown default minimum tls ".$self->{mintls});
}

sub _new_tls {
  my($self) = @_;

  if(exists &Net::SSLeay::TLS_method) { # openssl 1.1+
    # create an encryption context and restrict it to $self->{mintls}
    $self->{ctx} = Net::SSLeay::CTX_new_with_method(Net::SSLeay::TLS_method());
    Net::SSLeay::CTX_set_min_proto_version($self->{ctx}, $self->_tls_minver());
  } else {
    $self->{ctx} = Net::SSLeay::CTX_new_with_method($self->_tls_min_method());
  }

  # disable compression
  Net::SSLeay::CTX_set_options($self->{ctx}, $Net::SSLeay::OP_NO_COMPRESSION);

  # create ssl handle from encryption context
  $self->{ssl} = Net::SSLeay::new($self->{ctx}) or die_now("new ssl($!)");
}

sub _set_verify_hostname {
  my($self) = @_;

  # load the CA
  Net::SSLeay::CTX_load_verify_locations($self->{ctx}, $self->{certfile}, undef);

  # enable certificate verification
  Net::SSLeay::CTX_set_verify($self->{ctx}, $Net::SSLeay::VERIFY_PEER, undef);
  Net::SSLeay::CTX_set_verify_depth($self->{ctx}, 4);

  # get X509 verification parameter handle
  my $param = Net::SSLeay::get0_param($self->{ssl});
  # allow single label wildcards
  Net::SSLeay::X509_VERIFY_PARAM_set_hostflags($param, $Net::SSLeay::X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);
  # verify X509 hostname
  Net::SSLeay::X509_VERIFY_PARAM_set1_host($param, $self->{hostname}) or die_now("set1_host($!)");
  # send SNI hostname
  Net::SSLeay::set_tlsext_host_name($self->{ssl}, $self->{hostname}) or die_now("set_tlsext_host_name($!)");
}

sub _connect_and_verify {
  my($self) = @_;

  # connect
  $self->{sock} = IO::Socket::INET->new($self->{hostname}.":".$self->{port}) or die("connect failed: $@");
  Net::SSLeay::set_fd($self->{ssl}, $self->{sock}) or die_now("set_fd($!)");

  # connect SSL and do handshake
  my $status = Net::SSLeay::connect($self->{ssl});
  if($status <= 0) {
    my $err = Net::SSLeay::ERR_get_error();
    while($err > 0) {
      if($self->{debug}) {
        print "TLS error [$err] = ".Net::SSLeay::ERR_error_string($err)."\n";
      }
      $err = Net::SSLeay::ERR_get_error();
    }
    die_now("ssl connect($!) = $status");
  }
  if($self->{debug}) {
    print "connected with ".Net::SSLeay::get_version($self->{ssl})." / ".Net::SSLeay::get_cipher($self->{ssl})."\n";
    print "alpn = ".unpack("H*",Net::SSLeay::P_alpn_selected($self->{ssl}))."\n";
  }

  # check cert & hostname result
  my $verify = Net::SSLeay::get_verify_result($self->{ssl});
  if($verify != $Net::SSLeay::X509_V_OK) {
    die_now("verify failed: $verify = ".Net::SSLeay::X509_verify_cert_error_string($verify));
  }
}

sub get_keying_material {
  my($self,$length,$next_proto,$aead_algo) = @_;

  die("unexpected next proto $next_proto") if($next_proto != NEXTPROTO_NTP);

  my $c2s = Net::SSLeay::export_keying_material($self->{ssl}, $length, $self->{exportConst}, pack("n2C", $next_proto, $aead_algo, 0)) or die_now("export($!)");
  my $s2c = Net::SSLeay::export_keying_material($self->{ssl}, $length, $self->{exportConst}, pack("n2C", $next_proto, $aead_algo, 1)) or die_now("export($!)");

  return($c2s,$s2c);
}

sub write {
  my($self, $string) = @_;

  Net::SSLeay::write($self->{ssl}, $string) or die("write($!)");
}

sub read {
  my($self) = @_;
  my($msg, $retval) = Net::SSLeay::read($self->{ssl}, 32768);
  if(not defined($msg)) {
    die_now("read");
  }
  return $msg;
}

1;
