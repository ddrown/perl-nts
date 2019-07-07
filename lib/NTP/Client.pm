package NTP::Client;

# Based on Net::NTP, which has the copyright 2009 by Ask Bjørn Hansen; 2004 by James G. Willmore
#
# This library is free software; you can redistribute it and/or modify it under the same terms as Perl itself.

use strict;
use Socket qw(AF_INET AF_INET6 SOCK_DGRAM unpack_sockaddr_in getaddrinfo unpack_sockaddr_in6 inet_ntop SOL_SOCKET MSG_ERRQUEUE MSG_DONTWAIT);
use constant {
  SO_TIMESTAMPING => 37,
  SOF_TIMESTAMPING_SOFTWARE => 1<<4,
  SOF_TIMESTAMPING_TX_SOFTWARE => 1<<1,
  SOF_TIMESTAMPING_RX_SOFTWARE => 1<<3
};
use Socket::MsgHdr;
use NTP::Request;
use NTP::Response;
use NTP::Timestamp;

sub new {
  my $class = shift;
  my $self = {@_};
  bless($self,$class);

  return $self;
}

sub _msg_to_timestamp {
  my($self,$msg) = @_;

  my @cmsg = $msg->cmsghdr();
  while (my ($level, $type, $data) = splice(@cmsg, 0, 3)) {
    if($level == SOL_SOCKET and $type == SO_TIMESTAMPING) {
      my $kernel_ts = substr($data,0,16,"");
      return NTP::Timestamp::from_kernel($kernel_ts);
    }
  }

  return undef;
}

sub get_ntp_response {
  my($self) = @_;

  my $dropmsg = new Socket::MsgHdr(buflen => 1280, namelen => 32, controllen => 256);

  # check for any queued loopback packets and drop them
  while(recvmsg($self->{"socket"},$dropmsg,MSG_ERRQUEUE|MSG_DONTWAIT) > 0) {
  }

  my($sent,$sent2,$recv,$rx_timestamp,$tx_timestamp);
  my $recvmsg = new Socket::MsgHdr(buflen => 1280, namelen => 32, controllen => 256);
  my $sentmsg = new Socket::MsgHdr(buflen => 1280, namelen => 32, controllen => 256);
  my $ntp_request = NTP::Request->new(now => NTP::Timestamp::now(), context => $self->{context});
  my $ntp_msg = $ntp_request->packet();

  $sent = NTP::Timestamp::now();
  send($self->{"socket"},$ntp_msg,0,$self->{"addr"}) or die "send() failed: $!\n";
  $sent2 = NTP::Timestamp::now();

  eval {
    local $SIG{ALRM} = sub { die "Net::NTP timed out geting NTP packet\n"; };
    alarm(60);
    my $bytes = recvmsg($self->{"socket"},$recvmsg,0)
      or die "recvmsg() failed: $!\n";
    my $sentbytes = recvmsg($self->{"socket"},$sentmsg,MSG_ERRQUEUE|MSG_DONTWAIT)
      or die "recvmsg_errqueue() failed: $!\n";
    $recv = NTP::Timestamp::now();
    alarm(0);
    $rx_timestamp = $self->_msg_to_timestamp($recvmsg);
    $tx_timestamp = $self->_msg_to_timestamp($sentmsg);

    my($actual_port,$actual_ip);
    if($self->{family} == AF_INET6) {
      ($actual_port,$actual_ip) = unpack_sockaddr_in6($recvmsg->name);
    } else {
      ($actual_port,$actual_ip) = unpack_sockaddr_in($recvmsg->name);
    }
    $actual_ip = inet_ntop($self->{family},$actual_ip);
    if($actual_ip ne $self->{expected_ip}) {
      warn("expected $self->{expected_ip} got $actual_ip"); # TODO
    }
  };

  if ($@) {
    die "$@";
  }

  if($tx_timestamp) {
    $sent = $tx_timestamp;
  }
  if($rx_timestamp) {
    $recv = $rx_timestamp;
  }
  my $ip = $self->{expected_ip};

  return NTP::Response->new(pkt => $recvmsg->buf, sent => $sent, recv => $recv, sent2 => $sent2, ip => $ip, context => $self->{context});
}

sub lookup {
  my($self,$hostname,$port,$force_proto) = @_;

  if($force_proto eq "inet6") {
    $force_proto = AF_INET6;
  } elsif($force_proto eq "inet") {
    $force_proto = AF_INET;
  } else {
    $force_proto = 0;
  }

  my($err, @results) = getaddrinfo($hostname, $port, {protocol => "udp", socktype => SOCK_DGRAM, family => $force_proto});
  if($err) {
    die("getaddrinfo failed: $err");
  }

  if(defined($self->{"socket"}) and $self->{family} != $results[0]{family}) { # family changed
    warn("address family changed from $self->{family} to $results[0]{family}\n");

    close($self->{"socket"});
    $self->{"socket"} = undef;
  }

  $self->{family} = $results[0]{family};
  $self->{type} = $results[0]{socktype};
  $self->{protocol} = $results[0]{protocol};
  $self->{addr} = $results[0]{addr};

  my($expected_port,$expected_ip);
  if($self->{family} == AF_INET6) {
    ($expected_port,$expected_ip) = unpack_sockaddr_in6($self->{addr});
  } else {
    ($expected_port,$expected_ip) = unpack_sockaddr_in($self->{addr});
  }
  $self->{expected_ip} = inet_ntop($self->{family},$expected_ip);

  if(not defined $self->{"socket"}) {
    socket($self->{"socket"}, $self->{family}, $self->{type}, $self->{protocol});
    setsockopt($self->{"socket"}, SOL_SOCKET, SO_TIMESTAMPING, SOF_TIMESTAMPING_SOFTWARE|SOF_TIMESTAMPING_TX_SOFTWARE|SOF_TIMESTAMPING_RX_SOFTWARE);
  }
}

1;
