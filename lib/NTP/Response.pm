package NTP::Response;

# This library is free software; you can redistribute it and/or modify it under the same terms as Perl itself.

use strict;
use NTP::Timestamp;
use NTP::NTSKE::AES_SIV;
use NTP::NTSKE::Constants qw(EXT_UniqueIdentifier EXT_NTSCookie EXT_NTSAuthenticatorAndEncryptedExtension);

sub new {
  my $class = shift;
  my $self = {@_};
  bless($self,$class);

  $self->{saw_uniqueid} = 0;
  $self->{saw_auth} = 0;

  $self->_pkt_to_raw();
  $self->_process();
  $self->_process_extensions() if($self->{extensions});
  return $self;
}

sub _pkt_to_raw {
  my($self) = @_;

  my $pkt = $self->{pkt};

  my(@ntp_fields) = qw/byte1 stratum poll precision delay delay_fb disp disp_fb ident ref_time ref_time_fb org_time org_time_fb recv_time recv_time_fb trans_time trans_time_fb/;
  @{$self}{@ntp_fields} = unpack("C3c   n B16 n B16 N   N B32 N B32   N B32 N B32", substr($pkt, 0, 48, ""));
  my $offset = 48;

  my(@extensions);
  while(length($pkt) > 0) {
    if(length($pkt) == 20 or length($pkt) == 24) {
      $self->{mac} = unpack("H*", $pkt);
      $pkt = "";
    } elsif(length($pkt) >= 4) {
      my($type,$length) = unpack("nn", substr($pkt, 0, 4, ""));
      if($length >= 4 and $length-4 <= length($pkt)) {
        push(@extensions, {
            type => $type,
            length => $length,
            offset => $offset,
            data => substr($pkt, 0, $length-4, "")
            });
        $offset += $length;
      } else {
        $self->{corrupted} = $pkt;
        $pkt = "";
      }
    } else {
      $self->{corrupted} = $pkt;
      $pkt = "";
    }
  }
  if(@extensions) {
    $self->{extensions} = \@extensions;
  }
}

sub _process_extensions {
  my($self) = @_;

  for(my $i = 0; $i < @{ $self->{extensions} }; $i++) {
    my $extension = $self->{extensions}[$i];
    if($extension->{type} == EXT_UniqueIdentifier) {
      $self->{saw_uniqueid} = 1;
      if($extension->{data} ne $self->{context}->last_uniq_id()) {
        die("unique id expected ".unpack("H*", $self->{context}->last_uniq_id())." got ".unpack("H*", $extension->{data}));
      }
    } elsif($extension->{type} == EXT_NTSAuthenticatorAndEncryptedExtension) {
      if($extension->{offset}+$extension->{length} != length($self->{pkt})) {
        die("NTS auth&crypt packet must be at the end, ".($extension->{offset}+$extension->{length})." != ".length($self->{pkt}));
      }
      my $data = $extension->{data};
      my($nlen, $clen) = unpack("nn", substr($data, 0, 4, ""));
      if($nlen+$clen > length($data)) {
        die("nlen $nlen + clen $clen > data ".length($data));
      }
      my $nonce = substr($data, 0, $nlen, "");
      my $ciphertext = substr($data, 0, $clen, "");
      my $aes_obj = NTP::NTSKE::AES_SIV->new();
      my($status, $plaintext) = $aes_obj->Decrypt($self->{context}->s2c(), $nonce, $ciphertext, substr($self->{pkt}, 0, $extension->{offset}));
      if($status != 1) {
        die("AES_SIV decrypt failed status = $status");
      }
      $self->{saw_auth} = 1;
      while(length($plaintext) >= 4) {
        my($type,$length) = unpack("nn", substr($plaintext, 0, 4, ""));
        if($length >= 4 and $length-4 <= length($plaintext)) {
          my $data = substr($plaintext, 0, $length-4, "");
          if($type == EXT_NTSCookie) {
            $self->{context}->unshift_cookie($data);
          }
        } else {
          $plaintext = "";
        }
      }
    }
  }
  if(not $self->{saw_uniqueid} or not $self->{saw_auth}) {
    die("extensions present, but no unique/auth");
  }
}

sub saw_uniqueid {
  my($self) = @_;
  return $self->{saw_uniqueid};
}

sub saw_auth {
  my($self) = @_;
  return $self->{saw_auth};
}

sub _process {
  my($self) = @_;

  $self->{"Local Transmit Time"} = $self->{"sent"};
  $self->{"Local Recv Time"} = $self->{"recv"};

  $self->{"Remote Recv Time"} = NTP::Timestamp::from_ntp($self->{"recv_time"}, $self->{"recv_time_fb"});
  $self->{"Remote Transmit Time"} = NTP::Timestamp::from_ntp($self->{"trans_time"}, $self->{"trans_time_fb"});
}

sub is_kod {
  my($self) = @_;

  return(($self->stratum() == 0) and ($self->ident() eq "RATE"));
}

sub ident {
  my($self) = @_;

  if($self->{stratum} < 2) {
    return sprintf("%c%c%c%c", $self->{"ident"} >> 24, ($self->{"ident"} >> 16) & 0xff, ($self->{"ident"} >> 8) & 0xff, $self->{"ident"} & 0xff);
  } else {
    return sprintf("%d.%d.%d.%d", $self->{"ident"} >> 24, ($self->{"ident"} >> 16) & 0xff, ($self->{"ident"} >> 8) & 0xff, $self->{"ident"} & 0xff);
  }
}

sub stratum {
  my($self) = @_;

  return $self->{"stratum"};
}

sub local_transmit_time {
  my($self) = @_;
  return $self->{"Local Transmit Time"}->to_string();
}

sub local_transmit_time_after_processing {
  my($self) = @_;
  return $self->{"sent2"}->to_string();
}

sub local_recv_time {
  my($self) = @_;
  return $self->{"Local Recv Time"}->to_string();
}

sub remote_transmit_time {
  my($self) = @_;
  return $self->{"Remote Transmit Time"}->to_string();
}

sub remote_recv_time {
  my($self) = @_;
  return $self->{"Remote Recv Time"}->to_string();
}

sub rtt {
  my($self) = @_;

  return $self->{"Local Transmit Time"}->interval($self->{"Local Recv Time"});
}

sub turn_around {
  my($self) = @_;

  return $self->{"Remote Recv Time"}->interval($self->{"Remote Transmit Time"});
}

sub offset {
  my($self) = @_;

  my $rtt = $self->rtt();
  my $offset = $self->{"Local Transmit Time"}->interval($self->{"Remote Recv Time"}) - $rtt/2;
  $offset -= $self->{"Remote Recv Time"}->interval($self->{"Remote Transmit Time"}); # remove any delay from processing

  return $offset;
}

sub request {
  my($self) = @_;

  return $self->{"Local Transmit Time"}->interval($self->{"Remote Recv Time"});
}

sub response {
  my($self) = @_;

  return $self->{"Remote Transmit Time"}->interval($self->{"Local Recv Time"});
}

sub when {
  my($self) = @_;

  return $self->{"Local Transmit Time"}->seconds();
}

sub local_ts {
  my($self) = @_;

  return $self->{"Local Transmit Time"};
}

sub local_delta {
  my($self,$start) = @_;
  return $start->interval($self->{"Local Transmit Time"});
}

sub leap {
  my($self) = @_;
  return $self->{"byte1"} >> 6;
}
sub version {
  my($self) = @_;
  return ($self->{"byte1"} >> 3) & 0b111;
}
sub mode {
  my($self) = @_;
  return $self->{"byte1"} & 0b111;
}
sub poll {
  my($self) = @_;
  return $self->{"poll"};
}
sub precision {
  my($self) = @_;
  return $self->{"precision"};
}
sub ip {
  my($self) = @_;
  return $self->{"ip"};
}
sub root_delay {
  my($self) = @_;
  return NTP::Timestamp::from_ntp_short($self->{"delay"}, $self->{"delay_fb"})->to_string();
}
sub root_dispersion {
  my($self) = @_;
  return NTP::Timestamp::from_ntp_short($self->{"disp"}, $self->{"disp_fb"})->to_string();
}
sub reference_time {
  my($self) = @_;

  return NTP::Timestamp::from_ntp($self->{"ref_time"}, $self->{"ref_time_fb"})->to_string();
}
sub originate_time {
  my($self) = @_;

  return NTP::Timestamp::from_ntp($self->{"org_time"}, $self->{"org_time_fb"})->to_string();
}

sub packetsize {
  my($self) = @_;
  return length($self->{pkt});
}

1;
