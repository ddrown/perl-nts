package NTP::NTSKE::Records;

use strict;
use NTP::NTSKE::Record;

my(@message_ids) = qw(end-of-messages next-protocol error warning aead-algorithm new-cookie ntpv4-server ntpv4-port); 
my(%message_ids);
for(my $i = 0; $i < @message_ids; $i++) {
  $message_ids{$message_ids[$i]} = $i;
}

sub to_packet {
  my($records) = @_;

  my $packet = "";
  foreach my $record (@$records) {
    $packet .= $record->to_packet();
  }
  return $packet;
}

sub parse_record {
  my($raw) = @_;

  my($type, $length) = unpack("nn", $raw);
  my($critical) = $type >> 15;
  $type         = $type & 0b0111111111111111;
  return ($critical, $type, $length);
}

sub parse {
  my($raw) = @_;

  my(@records);
  while(length($raw) >= 2) {
    my($critical,$type,$length) = parse_record(substr($raw,0,4,""));
    if(length($raw) < $length) {
      die("length $length went over the end of the packet");
    }
    my $data = substr($raw,0,$length,"");
    my $name;
    eval {
      $name = id_to_name($type);
    };
    push(@records, NTP::NTSKE::Record->new(type => $type, critical => $critical, data => $data, name => $name));
  }
  
  return(@records);
}

sub record_from_name {
  my($name, $critical, $data) = @_;

  my $type = name_to_id($name);
  return NTP::NTSKE::Record->new(type => $type, critical => $critical, data => $data, name => $name);
}

sub generate {
  my(@records) = @_;

  my $packet = "";
  foreach my $record (@records) {
    $packet .= $record->to_packet();
  }
  return $packet;
}

sub name_to_id {
  my($name) = @_;
  if(defined($message_ids{$name})) {
    return $message_ids{$name};
  }
  die("unknown name: $name");
}

sub id_to_name {
  my($id) = @_;
  if(defined($message_ids[$id])) {
    return $message_ids[$id];
  }
  die("unknown id: $id");
}

sub dump {
  my($records) = @_;

  foreach my $record (@$records) {
    print STDERR $record->type()." ".$record->name()." ".length($record->data())." ".unpack("H*", $record->data())."\n";
  }
}

1;
