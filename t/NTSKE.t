use strict;
use Test::More tests => 6;

{
  package NTP::NTSKE::TLS::mock;

  use strict;

  sub new {
    my($class) = shift;
    return bless {@_}, $class;
  }

  sub connect {
  }

  sub write {
  }

  sub setdata {
    my($self,$data) = @_;
    $self->{data} = $data;
  }

  sub setkeying {
    my($self,$data) = @_;
    $self->{keying} = $data;
  }

  sub read {
    my($self) = @_;
    return pack("H*", $self->{data});
  }

  sub get_keying_material {
    my($self) = @_;
    return @{ $self->{keying} };
  }
}

require_ok("NTP::NTSKE");
require_ok("NTP::NTSKE::Context");

my $next_protocol = "800100020000";
my $aead = "00040002000f";
my $new_cookie = "0005001012341234123412341234123412341234";
my $ntp_servers = "000600093139322e302e322e31";
my $end_of_message = "80000000";
my $readdata = $next_protocol.$aead.$ntp_servers.$new_cookie.$end_of_message;
my(@keying) = ("12345", "54321");

my $tls = NTP::NTSKE::TLS::mock->new(data => $readdata, keying => \@keying);
my $obj = NTP::NTSKE->new(tls => $tls);
is(ref($obj), "NTP::NTSKE", "got an object back");

my $packet = $obj->clientmsg();
is($packet, pack("H*", "80010002000000040002000f80000000"), "client message");

my $context = $obj->get_context();
my $expected = NTP::NTSKE::Context->new(
    cookie => [pack("H*", "12341234123412341234123412341234")],
    server => ["192.0.2.1"],
    protocol => 0,
    aead => 15,
    c2s => "12345",
    s2c => "54321"
    );
is_deeply($context, $expected, "connection context");

$tls->setdata("80010002000000040002000f00050064001906b04525047fa0267593953628daa01d68fb5d073976ffa67df48c9b1db14b2048e9b7879277c56a0c631e0078b790721f6410ae583620705ab7c295da1c4f37db3d3b51be94a01f0b03d7f7d9951fdad72d7d831217544c8fcd5a06dfbf28f6dd0000050064001906b024d70b29501fe1989ade3801b0ff039d2ddf6f3fcc0f9741de8269640896d545edc5e57f0da92ad72c3d596951631d85c2090c5ac455abbcdb83744741f7987f1ba0bfacd022db59b7de25f2f8b6f07c7940649c12035b76e783f5a261bd949700050064001906b032c15a2b4b9c2b2559d0baf841d96a865f56d65da35f5b44ecc8990ceb7448095c2320e2d45d1cfc8c9a825841943664c9248aa36c8d4956ac6cf7c0338bbdd2dad2e3db591fa1f3219b632d9c2bba585778c54f7e2c871d4e234eb1987ffc1400050064001906b0ce9225674bfbf4691534a4be1048bd35c0b83221ebc99d31f419f14275ceaa1ab907b9573225e3f617f9e85d3913ed860c495f8ca36df3908cba881d075123b37e967541797e0ba6f8d366775054de883a0cd3b8fb68bf6e22e3a21d15fb916800050064001906b0b4cbd5796109a4a1e8873dedca67a9532e6d0d6cd9d4d4fccb1fc20595a7006631fc20fc53d28dadc22163c210579ac7d6f4b3398233fa01e976b0ede13b9c2765236e3bfe6c44a9922985822a69c2b0fd2524632712fedaa136b74db474157f00050064001906b0d49e8c64dd6cffbbb2e0b925b6a81f073c3a0ff2c642e2c9a611435f702acd14526eecf169f6a45815296762c28a0423d841196d1ee1d6f81caa09d9263203eaf7b1ec32e62b3b92b84996de96ec5ef13e46dc2e20836bcc3f44296fae91bcde00050064001906b0f9de37f22a7d623bf1c3f2d18d9e5ef12d067cb4ba0b8403168b3f34e24c1408bc28492edcec3557ff9ee083f5c36421182788aa9d8af14f9bd711d397e463c44f18884047d75087bee51f2948a87ed61ba25decab063bf1937b0bd9ab09799900070002007b80000000");
$context = $obj->get_context();
my(@cookies) = qw(
    001906b04525047fa0267593953628daa01d68fb5d073976ffa67df48c9b1db14b2048e9b7879277c56a0c631e0078b790721f6410ae583620705ab7c295da1c4f37db3d3b51be94a01f0b03d7f7d9951fdad72d7d831217544c8fcd5a06dfbf28f6dd00
    001906b024d70b29501fe1989ade3801b0ff039d2ddf6f3fcc0f9741de8269640896d545edc5e57f0da92ad72c3d596951631d85c2090c5ac455abbcdb83744741f7987f1ba0bfacd022db59b7de25f2f8b6f07c7940649c12035b76e783f5a261bd9497
    001906b032c15a2b4b9c2b2559d0baf841d96a865f56d65da35f5b44ecc8990ceb7448095c2320e2d45d1cfc8c9a825841943664c9248aa36c8d4956ac6cf7c0338bbdd2dad2e3db591fa1f3219b632d9c2bba585778c54f7e2c871d4e234eb1987ffc14
    001906b0ce9225674bfbf4691534a4be1048bd35c0b83221ebc99d31f419f14275ceaa1ab907b9573225e3f617f9e85d3913ed860c495f8ca36df3908cba881d075123b37e967541797e0ba6f8d366775054de883a0cd3b8fb68bf6e22e3a21d15fb9168
    001906b0b4cbd5796109a4a1e8873dedca67a9532e6d0d6cd9d4d4fccb1fc20595a7006631fc20fc53d28dadc22163c210579ac7d6f4b3398233fa01e976b0ede13b9c2765236e3bfe6c44a9922985822a69c2b0fd2524632712fedaa136b74db474157f
    001906b0d49e8c64dd6cffbbb2e0b925b6a81f073c3a0ff2c642e2c9a611435f702acd14526eecf169f6a45815296762c28a0423d841196d1ee1d6f81caa09d9263203eaf7b1ec32e62b3b92b84996de96ec5ef13e46dc2e20836bcc3f44296fae91bcde
    001906b0f9de37f22a7d623bf1c3f2d18d9e5ef12d067cb4ba0b8403168b3f34e24c1408bc28492edcec3557ff9ee083f5c36421182788aa9d8af14f9bd711d397e463c44f18884047d75087bee51f2948a87ed61ba25decab063bf1937b0bd9ab097999
    );
$expected = NTP::NTSKE::Context->new(
    cookie => [map { pack("H*",$_) } @cookies],
    protocol => 0,
    port => 123,
    aead => 15,
    c2s => "12345",
    s2c => "54321"
    );
is_deeply($context, $expected, "connection context");
