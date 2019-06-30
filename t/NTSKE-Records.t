use strict;
use Test::More tests => 18;

require_ok("NTP::NTSKE::Records");

my($critical,$type,$length) = NTP::NTSKE::Records::parse_record(pack("H*", "800100020000"));
is($critical, 1, "msg1 critical parsing");
is($type, 1, "msg1 type parsing");
is($length, 2, "msg1 length parsing");
($critical,$type,$length) = NTP::NTSKE::Records::parse_record(pack("H*", "000500020001"));
is($critical, 0, "msg2 critical parsing");
is($type, 5, "msg2 type parsing");
is($length, 2, "length parsing");
is(NTP::NTSKE::Records::name_to_id("next-protocol"), 1, "next protocol id");
is(NTP::NTSKE::Records::id_to_name(3), "warning", "id 3");

my $next_protocol = "800100020000";
my $aead = "00040002000f";
my $bad_request = "800200020001";
my $warning = "800300020000";
my $end_of_message = "80000000";
my $new_cookie = "0005001012341234123412341234123412341234";
my $ntp_servers = "000600093139322e302e322e31";
my $ntp_port = "00070002007b";

my $client_msg = pack("H*", $next_protocol.$aead.$end_of_message);
my(@records) = NTP::NTSKE::Records::parse($client_msg);
my(@expected) = (
    NTP::NTSKE::Records::record_from_name("next-protocol", 1, pack("H*", "0000")),
    NTP::NTSKE::Records::record_from_name("aead-algorithm", 0, pack("H*", "000f")),
    NTP::NTSKE::Records::record_from_name("end-of-messages", 1, ""),
    );
is_deeply(\@records, \@expected, "client message");

my $server_msg = pack("H*", $next_protocol.$aead.$ntp_servers.$new_cookie.$end_of_message);
(@records) = NTP::NTSKE::Records::parse($server_msg);
(@expected) = (
    NTP::NTSKE::Records::record_from_name("next-protocol", 1, pack("H*", "0000")),
    NTP::NTSKE::Records::record_from_name("aead-algorithm", 0, pack("H*", "000f")),
    NTP::NTSKE::Records::record_from_name("ntpv4-server", 0, "192.0.2.1"),
    NTP::NTSKE::Records::record_from_name("new-cookie", 0, pack("H*", "12341234123412341234123412341234")),
    NTP::NTSKE::Records::record_from_name("end-of-messages", 1, ""),
    );
is_deeply(\@records, \@expected, "server message");

my $error_msg = pack("H*", $bad_request.$end_of_message);
(@records) = NTP::NTSKE::Records::parse($error_msg);
(@expected) = (
    NTP::NTSKE::Records::record_from_name("error", 1, pack("H*","0001")),
    NTP::NTSKE::Records::record_from_name("end-of-messages", 1, ""),
    );
is_deeply(\@records, \@expected, "error message");

my $warning_msg = pack("H*", $warning.$end_of_message);
(@records) = NTP::NTSKE::Records::parse($warning_msg);
(@expected) = (
    NTP::NTSKE::Records::record_from_name("warning", 1, pack("H*","0000")),
    NTP::NTSKE::Records::record_from_name("end-of-messages", 1, ""),
    );
is_deeply(\@records, \@expected, "warning message");
my $warning_repack = NTP::NTSKE::Records::to_packet(\@records);
is($warning_repack, $warning_msg, "warning message encoding");

my $unknown_msg = pack("H*", "80080000");
(@records) = NTP::NTSKE::Records::parse($unknown_msg);
(@expected) = (
    NTP::NTSKE::Record->new(type => 8, critical => 1, data => "", name => undef)
    );
is_deeply(\@records, \@expected, "unknown message");
my $unknown_repack = NTP::NTSKE::Records::to_packet(\@records);
is($unknown_repack, $unknown_msg, "unknown message encoding");

my $badlength = pack("H*", "8008000f");
eval {
  (@records) = NTP::NTSKE::Records::parse($badlength);
};
ok($@, "fail on bad length");

(@records) = NTP::NTSKE::Records::parse(pack("H*", "80010002000000040002000f00050064001906b04525047fa0267593953628daa01d68fb5d073976ffa67df48c9b1db14b2048e9b7879277c56a0c631e0078b790721f6410ae583620705ab7c295da1c4f37db3d3b51be94a01f0b03d7f7d9951fdad72d7d831217544c8fcd5a06dfbf28f6dd0000050064001906b024d70b29501fe1989ade3801b0ff039d2ddf6f3fcc0f9741de8269640896d545edc5e57f0da92ad72c3d596951631d85c2090c5ac455abbcdb83744741f7987f1ba0bfacd022db59b7de25f2f8b6f07c7940649c12035b76e783f5a261bd949700050064001906b032c15a2b4b9c2b2559d0baf841d96a865f56d65da35f5b44ecc8990ceb7448095c2320e2d45d1cfc8c9a825841943664c9248aa36c8d4956ac6cf7c0338bbdd2dad2e3db591fa1f3219b632d9c2bba585778c54f7e2c871d4e234eb1987ffc1400050064001906b0ce9225674bfbf4691534a4be1048bd35c0b83221ebc99d31f419f14275ceaa1ab907b9573225e3f617f9e85d3913ed860c495f8ca36df3908cba881d075123b37e967541797e0ba6f8d366775054de883a0cd3b8fb68bf6e22e3a21d15fb916800050064001906b0b4cbd5796109a4a1e8873dedca67a9532e6d0d6cd9d4d4fccb1fc20595a7006631fc20fc53d28dadc22163c210579ac7d6f4b3398233fa01e976b0ede13b9c2765236e3bfe6c44a9922985822a69c2b0fd2524632712fedaa136b74db474157f00050064001906b0d49e8c64dd6cffbbb2e0b925b6a81f073c3a0ff2c642e2c9a611435f702acd14526eecf169f6a45815296762c28a0423d841196d1ee1d6f81caa09d9263203eaf7b1ec32e62b3b92b84996de96ec5ef13e46dc2e20836bcc3f44296fae91bcde00050064001906b0f9de37f22a7d623bf1c3f2d18d9e5ef12d067cb4ba0b8403168b3f34e24c1408bc28492edcec3557ff9ee083f5c36421182788aa9d8af14f9bd711d397e463c44f18884047d75087bee51f2948a87ed61ba25decab063bf1937b0bd9ab09799900070002007b80000000"));
(@expected) = (
    NTP::NTSKE::Records::record_from_name("next-protocol", 1, pack("H*", "0000")),
    NTP::NTSKE::Records::record_from_name("aead-algorithm", 0, pack("H*", "000f")),
    NTP::NTSKE::Records::record_from_name("new-cookie", 0, pack("H*", "001906b04525047fa0267593953628daa01d68fb5d073976ffa67df48c9b1db14b2048e9b7879277c56a0c631e0078b790721f6410ae583620705ab7c295da1c4f37db3d3b51be94a01f0b03d7f7d9951fdad72d7d831217544c8fcd5a06dfbf28f6dd00")),
    NTP::NTSKE::Records::record_from_name("new-cookie", 0, pack("H*", "001906b024d70b29501fe1989ade3801b0ff039d2ddf6f3fcc0f9741de8269640896d545edc5e57f0da92ad72c3d596951631d85c2090c5ac455abbcdb83744741f7987f1ba0bfacd022db59b7de25f2f8b6f07c7940649c12035b76e783f5a261bd9497")),
    NTP::NTSKE::Records::record_from_name("new-cookie", 0, pack("H*", "001906b032c15a2b4b9c2b2559d0baf841d96a865f56d65da35f5b44ecc8990ceb7448095c2320e2d45d1cfc8c9a825841943664c9248aa36c8d4956ac6cf7c0338bbdd2dad2e3db591fa1f3219b632d9c2bba585778c54f7e2c871d4e234eb1987ffc14")),
    NTP::NTSKE::Records::record_from_name("new-cookie", 0, pack("H*", "001906b0ce9225674bfbf4691534a4be1048bd35c0b83221ebc99d31f419f14275ceaa1ab907b9573225e3f617f9e85d3913ed860c495f8ca36df3908cba881d075123b37e967541797e0ba6f8d366775054de883a0cd3b8fb68bf6e22e3a21d15fb9168")),
    NTP::NTSKE::Records::record_from_name("new-cookie", 0, pack("H*", "001906b0b4cbd5796109a4a1e8873dedca67a9532e6d0d6cd9d4d4fccb1fc20595a7006631fc20fc53d28dadc22163c210579ac7d6f4b3398233fa01e976b0ede13b9c2765236e3bfe6c44a9922985822a69c2b0fd2524632712fedaa136b74db474157f")),
    NTP::NTSKE::Records::record_from_name("new-cookie", 0, pack("H*", "001906b0d49e8c64dd6cffbbb2e0b925b6a81f073c3a0ff2c642e2c9a611435f702acd14526eecf169f6a45815296762c28a0423d841196d1ee1d6f81caa09d9263203eaf7b1ec32e62b3b92b84996de96ec5ef13e46dc2e20836bcc3f44296fae91bcde")),
    NTP::NTSKE::Records::record_from_name("new-cookie", 0, pack("H*", "001906b0f9de37f22a7d623bf1c3f2d18d9e5ef12d067cb4ba0b8403168b3f34e24c1408bc28492edcec3557ff9ee083f5c36421182788aa9d8af14f9bd711d397e463c44f18884047d75087bee51f2948a87ed61ba25decab063bf1937b0bd9ab097999")),
    NTP::NTSKE::Records::record_from_name("ntpv4-port", 0, pack("n", 123)),
    NTP::NTSKE::Records::record_from_name("end-of-messages", 1, ""),
    );
is_deeply(\@records, \@expected, "time.cloudflare.com response");
