use strict;
use Test::More tests => 20;

require_ok("NTP::NTSKE::AES_SIV");

ok(NTP::NTSKE::AES_SIV::Version(), "got version number");

my $obj = NTP::NTSKE::AES_SIV->new();
is(ref($obj), "NTP::NTSKE::AES_SIV", "new object");

my $key = pack("H*", "fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
my $plaintext = pack("H*", "112233445566778899aabbccddee");
my $ad = pack("H*", "101112131415161718191a1b1c1d1e1f2021222324252627");
my $ciphertext = pack("H*", "85632d07c6e8f37f950acd320a2ecc9340c02b9690c4dc04daef7f6afe5c");

my($status, $out) = $obj->Encrypt($key, undef, $plaintext, $ad);
is($status, 1, "encrypt status");
is(unpack("H*", $out), unpack("H*", $ciphertext), "encrypted as expected");

($status, $out) = $obj->Decrypt($key, undef, $ciphertext, $ad);
is($status, 1, "decrypt status");
is(unpack("H*", $out), unpack("H*", $plaintext), "decrypted as expected");

$key = pack("H*", "7f7e7d7c7b7a79787776757473727170404142434445464748494a4b4c4d4e4f");
my $ad1 = pack("H*", "00112233445566778899aabbccddeeffdeaddadadeaddadaffeeddccbbaa99887766554433221100");
my $ad2 = pack("H*", "102030405060708090a0");
my $nonce = pack("H*", "09f911029d74e35bd84156c5635688c0");
$plaintext = pack("H*",  "7468697320697320736f6d6520706c61696e7465787420746f20656e6372797074207573696e67205349562d414553");
my $iv = pack("H*", "7bdb6e3b432667eb06f4d14bff2fbd0f");
$ciphertext = pack("H*", "cb900f2fddbe404326601965c889bf17dba77ceb094fa663b7a3f748ba8af829ea64ad544a272e9c485b62a3fd5c0d");

is($obj->Init($key), 1, "init status");
is($obj->AssociateData($ad1), 1, "associate ad1");
is($obj->AssociateData($ad2), 1, "associate ad2");
is($obj->AssociateData($nonce), 1, "associate nonce");
my $ivout;
($status,$ivout,$out) = $obj->EncryptFinal($plaintext);
is($status, 1, "encrypt final status");
is(unpack("H*", $ivout), unpack("H*",$iv), "iv");
is(unpack("H*", $out), unpack("H*",$ciphertext), "cipher text");

is($obj->Init($key), 1, "init status");
is($obj->AssociateData($ad1), 1, "associate ad1");
is($obj->AssociateData($ad2), 1, "associate ad2");
is($obj->AssociateData($nonce), 1, "associate nonce");
($status,$out) = $obj->DecryptFinal($iv,$ciphertext);
is($status, 1, "decrypt final status");
is(unpack("H*", $out), unpack("H*",$plaintext), "plain text");

