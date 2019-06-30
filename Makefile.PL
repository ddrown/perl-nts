use strict;
use ExtUtils::MakeMaker;

WriteMakefile(
    NAME => "NTP::NTSKE",
    VERSION_FROM => "lib/NTP/NTSKE.pm",
    PREREQ_PM => {
      "Net::SSLeay" => "1.88",
      "IO::Socket::INET" => 0
    }
    );
