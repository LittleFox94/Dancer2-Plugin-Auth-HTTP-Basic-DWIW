use 5.006;
use strict;
use warnings;
use ExtUtils::MakeMaker;

WriteMakefile(
    NAME             => 'Dancer2::Plugin::Auth::HTTP::Basic::DWIW',
    AUTHOR           => q{Moritz Grosch (LittleFox) <littlefox@fsfe.org>},
    VERSION_FROM     => 'lib/Dancer2/Plugin/Auth/HTTP/Basic/DWIW.pm',
    ABSTRACT_FROM    => 'lib/Dancer2/Plugin/Auth/HTTP/Basic/DWIW.pm',
    LICENSE          => 'artistic_2',
    PL_FILES         => {},
    MIN_PERL_VERSION => 5.006,
    CONFIGURE_REQUIRES => {
        'ExtUtils::MakeMaker' => 0,
    },
    BUILD_REQUIRES => {
        'Test::More' => 0,
        'Plack' => 0,
        'HTTP::Message' => 0
    },
    PREREQ_PM => {
        #'ABC'              => 1.6,
        #'Foo::Bar::Module' => 5.0401,
        'Dancer2' => 0.160000,
    },
    dist  => { COMPRESS => 'gzip -9f', SUFFIX => 'gz', },
    clean => { FILES => 'Dancer2-Plugin-Auth-HTTP-Basic-DWIW-*' },
);
