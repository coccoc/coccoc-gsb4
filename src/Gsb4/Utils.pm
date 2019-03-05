package Gsb4::Utils;

use strict;
use warnings;

use YAML();

use base qw(Exporter);
our @EXPORT = qw(get_config);

{
    my $config;
    sub get_config {
        unless ($config) {
            $config = YAML::LoadFile("/etc/coccoc-gsb4/main.yaml");
        }
        return $config;
    }
}

1;
