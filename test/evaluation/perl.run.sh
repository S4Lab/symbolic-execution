#!/usr/bin/perl
$data = "hello world\n";
# Functional style
use Digest::MD5 qw(md5 md5_hex md5_base64);
#$digest = md5($data);
$digest = md5_hex($data);
#$digest = md5_base64($data);
print $data, " -> ", $digest, "\n";
