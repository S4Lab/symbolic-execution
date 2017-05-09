#!/usr/bin/perl
$data = "hello world\n";
# Functional style
use Digest::CRC "crc16";
$digest = crc16($data);
print $data, " -> ", $digest, "\n";
