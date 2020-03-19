#!/usr/bin/env python3
# -*- encoding: utf-8 -*-

import dyndns53

import unittest
from ipaddress import ip_address, IPv4Address, IPv6Address

class ParseMyIPTest(unittest.TestCase):

    def ok(self, myip, expected_ipv4, expected_ipv6):
        if expected_ipv4:
            expected_ipv4 = IPv4Address(expected_ipv4)
        if expected_ipv6:
            expected_ipv6 = IPv6Address(expected_ipv6)
        ipv4, ipv6 = self.parse(myip)
        self.assertEqual(ipv4, expected_ipv4)
        self.assertEqual(ipv6, expected_ipv6)

    def parse(self, myip):
        return dyndns53.parse_myip(myip)


    def test_ipv4_only(self):
        self.ok('127.0.0.1', '127.0.0.1', None)

    def test_ipv6_only(self):
        self.ok('0000:0000:0000:0000:0000:0000:0000:0001', None, '::1')
        self.ok('::1', None, '::1')

    def test_ipv4_and_ipv6(self):
        self.ok('127.0.0.1,0000:0000:0000:0000:0000:0000:0000:0001', '127.0.0.1', '::1')
        self.ok('0000:0000:0000:0000:0000:0000:0000:0001,127.0.0.1', '127.0.0.1', '::1')

    def test_invalid_ipv4(self):
        with self.assertRaisesRegex(dyndns53.BadAgentException, '^Invalid IP string: 127\.0\.0\.256$'):
            self.parse('127.0.0.256')

    def test_invalid_ipv6(self):
        with self.assertRaisesRegex(dyndns53.BadAgentException, '^Invalid IP string: ::G$'):
            self.parse('::G')

    def test_only_one_ipv4(self):
        with self.assertRaisesRegex(dyndns53.BadAgentException, '^More than one IPv4 address provided: 127\.0\.0\.1,127\.0\.0\.2$'):
            self.parse('127.0.0.1,127.0.0.2')

    def test_only_one_ipv6(self):
        with self.assertRaisesRegex(dyndns53.BadAgentException, '^More than one IPv6 address provided: ::1,::2$'):
            self.parse('::1,::2')

    def test_empty_components(self):
        # TODO: Perhaps it would be better to ignore empty components?
        with self.assertRaisesRegex(dyndns53.BadAgentException, '^Invalid IP string: $'):
            self.parse('')
        with self.assertRaisesRegex(dyndns53.BadAgentException, '^Invalid IP string: ,$'):
            self.parse(',')
        with self.assertRaisesRegex(dyndns53.BadAgentException, '^Invalid IP string: 127\.0\.0\.1,$'):
            self.parse('127.0.0.1,')
        with self.assertRaisesRegex(dyndns53.BadAgentException, '^Invalid IP string: ,127\.0\.0\.1$'):
            self.parse(',127.0.0.1')
