#!/usr/bin/env python3
# -*- encoding: utf-8 -*-

from ipaddress import IPv4Address, IPv6Address
import json
import logging
import unittest
from unittest.case import skip
from unittest.mock import MagicMock

import dyndns53


# logger = logging.getLogger(__name__)
# logger.setLevel(logging.DEBUG)
# logging.basicConfig()
class GetIPsTest(unittest.TestCase):
    zone_id    = 'Z1234567890ABC'
    host       = "test1.example.com."
    host_next  = "test2.example.com."
    ipv4 = IPv4Address('172.16.0.1')
    ipv6 = IPv6Address('2001::1')


    def setUp(self):
        dyndns53.client53 = MagicMock()
        self.list_mock = dyndns53.client53.list_resource_record_sets

#------------------------------------------------------------------------------

    def test_ipv4_and_ipv6(self):
        self.list_mock.return_value = self._rrss(
            self._rrs(self.host, 'A', 3600, self.ipv4),
            self._rrs(self.host, 'AAAA', 300, self.ipv6),
            self._rrs(self.host, 'CAA', 300, '0 issue ";"'),
        )
        self._do(self.ipv4, self.ipv6)

#------------------------------------------------------------------------------

    def test_no_address_with_followup_other_type(self):
        self.list_mock.return_value = self._rrss(
            self._rrs(self.host, 'CAA', 300, '0 issue ";"'),
        )
        self._do(None, None)

    def test_no_host_with_followup_other_host(self):
        self.list_mock.return_value = self._rrss(
            self._rrs(self.host_next, 'A', 3600, self.ipv4),
        )
        self._do(None, None)

    def test_no_host_with_no_followup(self):
        self.list_mock.return_value = self._rrss(
        )
        self._do(None, None)

#------------------------------------------------------------------------------

    def test_ipv4_with_followup_same_host(self):
        self.list_mock.return_value = self._rrss(
            self._rrs(self.host, 'A', 3600, self.ipv4),
            self._rrs(self.host, 'CAA', 300, '0 issue ";"'),
        )
        self._do(self.ipv4, None)

    def test_ipv4_with_followup_other_host(self):
        self.list_mock.return_value = self._rrss(
            self._rrs(self.host, 'A', 3600, self.ipv4),
            self._rrs(self.host_next, 'AAAA', 3600, self.ipv6),
        )
        self._do(self.ipv4, None)

    def test_ipv4_with_no_followup(self):
        self.list_mock.return_value = self._rrss(
            self._rrs(self.host, 'A', 3600, self.ipv4),
        )
        self._do(self.ipv4, None)

#------------------------------------------------------------------------------

    def test_ipv6_with_followup_same_host(self):
        self.list_mock.return_value = self._rrss(
            self._rrs(self.host, 'AAAA', 3600, self.ipv6),
            self._rrs(self.host, 'CAA', 300, '0 issue ";"'),
        )
        self._do(None, self.ipv6)

    def test_ipv6_with_followup_other_host(self):
        self.list_mock.return_value = self._rrss(
            self._rrs(self.host, 'AAAA', 3600, self.ipv6),
            self._rrs(self.host_next, 'A', 3600, self.ipv4),
        )
        self._do(None, self.ipv6)

    def test_ipv6_with_no_followup(self):
        self.list_mock.return_value = self._rrss(
            self._rrs(self.host, 'AAAA', 3600, self.ipv6),
        )
        self._do(None, self.ipv6)

#------------------------------------------------------------------------------


    def _do(self, expected_ipv4, expected_ipv6):
        result = dyndns53.get_ips(self.host, self.zone_id)

        dyndns53.client53.list_resource_record_sets.assert_called_once_with(
            HostedZoneId = self.zone_id,
            StartRecordName = self.host,
            StartRecordType = 'A',
            MaxItems = '2'
        )
        self.assertEquals(result, (expected_ipv4, expected_ipv6))


    def _rrss(self, *rrs):
        return {
            'ResourceRecordSets': rrs
        }

    def _rrs(self, name: str, type: str, ttl: int, *values: str):
        return {
            'Name': name,
            'Type': type,
            'TTL': ttl,
            'ResourceRecords': [
                {
                    'Value': str(value)
                }
                for value in values
            ]
        }
