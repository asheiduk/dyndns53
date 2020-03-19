#!/usr/bin/env python3
# -*- encoding: utf-8 -*-

import json
from ipaddress import ip_address, IPv4Address, IPv6Address
import unittest

from dyndns53 import *

class CreateChangeBatchTest(unittest.TestCase):
    host = 'test.example.com'
    ttl = 3600

    old_ipv4 = ip_address('172.16.0.1')
    new_ipv4 = ip_address('172.16.0.2')

    old_ipv6 = ip_address('2001::1')
    new_ipv6 = ip_address('2001::2')

    def test_create(self):
        ips = [
            (None, self.new_ipv4),
            (None, self.new_ipv6),
        ]
        result = create_change_batch(self.host, self.ttl, ips)

        # either CREATE or UPSERT are allowed
        expected = {
            'Changes': [
                {
                    'Action': 'UPSERT',
                    'ResourceRecordSet': {
                        'Name': self.host,
                        'Type': 'A',
                        'TTL': self.ttl,
                        'ResourceRecords': [
                            {
                                'Value': str(self.new_ipv4)
                            }
                        ]
                    }
                },
                {
                    'Action': 'UPSERT',
                    'ResourceRecordSet': {
                        'Name': self.host,
                        'Type': 'AAAA',
                        'TTL': self.ttl,
                        'ResourceRecords': [
                            {
                                'Value': str(self.new_ipv6)
                            }
                        ]
                    }
                }
            ]
        }

        # print(json.dumps(result, indent=4))
        self.assertEqual(expected, result)


    def test_update(self):
        ips = [
            (self.old_ipv4, self.new_ipv4),
            (self.old_ipv6, self.new_ipv6),
        ]
        result = create_change_batch(self.host, self.ttl, ips)

        # only UPSERT is allowed
        expected = {
            'Changes': [
                {
                    'Action': 'UPSERT',
                    'ResourceRecordSet': {
                        'Name': self.host,
                        'Type': 'A',
                        'TTL': self.ttl,
                        'ResourceRecords': [
                            {
                                'Value': str(self.new_ipv4)
                            }
                        ]
                    }
                },
                {
                    'Action': 'UPSERT',
                    'ResourceRecordSet': {
                        'Name': self.host,
                        'Type': 'AAAA',
                        'TTL': self.ttl,
                        'ResourceRecords': [
                            {
                                'Value': str(self.new_ipv6)
                            }
                        ]
                    }
                }
            ]
        }

        # print(json.dumps(result, indent=4))
        self.assertEqual(expected, result)


    def test_delete(self):
        ips = [
            (self.old_ipv4, None),
            (self.old_ipv6, None),
        ]
        result = create_change_batch(self.host, self.ttl, ips)

        expected = {
            'Changes': [
                {
                    'Action': 'DELETE',
                    'ResourceRecordSet': {
                        'Name': self.host,
                        'Type': 'A',
                        'TTL': self.ttl,
                        'ResourceRecords': [
                            {
                                'Value': str(self.old_ipv4),
                            }
                        ]
                    }
                },
                {
                    'Action': 'DELETE',
                    'ResourceRecordSet': {
                        'Name': self.host,
                        'Type': 'AAAA',
                        'TTL': self.ttl,
                        'ResourceRecords': [
                            {
                                'Value': str(self.old_ipv6),
                            }
                        ]
                    }
                }
            ]
        }

        # print(json.dumps(result, indent=4))
        self.assertEqual(expected, result)


    def test_skip(self):
        ips = [
            (None, None),
            (None, None),
        ]
        result = create_change_batch(self.host, self.ttl, ips)

        expected = {
            'Changes': [],
        }

        # print(json.dumps(result, indent=4))
        self.assertEqual(expected, result)
