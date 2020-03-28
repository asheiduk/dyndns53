#!/usr/bin/env python3
# -*- encoding: utf-8 -*-

import logging
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

import json
from ipaddress import ip_address, IPv4Address, IPv6Address, AddressValueError
from base64 import b64decode

import boto3


class ClientError(Exception):
    pass
class AuthorizationMissing(ClientError):
    status = 401
    response = {"WWW-Authenticate":"Basic realm=dyndns53"}
class HostnameException(ClientError):
    status = 404
    response = "nohost"
class AuthorizationException(ClientError):
    status = 403
    response = "badauth"
class BadAgentException(ClientError):
    status = 400
    response = "badagent"


conf = {
    '<username>:<password>': {
        'hosts': {
            '<host.example.com.>': {
                'zone_id': '<MY_ZONE_ID>',
                'record': {
                    'ttl': 60,
                    'type': 'A',
                },
            },
        },
    },
}


def lambda_handler(event, context):
    def json_error(e, status, response):
        msg = json.dumps({'status': status, 'response': response, 'additional': str(e)})
        return type(e)(msg)

    try:
        response = _handler(event, context)
    except ClientError as e:
        raise json_error(e, status = e.status, response = e.response) from e
    except Exception as e:
        raise json_error(e, status = 500, response = '911') from e

    return { 'status': 200, 'response': response }


def _handler(event, context):

    if 'header' not in event:
        msg = "Headers not populated properly. Check API Gateway configuration."
        raise KeyError(msg)

    try:
        auth_header = event['header']['Authorization']
    except KeyError:
        raise AuthorizationMissing("Authorization required but not provided.")

    try:
        auth_user, auth_pass = (
            b64decode(auth_header[len('Basic '):]).decode('utf-8').split(':') )
    except Exception:
        msg = "Malformed basicauth string: {}"
        raise BadAgentException(msg.format(auth_header))

    auth_string = ':'.join([auth_user,auth_pass])
    if auth_string not in conf:
        raise AuthorizationException("Bad username/password.")

    try:
        host = event['querystring']['hostname']
    except KeyError:
        raise BadAgentException("Hostname required but not provided.")

    if not host.endswith('.'):
        host += '.'

    if host not in conf[auth_string]['hosts']:
        raise HostnameException()
    host_conf = conf[auth_string]['hosts'][host]

    try:
        myip = event['querystring']['myip']
        ipv4, ipv6 = parse_myip(myip)
        logger.debug(f'User supplied IP address(es): IPs: {ipv4}, {ipv6}')
    except KeyError:
        # possible bug: there is no source-ip (perhaps due to mapping errors or due to unknown protocols?)
        ip = ip_address(event['context']['source-ip'])
        if ip.version == 4:
            ipv4, ipv6 = ip, None
        elif ip.version == 6:
            ipv4, ipv6 = None, ip
        logger.debug(f'User omitted IP address, using best-guess from $context: {ip}')

    # prefer IPv4 if both are supplied
    ip = ipv4 or ipv6
    if r53_upsert(host, host_conf['zone_id'], host_conf['ttl'], ipv4, ipv6):
        return f'good {ip}'
    else:
        return f'nochg {ip}'


def parse_myip(myip: str) -> (IPv4Address, IPv6Address):
    ipv4, ipv6 = None, None
    for ipstring in myip.split(','):
        # TODO: ignore empty components?
        # TODO: move try/except to the caller?
        try:
            ip = ip_address(ipstring)
        except ValueError:
            raise BadAgentException(f'Invalid IP string: {myip}')

        if ip.version == 4:
            if ipv4:
                raise BadAgentException(f'More than one IPv4 address provided: {myip}')
            ipv4 = ip
        elif ip.version == 6:
            if ipv6:
                raise BadAgentException(f'More than one IPv6 address provided: {myip}')
            ipv6 = ip

    return ipv4, ipv6


client53 = boto3.client('route53','us-west-2')
def r53_upsert(host, zone_id, ttl, ipv4, ipv6):

    (old_ipv4, old_ipv6) = get_ips(host, zone_id)
    logger.debug(f'Old IPs: {old_ipv4}, {old_ipv6} -- New IPs: {ipv4}, {ipv6}')

    ips = [
        (old_ipv4, ipv4),
        (old_ipv6, ipv6)
    ]
    change_batch = create_change_batch(host, ttl, ips)
    if change_batch['Changes']:
        logger.debug('Performing %s change(s) in route53', len(change_batch['Changes']))
        client53.change_resource_record_sets(
            HostedZoneId = zone_id,
            ChangeBatch = change_batch
        )
        return True
    else:
        logger.debug('No changes for route53')
        return False


def get_ips(host: str, zone_id: str):
    if not host.endswith('.'):
        host += '.'

    response = client53.list_resource_record_sets(
        HostedZoneId = zone_id,
        StartRecordName = host,
        StartRecordType = 'A',
        MaxItems = '2'    # A and AAAA should be adjacent
    )

    record_sets = response['ResourceRecordSets']
    if not record_sets:
        return (None, None)

    def get_value():
        if len(record_set['ResourceRecords']) > 1:
            raise ValueError(f'Multiple existing records found for host {host} in zone_id {zone_id}')
        return record_set['ResourceRecords'][0]['Value']

    ipv4, ipv6 = None, None
    for record_set in record_sets:
        if record_set['Name'] == host:
            if record_set['Type'] == 'A':
                ipv4 = IPv4Address(get_value())
            if record_set['Type'] == 'AAAA':
                ipv6 = IPv6Address(get_value())

    # may still be empty!
    return (ipv4, ipv6)


def create_change_batch(host: str, ttl: int, ips):
    def get_type(ip):
        if ip.version == 4: return 'A'
        if ip.version == 6: return 'AAAA'
        return None

    def create_change(old_ip, new_ip):
        if new_ip:
            return {
                'Action': 'UPSERT',
                'ResourceRecordSet': {
                    'Name': host,
                    'Type': get_type(new_ip),
                    'TTL':  ttl,
                    'ResourceRecords': [
                        {
                            'Value': str(new_ip)
                        }
                    ]
                }
            }
        elif old_ip:
            return {
                'Action': 'DELETE',
                'ResourceRecordSet': {
                    'Name': host,
                    'Type': get_type(old_ip),
                    'TTL': ttl,
                    'ResourceRecords': [
                        {
                            'Value': str(old_ip)
                        }
                    ]
                }
            }

    return {
        'Changes': [
            create_change(old_ip, new_ip)
                for old_ip, new_ip in ips if (old_ip or new_ip) and old_ip != new_ip
        ]
    }
