#!/usr/bin/env python3
# -*- encoding: utf-8 -*-



import logging
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

import json
from ipaddress import IPv4Address, AddressValueError
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


client53 = boto3.client('route53','us-west-2')
def r53_upsert(host, hostconf, ip):

    record_type = hostconf['record']['type']

    record_set = client53.list_resource_record_sets(
        HostedZoneId=hostconf['zone_id'],
        StartRecordName=host,
        StartRecordType=record_type,
        MaxItems='1'
    )

    old_ip = None
    if len(record_set['ResourceRecordSets']) < 1:
        msg = "No existing record found for host {} in zone {}"
        logger.info(msg.format(host, hostconf['zone_id']))
    else:
        record = record_set['ResourceRecordSets'][0]
        if record['Name'] == host and record['Type'] == record_type:
            if len(record['ResourceRecords']) == 1:
                for subrecord in record['ResourceRecords']:
                    old_ip = subrecord['Value']
            else:
                msg = "Multiple existing records found for host {} in zone {}"
                raise ValueError(msg.format(host, hostconf['zone_id']))
        else:
            msg = "No existing record found for host {} in zone {}"
            logger.info(msg.format(host, hostconf['zone_id']))


    if old_ip == ip:
        logger.debug("Old IP same as new IP: {}".format(ip))
        return False

    logger.debug("Old IP was: {}".format(old_ip))
    return_status = client53.change_resource_record_sets(
        HostedZoneId=hostconf['zone_id'],
        ChangeBatch={
            'Changes': [
                {
                    'Action': 'UPSERT',
                    'ResourceRecordSet': {
                        'Name': host,
                        'Type': hostconf['record']['type'],
                        'TTL':  hostconf['record']['ttl'],
                        'ResourceRecords': [
                            {
                                'Value': ip
                            }
                        ]
                    }
                }
            ]
        }
    )

    return True


def _handler(event, context):

    if 'header' not in event:
        msg = "Headers not populated properly. Check API Gateway configuration."
        raise KeyError(msg)

    try:
        auth_header = event['header']['Authorization']
    except KeyError as e:
        raise AuthorizationMissing("Authorization required but not provided.")

    try:
        auth_user, auth_pass = (
            b64decode(auth_header[len('Basic '):]).decode('utf-8').split(':') )
    except Exception as e:
        msg = "Malformed basicauth string: {}"
        raise BadAgentException(msg.format(auth_header))

    auth_string = ':'.join([auth_user,auth_pass])
    if auth_string not in conf:
        raise AuthorizationException("Bad username/password.")

    try:
        hosts = set( h if h.endswith('.') else h+'.' for h in
                event['querystring']['hostname'].split(',') )
    except KeyError as e:
        raise BadAgentException("Hostname(s) required but not provided.")

    if any(host not in conf[auth_string]['hosts'] for host in hosts):
        raise HostnameException()

    try:
        ipstring = event['querystring']['myip']
        ip = str(IPv4Address(ipstring))
        logger.debug("User supplied IP address: {}".format(ip))
    except AddressValueError:
        raise BadAgentException("Invalid IP string: {}".format(ipstring))
    except KeyError as e:
        ip = str(IPv4Address(event['context']['source-ip']))
        msg = "User omitted IP address, using best-guess from $context: {}"
        logger.debug(msg.format(ip))

    if any(r53_upsert(host,conf[auth_string]['hosts'][host],ip) for host in hosts):
        return "good {}".format(ip)
    else:
        return "nochg {}".format(ip)


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
