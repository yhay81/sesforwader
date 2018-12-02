import os
from logging import getLogger, INFO
from email import message_from_bytes

from boto3 import client
from botocore.exceptions import ClientError

logger = None
ses_client = None
s3_client = None


def initialize(ses_region):
    global logger, ses_client, s3_client
    if logger is None:
        logger = getLogger(__name__)
        logger.setLevel(INFO)
    if ses_client is None:
        ses_client = client('ses', region_name=os.environ.get('SES_REGION') or ses_region or os.environ.get('AWS_REGION'))
    if s3_client is None:
        s3_client = client('s3')


def extract_ses(event):
    if not isinstance(event, dict) or len(event.get('Records')) != 1 or \
            event['Records'][0].get('eventSource') != 'aws:ses' or event['Records'][0].get('eventVersion') != '1.0':
        logger.error('parseEvent() received invalid SES message: %s', str(event), exc_info=True, stack_info=True)
        raise Exception('Received invalid event.')
    return event['Records'][0]['ses']


def fetch_message(bucket, key):
    copy_source = '{}/{}'.format(bucket, key)
    logger.info("Fetching email at s3://%s", copy_source)
    try:
        s3_client.copy_object(
            ACL='private',
            Bucket=bucket,
            ContentType='test/plain',
            CopySource=copy_source,
            Key=key,
            StorageClass='STANDARD'
        )
    except ClientError:
        logger.error('copy_object() returned error.', exc_info=True, stack_info=True)
        raise Exception('Error: S3 cannot be written.')
    try:
        result = s3_client.get_object(Bucket=bucket, Key=key)
    except ClientError:
        logger.error('get_object() returned error.', exc_info=True, stack_info=True)
        raise Exception('Error: S3 cannot be read.')
    return result['Body'].read()


def process_message(message, from_email, subject_prefix=None, to_email=None):
    prefix = 'X-Original'
    if 'From' in message:
        logger.info('Added Reply-To address of: %s', message.get('From'))
        message.add_header('{}-{}'.format(prefix, 'Reply-To'), '')
        message.add_header('Reply-To', message.get('From'))
    else:
        logger.info('Reply-To address not added because From address was not properly extracted.')

    #  SES does not allow sending messages from an unverified address,
    #  so replace the message's "From:" header with the original recipient (which is a verified domain)
    logger.info('Replaced From address from: %s to: %s', message.get('From'), from_email)
    message.add_header('{}-{}'.format(prefix, 'From'), message.get('From'))
    message.replace_header('From', from_email)

    if subject_prefix:
        logger.info('Added Subject prefix of: %s', subject_prefix)
        message.add_header('{}-{}'.format(prefix, 'Subject'), message.get('Subject'))
        message.replace_header('Subject', subject_prefix + message.get('Subject'))

    if to_email:
        logger.info('Replaced To address from: %s to: %s', message.get('To'), to_email)
        message.add_header('{}-{}'.format(prefix, 'To'), '')
        message.replace_header('To', to_email)

    if 'Return-Path' in message:
        message.add_header('{}-{}'.format(prefix, 'Return-Path'), message.get('Return-Path'))
        del message['Return-Path']

    if 'Sender' in message:
        message.add_header('{}-{}'.format(prefix, 'Sender'), message.get('Sender'))
        del message['Sender']

    if 'Message-ID' in message:
        message.add_header('{}-{}'.format(prefix, 'Message-ID'), message.get('Message-ID'))
        del message['Message-ID']

    if 'DKIM-Signature' in message:
        #  Remove all DKIM-Signature headers to prevent triggering an
        #  "InvalidParameterValue: Duplicate header 'DKIM-Signature'" error.
        #  These signatures will likely be invalid anyways, since the From header was modified.
        message.add_header('{}-{}'.format(prefix, 'DKIM-Signature'), message.get('DKIM-Signature'))
        del message['DKIM-Signature']

    logger.info('Deleted Return-Path, Sender, Message-ID and DKIM-Signature header.')
    return message


def send_message(original_recipients, forward_mapping, raw_message_data):
    for original_recipient in original_recipients:
        if original_recipient in forward_mapping:
            destinations = forward_mapping.get(original_recipient)
            logger.info("sendMessage: Sending email via SES. Original Recipient: %s. Transformed Recipients: %s",
                        original_recipient, ", ".join(destinations))
            try:
                ses_client.send_raw_email(
                    Source=original_recipient,
                    Destinations=destinations,
                    RawMessage={'Data': raw_message_data}
                )
            except ClientError:
                logger.error("send_raw_email() returned error.", exc_info=True, stack_info=True)
                raise Exception("Error: Email sending failed.")
            logger.info('send_email() successful.')


def handler(event, context, forward_mapping=None, ses_incoming_bucket=None, s3_key_prefix=None,
            from_email=None, to_email=None, subject_prefix=None, ses_region=None):
    initialize(ses_region)
    logger.info('Process started. Event: %s Context: %s', str(event), str(context))
    ses_incoming_bucket = os.environ.get('SES_INCOMING_BUCKET') or ses_incoming_bucket
    s3_key_prefix = os.environ.get('S3_KEY_PREFIX') or s3_key_prefix
    from_email = os.environ.get('FROM_EMAIL') or from_email
    to_email = os.environ.get('TO_EMAIL') or to_email
    subject_prefix = os.environ.get('SUBJECT_PREFIX') or subject_prefix

    ses = extract_ses(event)

    message_key = s3_key_prefix + ses['mail'].get('messageId')
    raw_message = fetch_message(bucket=ses_incoming_bucket, key=message_key)
    message = message_from_bytes(raw_message)
    processed_message = process_message(message,
                                        from_email=from_email, subject_prefix=subject_prefix, to_email=to_email)

    send_message(original_recipients=ses['receipt'].get('recipients'), forward_mapping=forward_mapping,
                 raw_message_data=processed_message.as_bytes())

    logger.info('Process finished successfully. %s', processed_message.as_bytes())
    return raw_message, processed_message.as_bytes()


def lambda_handler(event, context):
    handler(
        event,
        context,
        forward_mapping={'webmaster@sample.com': ['sample@gmail.com', ]},
        ses_incoming_bucket='inbox.sample',
        s3_key_prefix='webmaster/',
        from_email='webmaster@sample.com',
        subject_prefix='[Forward] ',
    )
