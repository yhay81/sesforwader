from sesforwader import handler


def lambda_handler(event, context):
    handler(
        event,
        context,
        forward_mapping={'webmaster@sample.com': ['sample@gmail.com', ]},
        ses_incoming_bucket='inbox_sample',
        s3_key_prefix='webmaster/',
        from_email='webmaster@sample.com',
        subject_prefix='[Forward] ',
    )
