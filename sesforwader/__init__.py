"""
Python package for forwarding Amazon SES E-mail to E-mail address
:copyright: (c) 2018 Yusuke Hayashi
:license: MIT, see LICENSE for more details.
"""

from sesforwader.sesforwader import handler, send_message, process_message, fetch_message, extract_ses, initialize

__title__ = 'mcmder'
__author__ = 'Yusuke Hayashi'
__license__ = 'MIT'
__copyright__ = 'Copyright 2018 Yusuke Hayashi'
__version__ = '0.1.0'
__all__ = [handler, send_message, process_message, fetch_message, extract_ses, initialize]
