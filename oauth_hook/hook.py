# -*- coding: utf-8 -*-
import time
import random
import urllib

from auth import Token, Consumer
from auth import RequestsSignatureMethod_HMAC_SHA1


class OAuthHook(object):
    OAUTH_VERSION = '1.0'
    signature = RequestsSignatureMethod_HMAC_SHA1()

    def __init__(self, access_token=None, access_token_secret=None,
                consumer_key=None, consumer_secret=None,
                auto_oauth_header=True, always_oauth_header=False):
        """
        Consumer is compulsory, while the user's Token can be retrieved through the API
        """
        if access_token is not None and access_token_secret is not None:
            self.token = Token(access_token, access_token_secret)
        else:
            self.token = None

        if consumer_key is None and consumer_secret is None:
            consumer_key = self.consumer_key
            consumer_secret = self.consumer_secret

        self.consumer = Consumer(consumer_key, consumer_secret)

        self.auto_oauth_header = auto_oauth_header
        self.always_oauth_header = always_oauth_header

    @staticmethod
    def authorization_header(oauth_params, realm=''):
        """Return Authorization header"""
        authorization_headers = 'OAuth realm="%s",' % realm
        authorization_headers += ','.join(['{0}="{1}"'.format(k, urllib.quote(str(v)))
            for k, v in oauth_params.items()])
        return {'Authorization': authorization_headers}

    def __call__(self, args):
        """
        Args hook that signs a Python-requests args for OAuth authentication
        """
        params = args.setdefault('params', {})
        data = args.setdefault('data', {})
        headers = args.setdefault('headers', {})

        oauth_params = args.setdefault('oauth_params', {
            'oauth_consumer_key': self.consumer.key,
            'oauth_timestamp': str(int(time.time())),
            'oauth_nonce': str(random.randint(0, 100000000)),
            'oauth_version': self.OAUTH_VERSION,
            'oauth_signature_method': self.signature.name,
        })

        if self.token:
            oauth_params['oauth_token'] = self.token.key
        if hasattr(self.token, 'verifier') and self.token.verifier:
            oauth_params['oauth_verifier'] = self.token.verifier

        oauth_params['oauth_signature'] = self.signature.sign(args, self.consumer, self.token)

        del args['oauth_params']  # remove not needed value in args

        if args['files'] and self.auto_oauth_header or self.always_oauth_header:
            headers.update(self.authorization_header(oauth_params))
        elif args['method'] in ('GET', 'DELETE'):
            params.update(oauth_params)
        else:
            data.update(oauth_params)

        return args
