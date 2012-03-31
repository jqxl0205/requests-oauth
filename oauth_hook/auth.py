import binascii
import hmac
import random
import urllib
from urlparse import urlparse, urlunparse, parse_qs
try:
    from hashlib import sha1
    sha = sha1
except ImportError:
    # hashlib was added in Python 2.5
    import sha

escape = lambda url: urllib.quote(to_utf8(url), safe='~')

def to_utf8(x):
    """
    Tries to utf-8 encode x when possible

    If x is a string returns it encoded, otherwise tries to iter x and
    encode utf-8 all strings it contains, returning a list.
    """
    if isinstance(x, basestring):
        return x.encode('utf-8') if isinstance(x, unicode) else x
    try:
        l = iter(x)
    except TypeError:
        return x
    return [to_utf8(i) for i in l]

generate_verifier = lambda length=8: ''.join([str(random.randint(0, 9)) for i in xrange(length)])


class OAuthObject(object):
    key = secret = None

    def __init__(self, key, secret):
        self.key, self.secret = key, secret
        if None in (self.key, self.secret):
            raise ValueError("Key and secret must be set.")


class Consumer(OAuthObject):
    pass


class Token(OAuthObject):
    callback = callback_confirmed = verifier = None

    def set_callback(self, callback):
        self.callback = callback
        self.callback_confirmed = True

    def set_verifier(self, verifier=None):
        if verifier is None:
            verifier = generate_verifier()
        self.verifier = verifier

    def get_callback_url(self):
        if self.callback and self.verifier:
            # Append the oauth_verifier.
            parts = urlparse(self.callback)
            scheme, netloc, path, params, query, fragment = parts[:6]
            if query:
                query = '%s&oauth_verifier=%s' % (query, self.verifier)
            else:
                query = 'oauth_verifier=%s' % self.verifier
            return urlunparse((scheme, netloc, path, params,
                query, fragment))
        return self.callback


class SignatureMethod_HMAC_SHA1(object):
    """
    This is a barebones implementation of a signature method only suitable for use
    for signing OAuth HTTP requests as a hook to requests library.
    """
    name = 'HMAC-SHA1'

    def check(self, request, consumer, token, signature):
        """Returns whether the given signature is the correct signature for
        the given consumer and token signing the given request."""
        built = self.sign(request, consumer, token)
        return built == signature

    def signing_base(self, request, consumer, token):
        pass

    def sign(self, request, consumer, token):
        """Builds the base signature string."""
        key, raw = self.signing_base(request, consumer, token)
        hashed = hmac.new(key, raw, sha)
        # Calculate the digest base 64.
        return binascii.b2a_base64(hashed.digest())[:-1]


class RequestsSignatureMethod_HMAC_SHA1(SignatureMethod_HMAC_SHA1):
    def signing_base(self, args, consumer, token):
        """
        This method generates the OAuth signature. It's defined here to avoid circular imports.
        """

        sig = (
            escape(args['method']),
            escape(self.get_normalized_url(args['url'])),
            escape(self.get_normalized_parameters(args)),
        )

        key = '%s&' % escape(consumer.secret)
        if token is not None:
            key += escape(token.secret)
        raw = '&'.join(sig)

        return key, raw

    def get_normalized_parameters(self, args):
        """
        Returns a string that contains the parameters that must be signed.
        This function is called by SignatureMethod subclass CustomSignatureMethod_HMAC_SHA1
        """

        data_and_params = dict(args['data'].items() + args['params'].items() +
                               args['oauth_params'].items())
        for key, value in data_and_params.items():
            data_and_params[to_utf8(key)] = to_utf8(value)

        if data_and_params.has_key('oauth_signature'):
            del data_and_params['oauth_signature']

        items = []
        for key, value in data_and_params.iteritems():
            # 1.0a/9.1.1 states that kvp must be sorted by key, then by value,
            # so we unpack sequence values into multiple items for sorting.
            if isinstance(value, basestring):
                items.append((key, value))
            else:
                try:
                    value = list(value)
                except TypeError, e:
                    assert 'is not iterable' in str(e)
                    items.append((key, value))
                else:
                    items.extend((key, item) for item in value)

        # Include any query string parameters included in the url
        query_string = urlparse(args['url'])[4]
        items.extend([(to_utf8(k), to_utf8(v)) for k, v in self._split_url_string(query_string).items()])
        items.sort()

        return urllib.urlencode(items).replace('+', '%20').replace('%7E', '~')

    def get_normalized_url(self, url):
        """
        Returns a normalized url, without params
        """
        scheme, netloc, path, params, query, fragment = urlparse(url)

        # Exclude default port numbers.
        if scheme == 'http' and netloc[-3:] == ':80':
            netloc = netloc[:-3]
        elif scheme == 'https' and netloc[-4:] == ':443':
            netloc = netloc[:-4]
        if scheme not in ('http', 'https'):
            raise ValueError("Unsupported URL %s (%s)." % (url, scheme))

        # Normalized URL excludes params, query, and fragment.
        return urlunparse((scheme, netloc, path, None, None, None))

    def _split_url_string(self, query_string):
        """
        Turns a `query_string` into a Python dictionary with unquoted values
        """
        parameters = parse_qs(to_utf8(query_string), keep_blank_values=True)
        for k, v in parameters.iteritems():
            parameters[k] = urllib.unquote(v[0])
        return parameters
