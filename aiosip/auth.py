from collections.abc import MutableMapping
from enum import Enum
from hashlib import md5
import logging

from . import utils


LOG = logging.getLogger(__name__)


class Algorithm(Enum):
    MD5 = 'md5'
    MD5Sess = 'md5-sess'


class Directive(Enum):
    Unspecified = ''
    Auth = 'auth'
    AuthInt = 'auth-int'


def md5digest(*args):
    return md5(':'.join(args).encode()).hexdigest()


class Auth(MutableMapping):
    def __init__(self, mode='Digest', **kwargs):
        self._auth = kwargs
        self.mode = mode

        if self.mode != 'Digest':
            raise ValueError('Authentication method not supported')

    def __str__(self, **kwargs):
        if not kwargs:
            kwargs = self._auth

        if self.mode == 'Digest':
            r = 'Digest '
            args = []
            for k, v in kwargs.items():
                if k == 'algorithm':
                    args.append('%s=%s' % (k, v))
                else:
                    args.append('%s="%s"' % (k, v))
            r += ', '.join(args)
        else:
            raise ValueError('Authentication method not supported')
        return r

    @classmethod
    def from_authorization_header(cls, authorization, method):
        if authorization.startswith('Digest'):
            params = {'method': method}
            params.update(cls.__parse_digest(authorization))
            auth = AuthorizationAuth(mode='Digest', **params)
        else:
            raise ValueError('Authentication method not supported')
        return auth

    @classmethod
    def from_authenticate_header(cls, authenticate, method):
        if authenticate.startswith('Digest'):
            params = {'method': method}
            params.update(cls.__parse_digest(authenticate))
            auth = AuthenticateAuth(mode='Digest', **params)
        else:
            raise ValueError('Authentication method not supported')
        return auth

    @classmethod
    def _parse_first_supported(cls, message, header, parse):
        """Parse the first value of ``header`` that ``parse`` understands.

        A header may appear more than once, in which case Message collapses the
        values into a list: RFC 8760 servers offer several Digest algorithms
        that way. Unsupported schemes are skipped rather than raised so that a
        challenge this library cannot answer leaves the response to its normal
        handling instead of breaking the dispatch that is delivering it.
        """
        if header not in message.headers:
            return None

        values = message.headers[header]
        if not isinstance(values, (list, tuple)):
            values = [values]

        for value in values:
            if not isinstance(value, str):
                continue
            try:
                return parse(value, message.method)
            except ValueError:
                continue
        return None

    @classmethod
    def from_message(cls, message, header=None):
        """Parse the challenge or credential carried by ``message``.

        Returns None when there is nothing parseable to answer.

        ``header`` names the one to read, for a response that carries both a
        WWW-Authenticate and a Proxy-Authenticate challenge: answering the
        wrong one loops until the attempts run out.
        """
        if header is not None:
            return cls._parse_first_supported(message, header, cls.from_authenticate_header)

        if 'Authorization' in message.headers:
            return cls._parse_first_supported(message, 'Authorization', cls.from_authorization_header)
        elif 'WWW-Authenticate' in message.headers:
            return cls._parse_first_supported(message, 'WWW-Authenticate', cls.from_authenticate_header)
        elif 'Proxy-Authenticate' in message.headers:
            return cls._parse_first_supported(message, 'Proxy-Authenticate', cls.from_authenticate_header)
        else:
            return None

    @classmethod
    def __parse_digest(cls, header):
        params = {}
        for arg in header[7:].split(','):
            k, v = arg.strip().split('=', 1)
            if '="' in arg:
                v = v[1:-1]
            params[k] = v
        return params

    def _calculate_response(self, password, payload, username=None, uri=None, cnonce=None, nonce_count=None):
        if self.mode != 'Digest':
            raise ValueError('Authentication method not supported')

        algorithm = Algorithm(self.get('algorithm', 'md5').lower())
        qop = Directive(self.get('qop', '').lower())

        if username is None:
            username = self['username']
        if uri is None:
            uri = self['uri']

        ha1 = md5digest(username, self['realm'], password)
        if algorithm is Algorithm.MD5Sess:
            ha1 = md5digest(ha1, self['nonce'], cnonce or self['cnonce'])

        if qop is Directive.AuthInt:
            ha2 = md5digest(self['method'], uri, md5digest(payload))
        else:
            ha2 = md5digest(self['method'], uri)

        # If there's no quality of prootection specified, we can return early,
        # our computation is much simpler
        if qop is Directive.Unspecified:
            return md5digest(ha1, self['nonce'], ha2)

        return md5digest(
            ha1,
            self['nonce'],
            nonce_count or self['nc'],
            cnonce or self['cnonce'],
            self['qop'],
            ha2)

    # MutableMapping API
    def __eq__(self, other):
        return self is other

    def __getitem__(self, key):
        return self._auth[key]

    def __setitem__(self, key, value):
        self._auth[key] = value

    def __delitem__(self, key):
        del self._auth[key]

    def __len__(self):
        return len(self._auth)

    def __iter__(self):
        return iter(self._auth)


class AuthenticateAuth(Auth):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    def generate_authorization(self, username, password, uri, payload=''):
        auth = AuthorizationAuth(mode=self.mode, uri=uri, username=username, response=None, **self)
        auth['response'] = auth._calculate_response(
            password=password,
            payload=payload
        )
        return auth

    def validate_authorization(self, authorization_auth, password, username, uri, payload=''):
        response = self._calculate_response(
                uri=uri,
                payload=payload,
                password=password,
                username=username,
                cnonce=authorization_auth.get('cnonce'),
                nonce_count=authorization_auth.get('nc')
            )

        return response == authorization_auth['response']

    def __str__(self):
        kwargs = {k: v for k, v in self._auth.items() if k != 'method'}
        return super().__str__(**kwargs)


class AuthorizationAuth(Auth):

    def __init__(self, *args, **kwargs):
        self.nc = 0

        if 'response' not in kwargs:
            raise ValueError('No authentication response')

        super().__init__(*args, **kwargs)

    def _calculate_response(self, password, username=None, uri=None, payload='', cnonce=None, nonce_count=None):
        if cnonce:
            self.nc = nonce_count or self.nc + 1
            self['nc'] = str(self.nc)
            self['cnonce'] = cnonce
        elif not cnonce and (
            self.get('algorithm') == 'md5-sess' or
            self.get('qop', '').lower() in ('auth', 'auth-int')
        ):
            self.nc = nonce_count or self.nc + 1
            self['nc'] = str(self.nc)
            self['cnonce'] = utils.gen_str(10)

        return super()._calculate_response(
            password=password,
            username=username,
            uri=uri,
            payload=payload,
            cnonce=self.get('cnonce'),
            nonce_count=self.get('nc')
        )
