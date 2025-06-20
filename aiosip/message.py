import logging
import re
import uuid

from pyquery import PyQuery
from multidict import CIMultiDict

from . import utils
from .contact import Contact
from .auth import Auth

FIRST_LINE_PATTERN = {
    'request': {
        'regex': re.compile(r'(?P<method>[A-Za-z]+) (?P<to_uri>.+) SIP/2.0'),
        'str': '{method} {to_uri} SIP/2.0'},
    'response': {
        'regex': re.compile(r'SIP/2.0 (?P<status_code>[0-9]{3}) (?P<status_message>.+)'),
        'str': 'SIP/2.0 {status_code} {status_message}'},
}

# Complete official mapping from RFCs and IANA SIP Parameters Registry
# https://www.iana.org/assignments/sip-parameters/sip-parameters.xhtml
compact_to_long = {
    # Core RFC 3261 compact headers
    'v': 'Via',                    # RFC 3261
    'f': 'From',                   # RFC 3261
    't': 'To',                     # RFC 3261
    'i': 'Call-ID',                # RFC 3261
    'm': 'Contact',                # RFC 3261
    'l': 'Content-Length',         # RFC 3261
    'c': 'Content-Type',           # RFC 3261
    'e': 'Content-Encoding',       # RFC 3261
    's': 'Subject',                # RFC 3261
    'k': 'Supported',              # RFC 3261

    # Extended compact headers from other RFCs
    'x': 'Session-Expires',        # RFC 4028
    'r': 'Refer-To',               # RFC 3515
    'b': 'Referred-By',            # RFC 3892
    'j': 'Reject-Contact',         # RFC 3841
    'a': 'Accept-Contact',         # RFC 3841
    'o': 'Event',                  # RFC 6665
    'u': 'Allow-Events',           # RFC 3265
    'd': 'Request-Disposition',    # RFC 3841
    'y': 'Identity',               # RFC 4474 (deprecated in RFC 8224)
}

long_to_compact = {value: key for key, value in compact_to_long.items()}


LOG = logging.getLogger(__name__)


class Message:
    def __init__(self,
                 headers=None,
                 payload=None,
                 from_details=None,
                 to_details=None,
                 contact_details=None,
                 ):

        if headers:
            self.headers = headers
        else:
            self.headers = CIMultiDict()

        if from_details:
            self._from_details = from_details
        elif 'From' not in self.headers:
            raise ValueError('From header or from_details is required')

        if to_details:
            self._to_details = to_details
        elif 'To' not in self.headers:
            raise ValueError('To header or to_details is required')

        if contact_details:
            self._contact_details = contact_details

        self._payload = payload
        self._raw_payload = None

        if 'Via' not in self.headers:
            self.headers['Via'] = 'SIP/2.0/%(protocol)s ' + \
                utils.format_host_and_port(self.contact_details['uri']['host'],
                                           self.contact_details['uri']['port']) + \
                ';branch=%s' % utils.gen_branch(10)

    @property
    def auth(self):
        if not hasattr(self, '_auth'):
            self._auth = Auth.from_message(self)
        return self._auth

    @property
    def payload(self):
        if self._payload:
            return self._payload
        elif self._raw_payload:
            self._payload = self._raw_payload.decode()
            return self._payload
        else:
            return ''

    @payload.setter
    def payload(self, payload):
        self._payload = payload

    @property
    def from_details(self):
        if not hasattr(self, '_from_details'):
            self._from_details = Contact.from_header(self.headers['From'])
        return self._from_details

    @from_details.setter
    def from_details(self, from_details):
        self._from_details = from_details

    @property
    def to_details(self):
        if not hasattr(self, '_to_details'):
            self._to_details = Contact.from_header(self.headers['To'])
        return self._to_details

    @to_details.setter
    def to_details(self, to_details):
        self._to_details = to_details

    @property
    def contact_details(self):
        if not hasattr(self, '_contact_details'):
            if 'Contact' in self.headers:
                self._contact_details = Contact.from_header(self.headers['Contact'])
            else:
                self._contact_details = None
        return self._contact_details

    @contact_details.setter
    def contact_details(self, contact_details):
        self._contact_details = contact_details

    @property
    def content_type(self):
        return self.headers['Content-Type']

    @content_type.setter
    def content_type(self, content_type):
        self.headers['Content-Type'] = content_type

    @property
    def cseq(self):
        if not hasattr(self, '_cseq'):
            self._cseq = int(self.headers['CSeq'].split(' ')[0])
        return self._cseq

    @cseq.setter
    def cseq(self, cseq):
        self._cseq = int(cseq)

    @property
    def method(self):
        if not hasattr(self, '_method'):
            self._method = self.headers['CSeq'].split(' ')[1]
        return self._method

    @method.setter
    def method(self, method):
        self._method = method

    def __str__(self):
        if self._payload:
            self._raw_payload = self._payload.encode()
        elif not self._raw_payload:
            self._raw_payload = b''

        msg = self._make_headers()
        return msg + self.payload

    def encode(self, *args, **kwargs):
        if self._payload:
            self._raw_payload = self._payload.encode(*args, **kwargs)
        elif not self._raw_payload:
            self._raw_payload = b''

        msg = self._make_headers()
        return msg.encode(*args, **kwargs) + self._raw_payload

    def _make_headers(self):
        if hasattr(self, '_from_details'):
            self.headers['From'] = str(self.from_details)

        if hasattr(self, '_to_details'):
            self.headers['To'] = str(self.to_details)

        if hasattr(self, '_contact_details'):
            self.headers['Contact'] = str(self.contact_details)

        if hasattr(self, '_cseq'):
            self.headers['CSeq'] = '%s %s' % (self.cseq, self.method)
        elif hasattr(self, '_method'):
            self.headers['CSeq'] = '%s %s' % (self.cseq, self.method)

        self.headers['Content-Length'] = str(len(self._raw_payload))
        if 'Max-Forwards' not in self.headers:
            self.headers['Max-Forwards'] = '70'
        if 'Call-ID' not in self.headers:
            self.headers['Call-ID'] = uuid.uuid4()

        return self._format_headers()

    def _format_headers(self):
        msg = []
        for k, v in sorted(self.headers.items()):
            if k == 'Via':
                if isinstance(v, (list, tuple)):
                    msg = ['%s: %s' % (k, i) for i in v] + msg
                else:
                    msg.insert(0, '%s: %s' % (k, v))
            else:
                if isinstance(v, (list, tuple)):
                    msg.extend(['%s: %s' % (k, i) for i in v])
                else:
                    msg.append('%s: %s' % (k, v))
        msg.append(utils.EOL)
        return utils.EOL.join(msg)

    def parsed_xml(self):
        if 'Content-Type' not in self.headers:
            return None
        if not self.headers['Content-Type'].endswith('+xml'):
            return None
        return PyQuery(self.payload).remove_namespaces()

    @classmethod
    def from_raw_headers(cls, raw_headers):
        headers = CIMultiDict()
        decoded_headers = raw_headers.decode().split(utils.EOL)
        for line in decoded_headers[1:]:
            k, v = line.split(': ', 1)
            if k.lower() in compact_to_long:
                k = compact_to_long[k.lower()]
            if k in headers:
                o = headers.setdefault(k, [])
                if not isinstance(o, list):
                    o = [o]
                o.append(v)
                headers[k] = o
            else:
                headers[k] = v

        m = FIRST_LINE_PATTERN['response']['regex'].match(decoded_headers[0])
        if m:
            d = m.groupdict()
            return Response(status_code=int(d['status_code']),
                            status_message=d['status_message'],
                            headers=headers,
                            first_line=decoded_headers[0])
        else:
            m = FIRST_LINE_PATTERN['request']['regex'].match(decoded_headers[0])
            if m:
                d = m.groupdict()
                cseq, _ = headers['CSeq'].split()
                return Request(method=d['method'],
                               headers=headers,
                               cseq=int(cseq),
                               first_line=decoded_headers[0])
            else:
                LOG.debug(decoded_headers)
                raise ValueError('Not a SIP message')


class Request(Message):
    def __init__(self,
                 method,
                 cseq,
                 from_details=None,
                 to_details=None,
                 contact_details=None,
                 headers=None,
                 payload=None,
                 first_line=None
                 ):

        super().__init__(
            headers=headers,
            payload=payload,
            from_details=from_details,
            to_details=to_details,
            contact_details=contact_details
        )

        self._method = method.upper()
        self._cseq = cseq

        if not first_line:
            self._first_line = FIRST_LINE_PATTERN['request']['str'].format(
                method=self.method,
                to_uri=str(self.to_details['uri'].short_uri())
            )
        else:
            self._first_line = first_line

    @property
    def to_details(self):
        if not hasattr(self, '_to_details'):
            self._to_details = Contact.from_header(self.headers['To'])
        return self._to_details

    @to_details.setter
    def to_details(self, to_details):
        self._to_details = to_details
        self._first_line = FIRST_LINE_PATTERN['request']['str'].format(method=self.method,
                                                                       to_uri=str(self._to_details['uri'].short_uri()))

    def __str__(self):
        return '%s%s%s' % (self._first_line, utils.EOL, super().__str__())

    def encode(self, *args, **kwargs):
        return self._first_line.encode(*args, **kwargs) + utils.BYTES_EOL + super().encode(*args, **kwargs)


class Response(Message):
    def __init__(self,
                 status_code,
                 status_message=None,
                 headers=None,
                 from_details=None,
                 to_details=None,
                 contact_details=None,
                 payload=None,
                 cseq=None,
                 method=None,
                 first_line=None
                 ):

        super().__init__(
            headers=headers,
            payload=payload,
            from_details=from_details,
            to_details=to_details,
            contact_details=contact_details
        )

        if not status_message:
            status_message = utils.STATUS[int(status_code)]

        if cseq:
            self._cseq = cseq
        elif 'CSeq' not in self.headers:
            raise ValueError('"CSeq" header or cseq is required')

        if method:
            self._method = method
        elif 'CSeq' not in self.headers:
            raise ValueError('"CSeq" header or method is required')

        self._status_code = status_code
        self._status_message = status_message

        if not first_line:
            self._first_line = FIRST_LINE_PATTERN['response']['str'].format(
                status_code=self._status_code,
                status_message=self._status_message
            )
        else:
            self._first_line = first_line

    @property
    def status_code(self):
        return self._status_code

    @status_code.setter
    def status_code(self, status_code):
        self._status_code = status_code
        self._first_line = FIRST_LINE_PATTERN['response']['str'].format(
            status_code=self._status_code,
            status_message=self._status_message
        )

    @property
    def status_message(self):
        return self._status_message

    @status_message.setter
    def status_message(self, status_message):
        self._status_message = status_message
        self._first_line = FIRST_LINE_PATTERN['response']['str'].format(
            status_code=self._status_code,
            status_message=self._status_message
        )

    @classmethod
    def from_request(cls, request, status_code, status_message, payload=None, headers=None):

        if not headers:
            headers = CIMultiDict()

        if 'Via' not in headers:
            headers['Via'] = request.headers['Via']

        return Response(
            status_code=status_code,
            status_message=status_message,
            cseq=request.cseq,
            method=request.method,
            headers=headers,
            from_details=request.from_details,
            to_details=request.to_details,
            contact_details=request.contact_details,
            payload=payload,
        )

    def __str__(self):
        return '%s%s%s' % (self._first_line, utils.EOL, super().__str__())

    def encode(self, *args, **kwargs):
        return self._first_line.encode(*args, **kwargs) + utils.BYTES_EOL + super().encode(*args, **kwargs)

class CompactHeaderResponse(Response):
    def _format_headers(self):
        msg = []
        for k, v in sorted(self.headers.items()):
            if k == 'Via':
                if k in long_to_compact:
                    k = long_to_compact[k]
                if isinstance(v, (list, tuple)):
                    msg = ['%s: %s' % (k, i) for i in v] + msg
                else:
                    msg.insert(0, '%s: %s' % (k, v))
            else:
                if k in long_to_compact:
                    k = long_to_compact[k]
                if isinstance(v, (list, tuple)):
                    msg.extend(['%s: %s' % (k, i) for i in v])
                else:
                    msg.append('%s: %s' % (k, v))
        msg.append(utils.EOL)
        return utils.EOL.join(msg)