import asyncio
import logging

import aiosip
from multidict import CIMultiDict

from .auth import Auth
from .contact import Contact
from .exceptions import AuthentificationFailed


# Which challenge answers which credential header (RFC 3261 sections 22.2-22.3)
CHALLENGE_HEADER = {
    'Authorization': 'WWW-Authenticate',
    'Proxy-Authorization': 'Proxy-Authenticate',
}


LOG = logging.getLogger(__name__)


class BaseTransaction:
    def __init__(self, dialog, original_msg=None, attempts=3, *, loop=None):
        self.dialog = dialog
        self.original_msg = original_msg
        self.loop = loop or asyncio.get_event_loop()
        self.attempts = attempts
        self.retransmission = None
        self.authentification = None
        self._running = True
        LOG.debug('Creating: %s', self)

    async def start(self):
        raise NotImplementedError

    def _incoming(self, msg):
        if self.retransmission:
            self.retransmission.cancel()
            self.retransmission = None

        if self.authentification and msg.status_code not in (401, 407):
            self.authentification.cancel()
            self.authentification = None

    def _error(self, error):
        raise NotImplementedError

    def _result(self, msg):
        raise NotImplementedError

    def close(self):
        self._running = False
        LOG.debug('Closing %s', self)
        if self.retransmission:
            self.retransmission.cancel()
            self.retransmission = None

    async def _timer(self, timeout=0.5):
        max_timeout = timeout * 64
        while timeout <= max_timeout:
            self.dialog.peer.send_message(self.original_msg)
            await asyncio.sleep(timeout)
            timeout *= 2

        self._error(asyncio.TimeoutError('SIP timer expired for {cseq}, {method}, {call_id}'.format(
            cseq=self.original_msg.cseq,
            method=self.original_msg.method,
            call_id=self.original_msg.headers['Call-ID']
        )))

    def _handle_authenticate(self, msg, header='Authorization'):
        if self.dialog.password is None:
            raise ValueError('Password required for authentication')

        # A response may carry both challenges; answer the one belonging to the
        # header the credential goes into.
        challenge = Auth.from_message(msg, header=CHALLENGE_HEADER[header]) or msg.auth
        if challenge is None:
            self._result(msg)
            return

        self.attempts -= 1
        if self.attempts < 1:
            self._error(AuthentificationFailed('Too many unauthorized attempts!'))
            return
        elif self.authentification:
            self.authentification.cancel()
            self.authentification = None

        if msg.method.upper() == 'REGISTER':
            username = msg.to_details['uri']['user']
        else:
            username = msg.from_details['uri']['user']

        # RFC 3261 sections 8.1.3.5 and 17.1.3: the request re-sent with
        # credentials is a new transaction. Build it through the dialog so it
        # gets a fresh CSeq (keeping dialog.cseq in step) and a fresh Via
        # branch, instead of mutating the request that is already on the wire.
        previous = self.original_msg
        headers = CIMultiDict(previous.headers)
        # Credentials are recomputed for the challenge's nonce; a stale one
        # copied along would be rejected and the retry would loop.
        for name in ('Via', 'CSeq', 'Content-Length', 'Authorization', 'Proxy-Authorization'):
            headers.popall(name, None)
        # RFC 3261 section 8.1.3.5: same Call-ID, To and From as the previous
        # request. The dialog's To object has meanwhile been stamped with the
        # 401's tag, so the To is taken back from the request as it was sent.
        if 'To' in previous.headers:
            to_details = Contact.from_header(previous.headers['To'])
        else:
            to_details = previous.to_details
        retry = self.dialog._prepare_request(previous.method, headers=headers, payload=previous.payload,
                                             to_details=to_details)
        retry.headers[header] = challenge.generate_authorization(
            username=username,
            password=self.dialog.password,
            payload=msg.payload,
            uri=msg.to_details['uri'].short_uri()
        )

        # Re-key the transaction: a retransmitted 401 for the old CSeq must not
        # find us again and trigger another retry.
        self.dialog.transactions[previous.method].pop(previous.cseq, None)
        self.original_msg = retry
        self.dialog.transactions[retry.method][retry.cseq] = self

        # The retry goes out with an untagged To, and RFC 3261 8.2.6.2 lets the
        # UAS pick a fresh tag for it. The dialog is registered under the tag
        # learned from the challenge, and its tagless fallback key was dropped
        # when that tag was learned, so a new tag would match neither. Forget
        # the challenge's tag and re-register so the fallback matches again.
        dialog = self.dialog
        dialog._unregister(dialog.dialog_id)
        dialog.to_details['params'].pop('tag', None)
        dialog._register()

        self.authentification = asyncio.ensure_future(self._timer())

    def _handle_proxy_authenticate(self, msg):
        """Retry with proxy credentials (RFC 3261 section 26.2.4).

        Identical to :meth:`_handle_authenticate` except that the challenge
        comes from Proxy-Authenticate and the answer goes in
        Proxy-Authorization; ``msg.auth`` parses either header.
        """
        return self._handle_authenticate(msg, header='Proxy-Authorization')

    def __repr__(self):
        return '<{0} cseq={1}, method={2}, dialog={3}>'.format(
            self.__class__.__name__, self.original_msg.cseq, self.original_msg.method, self.dialog
        )


class FutureTransaction(BaseTransaction):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._future = self.loop.create_future()

    async def start(self):
        self.retransmission = asyncio.ensure_future(self._timer())
        return await self._future

    def _incoming(self, msg):
        super()._incoming(msg)
        if msg.method == 'ACK':
            self._result(msg)
            return

        status_code = msg.status_code
        if self.original_msg.method.upper() == 'INVITE' and status_code >= 200:
            # RFC 3261 sections 17.1.1.3 and 13.2.2.4: every final response to an
            # INVITE is acknowledged, 2xx and non-2xx alike, a 401/407 that is
            # about to be retried with credentials included.
            self.dialog.ack(msg, request=self.original_msg)

        if status_code == 401 and msg.auth:
            self._handle_authenticate(msg)
        elif status_code == 407 and msg.auth:  # Proxy authentication
            self._handle_proxy_authenticate(msg)
        elif 100 <= status_code < 200:
            pass
        else:
            self._result(msg)

    def _error(self, error):
        if self.authentification:
            self.authentification.cancel()
            self.authentification = None
        if not self._future.done():
            self._future.set_exception(error)
        self.dialog.end_transaction(self)

    def _result(self, msg):
        if self.authentification:
            self.authentification.cancel()
            self.authentification = None
        if not self._future.done():  # the awaiting task may have been cancelled
            self._future.set_result(msg)
        self.dialog.end_transaction(self)

    def close(self):
        if self._running:
            super().close()
            if not self._future.done():
                self._future.cancel()


class UnreliableTransaction(FutureTransaction):
    def close(self):
        if self._running and not self._future.done():
            if type(self.dialog) is aiosip.dialog.InviteDialog:
                self.loop.run_until_complete(self.dialog.close())
            else:
                self.dialog.cancel(request=self.original_msg)
        super().close()
