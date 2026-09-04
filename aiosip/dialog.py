import enum
import asyncio
import logging

from contextlib import suppress

from multidict import CIMultiDict
from collections import defaultdict
from async_timeout import timeout as Timeout

from . import utils
from .auth import AuthenticateAuth, AuthorizationAuth
from .contact import Contact
from .message import Request, Response, CompactHeaderResponse
from .transaction import UnreliableTransaction


LOG = logging.getLogger(__name__)


class CallState(enum.Enum):
    Calling = enum.auto()
    Proceeding = enum.auto()
    Completed = enum.auto()
    Terminated = enum.auto()


class DialogBase:
    def __init__(self,
                 app,
                 method,
                 from_details,
                 to_details,
                 call_id,
                 peer,
                 contact_details,
                 *,
                 headers=None,
                 payload=None,
                 password=None,
                 cseq=0,
                 inbound=False):

        self.app = app
        self.from_details = from_details
        self.to_details = to_details
        self.contact_details = contact_details
        self.call_id = call_id
        self.peer = peer
        self.password = password
        self.cseq = cseq
        self.inbound = inbound
        self.transactions = defaultdict(dict)
        self.auth = None

        # TODO: Needs to be last because we need the above attributes set
        self.original_msg = self._prepare_request(method, headers=headers, payload=payload)

        self._closed = False
        self._closing = None

    @property
    def dialog_id(self):
        return frozenset((self.original_msg.to_details['params'].get('tag'),
                          self.original_msg.from_details['params']['tag'],
                          self.call_id))

    def _receive_response(self, msg):

        if 'tag' not in self.to_details['params'] and 'tag' in msg.to_details['params']:
            del self.app._dialogs[self.dialog_id]
            self.to_details['params']['tag'] = msg.to_details['params']['tag']
            self.app._dialogs[self.dialog_id] = self

        try:
            transaction = self.transactions[msg.method][msg.cseq]
            transaction._incoming(msg)
        except KeyError:
            if msg.method != 'ACK':
                # TODO: Hack to suppress warning on ACK messages,
                # since we don't quite handle them correctly. They're
                # ignored, for now...
                LOG.debug('Response without Request. The Transaction may already be closed. \n%s', msg)

    def _prepare_request(self, method, contact_details=None, headers=None, payload=None, cseq=None, to_details=None):

        if not cseq:
            self.cseq += 1

        if contact_details:
            self.contact_details = contact_details

        headers = CIMultiDict(headers or {})

        if 'User-Agent' not in headers:
            headers['User-Agent'] = self.app.defaults['user_agent']

        headers['Call-ID'] = self.call_id

        msg = Request(
            method=method,
            cseq=cseq or self.cseq,
            from_details=self.from_details,
            to_details=to_details or self.to_details,
            contact_details=self.contact_details,
            headers=headers,
            payload=payload,
        )
        return msg

    async def start(self, *, expires=None, timeout=None):
        # TODO: this is a hack
        headers = self.original_msg.headers
        if expires is not None:
            headers['Expires'] = expires
        return await self.request(self.original_msg.method, headers=headers, payload=self.original_msg.payload,
                                  timeout=timeout)

    def ack(self, msg, headers=None, *, request=None):
        """Acknowledge the final response ``msg`` to the INVITE ``request``.

        ``request`` is the INVITE as it was sent; it defaults to the dialog's
        initial INVITE, which is right for InviteDialog. Transactions pass
        their own sent request so that re-INVITEs and authenticated retries
        are acknowledged against the Via that actually went out.
        """
        headers = CIMultiDict(headers or {})
        if request is None:
            request = self.original_msg

        if msg.status_code >= 300:
            # RFC 3261 section 17.1.1.3: the ACK for a non-2xx final response is
            # part of the INVITE transaction and must carry the INVITE's top Via
            # (same branch). The request's Via is used rather than the
            # response's so that received/rport added by the peer are not copied.
            headers['Via'] = request.headers['Via']
        # else: RFC 3261 section 13.2.2.4 with 8.1.1.7, the ACK for a 2xx is a
        # new transaction; leaving Via unset lets Request build a fresh one
        # (current contact host/port, new branch) the same way as any request.

        ack = self._prepare_request('ACK', cseq=msg.cseq, to_details=msg.to_details, headers=headers)
        self.peer.send_message(ack)

    def _prepare_cancel(self, request, headers=None):
        """Build the CANCEL for ``request`` (RFC 3261 section 9.1).

        Request-URI, Call-ID, To, From and the CSeq number are those of the
        request being cancelled and the single Via must match its top Via, so
        the CANCEL shares the INVITE's branch and CSeq number.
        """
        headers = CIMultiDict(headers or {})
        headers['Via'] = request.headers['Via']
        # The dialog's To object is shared with the sent request and gains the
        # remote tag from the first response; the To header string was fixed
        # when the request was encoded, so it is the one to copy.
        if 'To' in request.headers:
            to_details = Contact.from_header(request.headers['To'])
        else:
            to_details = request.to_details
        return self._prepare_request('CANCEL', cseq=request.cseq, to_details=to_details, headers=headers)

    async def unauthorized(self, msg, realm='sip', algorithm='md5', **kwargs):
        if 'Authorization' not in msg.headers or self.auth is None:
            self.auth = AuthenticateAuth(
                nonce=utils.gen_str(10),
                realm=realm,
                method=msg.method,
                algorithm=algorithm,
                **kwargs
            )

        headers = CIMultiDict()
        headers['WWW-Authenticate'] = str(self.auth)
        await self.reply(msg, status_code=401, headers=headers)

    def validate_auth(self, message, password):
        if isinstance(message.auth, AuthorizationAuth) and self.auth.validate_authorization(
            message.auth,
            password=password,
            username=message.auth['username'],
            uri=message.auth['uri'],
            payload=message.payload
        ):
            return True
        elif message.method == 'CANCEL':
            return True
        else:
            return False

    def close_later(self, delay=None):
        if delay is None:
            delay = self.app.defaults['dialog_closing_delay']
        if self._closing:
            self._closing.cancel()

        async def closure():
            await asyncio.sleep(delay)
            await self.close()

        self._closing = asyncio.ensure_future(closure())
        self._closing.add_done_callback(utils._callback)

    def _maybe_close(self, msg):
        if msg.method in ('REGISTER', 'SUBSCRIBE') and not self.inbound:
            expire = int(msg.headers.get('Expires', 0))
            delay = int(expire * 1.1) if expire else None
            self.close_later(delay)
        elif msg.method == 'NOTIFY':
            pass
        else:
            self.close_later()

    def _close(self):
        LOG.debug('Closing: %s', self)
        if self._closing:
            self._closing.cancel()

        for transactions in self.transactions.values():
            for transaction in transactions.values():
                transaction.close()

        # Should not be necessary once dialog are correctly tracked
        try:
            del self.app._dialogs[self.dialog_id]
        except KeyError as e:
            pass

    def _connection_lost(self):
        for transactions in self.transactions.values():
            for transaction in transactions.values():
                transaction._error(ConnectionError)

    async def start_unreliable_transaction(self, msg, method=None):
        transaction = UnreliableTransaction(self, original_msg=msg, loop=self.app.loop)
        self.transactions[method or msg.method][msg.cseq] = transaction
        return await transaction.start()

    def end_transaction(self, transaction):
        to_delete = list()
        for method, values in self.transactions.items():
            for cseq, t in values.items():
                if transaction is t:
                    transaction.close()
                    to_delete.append((method, cseq))

        for item in to_delete:
            del self.transactions[item[0]][item[1]]

    async def request(self, method, contact_details=None, headers=None, payload=None, timeout=None):
        msg = self._prepare_request(method, contact_details, headers, payload)
        if msg.method != 'ACK':
            async with Timeout(timeout):
                return await self.start_unreliable_transaction(msg)
        else:
            self.peer.send_message(msg)

    async def reply(self, request, status_code, status_message=None, payload=None, headers=None, contact_details=None, compact=None):
        msg = self._prepare_response(request, status_code, status_message, payload, headers, contact_details, compact)
        self.peer.send_message(msg)

    def _prepare_response(self, request, status_code, status_message=None, payload=None, headers=None,
                          contact_details=None, compact=None):

        if compact is None:
            compact = False
        if contact_details:
            self.contact_details = contact_details

        headers = CIMultiDict(headers or {})

        if 'User-Agent' not in headers:
            headers['User-Agent'] = self.app.defaults['user_agent']

        headers['Call-ID'] = self.call_id
        headers['Via'] = request.headers['Via']

        if not compact:
            msg = Response(
                status_code=status_code,
                status_message=status_message,
                headers=headers,
                from_details=self.to_details,
                to_details=self.from_details,
                contact_details=self.contact_details,
                payload=payload,
                cseq=request.cseq,
                method=request.method
            )
        else:
            msg = CompactHeaderResponse(
                status_code=status_code,
                status_message=status_message,
                headers=headers,
                from_details=self.to_details,
                to_details=self.from_details,
                contact_details=self.contact_details,
                payload=payload,
                cseq=request.cseq,
                method=request.method
            )
        return msg

    def __repr__(self):
        return f'<{self.__class__.__name__} call_id={self.call_id}, peer={self.peer}>'

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc_info):
        await self.close()

    def __aiter__(self):
        return self

    async def __anext__(self):
        return await self.recv()


class Dialog(DialogBase):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self._nonce = None
        self._incoming = asyncio.Queue()

    async def receive_message(self, msg):
        if self._closing:
            self._closing.cancel()

        if self.cseq < msg.cseq:
            self.cseq = msg.cseq

        if isinstance(msg, Response) or msg.method == 'ACK':
            return self._receive_response(msg)
        else:
            return await self._receive_request(msg)

    async def _receive_request(self, msg):

        if 'tag' in msg.to_details['params']:
            try:
                del self.app._dialogs[
                    frozenset((self.original_msg.to_details['params'].get('tag'),
                               None,
                               self.call_id))
                ]
            except KeyError:
                pass

        await self._incoming.put(msg)
        self._maybe_close(msg)

    async def refresh(self, headers=None, expires=1800, *args, **kwargs):
        headers = CIMultiDict(headers or {})
        if 'Expires' not in headers:
            headers['Expires'] = int(expires)
        return await self.request(self.original_msg.method, headers=headers, *args, **kwargs)

    async def close(self, headers=None, fast=False, *args, **kwargs):
        if not self._closed:
            self._closed = True
            result = None
            if not fast and not self.inbound and self.original_msg.method in ('REGISTER', 'SUBSCRIBE'):
                headers = CIMultiDict(headers or {})
                if 'Expires' not in headers:
                    headers['Expires'] = 0
                try:
                    result = await self.request(self.original_msg.method, headers=headers, *args, **kwargs)
                finally:
                    self._close()

            self._close()
            return result

    async def notify(self, *args, headers=None, **kwargs):
        headers = CIMultiDict(headers or {})

        if 'Event' not in headers:
            headers['Event'] = 'dialog'

        if 'Content-Type' not in headers:
            headers['Content-Type'] = 'application/dialog-info+xml'

        if 'Subscription-State' not in headers:
            headers['Subscription-State'] = 'active'

        return await self.request('NOTIFY', *args, headers=headers, **kwargs)

    def _pending_invite(self, cseq=None):
        """Return the sent INVITE that is still awaiting its final response.

        With ``cseq`` the INVITE with that CSeq number is required; without it
        the most recent pending INVITE is returned, None when there is none.
        """
        pending = self.transactions.get('INVITE', {})
        if cseq is not None:
            if cseq not in pending:
                raise ValueError('No pending INVITE transaction with CSeq {}'.format(cseq))
            return pending[cseq].original_msg
        if pending:
            return pending[max(pending)].original_msg
        return None

    def cancel(self, *args, request=None, **kwargs):
        """Send a CANCEL for ``request``, or for the pending INVITE.

        ``cseq=`` selects which pending INVITE to cancel. The dialog's initial
        request is a template that is never sent, so it is not used as a
        fallback. Without any pending INVITE the previous behaviour of
        building a plain CANCEL from the arguments is kept.
        """
        if request is None:
            request = self._pending_invite(kwargs.pop('cseq', None))

        if request is not None:
            cancel = self._prepare_cancel(request, headers=kwargs.get('headers'))
        else:
            cancel = self._prepare_request('CANCEL', *args, **kwargs)
        self.peer.send_message(cancel)

    async def recv(self):
        return await self._incoming.get()


class InviteDialog(DialogBase):
    def __init__(self, *args, **kwargs):

        if 'method' not in kwargs:
            kwargs['method'] = 'INVITE'
        elif kwargs['method'] != 'INVITE':
            raise ValueError('method must be INVITE')

        super().__init__(*args, **kwargs)

        self._queue = asyncio.Queue()
        self._state = CallState.Calling
        self._waiter = asyncio.Future()
        self._auth_attempts = 3

    async def receive_message(self, msg):  # noqa: C901
        if 'tag' not in self.to_details['params'] and 'tag' in msg.to_details['params']:
            del self.app._dialogs[self.dialog_id]
            self.to_details['params']['tag'] = msg.to_details['params']['tag']
            self.app._dialogs[self.dialog_id] = self

        async def set_result(msg):
            self.ack(msg)
            if not self._waiter.done():
                self._waiter.set_result(msg)

        async def handle_final_response(msg):
            # RFC 3261 section 8.1.3.2: an unrecognised 2xx is treated as 200
            if 200 <= msg.status_code < 300:
                self._state = CallState.Terminated
                await set_result(msg)

            elif 300 <= msg.status_code < 700:
                self._state = CallState.Completed
                await set_result(msg)

        async def handle_calling_state(msg):
            if 100 <= msg.status_code < 200:
                self._state = CallState.Proceeding
            else:
                await handle_final_response(msg)

        async def handle_proceeding_state(msg):
            if 100 <= msg.status_code < 200:
                pass
            else:
                await handle_final_response(msg)

        if isinstance(msg, Response):
            initial_invite_response = msg.method == 'INVITE' and msg.cseq == self.original_msg.cseq
            if not initial_invite_response:
                # Response to a request sent inside the dialog (CANCEL, BYE,
                # re-INVITE, ...): it belongs to that transaction and is not
                # a call progress message to be passed up.
                return self._receive_response(msg)

            if self._state in (CallState.Completed, CallState.Terminated):
                # RFC 3261 sections 17.1.1.3 and 13.2.2.4: a retransmitted final
                # response (our ACK was lost) is acknowledged again, and is not
                # passed up a second time.
                if msg.status_code >= 200:
                    self.ack(msg)
                return

            if msg.status_code in (401, 407) and msg.auth and self._retry_with_auth(msg):
                return

        await self._queue.put(msg)

        # TODO: sip timers and flip to Terminated after timeout?
        if self._state == CallState.Calling:
            await handle_calling_state(msg)

        elif self._state == CallState.Proceeding:
            await handle_proceeding_state(msg)

        else:
            # Completed or Terminated: only requests from the peer reach here
            # (BYE, ...), responses returned above.
            if msg.method == 'ACK':
                return self._receive_response(msg)
            else:
                return await self._receive_request(msg)

    def _retry_with_auth(self, msg):
        """Re-send the initial INVITE with credentials after a 401/407.

        The initial INVITE is sent outside any transaction (see ``start()``),
        so ``FutureTransaction._handle_authenticate`` never sees its
        challenge. Returns True when a retry was sent.

        TODO: running the initial INVITE through an UnreliableTransaction the
        way ``Dialog.request()`` does would fold this, the CSeq based routing
        above and the re-ACK special case into the transaction layer.
        """
        if self.password is None:
            return False

        self._auth_attempts -= 1
        if self._auth_attempts < 1:
            return False

        # RFC 3261 17.1.1.3: the challenge is a final response and is ACKed
        # before the request is re-sent as a new transaction.
        self.ack(msg)

        previous = self.original_msg
        headers = CIMultiDict(previous.headers)
        for name in ('Via', 'CSeq', 'Content-Length', 'Authorization', 'Proxy-Authorization'):
            headers.popall(name, None)

        # Same To as sent: the dialog's Contact may already carry the
        # challenge's tag (RFC 3261 8.1.3.5).
        if 'To' in previous.headers:
            to_details = Contact.from_header(previous.headers['To'])
        else:
            to_details = previous.to_details

        retry = self._prepare_request(previous.method, headers=headers, payload=previous.payload,
                                      to_details=to_details)
        header = 'Proxy-Authorization' if msg.status_code == 407 else 'Authorization'
        retry.headers[header] = msg.auth.generate_authorization(
            username=previous.from_details['uri']['user'],
            password=self.password,
            payload=msg.payload,
            uri=to_details['uri'].short_uri()
        )

        # Responses are routed by the initial INVITE's CSeq, so the retry
        # becomes the request this dialog is waiting on.
        self.original_msg = retry
        self._state = CallState.Calling
        self.peer.send_message(retry)
        return True

    async def _receive_request(self, msg):
        if 'tag' in msg.from_details['params']:
            self.to_details['params']['tag'] = msg.from_details['params']['tag']

        if msg.method == 'BYE':
            self._closed = True

        self._maybe_close(msg)

    @property
    def state(self):
        return self._state

    async def start(self, *, expires=None):
        # TODO: this is a hack
        self.peer.send_message(self.original_msg)

    async def recv(self):
        return await self._queue.get()

    async def wait_for_terminate(self, timeout=10):
        try:
            while not (self._waiter.done() and self._queue.empty()):
                yield await asyncio.wait_for(self._queue.get(), timeout)
        except asyncio.TimeoutError:
            LOG.warning("Timeout during wait a response from the server")

    async def ready(self):
        msg = await self._waiter
        if msg.status_code != 200:
            raise RuntimeError("INVITE failed with {}".format(msg.status_code))

    def end_transaction(self, transaction):
        to_delete = list()
        for method, values in self.transactions.items():
            for cseq, t in values.items():
                if transaction is t:
                    transaction.close()
                    to_delete.append((method, cseq))

        for item in to_delete:
            del self.transactions[item[0]][item[1]]

    async def close(self, timeout=None):
        if not self._closed:
            self._closed = True

            msg = None
            if self._state == CallState.Terminated:
                msg = self._prepare_request('BYE')
            elif self._state != CallState.Completed:
                msg = self._prepare_cancel(self.original_msg)

            if msg:
                transaction = UnreliableTransaction(self, original_msg=msg, loop=self.app.loop)
                self.transactions[msg.method][msg.cseq] = transaction

                try:
                    async with Timeout(timeout):
                        await transaction.start()
                        if msg.method == 'CANCEL':
                            # RFC 3261 section 9.1: the 200 to the CANCEL does not
                            # end the INVITE transaction. Its final response
                            # (normally 487) still has to arrive and be ACKed, so
                            # the dialog must stay registered until then. 64*T1
                            # is how long the UAS retransmits that response.
                            with suppress(asyncio.TimeoutError):
                                await asyncio.wait_for(asyncio.shield(self._waiter), timeout=64 * 0.5)
                finally:
                    self._close()

        self._close()
