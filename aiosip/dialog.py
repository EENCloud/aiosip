import enum
import asyncio
import logging

from multidict import CIMultiDict
from collections import defaultdict
from async_timeout import timeout as Timeout

from . import utils
from .auth import AuthenticateAuth, AuthorizationAuth
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

        if 'tag' not in self.to_details['params']:
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

    def ack(self, msg, headers=None, *args, **kwargs):
        headers = CIMultiDict(headers or {})

        headers['Via'] = msg.headers['Via']
        ack = self._prepare_request('ACK', cseq=msg.cseq, to_details=msg.to_details, headers=headers, *args, **kwargs)
        self.peer.send_message(ack)

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

    def cancel(self, *args, **kwargs):
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

    async def receive_message(self, msg):  # noqa: C901
        if 'tag' not in self.to_details['params'] and 'tag' in msg.to_details['params']:
            del self.app._dialogs[self.dialog_id]
            self.to_details['params']['tag'] = msg.to_details['params']['tag']
            self.app._dialogs[self.dialog_id] = self

        async def set_result(msg):
            self.ack(msg)
            if not self._waiter.done():
                self._waiter.set_result(msg)

        async def handle_calling_state(msg):
            if 100 <= msg.status_code < 200:
                self._state = CallState.Proceeding

            elif msg.status_code == 200:
                self._state = CallState.Terminated
                await set_result(msg)

            elif 300 <= msg.status_code < 700:
                self._state = CallState.Completed
                await set_result(msg)

        async def handle_proceeding_state(msg):
            if 100 <= msg.status_code < 200:
                pass

            elif msg.status_code == 200:
                self._state = CallState.Terminated
                await set_result(msg)

            elif 300 <= msg.status_code < 700:
                self._state = CallState.Completed
                await set_result(msg)

        async def handle_completed_state(msg):
            # Any additional messages in this state MUST be acked but
            # are NOT to be passed up
            self.ack(msg)

        await self._queue.put(msg)

        # TODO: sip timers and flip to Terminated after timeout?
        if self._state == CallState.Calling:
            await handle_calling_state(msg)

        elif self._state == CallState.Proceeding:
            await handle_proceeding_state(msg)

        elif self._state == CallState.Completed:
            await handle_completed_state(msg)

        elif self._state == CallState.Terminated:
            if isinstance(msg, Response) or msg.method == 'ACK':
                return self._receive_response(msg)
            else:
                return await self._receive_request(msg)

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
                msg = self._prepare_request('CANCEL')

            if msg:
                transaction = UnreliableTransaction(self, original_msg=msg, loop=self.app.loop)
                self.transactions[msg.method][msg.cseq] = transaction

                try:
                    async with Timeout(timeout):
                        await transaction.start()
                finally:
                    self._close()

        self._close()
