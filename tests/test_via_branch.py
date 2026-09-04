import asyncio
import collections
import re

import pytest

import aiosip
from aiosip import utils


def branch_of(message):
    via = message.headers['Via']
    if isinstance(via, list):
        via = via[0]
    return re.search(r'branch=([^;,\s]+)', via).group(1)


def sent_by_of(message):
    via = message.headers['Via']
    if isinstance(via, list):
        via = via[0]
    return via.split(';')[0]


def record_requests(server_app, received_messages, futures_by_method=None):
    """Record every request the server receives, in order, at dispatch level.

    The server dialog does not hand ACK to the dialplan, so this is the only
    place to observe what really arrived on the wire.

    ``futures_by_method`` maps a method to a future resolved when it arrives,
    or to a ``(count, future)`` pair to wait for the count-th one.
    """
    original_dispatch = server_app._dispatch
    seen = collections.Counter()

    async def recording_dispatch(protocol, msg, addr):
        if isinstance(msg, aiosip.message.Request):
            received_messages.append(msg)
            seen[msg.method] += 1
            entry = (futures_by_method or {}).get(msg.method)
            if isinstance(entry, tuple):
                wanted, future = entry
            else:
                wanted, future = 1, entry
            if future is not None and seen[msg.method] >= wanted and not future.done():
                future.set_result(None)
        return await original_dispatch(protocol, msg, addr)

    server_app._dispatch = recording_dispatch


def test_gen_branch_has_magic_cookie_and_is_unique():
    branches = {utils.gen_branch() for _ in range(200)}
    assert len(branches) == 200
    for branch in branches:
        assert branch.startswith(utils.BRANCH_MAGIC_COOKIE)
        assert len(branch) == len(utils.BRANCH_MAGIC_COOKIE) + 16


async def test_authentication_retry_is_a_new_transaction(test_server, protocol, loop, from_details, to_details):
    password = 'abcdefg'
    received_messages = list()

    class Dialplan(aiosip.BaseDialplan):

        async def resolve(self, *args, **kwargs):
            await super().resolve(*args, **kwargs)
            return self.subscribe

        async def subscribe(self, request, message):
            dialog = request._create_dialog()
            received_messages.append(message)
            # The 401 is sent twice, identical, as a UAS retransmitting over
            # UDP would. The duplicate must not trigger a second retry.
            await dialog.unauthorized(message)
            await dialog.reply(message, status_code=401, headers={'WWW-Authenticate': str(dialog.auth)})

            async for message in dialog:
                received_messages.append(message)
                if dialog.validate_auth(message=message, password=password):
                    await dialog.reply(message, 200)
                else:
                    await dialog.unauthorized(message)

    app = aiosip.Application(loop=loop)
    server_app = aiosip.Application(loop=loop, dialplan=Dialplan())
    server = await test_server(server_app)

    peer = await app.connect(
        protocol=protocol,
        remote_addr=(server.sip_config['server_host'], server.sip_config['server_port'])
    )
    dialog = await peer.subscribe(
        expires=1800,
        from_details=aiosip.Contact.from_header(from_details),
        to_details=aiosip.Contact.from_header(to_details),
        headers={'X-Custom': 'kept'},
        password=password
    )
    await asyncio.sleep(0.1)

    assert len(received_messages) == 2
    first, retry = received_messages
    assert 'Authorization' in retry.headers
    # RFC 3261 8.1.3.5: the request with credentials is a new transaction
    assert retry.cseq == first.cseq + 1
    assert branch_of(retry) != branch_of(first)
    assert branch_of(retry).startswith(utils.BRANCH_MAGIC_COOKIE)
    assert sent_by_of(retry) == sent_by_of(first)
    # RFC 3261 8.1.3.5: same To as the previous request, i.e. still untagged
    assert 'tag' not in retry.to_details['params']
    assert retry.headers['To'] == first.headers['To']
    # the original headers travel with the retry and the dialog keeps counting
    assert retry.headers['X-Custom'] == 'kept'
    assert retry.headers['Expires'] == '1800'
    assert dialog.cseq == retry.cseq

    await app.close()
    await server_app.close()


async def invite_scenario(test_server, protocol, loop, from_details, to_details, status_code):
    """INVITE -> final response -> ACK (-> BYE for a 2xx); return the requests the server received."""
    received_messages = list()
    futures = {'ACK': loop.create_future()}

    class Dialplan(aiosip.BaseDialplan):

        async def resolve(self, *args, **kwargs):
            await super().resolve(*args, **kwargs)
            return self.invite

        async def invite(self, request, message):
            # request.prepare() closes the dialog for a non-2xx; reply through
            # the dialog directly so that both response classes are handled alike.
            dialog = request._create_dialog()
            await dialog.reply(message, status_code=status_code)
            async for message in dialog:
                if message.method == 'BYE':
                    await dialog.reply(message, 200)
                    break

    app = aiosip.Application(loop=loop)
    server_app = aiosip.Application(loop=loop, dialplan=Dialplan())
    record_requests(server_app, received_messages, futures)
    server = await test_server(server_app)

    peer = await app.connect(
        protocol=protocol,
        remote_addr=(server.sip_config['server_host'], server.sip_config['server_port'])
    )
    call = await peer.invite(
        from_details=aiosip.Contact.from_header(from_details),
        to_details=aiosip.Contact.from_header(to_details),
        headers={'Content-Type': 'application/sdp'},
        payload='v=0\r\n',
    )
    responses = list()
    async for msg in call.wait_for_terminate(timeout=2):
        responses.append(msg.status_code)
    await asyncio.wait_for(futures['ACK'], timeout=2)
    await call.close(timeout=2)
    await asyncio.sleep(0.1)

    await app.close()
    await server_app.close()
    return received_messages, responses


async def test_ack_for_2xx_uses_new_branch(test_server, protocol, loop, from_details, to_details):
    messages, responses = await invite_scenario(test_server, protocol, loop, from_details, to_details, 200)
    by_method = {m.method: m for m in messages}
    assert {'INVITE', 'ACK', 'BYE'} <= set(by_method)
    invite, ack, bye = by_method['INVITE'], by_method['ACK'], by_method['BYE']

    # RFC 3261 13.2.2.4 / 8.1.1.7: ACK for 2xx is its own transaction
    assert ack.cseq == invite.cseq
    assert branch_of(ack) != branch_of(invite)
    assert branch_of(ack).startswith(utils.BRANCH_MAGIC_COOKIE)
    assert sent_by_of(ack) == sent_by_of(invite)
    # BYE is another new transaction
    assert branch_of(bye) not in (branch_of(invite), branch_of(ack))
    # only INVITE responses are passed up; the 200 to our BYE is not
    assert responses == [200]


async def test_ack_for_non_2xx_reuses_invite_branch(test_server, protocol, loop, from_details, to_details):
    messages, responses = await invite_scenario(test_server, protocol, loop, from_details, to_details, 486)
    by_method = {m.method: m for m in messages}
    assert {'INVITE', 'ACK'} <= set(by_method)
    invite, ack = by_method['INVITE'], by_method['ACK']

    # RFC 3261 17.1.1.3: ACK for non-2xx belongs to the INVITE transaction
    assert ack.cseq == invite.cseq
    assert branch_of(ack) == branch_of(invite)
    assert sent_by_of(ack) == sent_by_of(invite)
    assert responses == [486]


async def test_cancel_belongs_to_invite_transaction(test_server, protocol, loop, from_details, to_details):
    received_messages = list()
    futures = {'ACK': loop.create_future()}

    class Dialplan(aiosip.BaseDialplan):

        async def resolve(self, *args, **kwargs):
            await super().resolve(*args, **kwargs)
            return self.invite

        async def invite(self, request, message):
            dialog = request._create_dialog()
            await dialog.reply(message, status_code=180)
            async for msg in dialog:
                if msg.method == 'CANCEL':
                    # RFC 3261 9.2 order: 200 to the CANCEL first, then the
                    # 487 to the INVITE. The dialog must survive the former to
                    # still be able to ACK the latter.
                    await dialog.reply(msg, status_code=200)
                    await asyncio.sleep(0.05)
                    await dialog.reply(message, status_code=487)
                    break

    app = aiosip.Application(loop=loop)
    server_app = aiosip.Application(loop=loop, dialplan=Dialplan())
    record_requests(server_app, received_messages, futures)
    server = await test_server(server_app)

    peer = await app.connect(
        protocol=protocol,
        remote_addr=(server.sip_config['server_host'], server.sip_config['server_port'])
    )
    call = await peer.invite(
        from_details=aiosip.Contact.from_header(from_details),
        to_details=aiosip.Contact.from_header(to_details),
    )
    ringing = await asyncio.wait_for(call.recv(), timeout=2)
    assert ringing.status_code == 180

    await call.close(timeout=2)
    await asyncio.wait_for(futures['ACK'], timeout=2)
    await asyncio.sleep(0.1)

    by_method = {m.method: m for m in received_messages}
    assert {'INVITE', 'CANCEL', 'ACK'} <= set(by_method)
    invite, cancel, ack = by_method['INVITE'], by_method['CANCEL'], by_method['ACK']

    # RFC 3261 9.1: CANCEL matches the INVITE's CSeq number and top Via
    assert cancel.cseq == invite.cseq
    assert cancel.headers['Via'] == invite.headers['Via']
    assert str(cancel.to_details) == str(invite.to_details)
    # and the ACK for the 487 is part of the INVITE transaction too
    assert ack.cseq == invite.cseq
    assert branch_of(ack) == branch_of(invite)

    await app.close()
    await server_app.close()


async def test_cancel_before_any_response_survives_tagless_cancel_response(
        test_server, protocol, loop, from_details, to_details):
    """CANCEL answered with a tagless response must not unregister the dialog."""
    received_messages = list()
    futures = {'ACK': loop.create_future()}

    class Dialplan(aiosip.BaseDialplan):

        async def resolve(self, *args, **kwargs):
            await super().resolve(*args, **kwargs)
            return self.invite

        async def invite(self, request, message):
            dialog = request._create_dialog()
            async for msg in dialog:
                if msg.method == 'CANCEL':
                    # No to-tag on this response, as a UAS answering a CANCEL
                    # for a dialog it has not confirmed may do.
                    await dialog.reply(msg, status_code=200, headers={'To': str(msg.to_details)})
                    await asyncio.sleep(0.05)
                    await dialog.reply(message, status_code=487)
                    break

    app = aiosip.Application(loop=loop)
    server_app = aiosip.Application(loop=loop, dialplan=Dialplan())
    record_requests(server_app, received_messages, futures)
    server = await test_server(server_app)

    peer = await app.connect(
        protocol=protocol,
        remote_addr=(server.sip_config['server_host'], server.sip_config['server_port'])
    )
    call = await peer.invite(
        from_details=aiosip.Contact.from_header(from_details),
        to_details=aiosip.Contact.from_header(to_details),
    )
    await asyncio.sleep(0.05)
    await call.close(timeout=5)
    await asyncio.wait_for(futures['ACK'], timeout=5)

    by_method = {m.method: m for m in received_messages}
    invite, ack = by_method['INVITE'], by_method['ACK']
    assert branch_of(ack) == branch_of(invite)

    await app.close()
    await server_app.close()


async def test_non_2xx_to_transaction_invite_is_acked(test_server, protocol, loop, from_details, to_details):
    """RFC 3261 17.1.1.3: a non-2xx final to an INVITE sent through a
    transaction (not InviteDialog) must be ACKed too."""
    received_messages = list()
    futures = {'ACK': loop.create_future()}

    class Dialplan(aiosip.BaseDialplan):

        async def resolve(self, *args, **kwargs):
            await super().resolve(*args, **kwargs)
            return self.invite

        async def invite(self, request, message):
            dialog = request._create_dialog()
            await dialog.reply(message, status_code=488)

    app = aiosip.Application(loop=loop)
    server_app = aiosip.Application(loop=loop, dialplan=Dialplan())
    record_requests(server_app, received_messages, futures)
    server = await test_server(server_app)

    peer = await app.connect(
        protocol=protocol,
        remote_addr=(server.sip_config['server_host'], server.sip_config['server_port'])
    )
    dialog = await peer.request(
        'INVITE',
        from_details=aiosip.Contact.from_header(from_details),
        to_details=aiosip.Contact.from_header(to_details),
        dialog_factory=aiosip.dialog.Dialog,
    )
    assert dialog.status_code == 488
    await asyncio.wait_for(futures['ACK'], timeout=5)

    by_method = {m.method: m for m in received_messages}
    invite, ack = by_method['INVITE'], by_method['ACK']
    # part of the INVITE transaction: same branch and CSeq number
    assert ack.cseq == invite.cseq
    assert branch_of(ack) == branch_of(invite)

    await app.close()
    await server_app.close()


async def test_dialog_cancel_uses_the_pending_invite(test_server, protocol, loop, from_details, to_details):
    """Dialog.cancel() must cancel the INVITE that was actually sent, not the
    unsent template request the dialog was built from."""
    received_messages = list()
    futures = {'CANCEL': loop.create_future()}

    class Dialplan(aiosip.BaseDialplan):

        async def resolve(self, *args, **kwargs):
            await super().resolve(*args, **kwargs)
            return self.invite

        async def invite(self, request, message):
            dialog = request._create_dialog()
            await dialog.reply(message, status_code=180)
            async for msg in dialog:
                if msg.method == 'CANCEL':
                    await dialog.reply(msg, status_code=200)
                    await dialog.reply(message, status_code=487)
                    break

    app = aiosip.Application(loop=loop)
    server_app = aiosip.Application(loop=loop, dialplan=Dialplan())
    record_requests(server_app, received_messages, futures)
    server = await test_server(server_app)

    peer = await app.connect(
        protocol=protocol,
        remote_addr=(server.sip_config['server_host'], server.sip_config['server_port'])
    )
    task = loop.create_task(peer.request(
        'INVITE',
        from_details=aiosip.Contact.from_header(from_details),
        to_details=aiosip.Contact.from_header(to_details),
        dialog_factory=aiosip.dialog.Dialog,
    ))
    await asyncio.sleep(0.2)
    task.cancel()  # peers.request() calls dialog.cancel() on cancellation
    with pytest.raises(asyncio.CancelledError):
        await task
    await asyncio.wait_for(futures['CANCEL'], timeout=5)

    by_method = {m.method: m for m in received_messages}
    invite, cancel = by_method['INVITE'], by_method['CANCEL']
    # RFC 3261 9.1: CSeq number, To and top Via all match the sent INVITE
    assert cancel.cseq == invite.cseq
    assert cancel.headers['Via'] == invite.headers['Via']
    assert str(cancel.to_details) == str(invite.to_details)
    assert 'tag' not in cancel.to_details['params']

    await app.close()
    await server_app.close()


async def test_unrecognised_2xx_is_treated_as_200(test_server, protocol, loop, from_details, to_details):
    """RFC 3261 8.1.3.2: a 2xx that is not 200 still terminates the call."""
    received_messages = list()
    futures = {'ACK': loop.create_future()}

    class Dialplan(aiosip.BaseDialplan):

        async def resolve(self, *args, **kwargs):
            await super().resolve(*args, **kwargs)
            return self.invite

        async def invite(self, request, message):
            dialog = request._create_dialog()
            await dialog.reply(message, status_code=202)

    app = aiosip.Application(loop=loop)
    server_app = aiosip.Application(loop=loop, dialplan=Dialplan())
    record_requests(server_app, received_messages, futures)
    server = await test_server(server_app)

    peer = await app.connect(
        protocol=protocol,
        remote_addr=(server.sip_config['server_host'], server.sip_config['server_port'])
    )
    call = await peer.invite(
        from_details=aiosip.Contact.from_header(from_details),
        to_details=aiosip.Contact.from_header(to_details),
    )
    msg = await asyncio.wait_for(call.recv(), timeout=5)
    assert msg.status_code == 202
    await asyncio.wait_for(futures['ACK'], timeout=5)
    assert call.state is aiosip.dialog.CallState.Terminated

    by_method = {m.method: m for m in received_messages}
    invite, ack = by_method['INVITE'], by_method['ACK']
    # 2xx: the ACK is a new transaction
    assert branch_of(ack) != branch_of(invite)

    await app.close()
    await server_app.close()


async def test_retransmitted_final_is_reacked_and_not_passed_up(
        test_server, protocol, loop, from_details, to_details):
    """A retransmitted final response is ACKed again but reaches the user once."""
    acks = list()
    second_ack = loop.create_future()

    class Dialplan(aiosip.BaseDialplan):

        async def resolve(self, *args, **kwargs):
            await super().resolve(*args, **kwargs)
            return self.invite

        async def invite(self, request, message):
            dialog = request._create_dialog()
            await dialog.reply(message, status_code=486)
            await asyncio.sleep(0.1)
            await dialog.reply(message, status_code=486)  # our ACK was 'lost'

    app = aiosip.Application(loop=loop)
    server_app = aiosip.Application(loop=loop, dialplan=Dialplan())
    received_messages = list()
    record_requests(server_app, received_messages, {'ACK': (2, second_ack)})
    server = await test_server(server_app)

    peer = await app.connect(
        protocol=protocol,
        remote_addr=(server.sip_config['server_host'], server.sip_config['server_port'])
    )
    call = await peer.invite(
        from_details=aiosip.Contact.from_header(from_details),
        to_details=aiosip.Contact.from_header(to_details),
    )
    responses = list()
    async for msg in call.wait_for_terminate(timeout=2):
        responses.append(msg.status_code)
    await asyncio.wait_for(second_ack, timeout=5)
    acks.extend(m for m in received_messages if m.method == 'ACK')

    # the retransmission was ACKed again but never queued for the user
    assert responses == [486]
    assert call._queue.empty()
    assert len(acks) == 2
    assert branch_of(acks[0]) == branch_of(acks[1])

    await call.close(timeout=2)
    await app.close()
    await server_app.close()


async def test_invite_dialog_authenticates(test_server, protocol, loop, from_details, to_details):
    """peer.invite(password=...) must answer a challenge instead of failing.

    The initial INVITE is sent outside a transaction, so the dialog itself
    has to retry it with credentials.
    """
    password = 'abcdefg'
    received_messages = list()

    class Dialplan(aiosip.BaseDialplan):

        async def resolve(self, *args, **kwargs):
            await super().resolve(*args, **kwargs)
            return self.invite

        async def invite(self, request, message):
            dialog = request._create_dialog()
            await dialog.unauthorized(message)
            async for message in dialog:
                if message.method == 'INVITE':
                    if dialog.validate_auth(message=message, password=password):
                        await dialog.reply(message, 200)
                    else:
                        await dialog.unauthorized(message)
                elif message.method == 'BYE':
                    await dialog.reply(message, 200)
                    break

    app = aiosip.Application(loop=loop)
    server_app = aiosip.Application(loop=loop, dialplan=Dialplan())
    both_acks = loop.create_future()
    record_requests(server_app, received_messages, {'ACK': (2, both_acks)})
    server = await test_server(server_app)

    peer = await app.connect(
        protocol=protocol,
        remote_addr=(server.sip_config['server_host'], server.sip_config['server_port'])
    )
    call = await peer.invite(
        from_details=aiosip.Contact.from_header(from_details),
        to_details=aiosip.Contact.from_header(to_details),
        password=password,
    )
    await asyncio.wait_for(call.ready(), timeout=5)
    await asyncio.wait_for(both_acks, timeout=5)
    assert call.state is aiosip.dialog.CallState.Terminated

    invites = [m for m in received_messages if m.method == 'INVITE']
    acks = [m for m in received_messages if m.method == 'ACK']
    assert len(invites) == 2
    first, retry = invites
    assert 'Authorization' in retry.headers
    # a new transaction: new CSeq and new branch, To still untagged
    assert retry.cseq == first.cseq + 1
    assert branch_of(retry) != branch_of(first)
    assert 'tag' not in retry.to_details['params']
    # the 401 is ACKed within the INVITE transaction, the 200 with a new branch
    assert len(acks) == 2
    assert branch_of(acks[0]) == branch_of(first)
    assert branch_of(acks[1]) not in (branch_of(first), branch_of(retry))

    await call.close(timeout=2)
    await app.close()
    await server_app.close()


async def test_auth_retry_keeps_the_dialog_registered(test_server, protocol, loop, from_details, to_details):
    """After the authenticated retry the dialog must still be findable.

    dialog_id is derived from the sent request's To, so swapping the request
    without re-registering leaks the dialog and drops its responses.
    """
    password = 'abcdefg'

    class Dialplan(aiosip.BaseDialplan):

        async def resolve(self, *args, **kwargs):
            await super().resolve(*args, **kwargs)
            return self.invite

        async def invite(self, request, message):
            dialog = request._create_dialog()
            await dialog.unauthorized(message)
            async for message in dialog:
                if message.method == 'INVITE':
                    await dialog.reply(message, 200)
                elif message.method == 'BYE':
                    await dialog.reply(message, 200)
                    break

    app = aiosip.Application(loop=loop)
    server_app = aiosip.Application(loop=loop, dialplan=Dialplan())
    server = await test_server(server_app)

    peer = await app.connect(
        protocol=protocol,
        remote_addr=(server.sip_config['server_host'], server.sip_config['server_port'])
    )
    call = await peer.invite(
        from_details=aiosip.Contact.from_header(from_details),
        to_details=aiosip.Contact.from_header(to_details),
        password=password,
    )
    await asyncio.wait_for(call.ready(), timeout=5)

    # registered under the key dialog_id currently computes
    assert app._dialogs.get(call.dialog_id) is call

    await call.close(timeout=2)
    # and removed again on close, rather than leaking for the process lifetime
    assert call not in app._dialogs.values()

    await app.close()
    await server_app.close()


async def test_auth_retry_survives_a_new_to_tag(test_server, protocol, loop, from_details, to_details):
    """RFC 3261 8.2.6.2: the UAS may pick a different To tag for the
    authenticated transaction; its 200 must still reach the dialog."""
    password = 'abcdefg'

    class Dialplan(aiosip.BaseDialplan):

        async def resolve(self, *args, **kwargs):
            await super().resolve(*args, **kwargs)
            return self.invite

        async def invite(self, request, message):
            dialog = request._create_dialog()
            await dialog.unauthorized(message)
            async for message in dialog:
                if message.method == 'INVITE':
                    await dialog.reply(message, 200)
                elif message.method == 'BYE':
                    await dialog.reply(message, 200)
                    break

    app = aiosip.Application(loop=loop)
    server_app = aiosip.Application(loop=loop, dialplan=Dialplan())
    server = await test_server(server_app)

    # Rewrite the To tag on every response after the challenge, as a UAS that
    # generates a fresh tag per transaction would.
    original_dispatch = app._dispatch
    seen = collections.Counter()

    async def retagging_dispatch(protocol_, msg, addr):
        if isinstance(msg, aiosip.message.Response):
            seen['response'] += 1
            if seen['response'] > 1:
                msg.headers['To'] = '{};tag=confirmed'.format(
                    str(msg.to_details).split(';tag=')[0])
                del msg._to_details
        return await original_dispatch(protocol_, msg, addr)

    app._dispatch = retagging_dispatch

    peer = await app.connect(
        protocol=protocol,
        remote_addr=(server.sip_config['server_host'], server.sip_config['server_port'])
    )
    call = await peer.invite(
        from_details=aiosip.Contact.from_header(from_details),
        to_details=aiosip.Contact.from_header(to_details),
        password=password,
    )
    await asyncio.wait_for(call.ready(), timeout=5)
    assert call.to_details['params']['tag'] == 'confirmed'

    await call.close(timeout=2)
    await app.close()
    await server_app.close()


async def test_close_is_bounded_when_the_487_never_arrives(test_server, protocol, loop, from_details, to_details):
    """A peer that answers the CANCEL and then stops must not block close()."""

    class Dialplan(aiosip.BaseDialplan):

        async def resolve(self, *args, **kwargs):
            await super().resolve(*args, **kwargs)
            return self.invite

        async def invite(self, request, message):
            dialog = request._create_dialog()
            await dialog.reply(message, status_code=180)
            async for msg in dialog:
                if msg.method == 'CANCEL':
                    await dialog.reply(msg, status_code=200)
                    break  # no 487 ever follows

    app = aiosip.Application(loop=loop)
    server_app = aiosip.Application(loop=loop, dialplan=Dialplan())
    server = await test_server(server_app)

    peer = await app.connect(
        protocol=protocol,
        remote_addr=(server.sip_config['server_host'], server.sip_config['server_port'])
    )
    call = await peer.invite(
        from_details=aiosip.Contact.from_header(from_details),
        to_details=aiosip.Contact.from_header(to_details),
    )
    await asyncio.wait_for(call.recv(), timeout=5)

    started = loop.time()
    # an explicit timeout bounds the wait and must not raise: the CANCEL
    # itself was answered
    await asyncio.wait_for(call.close(timeout=1), timeout=5)
    assert loop.time() - started < 4

    await app.close()
    await server_app.close()


async def test_proxy_challenge_is_retried(test_server, protocol, loop, from_details, to_details):
    """A 407 must be answered with Proxy-Authorization, not hang or recurse."""
    password = 'abcdefg'
    received_messages = list()

    class Dialplan(aiosip.BaseDialplan):

        async def resolve(self, *args, **kwargs):
            await super().resolve(*args, **kwargs)
            return self.subscribe

        async def subscribe(self, request, message):
            dialog = request._create_dialog()
            auth = aiosip.auth.AuthenticateAuth(
                mode='Digest', nonce='proxynonce', realm='proxy', algorithm='md5',
                method=message.method)
            await dialog.reply(message, status_code=407,
                               headers={'Proxy-Authenticate': str(auth)})
            async for message in dialog:
                await dialog.reply(message, 200)
                break

    app = aiosip.Application(loop=loop)
    server_app = aiosip.Application(loop=loop, dialplan=Dialplan())
    record_requests(server_app, received_messages)
    server = await test_server(server_app)

    peer = await app.connect(
        protocol=protocol,
        remote_addr=(server.sip_config['server_host'], server.sip_config['server_port'])
    )
    dialog = await asyncio.wait_for(peer.subscribe(
        expires=1800,
        from_details=aiosip.Contact.from_header(from_details),
        to_details=aiosip.Contact.from_header(to_details),
        password=password,
    ), timeout=5)
    assert dialog.status_code == 200

    subscribes = [m for m in received_messages if m.method == 'SUBSCRIBE']
    assert len(subscribes) == 2
    first, retry = subscribes
    assert 'Proxy-Authorization' in retry.headers
    assert 'Authorization' not in retry.headers
    assert retry.cseq == first.cseq + 1
    assert branch_of(retry) != branch_of(first)

    await app.close()
    await server_app.close()


async def test_stale_proxy_credential_is_not_copied(test_server, protocol, loop, from_details, to_details):
    """A Proxy-Authorization from an earlier nonce must not ride along."""
    password = 'abcdefg'
    received_messages = list()

    class Dialplan(aiosip.BaseDialplan):

        async def resolve(self, *args, **kwargs):
            await super().resolve(*args, **kwargs)
            return self.subscribe

        async def subscribe(self, request, message):
            dialog = request._create_dialog()
            await dialog.unauthorized(message)
            async for message in dialog:
                await dialog.reply(message, 200)
                break

    app = aiosip.Application(loop=loop)
    server_app = aiosip.Application(loop=loop, dialplan=Dialplan())
    record_requests(server_app, received_messages)
    server = await test_server(server_app)

    peer = await app.connect(
        protocol=protocol,
        remote_addr=(server.sip_config['server_host'], server.sip_config['server_port'])
    )
    await asyncio.wait_for(peer.subscribe(
        expires=1800,
        from_details=aiosip.Contact.from_header(from_details),
        to_details=aiosip.Contact.from_header(to_details),
        headers={'Proxy-Authorization': 'Digest nonce="stale"'},
        password=password,
    ), timeout=5)

    subscribes = [m for m in received_messages if m.method == 'SUBSCRIBE']
    assert len(subscribes) == 2
    retry = subscribes[1]
    assert 'Authorization' in retry.headers
    assert 'Proxy-Authorization' not in retry.headers

    await app.close()
    await server_app.close()


async def test_retransmitted_2xx_is_answered_with_the_same_ack(
        test_server, protocol, loop, from_details, to_details):
    """RFC 3261 13.2.2.4: retransmit the ACK, do not start a new transaction."""
    acks = list()
    second_ack = loop.create_future()

    class Dialplan(aiosip.BaseDialplan):

        async def resolve(self, *args, **kwargs):
            await super().resolve(*args, **kwargs)
            return self.invite

        async def invite(self, request, message):
            dialog = request._create_dialog()
            await dialog.reply(message, status_code=200)
            await asyncio.sleep(0.1)
            await dialog.reply(message, status_code=200)  # our ACK was 'lost'

    app = aiosip.Application(loop=loop)
    server_app = aiosip.Application(loop=loop, dialplan=Dialplan())
    received_messages = list()
    record_requests(server_app, received_messages, {'ACK': (2, second_ack)})
    server = await test_server(server_app)

    peer = await app.connect(
        protocol=protocol,
        remote_addr=(server.sip_config['server_host'], server.sip_config['server_port'])
    )
    call = await peer.invite(
        from_details=aiosip.Contact.from_header(from_details),
        to_details=aiosip.Contact.from_header(to_details),
    )
    await asyncio.wait_for(call.ready(), timeout=5)
    await asyncio.wait_for(second_ack, timeout=5)
    acks.extend(m for m in received_messages if m.method == 'ACK')

    assert len(acks) == 2
    # one client transaction retransmitting, so the same branch both times
    assert branch_of(acks[0]) == branch_of(acks[1])
    assert acks[0].cseq == acks[1].cseq

    await app.close()
    await server_app.close()


def test_cancel_without_pending_invite_keeps_the_requested_cseq():
    """dialog.cancel(cseq=N) must build a CANCEL with CSeq N, and an unknown
    CSeq must not raise out of a cleanup path."""
    sent = list()

    dialog = aiosip.dialog.Dialog.__new__(aiosip.dialog.Dialog)
    dialog.transactions = {}
    dialog.cseq = 5
    dialog.peer = type('P', (), {'send_message': lambda self, msg: sent.append(msg)})()

    def prepare(method, contact_details=None, headers=None, payload=None, cseq=None, to_details=None):
        return {'method': method, 'cseq': cseq, 'headers': headers, 'payload': payload,
                'contact_details': contact_details}

    dialog._prepare_request = prepare

    # no pending INVITE: the requested cseq survives instead of being dropped
    dialog.cancel(cseq=3)
    assert sent[-1]['cseq'] == 3
    # and an unknown cseq is a no-op-ish CANCEL, not a ValueError
    assert dialog._pending_invite(99) is None


def test_cancel_forwards_payload_and_contact_details():
    """Both cancel() paths honour the same arguments."""
    sent = list()

    dialog = aiosip.dialog.Dialog.__new__(aiosip.dialog.Dialog)
    invite = type('M', (), {'cseq': 4, 'headers': {'Via': 'SIP/2.0/UDP h:5060;branch=z9hG4bKx',
                                                   'To': '<sip:a@h>'},
                            'to_details': None})()
    dialog.transactions = {'INVITE': {4: type('T', (), {'original_msg': invite})()}}
    dialog.peer = type('P', (), {'send_message': lambda self, msg: sent.append(msg)})()

    def prepare(method, contact_details=None, headers=None, payload=None, cseq=None, to_details=None):
        return {'method': method, 'cseq': cseq, 'payload': payload,
                'contact_details': contact_details}

    dialog._prepare_request = prepare

    dialog.cancel(payload='body', contact_details='contact')
    assert sent[-1]['cseq'] == 4          # from the pending INVITE
    assert sent[-1]['payload'] == 'body'  # not silently dropped
    assert sent[-1]['contact_details'] == 'contact'
