import asyncio
import re

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


def test_gen_branch_has_magic_cookie_and_is_unique():
    branches = {utils.gen_branch() for _ in range(200)}
    assert len(branches) == 200
    for branch in branches:
        assert branch.startswith(utils.BRANCH_MAGIC_COOKIE)
        assert len(branch) == len(utils.BRANCH_MAGIC_COOKIE) + 16


def test_replace_branch_str():
    via = 'SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bKold;rport'
    assert utils.replace_branch(via, 'z9hG4bKnew') == 'SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bKnew;rport'
    new = utils.replace_branch(via)
    assert new != via
    assert new.startswith('SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK')
    assert new.endswith(';rport')


def test_replace_branch_without_branch_appends_one():
    via = utils.replace_branch('SIP/2.0/UDP 10.0.0.1:5060', 'z9hG4bKnew')
    assert via == 'SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bKnew'


def test_replace_branch_list_changes_only_top_via():
    vias = ['SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bKa', 'SIP/2.0/UDP 10.0.0.2:5060;branch=z9hG4bKb']
    assert utils.replace_branch(vias, 'z9hG4bKnew') == [
        'SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bKnew', 'SIP/2.0/UDP 10.0.0.2:5060;branch=z9hG4bKb']


async def test_authentication_retry_uses_new_branch(test_server, protocol, loop, from_details, to_details):
    password = 'abcdefg'
    received_messages = list()

    class Dialplan(aiosip.BaseDialplan):

        async def resolve(self, *args, **kwargs):
            await super().resolve(*args, **kwargs)
            return self.subscribe

        async def subscribe(self, request, message):
            dialog = request._create_dialog()
            received_messages.append(message)
            await dialog.unauthorized(message)

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
    await peer.subscribe(
        expires=1800,
        from_details=aiosip.Contact.from_header(from_details),
        to_details=aiosip.Contact.from_header(to_details),
        password=password
    )

    assert len(received_messages) == 2
    first, retry = received_messages
    assert 'Authorization' in retry.headers
    # RFC 3261 8.1.3.5: the request with credentials is a new transaction
    assert retry.cseq == first.cseq + 1
    assert branch_of(retry) != branch_of(first)
    assert branch_of(retry).startswith(utils.BRANCH_MAGIC_COOKIE)
    assert sent_by_of(retry) == sent_by_of(first)

    await app.close()
    await server_app.close()


async def invite_scenario(test_server, protocol, loop, from_details, to_details, status_code):
    """Run INVITE -> final response -> ACK (-> BYE for a 2xx) and return every
    request the server received, in order."""
    received_messages = list()
    ack_received = loop.create_future()

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

    # The server dialog does not hand the ACK to the dialplan, so record every
    # incoming request at dispatch level to see what really arrived on the wire.
    original_dispatch = server_app._dispatch

    async def recording_dispatch(protocol, msg, addr):
        if isinstance(msg, aiosip.message.Request):
            received_messages.append(msg)
            if msg.method == 'ACK' and not ack_received.done():
                ack_received.set_result(None)
        return await original_dispatch(protocol, msg, addr)

    server_app._dispatch = recording_dispatch
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
    async for _ in call.wait_for_terminate(timeout=2):
        pass
    await asyncio.wait_for(ack_received, timeout=2)
    await call.close(timeout=2)
    await asyncio.sleep(0.1)

    await app.close()
    await server_app.close()
    return received_messages


async def test_ack_for_2xx_uses_new_branch(test_server, protocol, loop, from_details, to_details):
    messages = await invite_scenario(test_server, protocol, loop, from_details, to_details, 200)
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


async def test_ack_for_non_2xx_reuses_invite_branch(test_server, protocol, loop, from_details, to_details):
    messages = await invite_scenario(test_server, protocol, loop, from_details, to_details, 486)
    by_method = {m.method: m for m in messages}
    assert {'INVITE', 'ACK'} <= set(by_method)
    invite, ack = by_method['INVITE'], by_method['ACK']

    # RFC 3261 17.1.1.3: ACK for non-2xx belongs to the INVITE transaction
    assert ack.cseq == invite.cseq
    assert branch_of(ack) == branch_of(invite)
    assert sent_by_of(ack) == sent_by_of(invite)
