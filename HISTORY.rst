.. :changelog:

History
-------

0.2.7 (2026-09-04)
------------------

* Via branch fixes (RFC 3261): a request re-sent with credentials after a
  401 is built as a new request (new CSeq and branch) instead of mutating the
  one on the wire; the ACK for a 2xx gets its own branch while the ACK for a
  non-2xx and CANCEL copy the INVITE's Via and CSeq number; a retransmitted
  2xx is acknowledged again; longer, cryptographically random branches.
* InviteDialog no longer passes responses to in-dialog requests (BYE, CANCEL)
  up through ``recv()``/``wait_for_terminate()``; they go to their transaction.
  A 2xx other than 200 is treated as 200, and a retransmitted final response
  is acknowledged again instead of being passed up a second time. After a
  CANCEL the dialog stays registered until the INVITE's 487 is ACKed.
* Every final response to an INVITE sent through a transaction (re-INVITE,
  ``peer.request('INVITE')``) is acknowledged, not just a 200.
* ``peer.invite(password=...)`` now answers a 401/407 challenge; the initial
  INVITE is sent outside a transaction, so InviteDialog retries it itself,
  re-registering the dialog so its responses are still routed to it.
* Proxy authentication works: ``Auth.from_message`` reads Proxy-Authenticate
  and ``_handle_proxy_authenticate`` answers with Proxy-Authorization instead
  of recursing into itself. Stale credentials are not copied into a retry.
* A retransmitted 2xx is answered by retransmitting the same ACK rather than
  building a new one with a fresh branch. The cache is keyed per 2xx (CSeq
  plus remote tag) so a forked INVITE gets one ACK per callee, and bounded.
* An unparseable or unsupported challenge makes ``Message.auth`` None instead
  of raising out of the dispatch task, and a header repeated for several
  Digest algorithms (RFC 8760) is answered from its first supported value.
* Closing a transaction cancels its authentication retransmission timer.
* ``close()`` bounds its wait for the 487 after a CANCEL and never raises
  because that response is missing.
* Closing a dialog removes every key it is registered under, not just the
  current ``dialog_id``; the keys are tracked on the dialog, so teardown
  stays O(1) rather than scanning every live dialog.
* The Dialog/transaction authentication retry re-registers its dialog too,
  so a UAS that picks a fresh To tag for the authenticated transaction is
  matched instead of having its response discarded.
* A response carrying both a WWW-Authenticate and a Proxy-Authenticate
  challenge is answered from the one matching the credential header.
* ``CANCEL`` shares the request's branch and CSeq only for an INVITE
  (RFC 3261 section 9.1); any other method gets a CANCEL of its own.
* ``close(timeout=T)`` spends at most ``T`` in total, not ``T`` on the
  CANCEL and ``T`` again on the 487.
* ``InviteDialog.ready()`` accepts any 2xx, matching the state machine.
* ``Dialog.cancel()`` cancels the pending INVITE transaction (``cseq=``
  picks one) instead of the unsent template request, and the authenticated
  retry keeps the To header of the request as it was sent.
* ``aiosip.pytest_plugin`` fails with a usage error when ``--loop`` selects
  no loop, and leaves a ``loop`` fixture parametrized downstream alone.
* Backwards-incompatible API changes (small, but note them when upgrading):
  the unused ``Peer.generate_via_headers`` is removed; ``DialogBase.ack()``
  takes responses only and its ``request`` argument is keyword-only; and
  ``Dialog.cancel()`` has an explicit signature mirroring
  ``_prepare_request`` instead of ``*args, **kwargs``, rejecting
  ``to_details`` when an INVITE is being cancelled because RFC 3261
  section 9.1 fixes the CANCEL's To to that of the cancelled request.
* Package version now comes from ``aiosip.__version__`` (also used in the
  default User-Agent).
* Test suite runs again on current pytest/Python: fixed the ``loop`` fixture
  parametrization in ``aiosip.pytest_plugin`` and the test server fixtures.

0.2.0 (2017-09-14)
------------------

* A lot of bugs fixes
* Proxy support
* aiohttp dependency removed in favor of multidict
* Code refactoring
* Special thanks to Simon Gomizelj (vodik) on this release: almost come from his contributions

0.1.0 (2014-12-28)
------------------

* First release on PyPI.
