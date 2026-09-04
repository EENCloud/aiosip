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
  building a new one with a fresh branch.
* ``close()`` bounds its wait for the 487 after a CANCEL and never raises
  because that response is missing.
* Closing a dialog removes every key it is registered under, not just the
  current ``dialog_id``.
* ``Dialog.cancel()`` cancels the pending INVITE transaction (``cseq=``
  picks one) instead of the unsent template request, and the authenticated
  retry keeps the To header of the request as it was sent.
* ``aiosip.pytest_plugin`` fails with a usage error when ``--loop`` selects
  no loop, and leaves a ``loop`` fixture parametrized downstream alone.
* Removed the unused ``Peer.generate_via_headers``.
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
