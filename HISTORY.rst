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
