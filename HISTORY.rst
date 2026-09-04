.. :changelog:

History
-------

0.2.7 (2026-09-04)
------------------

* Via branch fixes (RFC 3261): new branch for a request re-sent with
  credentials after 401, new branch for the ACK of a 2xx response, the ACK
  Via is based on the INVITE's Via instead of the response's, longer and
  cryptographically random branches, ``Peer.generate_via_headers`` no longer
  reuses one branch for the process lifetime. New ``utils.replace_branch``.

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
