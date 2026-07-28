# Identity Slice live-lab boundary

The committed Identity recordings are sanitized synthetic playback. Live
execution is disabled by default and must not run against a customer or
production tenant.

A future explicit lab run requires:

- the reviewed schema-2.0 manifest signed by the current production contract
  authority;
- a dedicated non-production tenant and `lab-only` Governance profile;
- manual administrator consent for only the scopes in the candidate matrix;
- synthetic non-protected users, static groups and test license SKUs;
- independent approval keys held outside the repository;
- recording sanitization and privacy scan before any fixture update;
- an explicit review of results before a candidate can become `stable`.

Recordings are updated only by a deliberate maintainer action. The default
pytest suite never authenticates, calls Graph, changes a tenant or reads
credentials. A live run must preserve ambiguous-write halt behavior and may
not retry a write whose commit state is uncertain.
