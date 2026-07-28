# Contributing

Thank you for improving `m365-secure-mcp`. Contributions are accepted under
the repository's Apache-2.0 terms and must preserve the
[project north star](docs/PROJECT_NORTH_STAR.md).

Before proposing a significant feature:

1. explain its effect on all five product pillars;
2. prefer complete workflows over endpoint or tool-count growth;
3. preserve fixed Graph v1.0 contracts, signed authority, tenant isolation,
   privacy projections, and permanent prohibitions;
4. keep customer policies, credentials, identifiers, evidence, and private
   WERIXO operations out of the repository;
5. add a self-contained ExecPlan for multi-milestone work.

New legacy writes and broader semantics for existing legacy writes are frozen.
Future effects must use compiled contracts and `ChangeSafeOperator`. See
[Secure Operations](docs/SECURE_OPERATIONS.md) and the
[Operator Foundation Definition of Done](docs/OPERATOR_FOUNDATION.md#definition-of-done-for-a-stable-t2t3-operation).

Run the repository validation documented in the active ExecPlan and include
the exact results in the pull request. A T3 operation requires a dedicated
architecture/security decision and external review before it can become
stable.
