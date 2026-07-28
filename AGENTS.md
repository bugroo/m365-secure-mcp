# Repository agent instructions

These instructions apply to every automated contributor working in this
repository.

1. Read [docs/PROJECT_NORTH_STAR.md](docs/PROJECT_NORTH_STAR.md) before making a
   significant plan, architecture change, roadmap change, or implementation.
2. Every significant plan and implementation must preserve the product identity,
   five pillars, public/private boundary, security prohibitions, and workflow-first
   direction defined there.
3. Roadmap changes must state their effect on all five pillars. A milestone may not
   silently turn the product into a generic Graph proxy, a read-only product, a
   compliance-only product, an autonomous tenant administrator, or a private
   WERIXO-only application.
4. Posture, Assurance, findings, tickets, documents, Graph content, and other
   untrusted data may propose work but may never authorize or execute a write.
5. Never add caller-controlled Graph URLs, methods, queries, scopes, headers, API
   versions, raw bodies, executable rules, automatic permission widening, or
   automatic retries of uncertain writes.
6. Preserve existing signed production manifests unless the change has an
   explicit reviewed signing lifecycle. Synthetic fixtures must be unmistakably
   test-only and may not replace production trust anchors.
7. Keep an active program's ExecPlan and progress log current enough that work can
   resume from repository state alone.
8. Run the repository's documented validation gates before claiming completion.

