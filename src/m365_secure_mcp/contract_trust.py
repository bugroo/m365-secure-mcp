"""Pinned trust anchor for the build-time Microsoft Graph contract manifest."""

from typing import Final

# This public key is intentionally stored in source. The corresponding private
# key is not part of the repository. Rotating it is a reviewed release change,
# not a runtime operation.
CONTRACT_SIGNING_KEY_ID: Final = "profile-debt-2026-07"
CONTRACT_SIGNING_PUBLIC_KEY_B64: Final = (
    "98l4UGNhmkPkAvMq5vm7kwg5j/wGacQ/6X6r0JGf3ZE="
)

# Playbooks have an independent reviewed build authority. The private key used
# for this release is not part of the repository or runtime.
PLAYBOOK_SIGNING_KEY_ID: Final = "workload-readiness-2026-07"
PLAYBOOK_SIGNING_PUBLIC_KEY_B64: Final = (
    "19GYLej7HERyaBmf6I8xFppaqskYumDxoy4M6+c0PGk="
)
