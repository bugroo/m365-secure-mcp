"""Pinned trust anchor for the build-time Microsoft Graph contract manifest."""

from typing import Final

# This public key is intentionally stored in source. The corresponding private
# key is not part of the repository. Rotating it is a reviewed release change,
# not a runtime operation.
CONTRACT_SIGNING_KEY_ID: Final = "assurance-2026-07"
CONTRACT_SIGNING_PUBLIC_KEY_B64: Final = (
    "5LY1sDnAh5dE5EZpLUq5DCs6Fu7goAbiwJeTTfyCiI4="
)
