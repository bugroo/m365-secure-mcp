from __future__ import annotations

from m365_secure_mcp.operations import (
    AlignmentStatus,
    OperationStatus,
    PlaybookStatus,
)


def test_write_state_machine_contains_governed_terminal_states() -> None:
    assert {status.value for status in OperationStatus} >= {
        "DENIED_OUT_OF_CONTRACT",
        "DENIED_BY_POLICY",
        "BLOCKED_PRECONDITION",
        "AWAITING_APPROVAL",
        "PLAN_EXPIRED",
        "EXECUTED_VERIFIED",
        "EXECUTED_ACCEPTED",
        "EXECUTED_UNCERTAIN",
        "FAILED_RETRYABLE",
        "HALTED_BY_OPERATOR",
    }


def test_playbook_state_machine_is_separate_from_write_state() -> None:
    assert {status.value for status in PlaybookStatus} == {
        "PLAYBOOK_PLANNED",
        "PLAYBOOK_RUNNING",
        "PLAYBOOK_PARTIALLY_APPLIED",
        "PLAYBOOK_COMPENSATION_REQUIRED",
        "PLAYBOOK_COMPLETED_VERIFIED",
        "PLAYBOOK_HALTED",
    }


def test_assurance_alignment_never_collapses_unknown_into_aligned() -> None:
    assert {status.value for status in AlignmentStatus} == {
        "aligned",
        "not_aligned",
        "not_applicable",
        "not_evaluated",
        "exception_approved",
    }
