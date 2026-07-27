from __future__ import annotations

from pathlib import Path
from xml.etree import ElementTree


def test_workload_readiness_evaluation_is_stable_read_only_and_complete() -> None:
    root = Path(__file__).resolve().parents[1]
    evaluation = ElementTree.parse(  # noqa: S314 - committed local fixture
        root / "evaluations/workload-identity-readiness.xml"
    ).getroot()
    pairs = evaluation.findall("qa_pair")

    assert len(pairs) == 10
    questions = []
    answers = []
    for pair in pairs:
        question = (pair.findtext("question") or "").strip()
        answer = (pair.findtext("answer") or "").strip()
        assert question
        assert answer
        questions.append(question)
        answers.append(answer)

    assert len(questions) == len(set(questions))
    assert all(
        forbidden not in " ".join(questions).lower()
        for forbidden in (
            "create a ",
            "delete ",
            "modify ",
            "send ",
            "grant consent",
        )
    )
    assert {
        "PLAYBOOK_COMPLETED_VERIFIED",
        "PLAYBOOK_HALTED",
        "aligned",
        "not_evaluated",
        "critical",
        "0",
        "2",
        "privileged-read",
        "false",
    }.issubset(set(answers))
