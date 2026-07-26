"""Strict Pydantic input models for MCP tools."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Annotated, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class ResponseFormat(StrEnum):
    MARKDOWN = "markdown"
    JSON = "json"


class StrictInput(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True, validate_assignment=True)


Limit = Annotated[int, Field(ge=1, le=50)]


class PageInput(StrictInput):
    limit: Limit = 20
    cursor: str | None = Field(default=None, min_length=40, max_length=8_000)
    response_format: ResponseFormat = ResponseFormat.MARKDOWN


class BasicInput(StrictInput):
    response_format: ResponseFormat = ResponseFormat.MARKDOWN


class CatalogReadInput(PageInput):
    """Bounded identifiers used by declarative, fixed-path Graph read tools."""

    resource_id: str | None = Field(default=None, min_length=1, max_length=512)
    container_id: str | None = Field(default=None, min_length=1, max_length=512)
    site_id: str | None = Field(default=None, min_length=1, max_length=1_000)
    team_id: str | None = Field(default=None, min_length=1, max_length=512)
    chat_id: str | None = Field(default=None, min_length=1, max_length=512)
    group_id: str | None = Field(default=None, min_length=1, max_length=512)


class MailSearchInput(PageInput):
    query: str = Field(
        min_length=2,
        max_length=300,
        description=(
            "Natural mail search terms, for example: quarterly report from:alex@example.com"
        ),
    )
    folder: str = Field(default="inbox", pattern=r"^[A-Za-z0-9_-]{1,64}$")
    include_body_preview: bool = False


class MailMessageInput(StrictInput):
    message_id: str = Field(min_length=1, max_length=512)
    max_body_characters: int = Field(default=8_000, ge=500, le=16_000)
    response_format: ResponseFormat = ResponseFormat.MARKDOWN


class CalendarInput(PageInput):
    start: datetime
    end: datetime
    timezone: str = Field(default="UTC", min_length=1, max_length=80)

    @field_validator("end")
    @classmethod
    def end_after_start(cls, value: datetime, info: object) -> datetime:
        data = getattr(info, "data", {})
        start = data.get("start")
        if start is not None and value <= start:
            raise ValueError("end must be after start")
        return value


class ScheduleInput(StrictInput):
    attendees: list[str] = Field(min_length=1, max_length=20)
    start: datetime
    end: datetime
    interval_minutes: int = Field(default=30, ge=5, le=1440)
    timezone: str = Field(default="UTC", min_length=1, max_length=80)
    response_format: ResponseFormat = ResponseFormat.MARKDOWN


class FileSearchInput(PageInput):
    query: str = Field(min_length=2, max_length=200)


class FileMetadataInput(StrictInput):
    item_id: str = Field(min_length=1, max_length=512)
    response_format: ResponseFormat = ResponseFormat.MARKDOWN


class SiteSearchInput(PageInput):
    query: str = Field(min_length=2, max_length=200)


class ContactSearchInput(PageInput):
    query: str = Field(min_length=2, max_length=200)


class TodoListInput(PageInput):
    list_id: str = Field(min_length=1, max_length=512)


class TeamsMessageInput(PageInput):
    team_id: str = Field(min_length=1, max_length=512)
    channel_id: str = Field(min_length=1, max_length=512)


class PlannerPlanInput(PageInput):
    plan_id: str = Field(min_length=1, max_length=512)


class PlannerTaskInput(StrictInput):
    task_id: str = Field(min_length=1, max_length=512)
    response_format: ResponseFormat = ResponseFormat.MARKDOWN


class WriteOperationQueryInput(StrictInput):
    """Select one metadata-only write receipt without enumerating the ledger."""

    operation_id: UUID | None = None
    tool: str | None = Field(
        default=None,
        pattern=r"^m365_[a-z0-9_]{3,96}$",
        max_length=128,
    )
    idempotency_key: UUID | None = None

    @model_validator(mode="after")
    def validate_selector(self) -> WriteOperationQueryInput:
        by_operation = self.operation_id is not None
        by_pair = self.tool is not None or self.idempotency_key is not None
        if by_operation == by_pair:
            raise ValueError(
                "provide either operation_id or the tool and idempotency_key pair"
            )
        if not by_operation and (self.tool is None or self.idempotency_key is None):
            raise ValueError("tool and idempotency_key must be supplied together")
        return self


class CreatePlannerTaskInput(StrictInput):
    plan_id: str = Field(min_length=1, max_length=512)
    bucket_id: str = Field(min_length=1, max_length=512)
    title: str = Field(min_length=1, max_length=255)
    assignee_user_ids: list[UUID] = Field(default_factory=list, max_length=20)
    start: datetime | None = None
    due: datetime | None = None
    priority: int = Field(default=5, ge=0, le=10)
    idempotency_key: UUID


class UpdatePlannerTaskInput(StrictInput):
    task_id: str = Field(min_length=1, max_length=512)
    plan_id: str = Field(min_length=1, max_length=512)
    etag: str = Field(min_length=4, max_length=1_000)
    title: str | None = Field(default=None, min_length=1, max_length=255)
    percent_complete: int | None = Field(default=None, ge=0, le=100)
    priority: int | None = Field(default=None, ge=0, le=10)
    due: datetime | None = None
    bucket_id: str | None = Field(default=None, min_length=1, max_length=512)
    idempotency_key: UUID


class PlannerChecklistAdditionInput(StrictInput):
    title: str = Field(min_length=1, max_length=255)
    is_checked: bool = False


class PlannerChecklistUpdateInput(StrictInput):
    item_id: UUID = Field(
        description="Existing checklist item UUID returned by m365_get_planner_task."
    )
    title: str | None = Field(default=None, min_length=1, max_length=255)
    is_checked: bool | None = None

    @model_validator(mode="after")
    def validate_update(self) -> PlannerChecklistUpdateInput:
        if self.title is None and self.is_checked is None:
            raise ValueError("at least one checklist item field must be provided")
        return self


class UpdatePlannerTaskDetailsInput(StrictInput):
    task_id: str = Field(min_length=1, max_length=512)
    plan_id: str = Field(min_length=1, max_length=512)
    details_etag: str = Field(
        min_length=4,
        max_length=1_000,
        description=(
            "ETag from m365_get_planner_task.details_etag. "
            "The basic Planner task ETag is a different concurrency token."
        ),
    )
    description: str | None = Field(default=None, min_length=1, max_length=4_000)
    preview_type: (
        Literal["automatic", "noPreview", "checklist", "description", "reference"] | None
    ) = None
    checklist_additions: list[PlannerChecklistAdditionInput] = Field(
        default_factory=list,
        max_length=20,
    )
    checklist_updates: list[PlannerChecklistUpdateInput] = Field(
        default_factory=list,
        max_length=20,
    )
    idempotency_key: UUID

    @field_validator("details_etag")
    @classmethod
    def validate_details_etag(cls, value: str) -> str:
        if any(ord(character) < 32 or ord(character) == 127 for character in value):
            raise ValueError("details_etag contains control characters")
        return value

    @model_validator(mode="after")
    def validate_update(self) -> UpdatePlannerTaskDetailsInput:
        if (
            self.description is None
            and self.preview_type is None
            and not self.checklist_additions
            and not self.checklist_updates
        ):
            raise ValueError("at least one Planner task-details field must be provided")
        update_ids = [item.item_id for item in self.checklist_updates]
        if len(update_ids) != len(set(update_ids)):
            raise ValueError("checklist_updates contains duplicate item IDs")
        return self


class CreateDraftInput(StrictInput):
    to: list[str] = Field(min_length=1, max_length=20)
    cc: list[str] = Field(default_factory=list, max_length=20)
    subject: str = Field(min_length=1, max_length=255)
    body_text: str = Field(min_length=1, max_length=50_000)
    idempotency_key: UUID


class SendDraftInput(StrictInput):
    draft_id: str = Field(min_length=1, max_length=512)
    idempotency_key: UUID


class CreateEventInput(StrictInput):
    subject: str = Field(min_length=1, max_length=255)
    start: datetime
    end: datetime
    timezone: str = Field(default="UTC", min_length=1, max_length=80)
    attendees: list[str] = Field(default_factory=list, max_length=50)
    body_text: str = Field(default="", max_length=20_000)
    location: str = Field(default="", max_length=255)
    idempotency_key: UUID

    @field_validator("end")
    @classmethod
    def end_after_start(cls, value: datetime, info: object) -> datetime:
        data = getattr(info, "data", {})
        start = data.get("start")
        if start is not None and value <= start:
            raise ValueError("end must be after start")
        return value


class UpdateEventInput(StrictInput):
    event_id: str = Field(min_length=1, max_length=512)
    etag: str = Field(min_length=4, max_length=1_000)
    subject: str | None = Field(default=None, min_length=1, max_length=255)
    start: datetime | None = None
    end: datetime | None = None
    timezone: str = Field(default="UTC", min_length=1, max_length=80)
    location: str | None = Field(default=None, max_length=255)
    idempotency_key: UUID

    @model_validator(mode="after")
    def validate_update(self) -> UpdateEventInput:
        if all(value is None for value in (self.subject, self.start, self.end, self.location)):
            raise ValueError("at least one event field must be provided")
        if (self.start is None) != (self.end is None):
            raise ValueError("start and end must be supplied together")
        if self.start is not None and self.end is not None and self.end <= self.start:
            raise ValueError("end must be after start")
        return self


class CreateContactInput(StrictInput):
    display_name: str = Field(min_length=1, max_length=255)
    email_addresses: list[str] = Field(default_factory=list, max_length=10)
    company_name: str = Field(default="", max_length=255)
    business_phones: list[str] = Field(default_factory=list, max_length=5)
    mobile_phone: str = Field(default="", max_length=50)
    idempotency_key: UUID


class CreateTodoTaskInput(StrictInput):
    list_id: str = Field(min_length=1, max_length=512)
    title: str = Field(min_length=1, max_length=255)
    body_text: str = Field(default="", max_length=20_000)
    importance: Literal["low", "normal", "high"] = "normal"
    due: datetime | None = None
    timezone: str = Field(default="UTC", min_length=1, max_length=80)
    idempotency_key: UUID


class UpdateTodoTaskInput(StrictInput):
    list_id: str = Field(min_length=1, max_length=512)
    task_id: str = Field(min_length=1, max_length=512)
    etag: str = Field(min_length=4, max_length=1_000)
    title: str | None = Field(default=None, min_length=1, max_length=255)
    status: (
        Literal["notStarted", "inProgress", "completed", "waitingOnOthers", "deferred"] | None
    ) = None
    importance: Literal["low", "normal", "high"] | None = None
    due: datetime | None = None
    timezone: str = Field(default="UTC", min_length=1, max_length=80)
    idempotency_key: UUID

    @model_validator(mode="after")
    def validate_update(self) -> UpdateTodoTaskInput:
        if all(value is None for value in (self.title, self.status, self.importance, self.due)):
            raise ValueError("at least one To Do task field must be provided")
        return self


class SendChannelMessageInput(StrictInput):
    team_id: str = Field(min_length=1, max_length=512)
    channel_id: str = Field(min_length=1, max_length=512)
    body_text: str = Field(min_length=1, max_length=20_000)
    idempotency_key: UUID


class SendChatMessageInput(StrictInput):
    chat_id: str = Field(min_length=1, max_length=512)
    body_text: str = Field(min_length=1, max_length=20_000)
    idempotency_key: UUID
