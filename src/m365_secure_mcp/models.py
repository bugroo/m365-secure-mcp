"""Strict Pydantic input models for MCP tools."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Annotated, Literal, TypeAlias
from uuid import UUID

from pydantic import (
    AfterValidator,
    BaseModel,
    ConfigDict,
    Field,
    field_validator,
    model_validator,
)


class ResponseFormat(StrEnum):
    MARKDOWN = "markdown"
    JSON = "json"


class StrictInput(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True, validate_assignment=True)


Limit = Annotated[int, Field(ge=1, le=50)]


def _safe_etag(value: str) -> str:
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise ValueError("etag contains control characters")
    return value


ETag = Annotated[
    str,
    Field(min_length=4, max_length=1_000),
    AfterValidator(_safe_etag),
]


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
    user_id: UUID | None = None
    device_id: UUID | None = None
    cloudpc_id: UUID | None = None
    application_id: UUID | None = None
    service_principal_id: UUID | None = None
    ediscovery_case_id: UUID | None = None
    retention_label_id: UUID | None = None


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


class OfficeFileInput(StrictInput):
    drive_id: str = Field(min_length=1, max_length=512)
    item_id: str = Field(min_length=1, max_length=512)
    max_characters: int = Field(default=24_000, ge=1_000, le=50_000)
    include_notes: bool = False
    response_format: ResponseFormat = ResponseFormat.MARKDOWN


class OfficeTextReplacement(StrictInput):
    old_text: str = Field(min_length=1, max_length=2_000)
    new_text: str = Field(max_length=4_000)


class ReplaceOfficeTextInput(StrictInput):
    drive_id: str = Field(min_length=1, max_length=512)
    item_id: str = Field(min_length=1, max_length=512)
    etag: ETag
    replacements: list[OfficeTextReplacement] = Field(
        min_length=1,
        max_length=20,
    )
    include_notes: bool = False
    idempotency_key: UUID

    @model_validator(mode="after")
    def validate_replacements(self) -> ReplaceOfficeTextInput:
        old_values = [item.old_text for item in self.replacements]
        if len(old_values) != len(set(old_values)):
            raise ValueError("Office replacements contain duplicate old_text values")
        if any(item.old_text == item.new_text for item in self.replacements):
            raise ValueError("Office replacement old_text and new_text must differ")
        return self


class WorkbookRangeInput(StrictInput):
    drive_id: str = Field(min_length=1, max_length=512)
    item_id: str = Field(min_length=1, max_length=512)
    worksheet: str = Field(
        min_length=1,
        max_length=255,
        pattern=r"^[^/\\\x00-\x1f\x7f]{1,255}$",
    )
    address: str = Field(
        min_length=2,
        max_length=32,
        pattern=r"^[A-Za-z]{1,3}[1-9][0-9]{0,6}(?::[A-Za-z]{1,3}[1-9][0-9]{0,6})?$",
    )
    response_format: ResponseFormat = ResponseFormat.MARKDOWN


class WorkbookInput(StrictInput):
    drive_id: str = Field(min_length=1, max_length=512)
    item_id: str = Field(min_length=1, max_length=512)
    response_format: ResponseFormat = ResponseFormat.MARKDOWN


WorkbookScalar: TypeAlias = str | int | float | bool | None


class UpdateWorkbookRangeInput(WorkbookRangeInput):
    values: list[list[WorkbookScalar]] = Field(
        min_length=1,
        max_length=100,
    )
    idempotency_key: UUID

    @field_validator("values")
    @classmethod
    def validate_values(
        cls,
        value: list[list[WorkbookScalar]],
    ) -> list[list[WorkbookScalar]]:
        if any(not row or len(row) > 50 for row in value):
            raise ValueError("Excel rows must contain between 1 and 50 cells")
        width = len(value[0])
        if any(len(row) != width for row in value):
            raise ValueError("Excel values must form a rectangular matrix")
        if len(value) * width > 5_000:
            raise ValueError("Excel write exceeds the 5,000-cell limit")
        for row in value:
            for cell in row:
                if isinstance(cell, str):
                    if len(cell) > 8_000:
                        raise ValueError("Excel cell text exceeds policy")
                    if cell.lstrip().startswith(("=", "+", "-", "@")):
                        raise ValueError(
                            "Excel formula-like strings are disabled; "
                            "values must be literal"
                        )
        return value


class OneNotePageInput(StrictInput):
    page_id: str = Field(min_length=1, max_length=512)
    max_characters: int = Field(default=24_000, ge=1_000, le=50_000)
    response_format: ResponseFormat = ResponseFormat.MARKDOWN


class AppendOneNotePageTextInput(StrictInput):
    page_id: str = Field(min_length=1, max_length=512)
    text: str = Field(min_length=1, max_length=20_000)
    idempotency_key: UUID


class PowerBIWorkspaceInput(PageInput):
    workspace_id: UUID


class PowerBIListInput(PageInput):
    pass


class PowerBIReportInput(StrictInput):
    workspace_id: UUID
    report_id: UUID
    response_format: ResponseFormat = ResponseFormat.MARKDOWN


class PowerBIDatasetInput(PageInput):
    workspace_id: UUID
    dataset_id: UUID


class RefreshPowerBIDatasetInput(StrictInput):
    workspace_id: UUID
    dataset_id: UUID
    notify_option: Literal["MailOnFailure", "NoNotification"] = (
        "MailOnFailure"
    )
    idempotency_key: UUID


class RebindPowerBIReportInput(StrictInput):
    workspace_id: UUID
    report_id: UUID
    dataset_id: UUID
    idempotency_key: UUID


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
    etag: ETag
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
    details_etag: Annotated[
        ETag,
        Field(
            description=(
                "ETag from m365_get_planner_task.details_etag. "
                "The basic Planner task ETag is a different concurrency token."
            ),
        ),
    ]
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
    etag: ETag
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
    etag: ETag
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


class UpdateEntraUserOperationalProfileInput(StrictInput):
    """Closed T1 input: three operational metadata fields and no identity controls."""

    user_id: UUID
    job_title: str | None = Field(default=None, min_length=1, max_length=128)
    department: str | None = Field(default=None, min_length=1, max_length=128)
    office_location: str | None = Field(default=None, min_length=1, max_length=128)
    idempotency_key: UUID

    @model_validator(mode="after")
    def validate_update(self) -> UpdateEntraUserOperationalProfileInput:
        profile_fields = {"job_title", "department", "office_location"}
        supplied = self.model_fields_set & profile_fields
        if not supplied:
            raise ValueError("at least one operational profile field is required")
        if any(getattr(self, field) is None for field in supplied):
            raise ValueError("operational profile fields cannot be null")
        return self


class SetDirectoryUserAccountInput(StrictInput):
    user_id: UUID
    account_enabled: bool
    idempotency_key: UUID


class UpdateDirectoryGroupInput(StrictInput):
    group_id: UUID
    display_name: str | None = Field(
        default=None,
        min_length=1,
        max_length=256,
    )
    description: str | None = Field(default=None, max_length=1_024)
    idempotency_key: UUID

    @model_validator(mode="after")
    def validate_update(self) -> UpdateDirectoryGroupInput:
        if self.display_name is None and self.description is None:
            raise ValueError("at least one group field is required")
        return self


class AddUserToGroupInput(StrictInput):
    group_id: UUID
    user_id: UUID
    idempotency_key: UUID


class ManagedDeviceActionInput(StrictInput):
    managed_device_id: UUID
    idempotency_key: UUID


class CloudPCActionInput(StrictInput):
    cloudpc_id: UUID
    idempotency_key: UUID


class UpdateApplicationInput(StrictInput):
    application_id: UUID
    display_name: str | None = Field(default=None, min_length=1, max_length=256)
    group_membership_claims: Literal["None", "SecurityGroup", "All"] | None = None
    idempotency_key: UUID

    @model_validator(mode="after")
    def validate_update(self) -> UpdateApplicationInput:
        if self.display_name is None and self.group_membership_claims is None:
            raise ValueError("at least one application field must be provided")
        return self


class UpdateServicePrincipalInput(StrictInput):
    service_principal_id: UUID
    display_name: str | None = Field(default=None, min_length=1, max_length=256)
    account_enabled: bool | None = None
    app_role_assignment_required: bool | None = None
    idempotency_key: UUID

    @model_validator(mode="after")
    def validate_update(self) -> UpdateServicePrincipalInput:
        if (
            self.display_name is None
            and self.account_enabled is None
            and self.app_role_assignment_required is None
        ):
            raise ValueError("at least one service-principal field must be provided")
        return self


class UpdateConditionalAccessPolicyInput(StrictInput):
    policy_id: UUID
    state: Literal["enabled", "disabled", "enabledForReportingButNotEnforced"]
    display_name: str | None = Field(default=None, min_length=1, max_length=256)
    idempotency_key: UUID
