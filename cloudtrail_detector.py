#!/usr/bin/env python3

from __future__ import annotations

import argparse
import json
from collections import Counter, defaultdict
from dataclasses import dataclass
from typing import Any


FAILED_LOGIN_THRESHOLD = 3
GET_OBJECT_THRESHOLD = 10

IAM_ENUMERATION_EVENTS = {
    "ListUsers",
    "ListRoles",
    "GetAccountAuthorizationDetails",
    "ListAccessKeys",
}

PRIVILEGE_ESCALATION_EVENTS = {
    "AttachUserPolicy",
    "PutUserPolicy",
    "AddUserToGroup",
    "CreateAccessKey",
    "UpdateAssumeRolePolicy",
}

S3_DATA_ACCESS_EVENTS = {
    "ListBuckets",
    "GetObject",
}

DESTRUCTIVE_OR_EVASION_EVENTS = {
    "DeleteBucket",
    "DeleteObject",
    "StopLogging",
    "DeleteTrail",
    "DisableKey",
    "ScheduleKeyDeletion",
}


@dataclass(frozen=True)
class Event:
    event_time: str
    event_name: str
    event_source: str
    user: str
    source_ip: str
    error_message: str
    request_parameters: Any
    response_elements: Any
    raw: dict[str, Any]


def load_records(path: str) -> list[dict[str, Any]]:
    with open(path, "r", encoding="utf-8") as log_file:
        data = json.load(log_file)

    records = data.get("Records", [])
    if not isinstance(records, list):
        raise ValueError("Expected logs JSON to contain a list at key 'Records'.")

    return records


def get_user(identity: Any) -> str:
    if not isinstance(identity, dict):
        return "Unknown"

    return (
        identity.get("userName")
        or identity.get("arn")
        or identity.get("principalId")
        or "Unknown"
    )


def normalize_event(record: dict[str, Any]) -> Event:
    return Event(
        event_time=str(record.get("eventTime", "Unknown")),
        event_name=str(record.get("eventName", "Unknown")),
        event_source=str(record.get("eventSource", "Unknown")),
        user=get_user(record.get("userIdentity")),
        source_ip=str(record.get("sourceIPAddress", "Unknown")),
        error_message=str(record.get("errorMessage") or ""),
        request_parameters=record.get("requestParameters"),
        response_elements=record.get("responseElements"),
        raw=record,
