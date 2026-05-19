# AWS Log Parser

A Python script that parses AWS cloudtrail json logs and detects suspicious activity using simple behavioral analysis.

## What It Does

Reads logs.json, extracts cloudtrail json logs, and generate alerts. Quite basic feel free to add your own relevant fields. Ive included the field extraction below if youre curious about the specifics.

## Extracted Fields

The script extracts:

- Event time
- Event name
- Event source
- User identity
- Source IP address
- Error message
- Request parameters
- Response elements

## Detection Rules

The parser detects:

- Multiple failed `ConsoleLogin` attempts from the same user or IP
- Successful `ConsoleLogin` after several failures from the same IP
- IAM enumeration activity such as:
  - `ListUsers`
  - `ListRoles`
  - `GetAccountAuthorizationDetails`
  - `ListAccessKeys`
- Privilege escalation activity such as:
  - `AttachUserPolicy`
  - `PutUserPolicy`
  - `AddUserToGroup`
  - `CreateAccessKey`
  - `UpdateAssumeRolePolicy`
- S3 access and possible exfiltration indicators such as:
  - `ListBuckets`
  - `GetObject`
  - A large number of `GetObject` events from the same user/IP
- Destructive or defense-evasion activity such as:
  - `DeleteBucket`
  - `DeleteObject`
  - `StopLogging`
  - `DeleteTrail`
  - `DisableKey`
  - `ScheduleKeyDeletion`

## Alert Output

Each alert includes:

- Severity
- Reason
- User
- Source IP
- Event time
- Event name

The script also prints a summary count of suspicious events by category.

## How To Use

switch out my logs.json with your own logs, its just a temp holder.

```text
logs.json
