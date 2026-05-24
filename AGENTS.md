# Project Agents Guide

## Purpose
This file describes how automation agents, helpers, or bots should behave when operating in this repository.

## Role
Agents assist contributors by performing safe, explicit tasks such as gathering context, creating or updating non-sensitive documentation, and running non-destructive checks.

## Allowed Without Extra Approval
- Read and summarize repository files.
- Create or update documentation, templates, or helper files when requested.
- Run linting, static analysis, or non-destructive tests when requested.

## Require Explicit Approval
Do not proceed without approval for actions that change behaviour, infrastructure, dependencies, or that modify production code in ways that affect runtime or data.

Examples requiring approval:
- Installing or removing dependencies
- Changing runtime configuration or environment settings
- Creating, deleting, or renaming source files that affect application behavior
- Running destructive operations or migrations against production data

## Decision Rules
- When a decision is needed, present up to three options with brief trade-offs.
- If the intent is unclear, stop and ask rather than guessing.

## Working Style
- Be minimal and reversible: prefer smaller, reviewable edits.
- Keep changes documented and scoped to the user's request.
- Avoid unasked-for refactors or style-only mass edits.

## Useful Local References
- Skills and guides: [skills/general](skills/general)

## Priority
Follow the user's explicit instructions first; when unsure, ask.
