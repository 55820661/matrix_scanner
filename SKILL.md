# SKILL.md - Project Skills Guide

## Overview
This is the master Skills guide for the repository. Skills are documented best-practices and checklists for common development domains.

## Available Skills

### General Skills (Applicable to Any Project)
Located in `skills/general/`:
- **testing.md** - Unit testing, integration testing, test coverage strategies
- **code-review.md** - Code quality standards, PR review checklist
- **performance-optimization.md** - Database optimization, caching, profiling

### Project-Specific Skills
Located in `skills/project/`:
- **architecture.md** - Matrix Scanner component boundaries and MVP architecture.
- **security.md** - Telegram identity, tool execution safety, secrets, and approved-fix constraints.
- **tool-design.md** - Safe internal tool contracts, registry rules, and handler patterns.
- **diagnostics.md** - Read-only diagnostic scanner rules for Linux and Laravel stack services.
- **telegram.md** - Telegram long polling, command handling, auth, and output rules.
- **testing.md** - Project-specific test strategy for scanners, tools, alerts, and Telegram.

## How to Use Skills

When working on a task:
1. Identify the relevant skill domain
2. Load the appropriate skill file from `skills/`
3. Follow the documented patterns and best practices
4. Reference the skill file in PRs or documentation when relevant

## Skill Structure
Each skill file should include:
- Purpose: What this skill covers
- Core Principles: Foundational concepts
- Patterns: Recommended code patterns
- Checklist: Quality verification steps
- Examples: Brief, real-world examples
- Common Pitfalls: What to avoid

## When NOT to Use Skills
- For general programming language reference (use upstream docs)
- For major architectural decisions (use project planning docs)

## When TO Use Skills
- Before writing tests, reviews, or optimizations
- When introducing new patterns in the codebase

## Contributing New Skills
1. Document the pattern and rationale
2. Add examples and checklist
3. Place under `skills/general` or `skills/project`
4. Link it from this `SKILL.md`
