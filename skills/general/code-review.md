# Code Review Skill - General Guidelines

## Purpose
This skill provides a structured approach to code review, helping maintain code quality and consistency across the project.

## Core Principles

1. **Review with Respect**
   - Separate code from person
   - Ask questions, don't demand
   - Acknowledge good work

2. **Review for Multiple Aspects**
   - Functionality: Does it work correctly?
   - Readability: Can others understand it?
   - Maintainability: Can it be easily modified?
   - Performance: Is it efficient?
   - Security: Are there vulnerabilities?

3. **Focus on What Matters**
   - Business logic correctness (High priority)
   - Error handling (High priority)
   - Code style (Low priority - use linters)
   - Naming clarity (Medium priority)

## Code Review Checklist

### Functionality
- [ ] Does the code solve the stated problem?
- [ ] Are edge cases handled?
- [ ] Are error cases handled?
- [ ] Are there any obvious bugs?
- [ ] Does it follow the existing patterns in the codebase?

### Readability & Clarity
- [ ] Are variable names descriptive?
- [ ] Are function/method names clear?
- [ ] Is complex logic commented?
- [ ] Are there unnecessary nested blocks?
- [ ] Is the code DRY (Don't Repeat Yourself)?

### Django Specific
- [ ] Are database queries optimized? (Use `select_related`, `prefetch_related`)
- [ ] Are there N+1 query problems?
- [ ] Are permissions/authentication checked?
- [ ] Are models using appropriate field types?
- [ ] Is business logic in models/services, not views?

### Testing
- [ ] Are tests included?
- [ ] Do tests cover happy path and error cases?
- [ ] Are tests clear and well-named?
- [ ] Is test coverage adequate?

### Security
- [ ] Are inputs validated?
- [ ] Is sensitive data logged?
- [ ] Are SQL injections prevented? (Use ORM)
- [ ] Are CSRF tokens used in forms?
- [ ] Are permissions enforced?

### Performance
- [ ] Are there obvious performance issues?
- [ ] Are database queries efficient?
- [ ] Is caching used appropriately?
- [ ] Are large operations async/background tasks?

## Common Review Comments

### ✅ Good Comments
```
"This would be clearer as a named constant"
"Consider using select_related() here to avoid N+1"
"This might fail if X is None - should we add a check?"
"Great use of the signal pattern here"
```

### ❌ Avoid These
```
"This is bad code"
"Why would you do this?"
"This is obviously wrong"
"Just use X instead" (without explanation)
```

## Review Response Guide

### For Reviewers' Questions
If unsure about a comment:
1. Ask for clarification
2. Explain your reasoning
3. Be open to learning

### For Authors' Responses
- Don't be defensive
- Explain your thinking if unclear
- Accept improvements gracefully
- Argue about important points, accept on style

## Approval Criteria

Before approving, verify:
- [ ] Code solves the stated problem
- [ ] Tests are included and passing
- [ ] No obvious bugs or security issues
- [ ] Follows project conventions
- [ ] Documentation updated (if needed)
- [ ] Performance is acceptable
- [ ] Error handling is adequate

## PR Template

```markdown
## Description
[What does this PR do?]

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Breaking change
- [ ] Documentation update

## How to Test
[How to verify the change works]

## Testing Done
- [ ] Unit tests added
- [ ] Integration tests added
- [ ] Tested locally

## Checklist
- [ ] Code follows project style
- [ ] No console.log / print statements left
- [ ] Comments added for complex logic
- [ ] Documentation updated
- [ ] No breaking changes (or documented)
```

## When to Request Changes vs Approve

### Request Changes If:
- [ ] Functionality is incorrect
- [ ] Security issue detected
- [ ] Tests are missing
- [ ] Performance is significantly degraded

### Approve With Comments If:
- [ ] Minor style issues (linter can fix)
- [ ] Suggestions for improvement
- [ ] Praise for good code

### Approve If:
- [ ] All checks pass
- [ ] Tests cover scenarios
- [ ] Code is clear and maintainable
- [ ] Follows project conventions

## Common Pitfalls

❌ **Don't:**
- Approve without reading the code
- Review based on author reputation
- Make personal comments about code style
- Approve outdated PRs without re-review
- Block on nitpicks

✅ **Do:**
- Read the entire diff
- Run the code locally if complex
- Check for consistency with codebase
- Re-review after changes
- Focus on impact
