# Testing Skill - General Guidelines

## Purpose
This skill provides testing strategies for Django applications, covering unit tests, integration tests, and test coverage standards.

## Core Principles

1. **Test at the Right Level**
   - Unit tests: Test individual functions/methods in isolation
   - Integration tests: Test components working together (models + views, API endpoints)
   - End-to-end: Test complete workflows

2. **Test Isolation**
   - Each test should be independent
   - Use fixtures and factories for test data
   - Clean up after tests (transactions, files, cache)

3. **Test Coverage**
   - Aim for >80% coverage on critical paths
   - Don't test framework code
   - Focus on business logic, not trivial getters/setters

4. **Test Clarity**
   - Test names should describe what is being tested
   - Use descriptive assertions
   - One assertion per test (or related assertions)

## Django Testing Patterns

### File Structure
```python
# apps/myapp/tests.py or apps/myapp/tests/
# For larger apps, use:
tests/
  __init__.py
  test_models.py
  test_views.py
  test_services.py
  test_api.py
  fixtures/
```

### Test Class Naming
```python
# Pattern: Test[Component][Scenario]
class TestUserModelCreation(TestCase):
    pass

class TestDashboardViewPermissions(TestCase):
    pass

class TestAPIWebhookProcessing(TestCase):
    pass
```

### Test Method Naming
```python
# Pattern: test_[what]_[given_condition]_[expected_result]
def test_create_user_with_valid_data_returns_success(self):
    pass

def test_create_user_without_email_raises_validation_error(self):
    pass

def test_dashboard_user_without_permission_gets_403(self):
    pass
```

## Common Test Patterns

### Model Tests
```python
from django.test import TestCase
from apps.users.models import User

class TestUserModel(TestCase):
    def setUp(self):
        self.user_data = {
            'username': 'testuser',
            'email': 'test@example.com'
        }
    
    def test_create_user_with_valid_data(self):
        user = User.objects.create(**self.user_data)
        self.assertEqual(user.username, 'testuser')
        self.assertTrue(user.is_active)
    
    def test_user_string_representation(self):
        user = User.objects.create(**self.user_data)
        self.assertEqual(str(user), 'testuser')
```

### View Tests
```python
from django.test import TestCase, Client as TestClient
from django.contrib.auth.models import User

class TestDashboardView(TestCase):
    def setUp(self):
        self.user = User.objects.create_user('testuser', 'test@test.com', 'pass123')
        self.client = TestClient()
    
    def test_dashboard_requires_login(self):
        response = self.client.get('/api/dashboard/')
        self.assertEqual(response.status_code, 302)  # Redirect to login
    
    def test_dashboard_accessible_to_logged_in_user(self):
        self.client.login(username='testuser', password='pass123')
        response = self.client.get('/api/dashboard/')
        self.assertEqual(response.status_code, 200)
```

### Service/Helper Tests
```python
from django.test import TestCase
from apps.services.validators import validate_email

class TestEmailValidator(TestCase):
    def test_validate_email_with_valid_email(self):
        result = validate_email('user@example.com')
        self.assertTrue(result)
    
    def test_validate_email_with_invalid_email(self):
        result = validate_email('invalid-email')
        self.assertFalse(result)
```

## Test Coverage Checklist

- [ ] Models: Create, read, update, delete operations
- [ ] Model methods: Custom methods, properties, validation
- [ ] Views: GET/POST requests, authentication, permissions
- [ ] Services: Business logic, error handling, edge cases
- [ ] Signals: If used, test signal handlers
- [ ] Managers: Custom queryset methods

## Running Tests

```bash
# Run all tests
python manage.py test

# Run specific app tests
python manage.py test apps.users

# Run specific test class
python manage.py test apps.users.tests.TestUserModel

# Run with coverage
coverage run --source='apps' manage.py test
coverage report
coverage html  # Generate HTML report
```

## Common Pitfalls

❌ **Don't:**
- Test framework behavior (Django's `save()`, `delete()`)
- Skip test cleanup (transactions are rolled back but fixtures need cleanup)
- Write tests without setup/teardown
- Test multiple unrelated things in one test
- Ignore test failures (fix them immediately)

✅ **Do:**
- Use `TestCase` for tests that need database
- Use `SimpleTestCase` for tests that don't need database
- Use factories for test data (django-factory)
- Mock external services (API calls, email)
- Run tests before committing
