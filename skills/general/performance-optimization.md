# Performance Optimization Skill - General Guidelines

## Purpose
This skill provides strategies for identifying and fixing performance issues in Django applications.

## Core Principles

1. **Measure First**
   - Identify the actual bottleneck before optimizing
   - Use profiling tools
   - Avoid premature optimization

2. **Optimize in Order of Impact**
   1. Database queries (biggest impact)
   2. Caching strategies
   3. Code efficiency
   4. Frontend/asset optimization

3. **Profile Before and After**
   - Verify the improvement
   - Ensure no regressions
   - Document the fix

## Database Query Optimization

### Identify N+1 Queries
```python
# ❌ BAD: N+1 query problem
for user in User.objects.all():
    print(user.profile.bio)  # New query for each user!

# ✅ GOOD: Use select_related
for user in User.objects.select_related('profile').all():
    print(user.profile.bio)  # Already loaded
```

### Use select_related vs prefetch_related

**select_related** (One-to-One, Foreign Key):
```python
# User has one Profile (FK)
users = User.objects.select_related('profile').all()
```

**prefetch_related** (Many-to-Many, Reverse FK):
```python
# User has many Posts (reverse FK)
users = User.objects.prefetch_related('post_set').all()
```

### Optimize Complex Queries
```python
# ❌ BAD: Too much data
events = Event.objects.all()  # Loads all fields

# ✅ GOOD: Select only needed fields
events = Event.objects.only('id', 'user_id', 'title')
```

### Use indexes
```python
class Event(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)
    status = models.CharField(max_length=20, db_index=True)
    
    class Meta:
        indexes = [
            models.Index(fields=['user', 'created_at']),
        ]
```

## Caching Strategies

### Query Caching
```python
from django.views.decorators.cache import cache_page
from django.core.cache import cache

# Cache entire view for 5 minutes
@cache_page(60 * 5)
def stats_view(request):
    return render(request, 'stats.html')

# Cache specific query result
def get_user_stats(user_id):
    key = f'user_stats_{user_id}'
    stats = cache.get(key)
    if stats is None:
        stats = calculate_stats(user_id)
        cache.set(key, stats, 60 * 60)  # Cache for 1 hour
    return stats
```

### Cache Invalidation
```python
from django.db.models.signals import post_save

# Invalidate cache when user changes
@receiver(post_save, sender=User)
def invalidate_user_cache(sender, instance, **kwargs):
    cache.delete(f'user_stats_{instance.id}')
    cache.delete(f'user_profile_{instance.id}')
```

## Async Tasks for Heavy Operations

```python
from celery import shared_task

# Don't block request for long-running tasks
@shared_task
def process_data_export(export_id):
    export = DataExport.objects.get(id=export_id)
    # Long-running operation
    result = generate_export(export)
    export.result = result
    export.save()

# In view
def create_export(request):
    export = DataExport.objects.create(...)
    process_data_export.delay(export.id)
    return JsonResponse({'status': 'processing'})
```

## Profiling Tools

### Django Debug Toolbar
```python
# settings.py
if DEBUG:
    INSTALLED_APPS += ['debug_toolbar']
    MIDDLEWARE += ['debug_toolbar.middleware.DebugToolbarMiddleware']
```

### Query Logging
```python
# settings.py
LOGGING = {
    'version': 1,
    'handlers': {
        'console': {
            'class': 'logging.StreamHandler',
        },
    },
    'loggers': {
        'django.db.backends': {
            'handlers': ['console'],
            'level': 'DEBUG',
        },
    },
}
```

### Python Profiling
```python
import cProfile
import pstats

def profile_function():
    pr = cProfile.Profile()
    pr.enable()
    
    # Your code here
    expensive_operation()
    
    pr.disable()
    ps = pstats.Stats(pr).sort_stats('cumulative')
    ps.print_stats(10)  # Print top 10 slowest functions
```

## Common Performance Checklist

- [ ] Are database queries using select_related/prefetch_related?
- [ ] Are frequently accessed queries cached?
- [ ] Are heavy operations moved to background tasks?
- [ ] Are indexes on frequently queried fields?
- [ ] Is pagination used for large result sets?
- [ ] Are raw SQL queries avoided in favor of ORM?
- [ ] Are assets minified and compressed?
- [ ] Is debug mode OFF in production?

## Monitoring in Production

```python
# Use APM tools like New Relic, Datadog
# Track:
# - Slow queries
# - Slow views
# - Error rates
# - Resource usage
```

## Common Pitfalls

❌ **Don't:**
- Optimize without measuring
- Over-cache and create stale data
- Block requests on heavy operations
