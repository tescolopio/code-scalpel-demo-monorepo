# Stage 10: Vibe Coding Adversarial Gauntlet

This stage contains tests for common pitfalls in AI-assisted "Vibe Coding"
where developers use LLMs to generate code without deep understanding.

These patterns represent real-world failures where:
- AI-generated code "works" but is insecure
- Code passes functional tests but has security holes
- Patterns look correct but are applied in wrong context
- Copy-paste from training data introduces vulnerabilities

## Why This Matters for Code Scalpel

If Code Scalpel can detect these patterns, it provides value that:
1. Pure LLMs cannot (they generate these patterns)
2. Traditional SAST misses (patterns are syntactically valid)
3. Human review often misses (code "looks right")

## Obstacles

### 10.1 - Stack Overflow Syndrome
Code copied from SO answers that worked in 2015 but is insecure now.
- MD5 for passwords (was common advice)
- `pickle.loads()` for serialization
- `shell=True` for "convenience"
- JWT without verification

### 10.2 - Framework Version Confusion
Code written for framework X.old applied to X.new where security defaults changed.
- Django CSRF exemptions
- Flask debug mode patterns
- Express.js middleware ordering
- SQLAlchemy 1.x vs 2.x patterns

### 10.3 - The "It Works" Fallacy
Functionally correct code that passes all tests but has security holes.
- Authentication that authenticates
- Authorization that authorizes the wrong thing
- Encryption that encrypts (but with hardcoded key)

### 10.4 - Context Window Blindness
Patterns where AI couldn't see relevant code in other files.
- Assuming validation exists elsewhere (it doesn't)
- Trusting data from "internal" APIs
- Missing rate limiting because it's "handled by nginx"

### 10.5 - Library Lookalikes
Confusing similar libraries with different security properties.
- `yaml.load()` vs `yaml.safe_load()`
- `json.loads()` vs `pickle.loads()`
- `requests` vs `urllib` (different SSL defaults)

### 10.6 - The Confident Comment
AI generates confident-sounding comments that are wrong.
- "This is secure because..."
- "No need to validate here since..."
- "XSS is not possible because..."

### 10.7 - Async Footguns
Async/await patterns that look correct but have races.
- Check-then-act without locking
- Shared mutable state across coroutines
- Resource exhaustion via unbounded concurrency

### 10.8 - The Deprecated API Trap
Using APIs that still work but are known insecure.
- `cgi` module in Python
- `mysql_real_escape_string` in PHP patterns
- `DES` encryption

### 10.9 - Environment Variable Trust
Blindly trusting environment variables.
- `DEBUG=True` in production
- API keys without validation
- URLs from env without sanitization

### 10.10 - The ORM Escape Hatch
Raw SQL injection in an otherwise ORM-heavy codebase.
- SQLAlchemy `text()`
- Django `raw()`
- Prisma `$queryRaw`

### 10.11 - Template Literal Injection
Modern template strings used unsafely.
- JavaScript template literals in SQL
- Python f-strings in queries
- Ruby string interpolation

### 10.12 - The Authorization Afterthought
Authentication exists, authorization doesn't.
- `@login_required` without permission checks
- JWT validation without claims checking
- Session exists but no role verification

### 10.13 - Implicit Trust Boundaries
Assuming internal services are trustworthy.
- Internal API without authentication
- Microservice-to-microservice trust
- Container-to-container assumptions

### 10.14 - The Partial Fix
Security fix that doesn't cover all paths.
- Input validated in POST but not GET
- API v2 fixed but v1 still exposed
- Admin panel secured but debug endpoint open
