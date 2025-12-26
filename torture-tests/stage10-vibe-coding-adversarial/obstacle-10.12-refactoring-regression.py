"""Obstacle 10.12: Refactoring Regression

When asked to rename or refactor, LLMs do surface-level regex-like replacements
that miss:
- String literals containing the symbol
- Dynamic attribute access (getattr)
- Serialization/deserialization mappings
- Database column names
- API response keys
- Configuration files
- Comments and documentation

This creates "Silent Failures" that compile but break at runtime.

DIFFERENTIATOR: Code Scalpel uses Program Dependency Graphs (PDG) to catch
every data-flow dependency, not just static references.

PASS CRITERIA:
- get_symbol_references must find ALL references including:
  - String literals
  - Dict keys matching symbol name
  - SQL column references
  - Reflection/getattr
  - Serialization mappings
- update_symbol must refuse or warn if string references exist
"""

import json
import pickle


# =============================================================================
# SCENARIO 1: Rename userID to accountId
# LLM updates function parameters but misses everything else
# =============================================================================

class UserService:
    """User service with multiple reference types."""

    def get_user(self, user_id: int) -> dict:
        """Get user by ID."""
        # LLM would rename user_id to account_id here...

        # MISSED REFERENCE: SQL column name in string
        query = f"SELECT * FROM users WHERE user_id = {user_id}"

        # MISSED REFERENCE: JSON key in API response
        return {
            "user_id": user_id,  # LLM might catch this dict key
            "data": self._fetch_data(user_id)
        }

    def _fetch_data(self, user_id: int) -> dict:
        """Fetch additional user data."""

        # MISSED REFERENCE: Dynamic attribute access
        field_name = "user_id"
        result = {}
        result[field_name] = user_id  # Dynamic key!

        # MISSED REFERENCE: Reflection pattern
        config = {"field": "user_id", "table": "users"}
        column = config["field"]  # Config references the old name

        return result

    def serialize_user(self, user_id: int) -> str:
        """Serialize user for API."""
        # MISSED REFERENCE: JSON serialization schema expects user_id
        data = {"user_id": user_id, "type": "user"}
        return json.dumps(data)

    def log_access(self, user_id: int) -> None:
        """Log user access."""
        # MISSED REFERENCE: Log format string
        import logging
        logging.info(f"Access by user_id={user_id}")

        # MISSED REFERENCE: Metrics/monitoring key
        metrics.increment("user.access", tags={"user_id": str(user_id)})


# External file would have matching references:
# config.yaml:
#   database:
#     user_table:
#       id_column: user_id  # MISSED!
#
# api_schema.json:
#   {"properties": {"user_id": {"type": "integer"}}}  # MISSED!


# =============================================================================
# SCENARIO 2: Rename helper function "process" to "transform"
# Function exists in multiple contexts with same name
# =============================================================================

def process(data: dict) -> dict:
    """Main process function to be renamed."""
    return {"processed": True, **data}


class DataPipeline:
    def run(self, raw_data: dict) -> dict:
        # DIRECT REFERENCE: LLM would catch this
        result = process(raw_data)

        # MISSED REFERENCE: Function name in string for dynamic dispatch
        handler = "process"
        func = globals()[handler]  # Dynamic lookup!

        # MISSED REFERENCE: Callback registration by name
        self.callbacks = {"on_process": self._on_process}

        # MISSED REFERENCE: String matching for routing
        if raw_data.get("action") == "process":
            return process(raw_data)

        return result

    def _on_process(self, data):
        """Callback when process completes."""
        pass


# MISSED REFERENCE: Celery task registration
# @app.task(name="tasks.process")  # Task name in decorator
# def process_async(data):
#     return process(data)


# MISSED REFERENCE: URL routing
# url_patterns = [
#     path("api/process/", views.process_view, name="process"),
# ]


# MISSED REFERENCE: Test file
# def test_process():
#     assert process({"x": 1}) == {"processed": True, "x": 1}


# =============================================================================
# SCENARIO 3: Rename class "User" to "Account"
# Database models, serializers, and ORM all have references
# =============================================================================

class User:  # To be renamed to Account
    """User model."""

    def __init__(self, id: int, name: str):
        self.id = id
        self.name = name

    def to_dict(self) -> dict:
        return {"id": self.id, "name": self.name, "type": "User"}  # MISSED: string


# ORM-style mapping
# MISSED REFERENCE: Table name derived from class name
USER_TABLE = "users"  # Would need to change to "accounts"

# MISSED REFERENCE: SQLAlchemy-style tablename
# __tablename__ = "users"  # In the class definition

# MISSED REFERENCE: Serialization registry
SERIALIZERS = {
    "User": lambda u: u.to_dict(),  # Key is class name as string
    "Order": lambda o: o.to_dict(),
}


def deserialize(data: dict):
    """Deserialize object from dict."""
    # MISSED REFERENCE: Type field in JSON
    obj_type = data.get("type")  # "User" as string!
    if obj_type == "User":  # String comparison
        return User(data["id"], data["name"])
    return None


# MISSED REFERENCE: Pickle compatibility
# Old pickled objects have User class, new code has Account
# This breaks deserialization of existing data!


# MISSED REFERENCE: Database migration needed
# ALTER TABLE users RENAME TO accounts;
# All foreign keys referencing users need updating


# =============================================================================
# SCENARIO 4: Rename API field "created_at" to "createdAt" (snake_case to camelCase)
# Common refactoring that breaks API consumers
# =============================================================================

def get_resource(resource_id: int) -> dict:
    """Get resource with timestamp."""
    import datetime

    return {
        "id": resource_id,
        "created_at": datetime.datetime.now().isoformat(),  # To be renamed
        "updated_at": datetime.datetime.now().isoformat(),
    }


# MISSED REFERENCES:

# 1. API documentation
# """
# Response:
#   - id: integer
#   - created_at: ISO 8601 timestamp  <-- Documentation
# """

# 2. Frontend JavaScript code
# const displayDate = response.created_at;  // Will break!

# 3. OpenAPI/Swagger schema
# created_at:
#   type: string
#   format: date-time

# 4. Database column
# SELECT id, created_at FROM resources;

# 5. Analytics queries
# SELECT DATE(created_at), COUNT(*) FROM resources GROUP BY 1;

# 6. Elasticsearch mapping
# {"created_at": {"type": "date"}}

# 7. Client SDK
# resource.created_at  // Generated client code


# =============================================================================
# SCENARIO 5: Rename constant MAX_RETRIES to RETRY_LIMIT
# Constants often have string references in configs and logs
# =============================================================================

MAX_RETRIES = 3  # To be renamed to RETRY_LIMIT


def with_retry(func):
    """Retry decorator."""

    def wrapper(*args, **kwargs):
        for attempt in range(MAX_RETRIES):  # Direct reference
            try:
                return func(*args, **kwargs)
            except Exception as e:
                # MISSED REFERENCE: Constant name in log message
                if attempt >= MAX_RETRIES - 1:
                    raise
                print(f"Retry {attempt + 1}/{MAX_RETRIES}")  # String with name
        return None

    return wrapper


# MISSED REFERENCES:

# Environment variable
# MAX_RETRIES = int(os.environ.get("MAX_RETRIES", 3))

# Config file
# max_retries: 3  # YAML key matches constant name

# Monitoring/alerting
# alert_rules:
#   - name: "too_many_retries"
#     condition: "retry_count >= MAX_RETRIES"

# Feature flags
# if feature_flags.get("use_new_MAX_RETRIES"):
#     retries = 5


# =============================================================================
# SCENARIO 6: The getattr/setattr Minefield
# Dynamic attribute access completely invisible to naive refactoring
# =============================================================================

class DynamicConfig:
    """Configuration with dynamic attribute access."""

    def __init__(self):
        self.database_host = "localhost"
        self.database_port = 5432
        self.cache_enabled = True

    def get(self, key: str, default=None):
        """Get config value by string key."""
        # MISSED: All callers using string keys
        return getattr(self, key, default)

    def set(self, key: str, value):
        """Set config value by string key."""
        setattr(self, key, value)

    def from_dict(self, data: dict):
        """Load config from dict."""
        for key, value in data.items():
            # MISSED: Dict keys become attributes
            setattr(self, key, value)

    def to_dict(self) -> dict:
        """Export config to dict."""
        return {
            "database_host": self.database_host,  # String keys!
            "database_port": self.database_port,
            "cache_enabled": self.cache_enabled,
        }


# Usage patterns that would break:
config = DynamicConfig()

# MISSED: String key access
host = config.get("database_host")

# MISSED: Dict-based configuration
CONFIG_SCHEMA = {
    "database_host": {"type": "string", "default": "localhost"},
    "database_port": {"type": "integer", "default": 5432},
}

# MISSED: Environment variable mapping
ENV_MAPPING = {
    "DB_HOST": "database_host",  # Maps to attribute name
    "DB_PORT": "database_port",
}


# =============================================================================
# EXPECTED: What Code Scalpel's get_symbol_references should find
# =============================================================================

REFACTORING_SCENARIOS = {
    "user_id -> account_id": {
        "should_find": [
            "UserService.get_user parameter",
            "SQL string: WHERE user_id =",
            "Dict key: 'user_id'",
            "Dynamic field_name = 'user_id'",
            "Config dict: 'field': 'user_id'",
            "JSON schema key",
            "Log format string",
            "Metrics tag key",
        ],
        "commonly_missed": [
            "SQL column in string literal",
            "Config file references",
            "API schema definitions",
            "Log format strings",
        ]
    },
    "process -> transform": {
        "should_find": [
            "Function definition",
            "Direct call: process(raw_data)",
            "globals()[handler] dynamic lookup",
            "Callback dict key: 'on_process'",
            "String comparison: == 'process'",
            "Celery task name decorator",
            "URL route name",
            "Test function name",
        ],
        "commonly_missed": [
            "Dynamic dispatch via globals()",
            "Callback registration by name",
            "Routing by string matching",
            "Celery/task queue names",
        ]
    },
    "User -> Account": {
        "should_find": [
            "Class definition",
            "Constructor calls",
            "Type annotations",
            "to_dict 'type' field",
            "Serializer registry key",
            "Deserialize string comparison",
            "Table name constant",
            "Pickle compatibility",
        ],
        "commonly_missed": [
            "String 'type' field in serialization",
            "Table/collection names",
            "Existing serialized data",
            "Database migrations needed",
        ]
    },
}
