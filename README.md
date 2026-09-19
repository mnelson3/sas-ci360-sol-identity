# SAS Customer Intelligence 360

## SAS 360 SOLUTIONS - Identity Module

> **Status: canonical.** This is the actively maintained client for the SCIM API.

This repository provides Python interfaces for SAS Customer Intelligence 360 Identity Management using SCIM APIs.

> This is an independent, third-party project maintained by Nelson Grey LLC. It is not affiliated with, endorsed by, or sponsored by SAS Institute Inc. "SAS" and "SAS Customer Intelligence 360" are trademarks of SAS Institute Inc.

### Overview

The Identity module enables programmatic management of users, groups, and identity-related operations within CI360 using the System for Cross-Domain Identity Management (SCIM) standard.

### Features

- User and group management
- SCIM API integration
- Identity provisioning and deprovisioning
- Role-based access control
- Identity synchronization

### Prerequisites

- Python 3.8+
- Access to SAS Customer Intelligence 360 environment
- Required dependencies (see requirements.txt)
- Access to the private package index hosting `sasci360apicore` and `sasci360apiscim` (internal Nelson Grey LLC packages, not published to PyPI)

### Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/mnelson3/sas-ci360-sol-identity.git
   cd sas-ci360-sol-identity
   ```

2. Install dependencies (requires access to the private package index above):
   ```bash
   pip install -r requirements.txt
   ```

### Getting Started

```python
from sasci360solidentity.base import CI360IdentityBase, CI360IdentityConfig

# Initialize identity client
config = CI360IdentityConfig(
    algorithm="HS256",
    api_base="/scim",
    encoding="utf-8",
    host="your-ci360-host",
    secret_key="your-secret-key",
    tenant_id="your-tenant-id"
)
identity_client = CI360IdentityBase(config)

# Manage users and groups
```

### Solutions Code

The identity module provides:

1. **User Management**: Create, update, and delete user accounts
2. **Group Operations**: Manage user groups and memberships
3. **SCIM Compliance**: Standards-based identity management
4. **Access Control**: Role and permission management

### Troubleshooting

- Verify SCIM endpoint configurations
- Check authentication and authorization
- Review identity schema compliance
- Monitor provisioning logs

## 🛠️ Developer/Implementation Guide

This section provides comprehensive guidance for developers implementing identity management solutions with SAS CI360.

### Architecture Overview

The SAS CI360 Identity module follows a SCIM-compliant architecture designed for enterprise identity management:

```
┌─────────────────────────────────────────────────────────────┐
│                  Identity Module                            │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐           │
│  │ User        │ │ Group       │ │ Provisioning │           │
│  │ Management  │ │ Operations  │ │ Management  │           │
│  └─────────────┘ └─────────────┘ └─────────────┘           │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐           │
│  │ SCIM API    │ │ JWT Auth    │ │ Async I/O   │           │
│  │ Client      │ │ & Security  │ │ Operations  │           │
│  └─────────────┘ └─────────────┘ └─────────────┘           │
└─────────────────────────────────────────────────────────────┘
```

#### Core Components

1. **User Management Layer**
   - `CI360IdentityBase`: Core client class for identity operations
   - User lifecycle management (create, read, update, delete)
   - Profile attribute management
   - User authentication and authorization

2. **Group Operations Layer**
   - Group creation and management
   - Membership operations (add/remove users)
   - Hierarchical group structures
   - Group-based permissions

3. **Provisioning Management Layer**
   - Automated user provisioning
   - Identity synchronization
   - Deprovisioning workflows
   - Integration with external identity providers

### Configuration Management

#### Environment Variables
```bash
export SAS_CI360_SECRET_KEY="your-secret-key"
export SAS_CI360_TENANT_ID="your-tenant-id"
```

#### Configuration Class
```python
from sasci360solidentity.base import CI360IdentityConfig

config = CI360IdentityConfig(
    algorithm="HS256",
    api_base="/scim",
    encoding="utf-8",
    host="your-ci360-host.sas.com",
    secret_key="your-secret-key",
    tenant_id="your-tenant-id"
)
```

### API Integration Patterns

#### User Management
```python
from sasci360solidentity.base import CI360IdentityBase, CI360IdentityConfig

# Initialize client
config = CI360IdentityConfig(
    host="your-ci360-host",
    secret_key="your-secret-key",
    tenant_id="your-tenant-id"
)
client = CI360IdentityBase(config)

# Create a new user
user_data = {
    'userName': 'john.doe@example.com',
    'name': {
        'givenName': 'John',
        'familyName': 'Doe'
    },
    'emails': [{
        'value': 'john.doe@example.com',
        'primary': True
    }],
    'active': True
}

result = client.create_user(user_data)
print(f"User created: {result['id']}")
```

#### Asynchronous Operations
```python
import asyncio
from sasci360solidentity.base import CI360IdentityBase, CI360IdentityConfig

async def manage_user_identity():
    config = CI360IdentityConfig(
        host="your-ci360-host",
        secret_key="your-secret-key",
        tenant_id="your-tenant-id"
    )
    client = CI360IdentityBase(config)

    # Get user details asynchronously
    user = await client.get_user_async('user-123')
    print(f"User: {user['name']['givenName']} {user['name']['familyName']}")

    # Update user attributes
    update_data = {
        'emails': [{
            'value': 'john.doe.new@example.com',
            'primary': True
        }],
        'active': True
    }
    result = await client.update_user_async('user-123', update_data)
    print(f"User updated: {result['id']}")

# Run async operations
asyncio.run(manage_user_identity())
```

#### Group Operations
```python
# Create a new group
group_data = {
    'displayName': 'Marketing Team',
    'description': 'Users responsible for marketing campaigns',
    'members': [
        {'value': 'user-123'},
        {'value': 'user-456'}
    ]
}

group = client.create_group(group_data)
print(f"Group created: {group['id']}")

# Add a user to the group
updated_members = group_data['members'] + [{'value': 'user-789'}]
result = client.update_group(group['id'], {**group_data, 'members': updated_members})
print(f"Group membership updated: {result['id']}")
```

### Error Handling

#### Exception Types
```python
from sasci360solidentity.base import (
    CI360IdentityBase,
    CI360IdentityConfig,
    CI360IdentityError,
    CI360IdentityAuthError,
    CI360IdentityValidationError
)

try:
    config = CI360IdentityConfig(
        host="your-ci360-host",
        secret_key="your-secret-key",
        tenant_id="your-tenant-id"
    )
    client = CI360IdentityBase(config)
    users = client.get_users()
except CI360IdentityAuthError as e:
    print(f"Authentication failed: {e}")
    # Handle auth issues (token refresh, credentials)
except CI360IdentityValidationError as e:
    print(f"Validation error: {e}")
    # Handle SCIM schema validation issues
except CI360IdentityError as e:
    print(f"API error: {e}")
    # Handle general identity management errors
```

#### Bulk User Operations
```python
def process_users_bulk(client, user_list, operation='create'):
    results = {
        'successful': [],
        'failed': []
    }

    for user_data in user_list:
        try:
            if operation == 'create':
                result = client.create_user(user_data)
            elif operation == 'update':
                result = client.update_user(user_data['id'], user_data)
            results['successful'].append(result)
        except CI360IdentityValidationError as e:
            results['failed'].append({
                'user': user_data,
                'error': str(e)
            })
        except Exception as e:
            results['failed'].append({
                'user': user_data,
                'error': f"Unexpected error: {str(e)}"
            })

    return results
```

### Testing Approaches

To run this repository's own test suite locally, you don't need access to the private package index: `requirements-dev.txt` installs only the lint/type-check/test tooling, and the unit tests stub out the private `sasci360apicore.encryption` dependency.

```bash
pip install -r requirements-dev.txt
pytest tests/
```

#### Unit Testing
```python
import unittest
from unittest.mock import Mock, patch
from sasci360solidentity.base import CI360IdentityBase, CI360IdentityConfig

class TestIdentityOperations(unittest.TestCase):
    def setUp(self):
        config = CI360IdentityConfig(
            host="https://api.example.com",
            secret_key="test-secret",
            tenant_id="test-tenant"
        )
        self.client = CI360IdentityBase(config)
        self.mock_response = Mock()
        self.mock_response.json.return_value = {'id': '123', 'userName': 'test@example.com'}

    @patch('requests.Session.request')
    def test_get_users(self, mock_request):
        mock_request.return_value = self.mock_response

        result = self.client.get_users()
        self.assertEqual(result['userName'], 'test@example.com')
        mock_request.assert_called_once()

    @patch('sasci360solidentity.base.CI360IdentityBase._generate_token')
    def test_identity_authentication(self, mock_generate):
        mock_generate.return_value = 'mock-jwt-token'

        headers = self.client.get_auth_headers()
        self.assertIn('Authorization', headers)
        self.assertEqual(headers['Authorization'], 'Bearer mock-jwt-token')
```

#### Integration Testing
```python
import pytest
from sasci360solidentity.base import CI360IdentityBase, CI360IdentityConfig

@pytest.fixture
def identity_client():
    config = CI360IdentityConfig(
        host="https://api.example.com",
        secret_key="test-secret",
        tenant_id="test-tenant"
    )
    return CI360IdentityBase(config)

@pytest.mark.integration
def test_user_lifecycle(identity_client):
    # Test complete user lifecycle
    user_data = {
        'userName': 'test.user@example.com',
        'name': {
            'givenName': 'Test',
            'familyName': 'User'
        },
        'emails': [{
            'value': 'test.user@example.com',
            'primary': True
        }],
        'active': True
    }

    # Create
    created = identity_client.create_user(user_data)
    user_id = created['id']

    # Read
    retrieved = identity_client.get_user(user_id)
    assert retrieved['userName'] == 'test.user@example.com'

    # Update
    updated_data = user_data.copy()
    updated_data['name']['givenName'] = 'Updated'
    updated = identity_client.update_user(user_id, updated_data)
    assert updated['name']['givenName'] == 'Updated'

    # Delete
    deleted = identity_client.delete_user(user_id)
    assert deleted is True
```

### Performance Considerations

#### Batch Processing
```python
# Process users in batches for better performance
async def process_users_batch_async(client, user_list, batch_size=50):
    async def process_batch(batch):
        tasks = [client.create_user_async(user) for user in batch]
        return await asyncio.gather(*tasks, return_exceptions=True)

    results = []
    for i in range(0, len(user_list), batch_size):
        batch = user_list[i:i + batch_size]
        batch_results = asyncio.run(process_batch(batch))
        results.extend(batch_results)

    return results
```

#### Connection Pooling
```python
# Configure session for identity operations
client.session.mount('https://', requests.adapters.HTTPAdapter(
    pool_connections=15,
    pool_maxsize=30,
    max_retries=3,
    pool_block=False
))
```

#### Caching Strategies
```python
from cachetools import TTLCache

class CachedIdentityClient(CI360IdentityBase):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._user_cache = TTLCache(maxsize=2000, ttl=300)  # 5 minute TTL
        self._group_cache = TTLCache(maxsize=500, ttl=600)  # 10 minute TTL

    def get_user(self, user_id: str):
        if user_id in self._user_cache:
            return self._user_cache[user_id]

        user = super().get_user(user_id)
        self._user_cache[user_id] = user
        return user

    def get_group(self, group_id: str):
        if group_id in self._group_cache:
            return self._group_cache[group_id]

        group = super().get_group(group_id)
        self._group_cache[group_id] = group
        return group
```

### Security Best Practices

1. **SCIM Compliance**: Ensure all operations follow SCIM 2.0 standards
2. **Data Protection**: Implement proper encryption for sensitive identity data
3. **Access Control**: Role-based access to identity management operations
4. **Audit Logging**: Comprehensive logging of all identity operations
5. **Token Security**: Secure JWT token generation and validation

### Contributing

We welcome your contributions! Please read [CONTRIBUTING](CONTRIBUTING.md) for details on how to submit contributions to this project.

### License

This project is licensed under the [Nelson Grey LLC Community License 1.0](LICENSE).

- **Free for individuals, education, and research**: use, modify, and distribute this software for non-commercial purposes
- **Commercial evaluation**: evaluate the software for a possible commercial use, free of charge
- **Commercial production use**: requires a commercial license from Nelson Grey LLC
- **Automatic conversion**: on December 13, 2029, this automatically converts to the Apache License 2.0

For commercial licensing inquiries, contact support@nelsongrey.com.

### Additional Resources

For more information, see [SCIM API](https://go.documentation.sas.com/doc/en/cintcdc/production.a/cintapis/rest-scim.htm).
