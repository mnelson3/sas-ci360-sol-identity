#!/usr/bin/env python3
# Business Source License 1.1
#
# Parameters
#
# Licensor:             Nelson Grey LLC
# Licensed Work:        SAS CI360 Identity Solution
# Additional Use Grant: None
# Change Date:          2029-12-13
# Change License:       Apache License 2.0
#
# Terms
#
# The Licensor hereby grants you the right to copy, modify, create derivative
# works, redistribute, and make non-production use of the Licensed Work. The
# Licensor may make an Additional Use Grant, above, permitting limited
# production use.
#
# Effective on the Change Date, or the fourth anniversary of the first publicly
# available distribution of a specific version of the Licensed Work under this
# License, whichever comes first, the Licensor hereby grants you rights under
# the terms of the Change License, and the rights granted in the paragraph
# above terminate.
#
# If your use of the Licensed Work does not comply with the requirements
# currently in effect as described in this License, you must purchase a
# commercial license from the Licensor, its affiliated entities, or authorized
# resellers, or you must refrain from using the Licensed Work.
#
# All copies of the original and modified Licensed Work, and derivative works
# of the Licensed Work, are subject to this License. This License applies
# separately for each version of the Licensed Work and the Change Date may vary
# for each version of the Licensed Work released by Licensor.
#
# You must conspicuously display this License on each original or modified copy
# of the Licensed Work. If you receive the Licensed Work in original or
# modified form from a third party, the terms and conditions set forth in this
# License apply to your use of that work.
#
# Any use of the Licensed Work in violation of this License will automatically
# terminate your rights under this License for the current and all other
# versions of the Licensed Work.
#
# This License does not grant you any right in any trademark or logo of
# Licensor or its affiliates (provided that you may use a trademark or logo of
# Licensor as expressly required by this License).
#
# TO THE EXTENT PERMITTED BY APPLICABLE LAW, THE LICENSED WORK IS PROVIDED ON
# AN "AS IS" BASIS. LICENSOR HEREBY DISCLAIMS ALL WARRANTIES AND CONDITIONS,
# EXPRESS OR IMPLIED, INCLUDING (WITHOUT LIMITATION) WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, NON-INFRINGEMENT, AND
# TITLE.
#
# MariaDB hereby grants you permission to use this License's text to license
# your works, and to refer to it using the trademark "Business Source License",
# as long as you comply with the Covenants of Licensor below.
#
# Covenants of Licensor
#
# In consideration of the right to use this License's text and the "Business
# Source License" name and trademark, Licensor covenants to MariaDB, a Delaware
# corporation, for the benefit of MariaDB and any other party that has
# contributed to the Licensed Work, to use best efforts to provide the Change
# License on the Change Date for each version of the Licensed Work, and to
# designate the Change License as "Apache License 2.0" or a later version of
# the Apache License.

#
# Copyright (c) 2025 Nelson Grey LLC
# Author: Nelson Grey LLC
#
# Licensed under the Business Source License 1.1 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# https://github.com/mnelson3/sas-ci360-sol-identity/blob/main/LICENSE
#
# -*- coding: utf-8 -*-
"""
SAS CI360 Identity Module Base Class

Provides foundational functionality for SAS Customer Intelligence 360
identity management operations using SCIM, including connection management,
authentication, and user/group management capabilities.
"""

import asyncio
import logging
from dataclasses import dataclass
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


@dataclass
class CI360IdentityConfig:
    """Configuration for CI360 Identity operations."""

    algorithm: str = "HS256"
    api_base: str = "/scim"
    encoding: str = "utf-8"
    host: Optional[str] = None
    secret_key: Optional[str] = None
    tenant_id: Optional[str] = None
    timeout: int = 30
    max_retries: int = 3
    retry_backoff: float = 0.5
    enable_compression: bool = True
    scim_version: str = "2.0"


class CI360IdentityError(Exception):
    """Base exception for CI360 Identity operations."""
    pass


class CI360IdentityAuthError(CI360IdentityError):
    """Authentication-related errors."""
    pass


class CI360IdentityConnectionError(CI360IdentityError):
    """Connection and network-related errors."""
    pass


class CI360IdentityValidationError(CI360IdentityError):
    """Data validation errors."""
    pass


class CI360IdentityBase:
    """
    Base class for SAS CI360 Identity operations.

    Provides authentication, connection management, and common functionality
    for identity and user management API interactions using SCIM with async support.
    """

    def __init__(self, config: Optional[CI360IdentityConfig] = None) -> None:
        """
        Initialize the CI360 Identity base client.

        Args:
            config: Configuration object for CI360 Identity operations

        Raises:
            CI360IdentityValidationError: If required configuration is missing
        """
        self.config = config or CI360IdentityConfig()
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")

        # Validate configuration
        self._validate_config()

        # Initialize HTTP session with retry strategy
        self.session = self._create_session()

        # Generate authentication token
        self.token = self._generate_token()

        # Connection state
        self._connected = False

        self.logger.info("CI360 Identity Base initialized successfully")

    def _validate_config(self) -> None:
        """Validate configuration parameters."""
        required_fields = ['host', 'secret_key', 'tenant_id']
        missing = [name for name in required_fields if not getattr(self.config, name)]

        if missing:
            raise CI360IdentityValidationError(f"Missing required configuration: {', '.join(missing)}")

        # Validate algorithm
        supported_algorithms = ['HS256', 'HS384', 'HS512', 'RS256', 'RS384', 'RS512']
        if self.config.algorithm not in supported_algorithms:
            raise CI360IdentityValidationError(f"Unsupported algorithm: {self.config.algorithm}")

        # Validate SCIM version
        supported_versions = ['2.0', '1.1']
        if self.config.scim_version not in supported_versions:
            raise CI360IdentityValidationError(f"Unsupported SCIM version: {self.config.scim_version}")

    def _create_session(self) -> requests.Session:
        """Create HTTP session with retry strategy."""
        session = requests.Session()

        # Configure retry strategy
        retry_strategy = Retry(
            total=self.config.max_retries,
            backoff_factor=self.config.retry_backoff,
            status_forcelist=[429, 500, 502, 503, 504],
        )

        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("http://", adapter)
        session.mount("https://", adapter)

        return session

    @property
    def _base_url(self) -> str:
        """Base URL for CI360 API requests (host is validated as non-None in __init__)."""
        assert self.config.host is not None
        return self.config.host + self.config.api_base

    def _generate_token(self) -> str:
        """Generate JWT authentication token."""
        try:
            # Import here to avoid circular imports
            from sasci360apicore.encryption import Encryption

            encryption = Encryption(
                algorithm=self.config.algorithm,
                encoding=self.config.encoding
            )

            return encryption.generate_jwt(
                tenant_id=self.config.tenant_id,
                secret_key=self.config.secret_key
            )
        except Exception as e:
            raise CI360IdentityAuthError(f"Failed to generate authentication token: {e}")

    def get_auth_headers(self) -> Dict[str, str]:
        """
        Get authentication headers for API requests.

        Returns:
            Dict[str, str]: Headers dictionary with authorization token
        """
        return {
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/scim+json",
            "Accept": "application/scim+json",
            "X-Tenant-ID": str(self.config.tenant_id),
            "SCIM-Version": self.config.scim_version
        }

    async def validate_connection_async(self) -> bool:
        """
        Asynchronously validate connection to CI360 service.

        Returns:
            bool: True if connection is valid
        """
        try:
            # SCIM service provider config endpoint
            sp_url = urljoin(self._base_url, "/ServiceProviderConfig")
            headers = self.get_auth_headers()

            loop = asyncio.get_event_loop()
            response = await loop.run_in_executor(
                None,
                lambda: self.session.get(
                    sp_url,
                    headers=headers,
                    timeout=self.config.timeout
                )
            )

            self._connected = response.status_code == 200
            return self._connected

        except Exception as e:
            self.logger.error(f"Connection validation failed: {e}")
            self._connected = False
            return False

    def validate_connection(self) -> bool:
        """
        Validate connection to CI360 service.

        Returns:
            bool: True if connection is valid
        """
        try:
            # Run async validation in sync context
            return asyncio.run(self.validate_connection_async())
        except Exception as e:
            self.logger.error(f"Sync connection validation failed: {e}")
            return False

    async def _make_request_async(
        self,
        method: str,
        endpoint: str,
        data: Optional[Dict[str, Any]] = None,
        params: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Make asynchronous HTTP request to CI360 SCIM API.

        Args:
            method: HTTP method (GET, POST, PUT, DELETE)
            endpoint: API endpoint path
            data: Request body data
            params: Query parameters

        Returns:
            Dict[str, Any]: Response data

        Raises:
            CI360IdentityConnectionError: For network/connection errors
            CI360IdentityAuthError: For authentication errors
        """
        if not self._connected:
            await self.validate_connection_async()
            if not self._connected:
                raise CI360IdentityConnectionError("No active connection to CI360 service")

        url = urljoin(self._base_url, endpoint.lstrip('/'))
        headers = self.get_auth_headers()

        try:
            loop = asyncio.get_event_loop()
            response = await loop.run_in_executor(
                None,
                lambda: self.session.request(
                    method=method,
                    url=url,
                    headers=headers,
                    json=data,
                    params=params,
                    timeout=self.config.timeout
                )
            )

            response.raise_for_status()
            return response.json() if response.content else {}

        except requests.exceptions.HTTPError as e:
            if response.status_code == 401:
                raise CI360IdentityAuthError(f"Authentication failed: {e}")
            elif response.status_code >= 500:
                raise CI360IdentityConnectionError(f"Server error: {e}")
            else:
                raise CI360IdentityError(f"SCIM API request failed: {e}")
        except requests.exceptions.RequestException as e:
            raise CI360IdentityConnectionError(f"Network error: {e}")

    def _make_request(
        self,
        method: str,
        endpoint: str,
        data: Optional[Dict[str, Any]] = None,
        params: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Make synchronous HTTP request to CI360 SCIM API.

        Args:
            method: HTTP method (GET, POST, PUT, DELETE)
            endpoint: API endpoint path
            data: Request body data
            params: Query parameters

        Returns:
            Dict[str, Any]: Response data
        """
        try:
            return asyncio.run(self._make_request_async(method, endpoint, data, params))
        except Exception as e:
            self.logger.error(f"Request failed: {e}")
            raise

    # User Management APIs

    async def get_users_async(
        self,
        limit: int = 100,
        offset: int = 0,
        filters: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Retrieve users asynchronously.

        Args:
            limit: Maximum number of users to return
            offset: Number of users to skip
            filters: Optional filters for users

        Returns:
            Dict containing user data and metadata
        """
        params = {
            "limit": limit,
            "offset": offset
        }
        if filters:
            params.update(filters)

        return await self._make_request_async("GET", "/Users", params=params)

    def get_users(
        self,
        limit: int = 100,
        offset: int = 0,
        filters: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Retrieve users synchronously."""
        params = {
            "limit": limit,
            "offset": offset
        }
        if filters:
            params.update(filters)

        return self._make_request("GET", "/Users", params=params)

    async def get_user_async(self, user_id: str) -> Dict[str, Any]:
        """
        Retrieve specific user data asynchronously.

        Args:
            user_id: Unique user identifier

        Returns:
            Dict containing user data
        """
        return await self._make_request_async("GET", f"/Users/{user_id}")

    def get_user(self, user_id: str) -> Dict[str, Any]:
        """Retrieve specific user data synchronously."""
        return self._make_request("GET", f"/Users/{user_id}")

    async def create_user_async(self, user_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Create new user asynchronously.

        Args:
            user_data: User data to create

        Returns:
            Dict containing created user data
        """
        return await self._make_request_async("POST", "/Users", data=user_data)

    def create_user(self, user_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create new user synchronously."""
        return self._make_request("POST", "/Users", data=user_data)

    async def update_user_async(self, user_id: str, user_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Update user data asynchronously.

        Args:
            user_id: Unique user identifier
            user_data: Updated user data

        Returns:
            Dict containing updated user data
        """
        return await self._make_request_async("PUT", f"/Users/{user_id}", data=user_data)

    def update_user(self, user_id: str, user_data: Dict[str, Any]) -> Dict[str, Any]:
        """Update user data synchronously."""
        return self._make_request("PUT", f"/Users/{user_id}", data=user_data)

    async def patch_user_async(self, user_id: str, patch_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Patch user data asynchronously (SCIM patch operation).

        Args:
            user_id: Unique user identifier
            patch_data: SCIM patch operations

        Returns:
            Dict containing updated user data
        """
        return await self._make_request_async("PATCH", f"/Users/{user_id}", data=patch_data)

    def patch_user(self, user_id: str, patch_data: Dict[str, Any]) -> Dict[str, Any]:
        """Patch user data synchronously (SCIM patch operation)."""
        return self._make_request("PATCH", f"/Users/{user_id}", data=patch_data)

    async def delete_user_async(self, user_id: str) -> bool:
        """
        Delete user asynchronously.

        Args:
            user_id: Unique user identifier

        Returns:
            True if deletion successful
        """
        await self._make_request_async("DELETE", f"/Users/{user_id}")
        return True

    def delete_user(self, user_id: str) -> bool:
        """Delete user synchronously."""
        self._make_request("DELETE", f"/Users/{user_id}")
        return True

    # Group Management APIs

    async def get_groups_async(
        self,
        limit: int = 100,
        offset: int = 0,
        filters: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Retrieve groups asynchronously.

        Args:
            limit: Maximum number of groups to return
            offset: Number of groups to skip
            filters: Optional filters for groups

        Returns:
            Dict containing group data and metadata
        """
        params = {
            "limit": limit,
            "offset": offset
        }
        if filters:
            params.update(filters)

        return await self._make_request_async("GET", "/Groups", params=params)

    def get_groups(
        self,
        limit: int = 100,
        offset: int = 0,
        filters: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Retrieve groups synchronously."""
        params = {
            "limit": limit,
            "offset": offset
        }
        if filters:
            params.update(filters)

        return self._make_request("GET", "/Groups", params=params)

    async def get_group_async(self, group_id: str) -> Dict[str, Any]:
        """
        Retrieve specific group data asynchronously.

        Args:
            group_id: Unique group identifier

        Returns:
            Dict containing group data
        """
        return await self._make_request_async("GET", f"/Groups/{group_id}")

    def get_group(self, group_id: str) -> Dict[str, Any]:
        """Retrieve specific group data synchronously."""
        return self._make_request("GET", f"/Groups/{group_id}")

    async def create_group_async(self, group_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Create new group asynchronously.

        Args:
            group_data: Group data to create

        Returns:
            Dict containing created group data
        """
        return await self._make_request_async("POST", "/Groups", data=group_data)

    def create_group(self, group_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create new group synchronously."""
        return self._make_request("POST", "/Groups", data=group_data)

    async def update_group_async(self, group_id: str, group_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Update group data asynchronously.

        Args:
            group_id: Unique group identifier
            group_data: Updated group data

        Returns:
            Dict containing updated group data
        """
        return await self._make_request_async("PUT", f"/Groups/{group_id}", data=group_data)

    def update_group(self, group_id: str, group_data: Dict[str, Any]) -> Dict[str, Any]:
        """Update group data synchronously."""
        return self._make_request("PUT", f"/Groups/{group_id}", data=group_data)

    async def delete_group_async(self, group_id: str) -> bool:
        """
        Delete group asynchronously.

        Args:
            group_id: Unique group identifier

        Returns:
            True if deletion successful
        """
        await self._make_request_async("DELETE", f"/Groups/{group_id}")
        return True

    def delete_group(self, group_id: str) -> bool:
        """Delete group synchronously."""
        self._make_request("DELETE", f"/Groups/{group_id}")
        return True

    # Authentication APIs

    async def authenticate_user_async(self, credentials: Dict[str, Any]) -> Dict[str, Any]:
        """
        Authenticate user asynchronously.

        Args:
            credentials: User authentication credentials

        Returns:
            Dict containing authentication result and tokens
        """
        return await self._make_request_async("POST", "/auth/authenticate", data=credentials)

    def authenticate_user(self, credentials: Dict[str, Any]) -> Dict[str, Any]:
        """Authenticate user synchronously."""
        return self._make_request("POST", "/auth/authenticate", data=credentials)

    async def validate_token_async(self, token: str) -> Dict[str, Any]:
        """
        Validate authentication token asynchronously.

        Args:
            token: JWT token to validate

        Returns:
            Dict containing token validation result
        """
        payload = {"token": token}
        return await self._make_request_async("POST", "/auth/validate", data=payload)

    def validate_token(self, token: str) -> Dict[str, Any]:
        """Validate authentication token synchronously."""
        payload = {"token": token}
        return self._make_request("POST", "/auth/validate", data=payload)

    async def refresh_token_async(self, refresh_token: str) -> Dict[str, Any]:
        """
        Refresh authentication token asynchronously.

        Args:
            refresh_token: Refresh token

        Returns:
            Dict containing new tokens
        """
        payload = {"refreshToken": refresh_token}
        return await self._make_request_async("POST", "/auth/refresh", data=payload)

    def refresh_token(self, refresh_token: str) -> Dict[str, Any]:
        """Refresh authentication token synchronously."""
        payload = {"refreshToken": refresh_token}
        return self._make_request("POST", "/auth/refresh", data=payload)

    # SCIM Service Provider Configuration

    async def get_service_provider_config_async(self) -> Dict[str, Any]:
        """
        Get SCIM service provider configuration asynchronously.

        Returns:
            Dict containing SCIM service provider configuration
        """
        return await self._make_request_async("GET", "/ServiceProviderConfig")

    def get_service_provider_config(self) -> Dict[str, Any]:
        """Get SCIM service provider configuration synchronously."""
        return self._make_request("GET", "/ServiceProviderConfig")

    # Bulk Operations

    async def bulk_operation_async(self, operations: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Perform bulk SCIM operations asynchronously.

        Args:
            operations: List of SCIM bulk operations

        Returns:
            Dict containing bulk operation results
        """
        payload = {
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:BulkRequest"],
            "Operations": operations
        }
        return await self._make_request_async("POST", "/Bulk", data=payload)

    def bulk_operation(self, operations: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Perform bulk SCIM operations synchronously."""
        payload = {
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:BulkRequest"],
            "Operations": operations
        }
        return self._make_request("POST", "/Bulk", data=payload)

    def __enter__(self):
        """Context manager entry."""
        if not self.validate_connection():
            raise CI360IdentityConnectionError("Failed to establish connection")
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.session.close()

    async def __aenter__(self):
        """Async context manager entry."""
        if not await self.validate_connection_async():
            raise CI360IdentityConnectionError("Failed to establish connection")
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        self.session.close()
