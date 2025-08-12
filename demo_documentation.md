# Demo API Documentation

Comprehensive API documentation generated from traffic analysis

**Version:** 1.0.0

**Contact:** api@demo.com

**Base URL:** `https://api.demo.com`

## Table of Contents

- [Overview](#overview)
- [AI-Generated Documentation](#ai-generated-documentation)
- [Authentication](#authentication)
- [Endpoints](#endpoints)
- [Data Models](#data-models)
- [Error Handling](#error-handling)

## Overview

This API provides the following functionality:

### Users Operations

- **GET** - List resources
- **GET** - Retrieve a specific resource
- **POST** - Create a new resource

### API Statistics

- **Total Endpoints:** 3
- **Total Requests Analyzed:** 6
- **Average Response Time:** 141.7ms
- **Overall Success Rate:** 88.9%

## AI-Generated Documentation

# Demo API

This is a demonstration API showing user management capabilities.

## Authentication

This API uses the following authentication methods:

- **API Key**: Include your API key in the `Authorization` header
- **Bearer Token**: Use `Authorization: Bearer <token>` for JWT authentication

### Example Authentication

```bash
curl -H "Authorization: Bearer YOUR_TOKEN" \
  https://api.demo.com/api/endpoint
```

## Endpoints

### `/users`

#### GET /users

List resources

**Statistics:**
- Requests analyzed: 2
- Average response time: 145.0ms
- Success rate: 100.0%

**Query Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `page` | integer | No | Page number for pagination (default: 1) |
| `limit` | integer | No | Number of items per page (default: 20) |

**Response Examples:**

**Success (200 OK):**
```json
{
  "data": {
    // Response data
  },
  "message": "Success"
}
```

**Error (4xx/5xx):**
```json
{
  "error": "ERROR_CODE",
  "message": "Error description",
  "details": {}
}
```

**cURL Example:**

```bash
curl -X GET \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  https://api.demo.com/users
```

---

#### POST /users

Create a new resource

**Statistics:**
- Requests analyzed: 1
- Average response time: 200.0ms
- Success rate: 100.0%

**Request Body:**

```json
{
  "data": {
    // Request data based on the resource
  }
}
```

**Response Examples:**

**Success (200 OK):**
```json
{
  "data": {
    // Response data
  },
  "message": "Success"
}
```

**Error (4xx/5xx):**
```json
{
  "error": "ERROR_CODE",
  "message": "Error description",
  "details": {}
}
```

**cURL Example:**

```bash
curl -X POST \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "data": {
      // Your request data
    }
  }' \
  https://api.demo.com/users
```

---

### `/users/{id}`

#### GET /users/{id}

Retrieve a specific resource

**Statistics:**
- Requests analyzed: 3
- Average response time: 80.0ms
- Success rate: 66.7%

**Path Parameters:**

| Parameter | Type | Description |
|-----------|------|--------------|
| `id` | string | The id identifier |

**Response Examples:**

**Success (200 OK):**
```json
{
  "data": {
    // Response data
  },
  "message": "Success"
}
```

**Error (4xx/5xx):**
```json
{
  "error": "ERROR_CODE",
  "message": "Error description",
  "details": {}
}
```

**cURL Example:**

```bash
curl -X GET \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  https://api.demo.com/users/123
```

---

## Data Models

The following data models are used by this API:

### users_response

```json
{
  "properties": {
    "pagination": {
      "$ref": "#/components/schemas/Pagination"
    },
    "users": {
      "items": {
        "$ref": "#/components/schemas/User"
      },
      "type": "array"
    }
  },
  "type": "object"
}
```

### User

```json
{
  "properties": {
    "active": {
      "type": "boolean"
    },
    "created_at": {
      "format": "date-time",
      "type": "string"
    },
    "email": {
      "format": "email",
      "type": "string"
    },
    "id": {
      "type": "integer"
    },
    "name": {
      "type": "string"
    },
    "profile": {
      "$ref": "#/components/schemas/UserProfile"
    }
  },
  "required": [
    "id",
    "name",
    "email"
  ],
  "type": "object"
}
```

## Error Handling

This API uses conventional HTTP response codes to indicate success or failure:

| Status Code | Description |
|-------------|-------------|
| 200 | OK - Request successful |
| 201 | Created - Resource created successfully |
| 404 | Not Found - Resource not found |

### Error Response Format

All error responses follow this format:

```json
{
  "error": "ERROR_CODE",
  "message": "Human-readable error message",
  "details": {
    // Additional error context (optional)
  }
}
```

