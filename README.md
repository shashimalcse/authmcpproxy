# AuthMCPProxy

## Overview
AuthMCPProxy is a security middleware that support the Model Context Protocol (MCP) Authorization Specification (2025-03-26). It sits in front of MCP servers to handle authentication and authorization, acting as a proxy that intercepts incoming requests, validates authentication tokens, and forwards authorized requests to the underlying MCP server.

## How It Works
1. AuthMCPProxy receives client requests intended for the MCP server
2. It validates authentication tokens using the configured OAuth/OIDC provider
3. If authentication is successful, it forwards the request to the MCP server
4. It then relays the MCP server's response back to the client

```
Client → AuthMCPProxy → MCP Server
               ↕
        Auth Provider
```

## Configuration

AuthMCPProxy is configured using a YAML file (`config.yaml`):

```yaml
auth_server_base_url: "<>"  # OAuth/OIDC server base URL
mcp_server_base_url: "<>"   # Target MCP server URL
listen_address: ":8080"     # Proxy listening address
jwks_url: "<>"               # JWKS endpoint of OAuth/OIDC server
timeout_seconds: 10         # Request timeout in seconds
mcp_paths:                  # MCP paths to proxy
  - /messages/
  - /sse
path_mapping:               # OAuth endpoint mappings
  /.well-known/oauth-authorization-server: /token/.well-known/openid-configuration
```

### Configuration Options

| Option | Description |
|--------|-------------|
| `auth_server_base_url` | Base URL of the OAuth/OIDC server |
| `mcp_server_base_url` | Base URL of the target MCP server |
| `listen_address` | Address and port where the proxy listens |
| `jwks_url` | URL to fetch JSON Web Key Sets for token validation |
| `timeout_seconds` | Request timeout in seconds |
| `mcp_paths` | Paths that should be proxied to the MCP server |
| `path_mapping` | Maps incoming OAuth-related paths to their corresponding endpoints |

## Setup and Installation

1. **Prerequisites**
   - Go 1.x or higher
   - Access to an OAuth/OIDC provider (e.g., Asgardeo)
   - A running MCP server

2. **Installation**
   ```bash
   git clone https://github.com/yourusername/AuthMCPProxy.git
   cd AuthMCPProxy
   go build
   ```

3. **Configuration**
   - Modify `config.yaml` to match your environment
   - Ensure your OAuth provider is properly configured

4. **Running the Proxy**
   ```bash
   ./authmcpproxy
   ```

## Usage

### Client Authentication Flow

1. Clients obtain an access token from the configured OAuth provider
2. Clients include the token in requests to the AuthMCPProxy
3. AuthMCPProxy validates the token and proxies the request to the MCP server

### Example Request

```bash
curl -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..." \
  http://localhost:8080/messages/
```

## Security Considerations

- The proxy validates JWT tokens using the JWKS provided by the OAuth server
- Requests without valid tokens are rejected
- The proxy helps isolate the MCP server from direct client access
- All authentication logic is handled in the proxy layer, simplifying the MCP server implementation
