# MCP Server with OAuth 2.0

A secure Model Context Protocol (MCP) server with Microsoft Azure OAuth authentication, featuring modular architecture and comprehensive logging anonymization.

## Features

- **OAuth 2.0 Authentication** - Microsoft Azure/MS365 integration with PKCE support
- **MCP Protocol Support** - Compatible with Claude Desktop and other MCP clients
- **Modular Architecture** - Clean separation of concerns for maintainability
- **Secure Logging** - Automatic anonymization of sensitive data (tokens, secrets, tenant IDs)
- **Optional Redis Storage** - Automatic fallback to in-memory for development
- **Production Ready** - Environment validation, graceful shutdown, security headers

## Quick Start

### Prerequisites
- Node.js 18+
- Microsoft Azure application registration

### Installation
```bash
git clone <repository-url>
cd mcp-server
npm install
```

### Environment Variables
Create a `.env` file:
```env
# Required
MS_CLIENT_ID=your-azure-client-id
MS_CLIENT_SECRET=your-azure-client-secret
MS_TENANT=your-azure-tenant-id
SESSION_SECRET=your-random-session-secret
REDIRECT_URI=http://localhost:3131/auth/callback

# Optional
REDIS_URL=redis://localhost:6379
PORT=3131
NODE_ENV=development
```

### Development
```bash
npm run dev     # Start with hot reload
npm run build   # Build TypeScript
npm start       # Production mode
```

## Usage

### Browser Access
1. Navigate to `http://localhost:3131`
2. Click "Login with MS365"
3. Complete Microsoft authentication
4. Access protected endpoints

### MCP Client Integration
```json
{
  "mcpServers": {
    "secure-mcp": {
      "command": "node",
      "args": ["/path/to/mcp-server/dist/server.js"],
      "env": {
        "MS_CLIENT_ID": "your-client-id",
        "MS_CLIENT_SECRET": "your-client-secret",
        "SESSION_SECRET": "your-session-secret",
        "REDIRECT_URI": "http://localhost:3131/auth/callback"
      }
    }
  }
}
```

## API Endpoints

- **`GET /`** - Landing page with authentication status
- **`GET /health`** - Health check (public)
- **`GET /login`** - Initiate OAuth flow
- **`GET /logout`** - Destroy session
- **`GET /status`** - User status (protected)
- **`POST /v1/mcp`** - MCP protocol endpoint (protected)
- **`GET /v1/mcp`** - MCP SSE endpoint (protected)

## OAuth 2.0 Authorization Server

Built-in OAuth server for MCP client authentication:
- **`GET /authorize`** - Authorization endpoint
- **`POST /token`** - Token exchange endpoint
- **`GET /.well-known/oauth-authorization-server`** - Discovery metadata

## Architecture

```
src/
├── server.ts          # Main Express application
├── auth/
│   ├── oauth.ts       # OAuth 2.0 authorization server
│   └── middleware.ts  # Authentication middleware
├── mcp/
│   └── server.ts      # MCP server factory and management
├── storage/
│   └── tokens.ts      # Token storage (Redis optional)
├── utils/
│   └── logger.ts      # Secure logging with anonymization
└── views/
    └── index.html     # HTML template
```

## Security Features

- **Key Anonymization** - All sensitive data in logs is automatically masked
- **Environment Validation** - Fails fast on missing required configuration
- **Secure Sessions** - HTTP-only cookies with CSRF protection
- **PKCE Support** - Proof Key for Code Exchange for enhanced security
- **Security Headers** - Helmet.js for comprehensive security headers

## Production Deployment

1. Set `NODE_ENV=production`
2. Configure `REDIS_URL` for token storage
3. Use HTTPS for `REDIRECT_URI`
4. Set secure session configuration
5. Monitor logs for security events

## Contributing

See [ARCHITECTURE.md](ARCHITECTURE.md) for detailed technical documentation.

## License

ISC