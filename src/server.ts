import express from 'express';
import cors from 'cors';
import session from 'express-session';
import helmet from 'helmet';
import { randomUUID } from 'crypto';
import { ConfidentialClientApplication } from '@azure/msal-node';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { z } from 'zod';
import dotenv from 'dotenv';
import * as jose from 'jose';

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3131;

// MSAL Configuration
const msalConfig = {
  auth: {
    clientId: process.env.MS_CLIENT_ID!,
    clientSecret: process.env.MS_CLIENT_SECRET!,
    authority: `https://login.microsoftonline.com/${process.env.MS_TENANT || 'common'}`
  }
};

const msal = new ConfidentialClientApplication(msalConfig);

// Express middleware
app.use(helmet());
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(session({
  secret: process.env.SESSION_SECRET!,
  resave: false,
  saveUninitialized: false,
  cookie: { 
    sameSite: 'lax', 
    secure: process.env.NODE_ENV === 'production',
    maxAge: 24 * 60 * 60 * 1000 // 24 hours
  }
}));

const transports: Record<string, StreamableHTTPServerTransport> = {};

// OAuth state storage (in-memory for demo - use Redis in production)
const authorizationCodes = new Map<string, {
  clientId: string;
  redirectUri: string;
  scope: string;
  codeChallenge?: string;
  codeChallengeMethod?: string;
  state?: string;
  userId: string;
  expiresAt: number;
}>();

const accessTokens = new Map<string, {
  token: string;
  clientId: string;
  userId: string;
  scope: string;
  expiresAt: number;
}>();

// Token validation function for our issued tokens
function verifyAccessToken(token: string): any {
  const tokenData = accessTokens.get(token);
  if (!tokenData || tokenData.expiresAt < Date.now()) {
    if (tokenData) {
      accessTokens.delete(token);
    }
    throw new Error('Token expired or invalid');
  }
  return tokenData;
}

// Authentication middleware
async function ensureAuthenticated(req: express.Request, res: express.Response, next: express.NextFunction): Promise<void> {
  // Option 1: Existing session (browsers)
  if ((req.session as any)?.user) {
    return next();
  }
  
  // Option 2: Bearer token (MCP clients)
  const authHeader = req.headers.authorization;
  if (authHeader?.startsWith('Bearer ')) {
    const token = authHeader.substring(7);
    try {
      const tokenData = verifyAccessToken(token);
      // For MCP clients, we'll set a minimal user object since we don't store full user data
      (req as any).user = {
        oid: tokenData.userId,
        name: 'MCP Client User',
        email: 'mcp-client@example.com'
      };
      return next();
    } catch (error) {
      console.error('Token validation failed:', error);
      res.status(401).json({ error: 'Invalid or expired token' });
      return;
    }
  }
  
  // No valid auth
  if (req.path.startsWith('/v1/')) {
    res.status(401).json({ error: 'Authentication required' });
    return;
  }
  
  res.redirect('/login');
}

// OAuth Authorization Server endpoints
app.get('/authorize', async (req, res) => {
  console.log('OAuth authorize request:', req.query);
  
  const { 
    response_type, 
    client_id, 
    redirect_uri, 
    scope, 
    code_challenge, 
    code_challenge_method, 
    state 
  } = req.query as Record<string, string>;

  // Validate required parameters
  if (response_type !== 'code') {
    res.status(400).json({ error: 'unsupported_response_type' });
    return;
  }
  if (!client_id || !redirect_uri) {
    res.status(400).json({ error: 'invalid_request' });
    return;
  }

  // Store OAuth request in session
  (req.session as any).oauthRequest = {
    clientId: client_id,
    redirectUri: redirect_uri,
    scope: scope || '',
    codeChallenge: code_challenge,
    codeChallengeMethod: code_challenge_method,
    state: state
  };

  // Check if user is already authenticated
  if ((req.session as any).user) {
    completeAuthorization(req, res);
    return;
  }

  // Redirect to MS365 for authentication
  try {
    const authUrl = await msal.getAuthCodeUrl({
      scopes: ['openid', 'profile', 'email'],
      redirectUri: process.env.REDIRECT_URI!
    });
    res.redirect(authUrl);
  } catch (error) {
    console.error('Error generating auth URL:', error);
    res.status(500).json({ error: 'server_error' });
  }
});

// Token endpoint
app.post('/token', async (req, res) => {
  console.log('Token request received:', req.body);
  console.log('Content-Type:', req.get('content-type'));
  
  if (!req.body || Object.keys(req.body).length === 0) {
    res.status(400).json({ error: 'invalid_request', error_description: 'Request body is required' });
    return;
  }

  const { grant_type, code, client_id, code_verifier, redirect_uri } = req.body;

  if (grant_type !== 'authorization_code') {
    res.status(400).json({ error: 'unsupported_grant_type' });
    return;
  }

  const codeData = authorizationCodes.get(code);
  if (!codeData || codeData.expiresAt < Date.now()) {
    authorizationCodes.delete(code);
    res.status(400).json({ error: 'invalid_grant' });
    return;
  }

  if (codeData.clientId !== client_id || codeData.redirectUri !== redirect_uri) {
    res.status(400).json({ error: 'invalid_client' });
    return;
  }

  // Verify PKCE if present
  if (codeData.codeChallenge && codeData.codeChallengeMethod === 'S256') {
    const crypto = await import('crypto');
    const hash = crypto.createHash('sha256').update(code_verifier || '').digest('base64url');
    if (hash !== codeData.codeChallenge) {
      res.status(400).json({ error: 'invalid_grant' });
      return;
    }
  }

  // Generate access token
  const accessToken = randomUUID();
  const tokenData = {
    token: accessToken,
    clientId: client_id,
    userId: codeData.userId,
    scope: codeData.scope,
    expiresAt: Date.now() + 3600000 // 1 hour
  };

  accessTokens.set(accessToken, tokenData);
  authorizationCodes.delete(code);

  res.json({
    access_token: accessToken,
    token_type: 'Bearer',
    expires_in: 3600,
    scope: codeData.scope
  });
});

// Helper function to complete authorization
function completeAuthorization(req: express.Request, res: express.Response) {
  const oauthRequest = (req.session as any).oauthRequest;
  const user = (req.session as any).user;

  if (!oauthRequest || !user) {
    res.status(400).json({ error: 'invalid_request' });
    return;
  }

  // Generate authorization code
  const authCode = randomUUID();
  const codeData = {
    clientId: oauthRequest.clientId,
    redirectUri: oauthRequest.redirectUri,
    scope: oauthRequest.scope,
    codeChallenge: oauthRequest.codeChallenge,
    codeChallengeMethod: oauthRequest.codeChallengeMethod,
    state: oauthRequest.state,
    userId: user.oid,
    expiresAt: Date.now() + 600000 // 10 minutes
  };

  authorizationCodes.set(authCode, codeData);

  // Clear OAuth request from session
  delete (req.session as any).oauthRequest;

  // Redirect back to client
  const redirectUrl = new URL(oauthRequest.redirectUri);
  redirectUrl.searchParams.set('code', authCode);
  if (oauthRequest.state) {
    redirectUrl.searchParams.set('state', oauthRequest.state);
  }

  res.redirect(redirectUrl.toString());
}

// OAuth routes (keep existing for browser access)
app.get('/login', async (req, res) => {
  try {
    const authUrl = await msal.getAuthCodeUrl({
      scopes: ['openid', 'profile', 'email'],
      redirectUri: process.env.REDIRECT_URI!
    });
    res.redirect(authUrl);
  } catch (error) {
    console.error('Error generating auth URL:', error);
    res.status(500).send('Error initiating authentication');
  }
});

app.get('/auth/callback', async (req, res) => {
  try {
    const tokenResponse = await msal.acquireTokenByCode({
      code: req.query.code as string,
      scopes: ['openid', 'profile', 'email'],
      redirectUri: process.env.REDIRECT_URI!
    });

    (req.session as any).user = {
      oid: tokenResponse.account?.homeAccountId,
      name: (tokenResponse.idTokenClaims as any)?.name,
      email: (tokenResponse.idTokenClaims as any)?.preferred_username
    };

    // Check if this was part of an OAuth flow
    if ((req.session as any).oauthRequest) {
      completeAuthorization(req, res);
      return;
    }

    res.redirect('/');
  } catch (error) {
    console.error('Error in auth callback:', error);
    res.status(500).send('Authentication failed');
  }
});

// OAuth Discovery/Metadata endpoint
app.get('/.well-known/oauth-authorization-server', (req, res) => {
  // Force HTTPS for OAuth metadata
  const protocol = req.get('x-forwarded-proto') || req.protocol;
  const baseUrl = `${protocol === 'http' && req.get('host')?.includes('test-mcp.netdaisy.com') ? 'https' : protocol}://${req.get('host')}`;
  res.json({
    issuer: baseUrl,
    authorization_endpoint: `${baseUrl}/authorize`,
    token_endpoint: `${baseUrl}/token`,
    response_types_supported: ['code'],
    grant_types_supported: ['authorization_code'],
    code_challenge_methods_supported: ['S256'],
    scopes_supported: ['claudeai', 'mcp'],
    token_endpoint_auth_methods_supported: ['none']
  });
});

app.get('/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      console.error('Error destroying session:', err);
    }
    res.redirect('/');
  });
});

// Landing page
app.get('/', (req, res) => {
  const user = (req.session as any)?.user;
  const html = `
<!DOCTYPE html>
<html>
<head>
    <title>MCP Server with OAuth</title>
    <style>
        body { font-family: Arial, sans-serif; max-width: 800px; margin: 50px auto; padding: 20px; }
        .status { padding: 10px; border-radius: 5px; margin: 10px 0; }
        .authenticated { background-color: #d4edda; border: 1px solid #c3e6cb; color: #155724; }
        .unauthenticated { background-color: #f8d7da; border: 1px solid #f5c6cb; color: #721c24; }
        .button { display: inline-block; padding: 10px 20px; margin: 10px 5px; text-decoration: none; border-radius: 5px; }
        .login { background-color: #007bff; color: white; }
        .logout { background-color: #dc3545; color: white; }
        .info { background-color: #e2e3e5; color: #383d41; }
    </style>
</head>
<body>
    <h1>MCP Server with MS365 OAuth</h1>
    
    ${user 
      ? `<div class="status authenticated">
           <strong>✓ Authenticated</strong><br>
           Welcome, ${user.name || user.email}!<br>
           <a href="/logout" class="button logout">Logout</a>
           <a href="/status" class="button info">Status</a>
         </div>`
      : `<div class="status unauthenticated">
           <strong>✗ Not Authenticated</strong><br>
           Please log in to access the MCP server.<br>
           <a href="/login" class="button login">Login with MS365</a>
         </div>`
    }
    
    <h2>Endpoints</h2>
    <ul>
        <li><strong>Health:</strong> <a href="/health">/health</a> (public)</li>
        <li><strong>Login:</strong> <a href="/login">/login</a></li>
        <li><strong>Status:</strong> <a href="/status">/status</a> (protected)</li>
        <li><strong>MCP:</strong> <code>/v1/mcp</code> (protected)</li>
    </ul>
    
    <p><em>This server uses MS365 OAuth for authentication. Only authenticated users can access the MCP endpoints.</em></p>
</body>
</html>`;
  
  res.send(html);
});

// MCP server factory function (following Anthropic pattern)
const getServer = () => {
  const server = new McpServer({
    name: 'outline-mcp-hello-world',
    version: '1.0.0',
  }, { 
    capabilities: { 
      logging: {},
      tools: {}
    } 
  });

  server.tool('hello', 'A simple hello world function', {
    name: z.string().describe('Name to greet').optional(),
  }, async ({ name }) => {
    console.log('Hello tool called with:', { name });
    const greeting = name || 'world';
    return {
      content: [
        {
          type: 'text',
          text: `Hello, ${greeting}! Server: outline-mcp.netdaisy.com at ${new Date().toISOString()}`,
        }
      ],
    };
  });

  return server;
};

// Helper function to check if request is an initialize request
const isInitializeRequest = (body: any): boolean => {
  return body && body.method === 'initialize';
};

// Health endpoint (no auth required)
app.get('/health', (req, res) => {
  res.json({ 
    status: 'ok', 
    timestamp: new Date().toISOString(),
    activeConnections: Object.keys(transports).length,
    server: 'outline-mcp.netdaisy.com',
    authenticated: !!(req.session as any)?.user
  });
});

// Protected status endpoint
app.get('/status', ensureAuthenticated, (req, res) => {
  const user = (req.session as any).user;
  res.json({
    authenticated: true,
    user: {
      name: user.name,
      email: user.email
    },
    activeConnections: Object.keys(transports).length
  });
});

// MCP POST handler (following Anthropic pattern)
const mcpPostHandler = async (req: express.Request, res: express.Response) => {
  console.log('MCP POST request:', req.body);
  
  const sessionId = req.headers['mcp-session-id'] as string | undefined;
  
  if (!sessionId && isInitializeRequest(req.body)) {
    console.log('New MCP session initialization');
    
    const transport = new StreamableHTTPServerTransport({
      sessionIdGenerator: () => randomUUID(),
      onsessioninitialized: (sessionId: string) => {
        console.log(`MCP session initialized: ${sessionId}`);
        transports[sessionId] = transport;
      }
    });

    const server = getServer();
    await server.connect(transport);
    await transport.handleRequest(req, res, req.body);
  } else if (sessionId && transports[sessionId]) {
    console.log(`Using existing session: ${sessionId}`);
    await transports[sessionId].handleRequest(req, res, req.body);
  } else {
    console.error('No valid session found');
    res.status(400).json({ error: 'Invalid session' });
  }
};

// MCP GET handler for SSE
const mcpGetHandler = async (req: express.Request, res: express.Response) => {
  console.log('MCP GET request for SSE');
  
  const sessionId = req.headers['mcp-session-id'] as string | undefined;
  
  if (sessionId && transports[sessionId]) {
    console.log(`SSE request for session: ${sessionId}`);
    await transports[sessionId].handleRequest(req, res);
  } else {
    console.error('No valid session for SSE');
    res.status(400).json({ error: 'Invalid session' });
  }
};

// MCP StreamableHTTP endpoints (protected)
app.post('/v1/mcp', ensureAuthenticated, mcpPostHandler);
app.get('/v1/mcp', ensureAuthenticated, mcpGetHandler);

const server = app.listen(PORT, () => {
  console.log(`MCP Server with OAuth listening on port ${PORT}`);
  console.log(`Health check: http://localhost:${PORT}/health`);
  console.log(`Login: http://localhost:${PORT}/login`);
  console.log(`MCP StreamableHTTP endpoint: http://localhost:${PORT}/v1/mcp`);
  console.log('Public URL: outline-mcp.netdaisy.com:3131');
  console.log('OAuth Configuration:');
  console.log(`  Client ID: ${process.env.MS_CLIENT_ID ? '✓ Set' : '✗ Missing'}`);
  console.log(`  Client Secret: ${process.env.MS_CLIENT_SECRET ? '✓ Set' : '✗ Missing'}`);
  console.log(`  Redirect URI: ${process.env.REDIRECT_URI || '✗ Missing'}`);
});

process.on('SIGINT', async () => {
  console.log('Shutting down server...');
  
  for (const sessionId in transports) {
    try {
      console.log(`Closing transport for session ${sessionId}`);
      await transports[sessionId].close();
      delete transports[sessionId];
    } catch (error) {
      console.error(`Error closing transport for session ${sessionId}:`, error);
    }
  }
  
  server.close(() => {
    console.log('Server shutdown complete');
    process.exit(0);
  });
});

process.on('SIGTERM', async () => {
  console.log('Received SIGTERM, shutting down gracefully...');
  
  for (const sessionId in transports) {
    try {
      await transports[sessionId].close();
      delete transports[sessionId];
    } catch (error) {
      console.error(`Error closing transport for session ${sessionId}:`, error);
    }
  }
  
  server.close(() => {
    console.log('Server closed');
    process.exit(0);
  });
});

export default app;