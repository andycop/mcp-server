import express from 'express';
import cors from 'cors';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { SSEServerTransport } from '@modelcontextprotocol/sdk/server/sse.js';
import { z } from 'zod';

const app = express();
const PORT = process.env.PORT || 3131;

app.use(cors());
app.use(express.json());

const transports: Record<string, SSEServerTransport> = {};

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

app.get('/health', (req, res) => {
  res.json({ 
    status: 'ok', 
    timestamp: new Date().toISOString(),
    activeConnections: Object.keys(transports).length,
    server: 'outline-mcp.netdaisy.com'
  });
});

app.get('/v1/mcp', async (req, res) => {
  console.log('Received GET request to /v1/mcp (establishing SSE stream)');
  
  try {
    const transport = new SSEServerTransport('/v1/messages', res);
    const sessionId = transport.sessionId;
    transports[sessionId] = transport;

    transport.onclose = () => {
      console.log(`SSE transport closed for session ${sessionId}`);
      delete transports[sessionId];
    };

    const server = getServer();
    await server.connect(transport);
    
    console.log(`Established SSE stream with session ID: ${sessionId}`);
    console.log(`Total active connections: ${Object.keys(transports).length}`);
  } catch (error) {
    console.error('Error establishing SSE stream:', error);
    if (!res.headersSent) {
      res.status(500).send('Error establishing SSE stream');
    }
  }
});

app.post('/v1/messages', async (req, res) => {
  console.log('Received POST request to /v1/messages');
  
  const sessionId = req.query.sessionId as string;
  if (!sessionId) {
    console.error('No session ID provided in request URL');
    res.status(400).send('Missing sessionId parameter');
    return;
  }

  const transport = transports[sessionId];
  if (!transport) {
    console.error(`No active transport found for session ID: ${sessionId}`);
    res.status(404).send('Session not found');
    return;
  }

  try {
    await transport.handlePostMessage(req, res, req.body);
  } catch (error) {
    console.error('Error handling request:', error);
    if (!res.headersSent) {
      res.status(500).send('Error handling request');
    }
  }
});

const server = app.listen(PORT, () => {
  console.log(`MCP Server listening on port ${PORT}`);
  console.log(`Health check: http://localhost:${PORT}/health`);
  console.log(`MCP SSE endpoint: http://localhost:${PORT}/v1/mcp`);
  console.log(`MCP Messages endpoint: http://localhost:${PORT}/v1/messages`);
  console.log('Public URL: outline-mcp.netdaisy.com:3131');
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