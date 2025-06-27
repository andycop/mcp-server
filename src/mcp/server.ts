import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { z } from 'zod';
import { randomUUID } from 'crypto';
import { Request, Response } from 'express';
import { logger, anonymizeKey } from '../utils/logger.js';

export class McpServerManager {
  private transports: Record<string, StreamableHTTPServerTransport> = {};

  createServer(): McpServer {
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
      logger.debug('Hello tool called', { name: name || 'world' });
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
  }

  private isInitializeRequest(body: any): boolean {
    return body && body.method === 'initialize';
  }

  async handlePost(req: Request, res: Response): Promise<void> {
    const sessionId = req.headers['mcp-session-id'] as string | undefined;
    
    logger.debug('MCP POST request', {
      sessionId: sessionId ? anonymizeKey(sessionId) : 'none',
      method: req.body?.method || 'unknown',
      hasBody: !!req.body
    });
    
    if (!sessionId && this.isInitializeRequest(req.body)) {
      logger.info('New MCP session initialization');
      
      const transport = new StreamableHTTPServerTransport({
        sessionIdGenerator: () => randomUUID(),
        onsessioninitialized: (sessionId: string) => {
          logger.info('MCP session initialized', { sessionId: anonymizeKey(sessionId) });
          this.transports[sessionId] = transport;
        }
      });

      const server = this.createServer();
      await server.connect(transport);
      await transport.handleRequest(req, res, req.body);
    } else if (sessionId && this.transports[sessionId]) {
      logger.debug('Using existing MCP session', { sessionId: anonymizeKey(sessionId) });
      await this.transports[sessionId].handleRequest(req, res, req.body);
    } else {
      logger.warn('No valid MCP session found', { sessionId: sessionId ? anonymizeKey(sessionId) : 'none' });
      res.status(400).json({ error: 'Invalid session' });
    }
  }

  async handleGet(req: Request, res: Response): Promise<void> {
    const sessionId = req.headers['mcp-session-id'] as string | undefined;
    
    logger.debug('MCP GET request for SSE', { 
      sessionId: sessionId ? anonymizeKey(sessionId) : 'none' 
    });
    
    if (sessionId && this.transports[sessionId]) {
      logger.debug('SSE connection established', { sessionId: anonymizeKey(sessionId) });
      await this.transports[sessionId].handleRequest(req, res);
    } else {
      logger.warn('No valid session for SSE', { sessionId: sessionId ? anonymizeKey(sessionId) : 'none' });
      res.status(400).json({ error: 'Invalid session' });
    }
  }

  getActiveConnections(): number {
    return Object.keys(this.transports).length;
  }

  async closeAllTransports(): Promise<void> {
    const sessionCount = Object.keys(this.transports).length;
    if (sessionCount > 0) {
      logger.info(`Closing ${sessionCount} MCP transport sessions`);
    }
    
    for (const sessionId in this.transports) {
      try {
        logger.debug('Closing MCP transport', { sessionId: anonymizeKey(sessionId) });
        await this.transports[sessionId].close();
        delete this.transports[sessionId];
      } catch (error) {
        logger.error('Error closing MCP transport', { 
          sessionId: anonymizeKey(sessionId),
          error: error instanceof Error ? error.message : 'Unknown error'
        });
      }
    }
  }
}