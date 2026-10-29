import { requireBearerAuth } from '@modelcontextprotocol/sdk/server/auth/middleware/bearerAuth.js';
import { getOAuthProtectedResourceMetadataUrl } from '@modelcontextprotocol/sdk/server/auth/router.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import express, { Router } from 'express';
import type { AppDeps } from '../app.js';
import { mcpUrl } from '../config.js';
import { findUserById } from '../db/users.js';
import { buildMcpServer } from './server.js';

export function mcpRouter(deps: AppDeps): Router {
  const router = Router();
  const auth = requireBearerAuth({
    verifier: deps.provider,
    resourceMetadataUrl: getOAuthProtectedResourceMetadataUrl(mcpUrl(deps.config)),
  });

  router.post('/mcp', auth, express.json({ limit: '1mb' }), async (req, res) => {
    const userId = Number(req.auth?.extra?.userId);
    const user = findUserById(deps.db, userId);
    if (!user) {
      res.status(401).json({ error: 'invalid_token', error_description: 'Account no longer exists' });
      return;
    }
    const server = buildMcpServer(
      { db: deps.db, config: deps.config, pool: deps.pool, smtpFactory: deps.smtpFactory, mailGuard: deps.mailGuard, userId, requestId: res.locals.requestId as string | undefined },
      user.permissionLevel,
    );
    const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined, enableJsonResponse: true });
    res.on('close', () => {
      void transport.close();
      void server.close();
    });
    await server.connect(transport);
    await transport.handleRequest(req, res, req.body);
  });

  router.all('/mcp', auth, (_req, res) => {
    res.status(405).set('Allow', 'POST').json({ error: 'Method not allowed' });
  });

  return router;
}
