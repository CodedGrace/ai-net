/**
 * expressRateLimit.ts
 *
 * Express-rate-limit based middleware for protecting /api/* routes.
 *
 * Three tiers:
 *  - public     : 100 req/min per IP  (unauthenticated endpoints)
 *  - authed     : 30 req/min per wallet address (authenticated endpoints)
 *  - veniceProxy: 10 req/min per IP  (Venice AI proxy — respects upstream quota)
 *
 * All limits are configurable via environment variables and return a proper
 * 429 Too Many Requests response with a `Retry-After` header.
 *
 * Rate-limit violations are logged through the application logger so they
 * surface in structured logs alongside other API events.
 *
 * Issue #2 / #23: Implement rate limiting middleware for API endpoints
 */

import rateLimit, { type Options as RateLimitOptions } from "express-rate-limit";
import type { Request, Response, NextFunction } from "express";
import { createLogger } from "../../utils/logger";

const logger = createLogger({ module: "rate-limit" });

// ── Env-var helpers ───────────────────────────────────────────────────────────

function readEnvInt(key: string, fallback: number): number {
  const raw = process.env[key];
  if (!raw) return fallback;
  const n = parseInt(raw, 10);
  return Number.isFinite(n) && n > 0 ? n : fallback;
}

// ── Key generators ────────────────────────────────────────────────────────────

/**
 * Uses the wallet public key from the Authorization header when present,
 * falling back to IP address. This ensures authenticated users share a per-
 * wallet quota rather than a per-IP quota (multiple clients can share an IP
 * on NAT'd networks).
 */
function walletOrIpKey(req: Request): string {
  const authHeader = req.headers.authorization;
  if (authHeader?.startsWith("Bearer ")) {
    const token = authHeader.slice(7).trim();
    if (token.length > 0) {
      return `wallet:${token}`;
    }
  }
  return `ip:${req.ip ?? "unknown"}`;
}

/**
 * Always keys by IP address — used for public and Venice proxy endpoints.
 */
function ipKey(req: Request): string {
  return req.ip ?? "unknown";
}

// ── Shared handler factory ────────────────────────────────────────────────────

/**
 * Produces a standardised options object for `express-rate-limit`.
 *
 * @param tierName  - Human-readable name for logging ("public", "authed", "venice").
 * @param max       - Max requests per window.
 * @param windowMs  - Rolling window in milliseconds.
 * @param keyFn     - Function to derive the rate-limit key from a request.
 */
function makeLimiterOptions(
  tierName: string,
  max: number,
  windowMs: number,
  keyFn: (req: Request) => string,
): Partial<RateLimitOptions> {
  return {
    windowMs,
    max,
    standardHeaders: "draft-7",   // Return standard RateLimit-* headers (RFC draft 7)
    legacyHeaders: true,           // Also emit X-RateLimit-* for backwards compat
    keyGenerator: keyFn,
    skipSuccessfulRequests: false,

    handler(req: Request, res: Response, _next: NextFunction): void {
      const key = keyFn(req);
      const retryAfter = Math.ceil(windowMs / 1000);

      logger.warn(
        {
          tier: tierName,
          key,
          ip: req.ip,
          path: req.path,
          method: req.method,
          max,
          windowMs,
        },
        `[rate-limit] 429 ${tierName.toUpperCase()} tier — key="${key}" path="${req.path}"`,
      );

      res.setHeader("Retry-After", String(retryAfter));
      res.status(429).json({
        error: {
          message: "Too Many Requests",
          code: "RATE_LIMITED",
          retryAfter,
          tier: tierName,
        },
        requestId: res.locals.requestId as string | undefined,
      });
    },
  };
}

// ── Public limiter ─────────────────────────────────────────────────────────────
//
// Applied to unauthenticated endpoints: /api/agents (GET), /api/stats, /health.
// Default: 100 requests per minute per IP.
// Override via env vars: RATE_LIMIT_PUBLIC_MAX_REQUESTS, RATE_LIMIT_PUBLIC_WINDOW_MS

export const publicApiLimiter = rateLimit({
  ...makeLimiterOptions(
    "public",
    readEnvInt("RATE_LIMIT_PUBLIC_MAX_REQUESTS", 100),
    readEnvInt("RATE_LIMIT_PUBLIC_WINDOW_MS", 60_000),
    ipKey,
  ),
  message: {
    error: {
      message: "Too Many Requests",
      code: "RATE_LIMITED",
      tier: "public",
    },
  },
  skip: (req) => req.method === "OPTIONS",
});

// ── Authenticated limiter ──────────────────────────────────────────────────────
//
// Applied to wallet-authenticated endpoints: POST /api/tasks.
// Default: 30 requests per minute per wallet address (or IP as fallback).
// Override via env vars: RATE_LIMIT_AUTHED_MAX_REQUESTS, RATE_LIMIT_AUTHED_WINDOW_MS

export const authedApiLimiter = rateLimit({
  ...makeLimiterOptions(
    "authed",
    readEnvInt("RATE_LIMIT_AUTHED_MAX_REQUESTS", 30),
    readEnvInt("RATE_LIMIT_AUTHED_WINDOW_MS", 60_000),
    walletOrIpKey,
  ),
  skip: (req) => req.method === "OPTIONS",
});

// ── Venice AI proxy limiter ────────────────────────────────────────────────────
//
// Applied to any route that proxies requests to Venice AI.
// Default: 10 requests per minute per IP — conservative to respect upstream
// quota limits and avoid triggering Venice AI's own rate limiter.
// Override via env vars: RATE_LIMIT_VENICE_MAX_REQUESTS, RATE_LIMIT_VENICE_WINDOW_MS

export const veniceProxyLimiter = rateLimit({
  ...makeLimiterOptions(
    "venice",
    readEnvInt("RATE_LIMIT_VENICE_MAX_REQUESTS", 10),
    readEnvInt("RATE_LIMIT_VENICE_WINDOW_MS", 60_000),
    ipKey,
  ),
  skip: (req) => req.method === "OPTIONS",
});

// ── Admin limiter ──────────────────────────────────────────────────────────────
//
// Applied to /api/admin/* endpoints. Conservative limit for privileged operations.
// Default: 20 requests per minute per IP.
// Override via env vars: RATE_LIMIT_ADMIN_MAX_REQUESTS, RATE_LIMIT_ADMIN_WINDOW_MS

export const adminApiLimiter = rateLimit({
  ...makeLimiterOptions(
    "admin",
    readEnvInt("RATE_LIMIT_ADMIN_MAX_REQUESTS", 20),
    readEnvInt("RATE_LIMIT_ADMIN_WINDOW_MS", 60_000),
    ipKey,
  ),
  skip: (req) => req.method === "OPTIONS",
});

// ── Global catch-all limiter ───────────────────────────────────────────────────
//
// Broad protection applied to all /api/* routes before tier-specific limiters.
// This ensures even unknown or new routes are protected.
// Default: 200 requests per minute per IP (permissive intentionally).
// Override via: RATE_LIMIT_GLOBAL_MAX_REQUESTS, RATE_LIMIT_GLOBAL_WINDOW_MS

export const globalApiLimiter = rateLimit({
  ...makeLimiterOptions(
    "global",
    readEnvInt("RATE_LIMIT_GLOBAL_MAX_REQUESTS", 200),
    readEnvInt("RATE_LIMIT_GLOBAL_WINDOW_MS", 60_000),
    ipKey,
  ),
  skip: (req) => req.method === "OPTIONS",
});

// ── Named exports for application wiring ─────────────────────────────────────

/** Middleware for public/unauthenticated routes. */
export function publicRateLimit(req: Request, res: Response, next: NextFunction): void {
  publicApiLimiter(req, res, next);
}

/** Middleware for wallet-authenticated routes. */
export function authedRateLimit(req: Request, res: Response, next: NextFunction): void {
  authedApiLimiter(req, res, next);
}

/** Middleware for Venice AI proxy routes. */
export function veniceRateLimit(req: Request, res: Response, next: NextFunction): void {
  veniceProxyLimiter(req, res, next);
}

/** Middleware for admin routes. */
export function adminRateLimit(req: Request, res: Response, next: NextFunction): void {
  adminApiLimiter(req, res, next);
}

/** Global catch-all middleware — apply before route-specific limiters. */
export function globalRateLimit(req: Request, res: Response, next: NextFunction): void {
  globalApiLimiter(req, res, next);
}
