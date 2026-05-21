#!/usr/bin/env node
/**
 * Cloudflare Workers Security Scanner Integration
 * Runs lightweight security checks on edge
 */

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    
    // Security headers check
    const securityHeaders = {
      'X-Content-Type-Options': 'nosniff',
      'X-Frame-Options': 'DENY',
      'X-XSS-Protection': '1; mode=block',
      'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
      'Content-Security-Policy': "default-src 'self'",
      'Permissions-Policy': 'geolocation=(), microphone=(), camera=()'
    };
    
    // Rate limiting
    const rateLimitKey = `rate_limit:${request.headers.get('CF-Connecting-IP')}`;
    const rateLimit = await env.KV.get(rateLimitKey);
    
    if (rateLimit && parseInt(rateLimit) > 100) {
      return new Response('Rate limit exceeded', { status: 429 });
    }
    
    await env.KV.put(rateLimitKey, (parseInt(rateLimit || 0) + 1).toString(), {
      expirationTtl: 60
    });
    
    // Block suspicious patterns
    const suspiciousPatterns = [
      /\.\.\//,  // Path traversal
      /<script/i,  // XSS
      /union.*select/i,  // SQL injection
      /eval\(/,  // Code injection
    ];
    
    const fullUrl = url.pathname + url.search;
    for (const pattern of suspiciousPatterns) {
      if (pattern.test(fullUrl)) {
        await logSecurityEvent(env, {
          type: 'blocked_request',
          pattern: pattern.toString(),
          url: fullUrl,
          ip: request.headers.get('CF-Connecting-IP'),
          timestamp: new Date().toISOString()
        });
        
        return new Response('Blocked', { status: 403 });
      }
    }
    
    // Forward to origin with security headers
    const response = await fetch(request);
    const newResponse = new Response(response.body, response);
    
    Object.entries(securityHeaders).forEach(([key, value]) => {
      newResponse.headers.set(key, value);
    });
    
    return newResponse;
  }
};

async function logSecurityEvent(env, event) {
  await env.KV.put(
    `security_event:${Date.now()}`,
    JSON.stringify(event),
    { expirationTtl: 86400 * 7 }  // 7 days
  );
}
