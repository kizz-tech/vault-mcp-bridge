import { timingSafeEqual, randomBytes } from 'node:crypto';
import { isIP } from 'node:net';

export function isLoopbackHost(host: string | undefined): boolean {
  if (!host) return false;
  const hostname = host.replace(/^\[/, '').replace(/\](:\d+)?$/, '').replace(/:\d+$/, '').toLowerCase();
  return hostname === 'localhost' || hostname === '127.0.0.1' || hostname === '::1' || (isIP(hostname) === 6 && hostname === '0:0:0:0:0:0:0:1');
}

export function allowedRemoteUrl(raw: string, allowLoopback = false): URL {
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    throw new Error('remoteServerUrl must be a valid URL');
  }
  if (url.username || url.password) throw new Error('remoteServerUrl must not contain credentials');
  if (url.protocol !== 'https:' && !(allowLoopback && url.protocol === 'http:' && isLoopbackHost(url.host))) {
    throw new Error('remoteServerUrl must use HTTPS (HTTP is allowed only for loopback development)');
  }
  if (url.pathname === '/' || url.pathname === '') url.pathname = '';
  return url;
}

export function newCsrfToken(): string {
  return randomBytes(32).toString('base64url');
}

export function sameOrigin(requestOrigin: string | undefined, expectedOrigin: string): boolean {
  return Boolean(requestOrigin && requestOrigin === expectedOrigin);
}

export function safeEqual(a: string | undefined, b: string | undefined): boolean {
  if (!a || !b) return false;
  const left = Buffer.from(a);
  const right = Buffer.from(b);
  return left.length === right.length && timingSafeEqual(left, right);
}

export function nonce(): string {
  return randomBytes(16).toString('base64url');
}

export function containsPathLikeSecret(value: unknown): boolean {
  if (typeof value === 'string') return /(?:^|[\\/])(?:Users|home|var|private|tmp)(?:[\\/]|$)/i.test(value) || value.includes('file://');
  if (Array.isArray(value)) return value.some(containsPathLikeSecret);
  if (value && typeof value === 'object') return Object.entries(value).some(([key, child]) => key.toLowerCase().includes('path') || containsPathLikeSecret(child));
  return false;
}
