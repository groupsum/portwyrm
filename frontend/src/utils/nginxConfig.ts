import type { Host } from '../types';

export interface ConfigDiffLine { type: 'same' | 'add' | 'remove'; line: string }

export function generateNginxConfig(host: Host): string {
  const domains = host.source.split(',').map(value => value.trim()).filter(Boolean);
  if (host.type === 'stream') {
    return `stream {\n    upstream portwyrm_${host.id.replace(/\W/g, '_')} { server ${host.destination}; }\n    server {\n        listen ${host.source.split(':').pop()?.trim() || '0'};\n        proxy_pass portwyrm_${host.id.replace(/\W/g, '_')};\n${indent(host.customNginxConfig, 8)}    }\n}`;
  }
  const lines = ['server {', '    listen 80;', '    listen [::]:80;', `    server_name ${domains.join(' ')};`];
  if (host.sslId) {
    lines.push('    listen 443 ssl' + (host.http2 ? ' http2;' : ';'));
    lines.push(`    # certificate: ${host.sslName}`);
  }
  if (host.forceHttps) lines.push('    # HTTP requests are redirected to HTTPS');
  if (host.hsts) lines.push(`    add_header Strict-Transport-Security "max-age=31536000${host.hstsSubdomains ? '; includeSubDomains' : ''}" always;`);
  if (host.accessListIds.length) {
    lines.push('    satisfy all;', '    auth_basic "Protected Area";');
    lines.push(`    auth_basic_user_file /data/access/${host.accessListIds.length > 1 ? `proxy-host-${host.id.split(':').pop()}` : host.accessListIds[0]};`);
  }
  if (host.customNginxConfig) lines.push(indent(host.customNginxConfig, 4).trimEnd());
  if (host.type === 'redirect') lines.push(`    return ${host.destination.includes('308') ? '308' : host.destination.includes('302') ? '302' : '301'} ${host.destination.replace(/^\w+:\/\//, 'https://').split(' (')[0]};`);
  else if (host.type === '404') lines.push('    location / { return 404; }');
  else {
    lines.push('    location / {', `        proxy_pass ${host.destination};`, '        proxy_set_header Host $host;', '        proxy_set_header X-Real-IP $remote_addr;', '        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;', '        proxy_set_header X-Forwarded-Proto $scheme;');
    if (host.websocket) lines.push('        proxy_http_version 1.1;', '        proxy_set_header Upgrade $http_upgrade;', '        proxy_set_header Connection "upgrade";');
    if (host.caching) lines.push('        proxy_cache public-cache;');
    lines.push('    }');
  }
  lines.push('}');
  return lines.join('\n');
}

function indent(value: string | undefined, spaces: number): string {
  if (!value) return '';
  const prefix = ' '.repeat(spaces);
  return value.split('\n').map(line => `${prefix}${line}`).join('\n') + '\n';
}

export function diffConfig(before: string, after: string): ConfigDiffLine[] {
  const left = before.split('\n');
  const right = after.split('\n');
  const matrix = Array.from({ length: left.length + 1 }, () => Array(right.length + 1).fill(0));
  for (let i = left.length - 1; i >= 0; i--) for (let j = right.length - 1; j >= 0; j--) matrix[i][j] = left[i] === right[j] ? matrix[i + 1][j + 1] + 1 : Math.max(matrix[i + 1][j], matrix[i][j + 1]);
  const result: ConfigDiffLine[] = [];
  let i = 0; let j = 0;
  while (i < left.length && j < right.length) {
    if (left[i] === right[j]) { result.push({ type: 'same', line: left[i] }); i++; j++; }
    else if (matrix[i + 1][j] >= matrix[i][j + 1]) { result.push({ type: 'remove', line: left[i++] }); }
    else { result.push({ type: 'add', line: right[j++] }); }
  }
  while (i < left.length) result.push({ type: 'remove', line: left[i++] });
  while (j < right.length) result.push({ type: 'add', line: right[j++] });
  return result;
}
