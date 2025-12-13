#!/usr/bin/env node
const https = require('https');
const fs = require('fs');
const path = require('path');
const url = require('url');

// Simple argument parsing (no external deps) - supports --cert, --key, --port, --root
const rawArgs = process.argv.slice(2);
const argv = rawArgs.reduce((acc, cur, idx, arr) => {
  if (cur.startsWith('--')) {
    const key = cur.slice(2);
    const next = arr[idx + 1];
    if (next && !next.startsWith('-')) {
      acc[key] = next;
    } else {
      acc[key] = true;
    }
  } else if (cur.startsWith('-') && cur.length === 2) {
    const key = cur.slice(1);
    const next = arr[idx + 1];
    if (next && !next.startsWith('-')) {
      acc[key] = next;
    } else {
      acc[key] = true;
    }
  }
  return acc;
}, {});

const PORT = Number(argv.port || argv.p || argv.port || argv.p || 8080);
const CERT = argv.cert || argv.c || '192.168.56.1+2.pem';
const KEY = argv.key || argv.k || '192.168.56.1+2-key.pem';
const ROOT = argv.root || argv.r || path.join(__dirname);

function contentType(file) {
  const ext = path.extname(file).toLowerCase();
  switch (ext) {
    case '.html': return 'text/html; charset=utf-8';
    case '.js': return 'application/javascript; charset=utf-8';
    case '.css': return 'text/css; charset=utf-8';
    case '.json': return 'application/json';
    case '.png': return 'image/png';
    case '.jpg': case '.jpeg': return 'image/jpeg';
    case '.svg': return 'image/svg+xml';
    case '.ico': return 'image/x-icon';
    default: return 'application/octet-stream';
  }
}

function safeJoin(root, reqPath) {
  const p = path.normalize(path.join(root, reqPath));
  if (!p.startsWith(path.normalize(root))) return null;
  return p;
}

let cert, key;
try {
  cert = fs.readFileSync(path.resolve(CERT));
  key = fs.readFileSync(path.resolve(KEY));
} catch (err) {
  console.error('Failed to read cert/key:', err.message || err);
  process.exit(2);
}

const server = https.createServer({ key, cert }, (req, res) => {
  const parsed = url.parse(req.url || '/');
  let pathname = decodeURIComponent(parsed.pathname || '/');
  if (pathname.endsWith('/')) pathname += 'index.html';
  const filePath = safeJoin(ROOT, '.' + pathname);
  if (!filePath) {
    res.writeHead(400, { 'Content-Type': 'text/plain' });
    res.end('Bad request');
    return;
  }
  fs.stat(filePath, (err, st) => {
    if (err || !st.isFile()) {
      res.writeHead(404, { 'Content-Type': 'text/plain' });
      res.end('Not found');
      return;
    }
    const ct = contentType(filePath);
    res.writeHead(200, { 'Content-Type': ct });
    fs.createReadStream(filePath).pipe(res);
  });
});

server.listen(PORT, () => {
  console.log(`Serving ${ROOT} over HTTPS on https://localhost:${PORT}`);
  console.log('TIP: If you access via IP, use the cert host you generated (e.g., https://192.168.56.1:8080)');
});
