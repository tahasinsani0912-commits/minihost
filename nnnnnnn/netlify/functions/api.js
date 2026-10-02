// MiniHost backend (Netlify Function) -> /.netlify/functions/api
// Credentials are read ONLY here, from Netlify environment variables:
//   NETLIFY_TOKEN   Netlify personal access token
//   ADMIN_PASSWORD  your MiniHost password
// All replies are JSON: { success: true, data } or { success: false, error }.
const crypto = require('crypto');
const API = 'https://api.netlify.com/api/v1', PREFIX = 'mh-', MAX_ZIP = 4.5 * 1024 * 1024;
const ALLOWED = /\.(html?|css|m?js|json|txt|xml|svg|png|jpe?g|gif|webp|avif|ico|woff2?|ttf|otf|eot|map|mp4|webm|mp3|pdf)$/i;

class Fail extends Error { constructor(m, code = 400) { super(m); this.code = code; } }
const out = (c, o) => ({ statusCode: c, headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' }, body: JSON.stringify(o) });
const sha = s => crypto.createHash('sha256').update(String(s)).digest();

async function nf(path, opt = {}) {
  let r;
  try { r = await fetch(API + path, { ...opt, headers: { Authorization: 'Bearer ' + process.env.NETLIFY_TOKEN, ...opt.headers } }); }
  catch { throw new Fail('Could not reach the Netlify API.', 502); }
  const t = await r.text();
  if (!r.ok) {
    if (r.status === 401) throw new Fail('Netlify rejected NETLIFY_TOKEN. Check that it is valid.', 502);
    if (r.status === 422) throw new Fail('That slug is already taken. Try another.', 409);
    if (r.status === 404) throw new Fail('Website not found on Netlify.', 404);
    throw new Fail(`Netlify API error (${r.status}).`, 502);
  }
  try { return t ? JSON.parse(t) : {}; } catch { throw new Fail('Invalid response from Netlify.', 502); }
}
const slim = (s, d) => { d = d || s.published_deploy || {}; return { id: s.id, slug: s.name.slice(PREFIX.length), url: s.ssl_url || s.url, updated: d.updated_at || s.updated_at, deployId: d.id || null, state: d.state || null, online: d.state === 'ready' }; };
const siteId = id => { if (!/^[\w-]+$/.test(id || '')) throw new Fail('Bad site id'); return id; };
const slugOf = s => String(s || '').toLowerCase().replace(/[^a-z0-9-]+/g, '-').replace(/-+/g, '-').replace(/^-+|-+$/g, '').slice(0, 40);
async function ownSite(id) { const s = await nf('/sites/' + siteId(id)); if (!s.name.startsWith(PREFIX)) throw new Fail('Not a MiniHost website.', 403); return s; }

// Reads the ZIP's directory (no extraction) and rejects unsafe paths / file types.
function checkZip(buf) {
  if (buf.length < 22 || buf.readUInt32LE(0) !== 0x04034b50) throw new Fail('Invalid ZIP file.');
  let p = -1;
  for (let i = buf.length - 22; i >= Math.max(0, buf.length - 65557); i--) if (buf.readUInt32LE(i) === 0x06054b50) { p = i; break; }
  if (p < 0) throw new Fail('Invalid ZIP file.');
  const n = buf.readUInt16LE(p + 10); let o = buf.readUInt32LE(p + 16), index = false;
  if (!n || n > 2000) throw new Fail('ZIP must contain between 1 and 2000 files.');
  for (let i = 0; i < n; i++) {
    if (o + 46 > buf.length || buf.readUInt32LE(o) !== 0x02014b50) throw new Fail('Corrupt ZIP file.');
    const len = buf.readUInt16LE(o + 28), ex = buf.readUInt16LE(o + 30), cm = buf.readUInt16LE(o + 32);
    const name = buf.toString('utf8', o + 46, o + 46 + len); o += 46 + len + ex + cm;
    if (name.endsWith('/')) continue;
    if (/^[\/]|[\\:]/.test(name) || name.split('/').includes('..') || !ALLOWED.test(name)) throw new Fail('Blocked file in ZIP: ' + name.slice(0, 80));
    if (name === 'index.html') index = true;
  }
  if (!index) throw new Fail('index.html is required to publish this website.');
}

exports.handler = async e => {
  try {
    if (!process.env.NETLIFY_TOKEN) throw new Fail('NETLIFY_TOKEN is not configured.', 500);
    if (!process.env.ADMIN_PASSWORD) throw new Fail('ADMIN_PASSWORD is not configured.', 500);
    if (e.httpMethod !== 'POST') throw new Fail('Use POST.', 405);
    if (!crypto.timingSafeEqual(sha(e.headers['x-password'] || ''), sha(process.env.ADMIN_PASSWORD))) throw new Fail('Wrong password.', 401);
    let b; try { b = JSON.parse(e.body || '{}'); } catch { throw new Fail('Invalid JSON request.'); }
    const ok = d => out(200, { success: true, data: d });

    if (b.action === 'list') {
      const all = await nf('/sites?filter=all&per_page=100');
      return ok(all.filter(s => s.name.startsWith(PREFIX)).map(s => slim(s)));
    }
    if (b.action === 'delete') {
      const s = await ownSite(b.id);
      await nf('/sites/' + s.id, { method: 'DELETE' });
      return ok({ id: s.id });
    }
    if (b.action === 'publish') {
      const buf = Buffer.from(String(b.zip || ''), 'base64');
      if (buf.length > MAX_ZIP) throw new Fail('Website is too large (max 4.5 MB zipped).');
      checkZip(buf);
      let site;
      if (b.id) site = await ownSite(b.id);
      else {
        const slug = slugOf(b.slug);
        if (slug.length < 3) throw new Fail('Slug must be at least 3 letters/numbers.');
        site = await nf('/sites', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ name: PREFIX + slug }) });
      }
      let d = await nf(`/sites/${site.id}/deploys`, { method: 'POST', headers: { 'Content-Type': 'application/zip' }, body: buf });
      for (let i = 0; i < 20 && d.state !== 'ready'; i++) {
        if (d.state === 'error') throw new Fail('Deployment failed: ' + (d.error_message || 'unknown error'), 502);
        await new Promise(r => setTimeout(r, 1000));
        d = await nf('/deploys/' + d.id);
      }
      if (d.state !== 'ready') throw new Fail('Deployment is still processing. Refresh the list in a moment.', 504);
      return ok(slim(site, d));
    }
    throw new Fail('Unknown action.');
  } catch (err) {
    if (err instanceof Fail) return out(err.code, { success: false, error: err.message });
    console.error(err);
    return out(500, { success: false, error: 'Unexpected server error.' });
  }
};
