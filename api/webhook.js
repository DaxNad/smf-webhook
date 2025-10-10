// api/webhook.js — Vercel Edge Function per webhook GitHub
export const config = { runtime: 'edge' };

function timingSafeEqual(a,b){ if(a.length!==b.length)return false; let r=0; for(let i=0;i<a.length;i++) r|=a.charCodeAt(i)^b.charCodeAt(i); return r===0; }

export default async function handler(req){
  if(req.method!=='POST') return new Response('Method Not Allowed',{status:405});

  const sig = req.headers.get('x-hub-signature-256')||'';
  const body = await req.text();
  const secret = (process.env.WEBHOOK_SECRET||'').trim();

  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey('raw', enc.encode(secret), {name:'HMAC', hash:'SHA-256'}, false, ['sign']);
  const mac = await crypto.subtle.sign('HMAC', key, enc.encode(body));
  const hex = Array.from(new Uint8Array(mac)).map(b=>b.toString(16).padStart(2,'0')).join('');
  const exp = `sha256=${hex}`;

  if(!timingSafeEqual(sig, exp)) return new Response('Invalid signature',{status:401});
  return new Response('OK',{status:200});
}
add webhook
