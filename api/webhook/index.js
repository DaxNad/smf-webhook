import crypto from "crypto";

function readRawBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on("data", c => chunks.push(c));
    req.on("end", () => resolve(Buffer.concat(chunks)));
    req.on("error", reject);
  });
}

function safeLog(obj, label = "") {
  try {
    console.log(label ? `${label}:` : "", JSON.stringify(obj));
  } catch {
    console.log(label, obj);
  }
}

export default async function handler(req, res) {
  // Health check rapido
  if (req.method === "GET") return res.status(200).send("OK");
  if (req.method !== "POST") return res.status(405).send("Method Not Allowed");

  // --- Validazione firma HMAC GitHub ---
  const secret = process.env.WEBHOOK_SECRET || "";
  const sig = req.headers["x-hub-signature-256"] || "";
  const raw = await readRawBody(req);
  const expected = "sha256=" + crypto.createHmac("sha256", secret).update(raw).digest("hex");
  console.log("signature header:", sig.slice(0, 20));
console.log("expected value:", expected.slice(0, 20));
  const ok = sig.length === expected.length &&
             crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected));
  if (!ok) return res.status(401).send("Invalid signature");

  const event = req.headers["x-github-event"] || "";
  const payload = JSON.parse(raw.toString("utf8"));
  safeLog({ event, delivery: req.headers["x-github-delivery"] }, "github-meta");

  // --- Router eventi ---
  switch (event) {
    case "ping": {
      // handshake iniziale
      safeLog({ zen: payload.zen }, "ping");
      return res.status(200).json({ ok: true, event: "ping" });
    }

    case "push": {
      const repo = payload.repository?.full_name;
      const ref = payload.ref;                       // es. "refs/heads/main"
      const branch = ref?.split("/").pop();
      const head = payload.after;                    // sha commit
      const pusher = payload.pusher?.name || payload.sender?.login;

      // estrai file cambiati dal set di commit
      const changes = { added: [], modified: [], removed: [] };
      for (const c of payload.commits || []) {
        changes.added.push(...(c.added || []));
        changes.modified.push(...(c.modified || []));
        changes.removed.push(...(c.removed || []));
      }

      // Filtri utili per SuperMegaFile (personalizzabili)
      const watchGlobs = (process.env.WATCH_GLOBS || "schede/,checklist/,crm/,crt/,SuperMegaFile").split(",");
      const touched = [
        ...changes.added, ...changes.modified, ...changes.removed
      ].filter(p => watchGlobs.some(g => p.toLowerCase().includes(g.trim().toLowerCase())));

      safeLog({ repo, branch, head, pusher, changes, touched }, "push");

      // TODO: qui metteremo la vera “Sync” del SuperMegaFile
      // Esempi:
      // - chiamata HTTP a un tuo endpoint interno (Google Apps Script / API aziendale)
      // - fetch di file specifici e normalizzazione
      // - aggiornamento storage
      //
      // Se vuoi una callout HTTP:
      // await fetch(process.env.SYNC_URL, { method:'POST', headers:{'Content-Type':'application/json', 'Authorization':`Bearer ${process.env.SYNC_TOKEN}`}, body: JSON.stringify({repo, branch, head, changes, touched}) });

      return res.status(200).json({ ok: true, event: "push", touched });
    }

    case "pull_request": {
      const action = payload.action;                 // opened, synchronize, closed…
      const repo = payload.repository?.full_name;
      const number = payload.number;
      const title = payload.pull_request?.title;
      safeLog({ repo, number, action, title }, "pull_request");
      return res.status(200).json({ ok: true, event: "pull_request", action });
    }

    case "create": {
      safeLog({ ref: payload.ref, ref_type: payload.ref_type }, "create");
      return res.status(200).json({ ok: true, event: "create" });
    }

    case "delete": {
      safeLog({ ref: payload.ref, ref_type: payload.ref_type }, "delete");
      return res.status(200).json({ ok: true, event: "delete" });
    }

    default: {
      // Eventi non gestiti: log e 200 per non far riprovare GitHub
      safeLog({ event }, "unhandled");
      return res.status(200).json({ ok: true, event });
    }
  }
}
