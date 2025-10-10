// api/webhook.js — Vercel Serverless Function (Node.js 20)

import crypto from "crypto";

export default async function handler(req, res) {
  if (req.method !== "POST") {
    return res.status(405).send("Method Not Allowed");
  }

  const chunks = [];
  for await (const c of req) chunks.push(c);
  const body = Buffer.concat(chunks);

  const signature = req.headers["x-hub-signature-256"] || "";
  const secret = (process.env.WEBHOOK_SECRET || "").trim();

  const expected =
    "sha256=" + crypto.createHmac("sha256", secret).update(body).digest("hex");

  const a = Buffer.from(signature);
  const b = Buffer.from(expected);

  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
    return res.status(401).send("Invalid signature");
  }

  return res.status(200).send("OK");
}

