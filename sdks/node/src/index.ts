/**
 * aegis-webhooks — verify Aegis webhook signatures.
 *
 * @example
 * ```typescript
 * import { verifySignature, AegisWebhookError } from "@aegis/webhooks";
 *
 * app.post("/webhook", express.raw({ type: "*\/*" }), (req, res) => {
 *   try {
 *     verifySignature(req.body, process.env.WEBHOOK_SECRET!, req.headers);
 *   } catch (err) {
 *     if (err instanceof AegisWebhookError) return res.sendStatus(400);
 *     throw err;
 *   }
 *   // handle req.body ...
 *   res.sendStatus(200);
 * });
 * ```
 */
export {
  verifySignature,
  AegisWebhookError,
  InvalidTimestampError,
  InvalidSignatureError,
} from "./verify.js";
export type { VerifyOptions } from "./verify.js";
