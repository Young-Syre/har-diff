/**
 * har-diff - diff HAR captures taken at different privilege levels and
 * generate an authorisation test plan.
 *
 * @example
 * ```ts
 * import { parseHarFile, diffCaptures, buildPlan, Redactor, renderPlan } from 'har-diff';
 *
 * const admin = await parseHarFile('admin.har', { label: 'admin' });
 * const user = await parseHarFile('user.har', { label: 'user' });
 * const diff = diffCaptures([admin, user]);
 * const plan = buildPlan([admin, user], diff);
 * const redactor = new Redactor([...admin.secrets, ...user.secrets]);
 * console.log(renderPlan(plan, 'markdown', redactor));
 * ```
 */

export { parseHar, parseHarFile, groupBySignature, walkJson } from './har.js';
export { classifyIdentifier, looksLikeCollection, placeholderFor, templatePath } from './identifiers.js';
export { extractObjects, findSequentialSlots, refsBySlot, slotKey } from './objects.js';
export { diffCaptures, objectsExclusiveToCapture } from './diff.js';
export {
  applySubstitution,
  buildPlan,
  cookieVarFor,
  currentSlotValue,
  replaceJsonLeaves,
  sanitiseBody,
  tokenVarFor,
} from './plan.js';
export {
  isSensitiveHeader,
  isSensitiveKey,
  looksLikeSecret,
  redactBodyString,
  Redactor,
  REDACTED,
  SENSITIVE_HEADERS,
  UNSAFE_WARNING,
} from './redact.js';
export { renderDiff, renderObjects, renderParse, renderPlan } from './format.js';

export type { ExtractOptions } from './objects.js';
export type { DiffOptions } from './diff.js';
export type { JsonLeaf } from './har.js';
export type { ClassifyContext, TemplateResult } from './identifiers.js';
export type * from './types.js';
