/** Same rule as VARIABLE_NAME in validate.ts; kept here so the parser has no import cycle. */
const NAME = /^[A-Za-z_][A-Za-z0-9_]{0,127}$/;
const SAFE_MODIFIER = /^[A-Za-z0-9_-]{1,20}$/;
export const MAX_TEMPLATE_LENGTH = 2000;

export type TemplatePart = { literal: string } | { ref: string; url: boolean };

export class TemplateSyntaxError extends Error {}

/**
 * Parses `${NAME}` (raw), `${NAME:url}` (percent-encoded) and `$${` (a literal `${`).
 * Any other text, including a lone `$`, is literal.
 */
export function parseTemplate(text: string): TemplatePart[] {
  const parts: TemplatePart[] = [];
  let literal = "";
  let i = 0;
  while (i < text.length) {
    if (text.startsWith("$${", i)) {
      literal += "${";
      i += 3;
      continue;
    }
    if (!text.startsWith("${", i)) {
      literal += text[i];
      i++;
      continue;
    }
    const end = text.indexOf("}", i + 2);
    if (end === -1) throw new TemplateSyntaxError(`unclosed \${ at position ${i}; write $\${ for a literal \${`);
    const inner = text.slice(i + 2, end);
    const colon = inner.indexOf(":");
    const name = colon === -1 ? inner : inner.slice(0, colon);
    const modifier = colon === -1 ? undefined : inner.slice(colon + 1);
    if (!NAME.test(name)) throw new TemplateSyntaxError(`invalid variable name in \${...} at position ${i}`);
    if (modifier !== undefined && modifier !== "url") {
      throw new TemplateSyntaxError(
        SAFE_MODIFIER.test(modifier) ? `unknown modifier "${modifier}" (only :url)` : "unknown modifier (only :url)",
      );
    }
    if (literal) parts.push({ literal });
    literal = "";
    parts.push({ ref: name, url: modifier === "url" });
    i = end + 1;
  }
  if (literal) parts.push({ literal });
  return parts;
}

/** Referenced variable names, each once, in order of first appearance. */
export function templateRefs(parts: TemplatePart[]): string[] {
  const refs: string[] = [];
  for (const part of parts) if ("ref" in part && !refs.includes(part.ref)) refs.push(part.ref);
  return refs;
}
