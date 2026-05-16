/**
 * Shared CJK (Chinese, Japanese, Korean) detection and handling primitives.
 *
 * Scope: BMP-only Unicode ranges that cover ~99% of real CJK content:
 *   - Han (CJK Unified Ideographs): U+4E00 to U+9FFF
 *   - Hiragana: U+3040 to U+309F
 *   - Katakana: U+30A0 to U+30FF
 *   - Hangul Syllables: U+AC00 to U+D7AF
 *
 * Out of scope: Han extensions A/B/C, halfwidth katakana, compatibility
 * ideographs, compatibility Jamo, iteration marks.
 */

export const CJK_SLUG_CHARS = "一-鿿぀-ゟ゠-ヿ가-힯";

export const CJK_RANGES_REGEX = new RegExp(`[${CJK_SLUG_CHARS}]`);

export const CJK_SENTENCE_DELIMITERS = ["。", "！", "？"];
export const CJK_CLAUSE_DELIMITERS = ["；", "：", "，", "、"];

/**
 * Density threshold for switching word-count strategy. Below this CJK char
 * density, a doc is treated as Latin-mostly and stays whitespace-tokenized.
 * At or above, it is CJK-mostly.
 */
export const CJK_DENSITY_THRESHOLD = 0.3;

export function hasCJK(s: string): boolean {
  return CJK_RANGES_REGEX.test(s);
}

/**
 * CJK-aware word count. CJK languages are not whitespace-tokenized, so a
 * paragraph of Chinese would collapse to 1 word under /\S+/g and downstream
 * chunkers would never split it. The heuristic switches on CJK density.
 */
export function countCJKAwareWords(s: string): number {
  if (s.length === 0) return 0;
  const cjkMatches = s.match(new RegExp(`[${CJK_SLUG_CHARS}]`, "g"));
  const cjkCount = cjkMatches ? cjkMatches.length : 0;
  const nonWhitespace = s.replace(/\s/g, "").length;
  if (nonWhitespace === 0) return 0;
  const density = cjkCount / nonWhitespace;
  if (density >= CJK_DENSITY_THRESHOLD) {
    return nonWhitespace;
  }
  return (s.match(/\S+/g) || []).length;
}

/**
 * LIKE-pattern escape for ILIKE ... ESCAPE '\\'. Escape backslash first so
 * introduced backslashes are not double-escaped.
 */
export function escapeLikePattern(s: string): string {
  return s.replace(/\\/g, "\\\\").replace(/%/g, "\\%").replace(/_/g, "\\_");
}
