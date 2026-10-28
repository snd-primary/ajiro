// visible makes attacker-written strings safe to *look at*. Solid already
// escapes HTML when rendering text, so this is not about XSS; it is about
// characters that would lie to the reader: control codes (ANSI escapes,
// NUL, CR), bidi overrides that reorder text, and zero-width characters.
// Each one becomes a visible \x.. / \u{..} token.
const HIDDEN_SOURCE = "[\\u0000-\\u001f\\u007f-\\u009f\\u200b-\\u200f\\u2028-\\u202e\\u2060-\\u2069\\ufeff]";
const HIDDEN = new RegExp(HIDDEN_SOURCE, "g");
const HAS_HIDDEN = new RegExp(HIDDEN_SOURCE);

export function visible(s: string | null | undefined): string {
  if (s == null) return "";
  return s.replace(HIDDEN, (c) => {
    const code = c.charCodeAt(0);
    return code <= 0xff ? `\\x${code.toString(16).padStart(2, "0")}` : `\\u{${code.toString(16)}}`;
  });
}

export function hasHidden(s: string | null | undefined): boolean {
  return s != null && HAS_HIDDEN.test(s);
}
