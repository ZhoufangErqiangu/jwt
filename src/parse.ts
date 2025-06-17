import { JWTError } from "./error";

/**
 * Parse the token
 * @param input The token to parse
 * @returns The header, payload, and signature of the token
 */
export function parse(input: string): [string, string, string] {
  const r = input.split(".", 3);
  if (r.length !== 3) throw new JWTError(`Token parts is not 3 ${input}`);
  return r as [string, string, string];
}
