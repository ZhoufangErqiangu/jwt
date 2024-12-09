/**
 * Encode data to base64 url
 * @param data The data to encode
 * @returns The base64 encoded data
 */
export function encode(data: unknown): string {
  return Buffer.from(JSON.stringify(data)).toString("base64url");
}
