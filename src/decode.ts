/**
 * Decode base64 url data
 * @param data The base64 encoded data
 * @returns The decoded data
 */
export function decode<T = unknown>(data: string): T {
  return JSON.parse(Buffer.from(data, "base64url").toString());
}
