/**
 * Returns the current Unix timestamp in seconds.
 * @returns The current Unix timestamp in seconds.
 */
export function now(): number {
  return Math.floor(Date.now() / 1000.0);
}
