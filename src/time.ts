/**
 * Converts a time in milliseconds to seconds.
 * @param time The time in milliseconds.
 * @returns The time in seconds.
 */
export function buildTime(time: number): number {
  return Math.floor(time / 1000.0);
}

/**
 * Returns the current Unix timestamp in seconds.
 * @returns The current Unix timestamp in seconds.
 */
export function now(): number {
  return buildTime(Date.now());
}
