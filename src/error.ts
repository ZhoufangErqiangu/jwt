/**
 * Error class for JWT
 */
export class JWTError extends Error {
  constructor(message: string) {
    super(message);
  }
}
