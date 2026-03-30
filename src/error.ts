/**
 * Error class for JWT
 */
export abstract class JWTError extends Error {
  constructor(message: string) {
    super(message);
  }
}

export class JWTErrorAlgorithmNotSupport extends JWTError {
  constructor(algorithm: string) {
    super(`Algorithm  \`${algorithm} \` is not supported`);
  }
}

export class JWTErrorSecretNotFound extends JWTError {
  constructor() {
    super("Secrete not found");
  }
}

export class JWTErrorPrivateKeyNotFound extends JWTError {
  constructor() {
    super("Private key not found");
  }
}

export class JWTErrorInvalidType extends JWTError {
  constructor(type: string) {
    super(`Invalid type  \`${type} \`, the \`typ\` must be \`JWT\``);
  }
}

export class JWTErrorInvalidIssuer extends JWTError {
  constructor(issuer: string | undefined, expect: string) {
    super(`Invalid issuer  \`${issuer} \`, the \`iss\` must be \`${expect}\``);
  }
}

export class JWTErrorInvalidSubject extends JWTError {
  constructor(subject: string | undefined, expect: string) {
    super(
      `Invalid subject  \`${subject} \`, the \`sub\` must be \`${expect}\``,
    );
  }
}

export class JWTErrorInvalidAudience extends JWTError {
  constructor(audience: string | undefined, expect: string) {
    super(
      `Invalid audience  \`${audience} \`, the \`aud\` must be \`${expect}\``,
    );
  }
}

export class JWTErrorExpired extends JWTError {
  constructor(expiredAt: number) {
    super(`Token expired at ${new Date(expiredAt * 1000).toISOString()}`);
  }
}

export class JWTErrorNotBefore extends JWTError {
  constructor(notBefore: number) {
    super(`Token not before ${new Date(notBefore * 1000).toISOString()}`);
  }
}

export class JWTErrorInvalidJwtId extends JWTError {
  constructor(jwtId: string | undefined, expect: string) {
    super(`Invalid jwt id  \`${jwtId} \`, the \`jti\` must be \`${expect}\``);
  }
}

export class JWTErrorInvalidSignature extends JWTError {
  constructor() {
    super("Invalid signature");
  }
}

export class JWTErrorPublicKeyNotFound extends JWTError {
  constructor() {
    super("Public key not found");
  }
}

export class JWTErrorInvalidTokenLength extends JWTError {
  constructor(len: number) {
    super(
      `Invalid token parts length \`${len}\`, the token parts length must be \`3\``,
    );
  }
}
