import {
  createHmac,
  createPrivateKey,
  createPublicKey,
  createSecretKey,
  createSign,
  createVerify,
  generateKeyPairSync,
  JsonWebKeyInput,
  KeyObject,
  PrivateKeyInput,
  PublicKeyInput,
} from "crypto";
import {
  JWTErrorAlgorithmNotSupport,
  JWTErrorExpired,
  JWTErrorInvalidAudience,
  JWTErrorInvalidIssuer,
  JWTErrorInvalidJwtId,
  JWTErrorInvalidSignature,
  JWTErrorInvalidSubject,
  JWTErrorInvalidTokenLength,
  JWTErrorInvalidType,
  JWTErrorNotBefore,
  JWTErrorPrivateKeyNotFound,
  JWTErrorPublicKeyNotFound,
  JWTErrorSecretNotFound,
} from "./error";

/**
 * The key used to sign and verify the token
 *
 * If input a string, it will be used as the secret
 *
 * Secret is used for HS256, HS384, HS512
 *
 * Private key and public key are used for RS256, RS384, RS512, ES256, ES384, ES512, PS256, PS384, PS512
 */
export type JWTKey = JWTKeySecret | (JWTKeyPrivateKey & JWTKeyPublicKey);

export type JWTKeySecret = string | Buffer;
export type JWTKeyPrivateKey = {
  privateKey?: PrivateKeyInput | string | Buffer | JsonWebKeyInput;
};
export type JWTKeyPublicKey = {
  publicKey?: PublicKeyInput | string | Buffer | KeyObject | JsonWebKeyInput;
};

/**
 * The algorithm used to sign the token
 *
 * HS - HMAC with SHA
 *
 * PS - RSA (RSASSA-PSS) with SHA
 *
 * RS - RSA (RSASSA-PKCS1-v1_5) with SHA
 *
 * ES - ECDSA with SHA
 */
export type JWTAlgorithm =
  | "HS256"
  | "HS384"
  | "HS512"
  | "PS256"
  | "PS384"
  | "PS512"
  | "RS256"
  | "RS384"
  | "RS512"
  | "ES256"
  | "ES256K"
  | "ES384"
  | "ES512"
  | "EdDSA";

/**
 * Options for the JWT class
 */
export interface JWTOptions {
  /**
   * The algorithm used to sign the token
   */
  algorithm?: JWTAlgorithm | string;
  /**
   * Issuer
   *
   * If set, the token `iss` will be set to this value when sign.
   *
   * If set, the token `iss` must be same value
   */
  issuer?: string;
  /**
   * Subject
   *
   * If set, the token `sub` will be set to this value when sign.
   *
   * If set, the token `sub` must be same value
   */
  subject?: string;
  /**
   * Audience
   *
   * If set, the token `aud` will be set to this value when sign.
   *
   * If set, the token `aud` must be same value
   */
  audience?: string;
  /**
   * Expiration time, in seconds
   *
   * If set, the token `exp` will be set to the value
   */
  expirationTime?: number;
  /**
   * Not before, in seconds
   *
   * If set, the token `nbf` will be set to the value
   */
  notBefore?: number;
  /**
   * Issued at, in seconds
   *
   * If set, the token `iat` will be set to the value
   */
  issuedAt?: number;
  /**
   * JWT ID
   *
   * If set, the token `jti` will be set to this value when sign.
   *
   * If set, the token `jti` must be same value
   */
  jwtID?: string;
}

export interface JWTHeader {
  typ: string;
  alg: JWTAlgorithm | string;
}

/**
 * Registered claims for a JWT
 */
export interface JWTPayloadRegisteredClaims {
  /**
   * Issuer
   */
  iss?: string;
  /**
   * Subject
   */
  sub?: string;
  /**
   * Audience
   */
  aud?: string;
  /**
   * Expiration Time, in seconds
   */
  exp?: number;
  /**
   * Not Before, in seconds
   */
  nbf?: number;
  /**
   * Issued At, in seconds
   */
  iat?: number;
  /**
   * JWT ID
   */
  jti?: string;
}

/**
 * The payload of a JWT
 *
 * If you want to use private claims, you should crypto it by yourself.
 */
export type JWTPayload = JWTPayloadRegisteredClaims & Record<string, unknown>;

export interface JWTSignOptions {
  /**
   * Issuer
   *
   * If set, the token `iss` will be set to this value when sign.
   */
  issuer?: string;
  /**
   * Subject
   *
   * If set, the token `sub` will be set to this value when sign.
   */
  subject?: string;
  /**
   * Audience
   *
   * If set, the token `aud` will be set to this value when sign.
   */
  audience?: string;
  /**
   * Expiration time, in seconds
   *
   * If set, the token `exp` will be set to the value
   */
  expirationTime?: number;
  /**
   * Not before, in seconds
   *
   * If set, the token `nbf` will be set to the value
   */
  notBefore?: number;
  /**
   * Issued at, in seconds
   *
   * If set, the token `iat` will be set to the value
   */
  issuedAt?: number;
  /**
   * JWT ID
   *
   * If set, the token `jti` will be set to this value when sign.
   */
  jwtID?: string;
}

export interface JWTVerifyOptions {
  /**
   * Issuer
   *
   * If set, the token `iss` must be same value
   */
  issuer?: string;
  /**
   * Subject
   *
   * If set, the token `sub` must be same value
   */
  subject?: string;
  /**
   * Audience
   *
   * If set, the token `aud` must be same value
   */
  audience?: string;
  /**
   * Current time, in milliseconds
   *
   * If set, the token will check if the current time is less than the expiration time
   *
   * If not set, the current time will be set to `Date.now()`
   */
  currentTime?: number;
  /**
   * JWT ID
   *
   * If set, the token `jti` must be same value
   */
  jwtID?: string;
}

const JWT_HASH_ALGORITHM_MAP: Record<
  JWTAlgorithm | string,
  string | undefined
> = {
  HS256: "sha256",
  HS384: "sha384",
  HS512: "sha512",
  RS256: "sha256",
  RS384: "sha384",
  RS512: "sha512",
};

/**
 * A class to create and verify JSON Web Tokens
 *
 * https://jwt.io/
 *
 * https://datatracker.ietf.org/doc/html/rfc7519
 */
export class JWT {
  /**
   * The secret used to sign the token
   *
   * Secret is for HS256, HS384, HS512
   */
  private readonly secret?: KeyObject;

  /**
   * The private key used to sign the token
   *
   * Private key is for RS256, RS384, RS512, ES256, ES384, ES512, PS256, PS384, PS512
   */
  private readonly privateKey?: KeyObject;
  /**
   * The public key used to verify the token
   *
   * Public key is for RS256, RS384, RS512, ES256, ES384, ES512, PS256, PS384, PS512
   */
  public readonly publicKey?: KeyObject;

  /**
   * The algorithm used to sign the token
   *
   * Set in header
   */
  public algorithm: JWTAlgorithm | string;

  /**
   * Returns the current Unix timestamp in seconds.
   * @returns The current Unix timestamp in seconds.
   */
  public get now(): number {
    return JWT.ms2s(Date.now());
  }

  public issuer?: string;
  public subject?: string;
  public audience?: string;
  public expirationTime?: number;
  public notBefore?: number;
  public issuedAt?: number;
  public jwtID?: string;

  /**
   * Create a new JWT instance
   * @param secret The secret used to sign the token
   * @param options Options for the token
   */
  constructor(key: JWTKey, options: JWTOptions = {}) {
    if (typeof key === "string") {
      this.secret = createSecretKey(key, "utf-8");
    } else if (key instanceof Buffer) {
      this.secret = createSecretKey(key);
    } else {
      const { privateKey, publicKey } = key as JWTKeyPrivateKey &
        JWTKeyPublicKey;

      if (privateKey) {
        switch (options.algorithm) {
          case "RS256":
          case "RS384":
          case "RS512":
            this.privateKey = createPrivateKey(privateKey);
            this.publicKey = createPublicKey(this.privateKey);
            break;
          case undefined:
            throw new JWTErrorAlgorithmNotSupport("undefined");
          default:
            throw new JWTErrorAlgorithmNotSupport(options.algorithm);
        }
      } else if (publicKey) {
        // only set public key
        this.publicKey = createPublicKey(publicKey);
      }
    }

    this.algorithm = options.algorithm ?? "HS256";

    this.issuer = options.issuer;
    this.subject = options.subject;
    this.audience = options.audience;
    this.expirationTime = options.expirationTime;
    this.notBefore = options.notBefore;
    this.issuedAt = options.issuedAt;
    this.jwtID = options.jwtID;
  }

  /**
   * @returns The header of the token
   */
  private buildHeader(): JWTHeader {
    return {
      alg: this.algorithm,
      typ: "JWT",
    };
  }

  private buildPayload(
    input: JWTPayload,
    options: JWTSignOptions = {},
  ): JWTPayload {
    const rc: JWTPayloadRegisteredClaims = {
      iss: this.issuer ?? options.issuer,
      sub: this.subject ?? options.subject,
      aud: this.audience ?? options.audience,
      exp: this.expirationTime ?? options.expirationTime,
      nbf: this.notBefore ?? options.notBefore,
      iat: this.issuedAt ?? options.issuedAt ?? this.now,
      jti: this.jwtID ?? options.jwtID,
    };

    return { ...rc, ...input };
  }

  private buildSignature(
    input: string,
    algorithm: JWTAlgorithm | string,
    encoding: BufferEncoding,
  ): string {
    switch (algorithm) {
      case "HS256":
      case "HS384":
      case "HS512":
        return this.buildSignatureHmac(input, algorithm, encoding);
      case "RS256":
      case "RS384":
      case "RS512":
        return this.buildSignatureSign(input, algorithm, encoding);
      default:
        throw new JWTErrorAlgorithmNotSupport(algorithm);
    }
  }

  private buildSignatureHmac(
    input: string,
    algorithm: JWTAlgorithm | string,
    encoding: BufferEncoding,
  ): string {
    if (!this.secret) throw new JWTErrorSecretNotFound();

    const hmac = createHmac(JWT.hashAlgorithm(algorithm), this.secret);
    hmac.update(input, encoding);

    return hmac.digest("base64url");
  }

  private buildSignatureSign(
    input: string,
    algorithm: JWTAlgorithm | string,
    encoding: BufferEncoding,
  ): string {
    if (!this.privateKey) throw new JWTErrorPrivateKeyNotFound();

    const sign = createSign(JWT.hashAlgorithm(algorithm));
    sign.update(input, encoding);
    sign.end();

    return sign.sign(this.privateKey, "base64url");
  }

  /**
   * @param input The payload of the token
   * @returns The signed token
   */
  public sign(input: JWTPayload, options: JWTSignOptions = {}): string {
    const h = JWT.encode(this.buildHeader());
    const p = JWT.encode(this.buildPayload(input, options));

    const hp = `${h}.${p}`;

    console.log("hp", hp);

    const s = this.buildSignature(hp, this.algorithm, "utf-8");

    return `${hp}.${s}`;
  }

  private checkHeader(input: JWTHeader) {
    if (input.typ !== "JWT") throw new JWTErrorInvalidType(input.typ);
  }

  private checkPayload(input: JWTPayload, options: JWTVerifyOptions = {}) {
    // check issuer
    const iss = this.issuer ?? options.issuer;
    if (iss && iss !== input.iss) {
      throw new JWTErrorInvalidIssuer(input.iss, iss);
    }

    // check subject
    const sub = this.subject ?? options.subject;
    if (sub && sub !== input.sub) {
      throw new JWTErrorInvalidSubject(input.sub, sub);
    }
    // check audience
    const aud = this.audience ?? options.audience;
    if (aud && aud !== input.aud) {
      throw new JWTErrorInvalidAudience(input.aud, aud);
    }

    const n = JWT.ms2s(options.currentTime ?? Date.now());
    // check expiration time
    if (input.exp && input.exp < n) {
      throw new JWTErrorExpired(input.exp);
    }
    // check not before
    if (input.nbf && input.nbf > n) {
      throw new JWTErrorNotBefore(input.nbf);
    }

    // check jwt id
    const jti = this.jwtID ?? options.jwtID;
    if (jti && jti !== input.jti) {
      throw new JWTErrorInvalidJwtId(input.jti, jti);
    }
  }

  private checkSignature(
    signature: string,
    input: string,
    algorithm: JWTAlgorithm | string,
    encoding: BufferEncoding = "utf-8",
  ) {
    switch (this.algorithm) {
      case "HS256":
      case "HS384":
      case "HS512":
        return this.checkSignatureHmac(signature, input, algorithm, encoding);
      case "RS256":
      case "RS384":
      case "RS512":
        return this.checkSignatureVerify(signature, input, algorithm, encoding);
      default:
        throw new JWTErrorAlgorithmNotSupport(algorithm);
    }
  }

  private checkSignatureHmac(
    signature: string,
    input: string,
    algorithm: JWTAlgorithm | string,
    encoding: BufferEncoding = "utf-8",
  ) {
    const s = this.buildSignature(input, algorithm, encoding);
    if (s !== signature) {
      throw new JWTErrorInvalidSignature();
    }
  }

  private checkSignatureVerify(
    signature: string,
    input: string,
    algorithm: JWTAlgorithm | string,
    encoding: BufferEncoding = "utf-8",
  ) {
    if (!this.publicKey) {
      throw new JWTErrorPublicKeyNotFound();
    }

    const verify = createVerify(JWT.hashAlgorithm(algorithm));
    verify.update(input, encoding);
    verify.end();

    if (!verify.verify(this.publicKey, signature, "base64url")) {
      throw new JWTErrorInvalidSignature();
    }
  }

  /**
   * @param input The token to verify
   * @returns The payload of the token
   */
  public verify<T extends JWTPayload = JWTPayload>(
    input: string,
    options: JWTVerifyOptions = {},
  ): T {
    const [header, payload, signature] = JWT.parse(input);

    // check header
    const h = JWT.decode<JWTHeader>(header);
    this.checkHeader(h);

    // check payload
    const p = JWT.decode<T>(payload);
    this.checkPayload(p, options);

    // check signature
    const hp = `${header}.${payload}`;
    this.checkSignature(signature, hp, h.alg);

    return p;
  }

  /**
   * Read hash algorithm
   * @param algorithm jwt algorithm
   * @returns hash algorithm
   */
  public static hashAlgorithm(algorithm: JWTAlgorithm | string): string {
    const a = JWT_HASH_ALGORITHM_MAP[algorithm];
    if (!a) {
      throw new JWTErrorAlgorithmNotSupport(algorithm);
    }
    return a;
  }

  /**
   * Decode base64 url data
   * @param data The base64 encoded data
   * @returns The decoded data
   */
  public static decode<T = unknown>(
    data: string,
    encoding: BufferEncoding = "utf-8",
  ): T {
    return JSON.parse(Buffer.from(data, "base64url").toString(encoding));
  }

  /**
   * Encode data to base64 url
   * @param data The data to encode
   * @returns The base64 encoded data
   */
  public static encode(
    data: unknown,
    encoding: BufferEncoding = "utf-8",
  ): string {
    return Buffer.from(JSON.stringify(data), encoding).toString("base64url");
  }

  /**
   * Parse the token
   * @param input The token to parse
   * @returns The header, payload, and signature of the token
   */
  public static parse(input: string): [string, string, string] {
    const r = input.split(".", 3);
    if (r.length !== 3) {
      throw new JWTErrorInvalidTokenLength(r.length);
    }

    return r as [string, string, string];
  }

  /**
   * Converts a time in milliseconds to seconds.
   * @param ms The time in milliseconds.
   * @returns The time in seconds.
   */
  public static ms2s(ms: number): number {
    return Math.floor(ms / 1000.0);
  }
}

export * from "./error";

export default JWT;
