import { createHmac } from "crypto";
import { decode } from "./decode";
import { encode } from "./encode";
import { JWTError } from "./error";
import { buildTime } from "./time";

/**
 * The key used to sign and verify the token
 *
 * If input a string, it will be used as the secret
 *
 * Secret is used for HS256, HS384, HS512
 *
 * Private key and public key are used for RS256, RS384, RS512, ES256, ES384, ES512, PS256, PS384, PS512
 */
export type JWTKey = string | { publicKey: string; privateKey: string };

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
   * If set, the token will check if the issuer is the same
   */
  issuer?: string;
  /**
   * Subject
   *
   * If set, the token will check if the subject is the same
   */
  subject?: string;
  /**
   * Audience
   *
   * If set, the token will check if the audience is the same
   */
  audience?: string;
  /**
   * Expiration time, in milliseconds
   *
   * If set, the token exp will be set to the value
   */
  expirationTime?: number;
  /**
   * Not before, in milliseconds
   *
   * If set, the token nbf will be set to the value
   */
  notBefore?: number;
  /**
   * Issued at, in milliseconds
   *
   * If set, the token iat will be set to the value
   */
  issuedAt?: number;
  /**
   * JWT ID
   *
   * If set, the token will check if the JWT ID is the same
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
   * If set, the token iss will be set to the value
   */
  issuer?: string;
  /**
   * Subject
   *
   * If set, the token sub will be set to the value
   */
  subject?: string;
  /**
   * Audience
   *
   * If set, the token aud will be set to the value
   */
  audience?: string;
  /**
   * Expiration time, in milliseconds
   *
   * If set, the token exp will be set to the value
   */
  expirationTime?: number;
  /**
   * Not before, in milliseconds
   *
   * If set, the token nbf will be set to the value
   */
  notBefore?: number;
  /**
   * Issued at, in milliseconds
   *
   * If set, the token iat will be set to the value
   */
  issuedAt?: number;
  /**
   * JWT ID
   *
   * If set, the token jti will be set to the value
   */
  jwtID?: string;
}

export interface JWTVerifyOptions {
  /**
   * Issuer
   *
   * If set, the token will check if the issuer is the same
   */
  issuer?: string;
  /**
   * Subject
   *
   * If set, the token will check if the subject is the same
   */
  subject?: string;
  /**
   * Audience
   *
   * If set, the token will check if the audience is the same
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
   * If set, the token will check if the JWT ID is the same
   */
  jwtID?: string;
}

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
  private readonly secret?: string;

  /**
   * The public key used to verify the token
   *
   * Public key is for RS256, RS384, RS512, ES256, ES384, ES512, PS256, PS384, PS512
   */
  public readonly publicKey?: string;
  /**
   * The private key used to sign the token
   *
   * Private key is for RS256, RS384, RS512, ES256, ES384, ES512, PS256, PS384, PS512
   */
  private readonly privateKey?: string;

  /**
   * The algorithm used to sign the token
   *
   * Set in header
   */
  public algorithm: JWTAlgorithm | string;

  public algorithmMap: Record<string, string> = {
    HS256: "sha256",
    HS384: "sha384",
    HS512: "sha512",
  };

  public get realAlgorithm(): string {
    const a = this.algorithmMap[this.algorithm];
    if (!a) {
      throw new JWTError(`Algorithm ${this.algorithm} is not supported`);
    }
    return a;
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
      this.secret = key;
    } else {
      this.publicKey = key.publicKey;
      this.privateKey = key.privateKey;
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
  public buildHeader(): JWTHeader {
    return {
      alg: this.algorithm,
      typ: "JWT",
    };
  }

  /**
   * @param input The payload of the token
   * @returns The payload of the token
   */
  public buildPayload(
    input: JWTPayload,
    options: JWTSignOptions = {},
  ): JWTPayload {
    const rc: JWTPayloadRegisteredClaims = {
      iss: this.issuer ?? options.issuer,
      sub: this.subject ?? options.subject,
      aud: this.audience ?? options.audience,
      exp: this.expirationTime ?? options.expirationTime,
      nbf: this.notBefore ?? options.notBefore,
      iat: this.issuedAt ?? options.issuedAt,
      jti: this.jwtID ?? options.jwtID,
    };

    if (rc.exp) {
      rc.exp = buildTime(rc.exp);
    }
    if (rc.nbf) {
      rc.nbf = buildTime(rc.nbf);
    }
    if (rc.iat) {
      rc.iat = buildTime(rc.iat);
    }

    return { ...rc, ...input };
  }

  /**
   * @param input The input to sign
   * @returns The signature of the input
   */
  public buildSignature(
    input: string,
    algorithm: string = this.algorithm,
  ): string {
    switch (algorithm) {
      case "HS256":
      case "HS384":
      case "HS512": {
        if (!this.secret) {
          throw new JWTError("Secret is required for HS256, HS384, HS512");
        }
        const hmac = createHmac(this.realAlgorithm, this.secret);
        hmac.update(input);
        return hmac.digest("base64url");
      }
      default:
        throw new JWTError(`Algorithm ${this.algorithm} is not supported`);
    }
  }

  /**
   * @param input The payload of the token
   * @returns The signed token
   */
  public sign(input: JWTPayload, options: JWTSignOptions = {}): string {
    const h = encode(this.buildHeader());
    const p = encode(this.buildPayload(input, options));

    const s1 = `${h}.${p}`;

    const s = this.buildSignature(s1);

    return `${s1}.${s}`;
  }

  /**
   * Check the header of the token
   * @param input The header of the token
   */
  public checkHeader(input: JWTHeader) {
    if (input.typ !== "JWT") {
      throw new JWTError(`Invalid type ${input.typ}`);
    }
  }

  /**
   * Check the payload of the token
   * @param input The payload of the token
   */
  public checkPayload(input: JWTPayload, options: JWTVerifyOptions = {}) {
    // check issuer
    const iss = this.issuer ?? options.issuer;
    if (iss && iss !== input.iss) {
      throw new JWTError(`Invalid issuer ${input.iss}`);
    }
    // check subject
    const sub = this.subject ?? options.subject;
    if (sub && sub !== input.sub) {
      throw new JWTError(`Invalid subject ${input.sub}`);
    }
    // check audience
    const aud = this.audience ?? options.audience;
    if (aud && aud !== input.aud) {
      throw new JWTError(`Invalid audience ${input.aud}`);
    }

    const n = buildTime(options.currentTime ?? Date.now());
    // check expiration time
    if (input.exp && input.exp < n) {
      throw new JWTError(
        `Token expired at ${new Date(input.exp * 1000).toISOString()}`,
      );
    }
    // check not before
    if (input.nbf && input.nbf > n) {
      throw new JWTError(
        `Token not before ${new Date(input.nbf * 1000).toISOString()}`,
      );
    }

    // check jwt id
    const jti = this.jwtID ?? options.jwtID;
    if (jti && jti !== input.jti) {
      throw new JWTError(`Invalid JWT ID ${input.jti}`);
    }
  }

  /**
   * Chec the signature of the input
   * @param algorithm The algorithm to use
   * @param input The input to verify
   * @param signature The signature to check
   * @returns If the signature is correct
   */
  public checkSignature(
    signature: string,
    input: string,
    algorithm: JWTAlgorithm | string,
  ) {
    const s = this.buildSignature(input, algorithm);
    if (s !== signature) {
      throw new JWTError("Invalid signature");
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
    const h = decode<JWTHeader>(header);
    this.checkHeader(h);

    // check payload
    const p = decode<T>(payload);
    this.checkPayload(p, options);

    // check signature
    const s1 = `${header}.${payload}`;
    this.checkSignature(signature, s1, h.alg);

    return p;
  }

  /**
   * Parse the token
   * @param input The token to parse
   * @returns The header, payload, and signature of the token
   */
  static parse(input: string): [string, string, string] {
    return input.split(".", 3) as [string, string, string];
  }

  /**
   * Decode header or payload
   * @param input The input to decode
   * @returns The decoded input
   */
  static decode<T>(input: string) {
    return decode<T>(input);
  }

  /**
   * Encode data
   * @param data The data to encode
   * @returns The encoded data
   */
  static encode(data: unknown): string {
    return encode(data);
  }
}

export * from "./error";

export default JWT;
