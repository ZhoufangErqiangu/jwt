import { createHmac } from "crypto";
import { decode } from "./decode";
import { encode } from "./encode";

/**
 * The algorithm used to sign the token
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
   * Registered claims
   *
   * This option will mixed with the payload
   */
  registeredClaims?: JWTPayloadRegisteredClaims;
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
   * Expiration Time
   */
  exp?: number;
  /**
   * Not Before
   */
  nbf?: number;
  /**
   * Issued At
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

  /**
   * Registered claims
   */
  public registeredClaims: JWTPayloadRegisteredClaims;

  /**
   * Create a new JWT instance
   * @param secret The secret used to sign the token
   * @param options Options for the token
   */
  constructor(
    key: string | { publicKey: string; privateKey: string },
    options: JWTOptions = {},
  ) {
    if (typeof key === "string") {
      this.secret = key;
    } else {
      this.publicKey = key.publicKey;
      this.privateKey = key.privateKey;
    }

    this.algorithm = options.algorithm || "HS256";

    this.registeredClaims = options.registeredClaims || {};
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
  public buildPayload(input: JWTPayload): JWTPayload {
    return {
      ...this.registeredClaims,
      ...input,
    };
  }

  /**
   * @param input The input to sign
   * @returns The signature of the input
   */
  public buildSignature(input: string): string {
    switch (this.algorithm) {
      case "HS256":
      case "HS384":
      case "HS512": {
        if (!this.secret) {
          throw new Error("Secret is required for HS256, HS384, HS512");
        }
        const hmac = createHmac(
          this.algorithm.replace("HS", "sha") as string,
          this.secret,
        );
        hmac.update(input);
        return hmac.digest("base64url");
      }
      default:
        throw new Error(`Algorithm ${this.algorithm} is not supported`);
    }
  }

  /**
   * @param input The payload of the token
   * @returns The signed token
   */
  public sign(input: JWTPayload): string {
    const h = encode(this.buildHeader());
    const p = encode(this.buildPayload(input));

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
      throw new Error(`Invalid type ${input.typ}`);
    }
  }

  /**
   * Check the payload of the token
   * @param input The payload of the token
   */
  public checkPayload(input: JWTPayload) {
    // check issuer
    if (this.registeredClaims.iss && this.registeredClaims.iss !== input.iss) {
      throw new Error(`Invalid issuer ${input.iss}`);
    }
    // check subject
    if (this.registeredClaims.sub && this.registeredClaims.sub !== input.sub) {
      throw new Error(`Invalid subject ${input.sub}`);
    }
    // check audience
    if (this.registeredClaims.aud && this.registeredClaims.aud !== input.aud) {
      throw new Error(`Invalid audience ${input.aud}`);
    }
    // check expiration time
    if (input.exp) {
      if (input.exp < Date.now() / 1000) {
        throw new Error(
          `Token expired at ${new Date(input.exp * 1000).toISOString()}`,
        );
      }
    }
    // check not before
    if (input.nbf) {
      if (input.nbf > Date.now() / 1000) {
        throw new Error(
          `Token not before ${new Date(input.nbf * 1000).toISOString()}`,
        );
      }
    }
    if (this.registeredClaims.iat && this.registeredClaims.iat !== input.iat) {
      throw new Error(`Invalid issued at ${input.iat}`);
    }
    // check jwt id
    if (this.registeredClaims.jti && this.registeredClaims.jti !== input.jti) {
      throw new Error(`Invalid JWT ID ${input.jti}`);
    }
  }

  /**
   * Chec the signature of the input
   * @param input The input to verify
   * @param signature The signature to check
   * @returns If the signature is correct
   */
  public checkSignature(
    algorithm: JWTAlgorithm | string,
    input: string,
    signature: string,
  ) {
    switch (algorithm) {
      case "HS256":
      case "HS384":
      case "HS512": {
        const s = this.buildSignature(input);
        if (s !== signature) {
          throw new Error("Invalid signature");
        }
        break;
      }
      default:
        throw new Error(`Algorithm ${algorithm} is not supported`);
    }
  }

  /**
   * @param input The token to verify
   * @returns The payload of the token
   */
  public verify<T extends JWTPayload = JWTPayload>(input: string): T {
    const [header, payload, signature] = input.split(".");

    // check header
    const h = decode<JWTHeader>(header);
    this.checkHeader(h);

    // check payload
    const p = decode<T>(payload);
    this.checkPayload(p);

    // check signature
    const s1 = `${header}.${payload}`;
    this.checkSignature(h.alg, s1, signature);

    return p;
  }
}

export default JWT;
