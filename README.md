# JWT

JSON Web Token

## Reference

> https://jwt.io/
>
> https://datatracker.ietf.org/doc/html/rfc7519

## How to use

```bash
npm install --save @liuhlightning/jwt
# or
yarn add @liuhlightning/jwt
```

```typescript
import JWT from "@liuhlightning/jwt";

const jwt = new JWT("your jwt secret");
```

### Sign a token

```typescript
const token = jwt.sign({ uid: 1234, username: "alex" });
```

### Verify a token and use payload

```typescript
const payload = jwt.verify("input token");
```

`verify` throws a `JWTError` subclass (e.g. `JWTErrorInvalidSignature`, `JWTErrorExpired`) when the token is not valid.

```typescript
import { JWTError } from "@liuhlightning/jwt";

try {
  const payload = jwt.verify("input token");
} catch (err) {
  if (err instanceof JWTError) {
    // invalid token
  }
}
```

## Algorithms

| Algorithm               | Key                      |
| ----------------------- | ------------------------ |
| `HS256` `HS384` `HS512` | secret (string / Buffer) |
| `RS256` `RS384` `RS512` | RSA private / public key |

The default is `HS256` for a secret, and `RS256` for a private / public key.
The `alg` in the token header must be the same as the algorithm of the instance.

### Use RSA key

```typescript
// sign and verify, the public key is derived from the private key
const signer = new JWT({ privateKey: "-----BEGIN PRIVATE KEY-----..." });
const token = signer.sign({ uid: 1234 });

// verify only
const verifier = new JWT(
  { publicKey: "-----BEGIN PUBLIC KEY-----..." },
  { algorithm: "RS256" },
);
const payload = verifier.verify(token);
```

A JWK is also supported.

```typescript
const verifier = new JWT({ publicKey: { format: "jwk", key: jwk } });
```

## Options

### Constructor

```typescript
const jwt = new JWT("your jwt secret", {
  algorithm: "HS512",
  issuer: "my-service",
});
```

| Option           | Claim | Description                                              |
| ---------------- | ----- | -------------------------------------------------------- |
| `algorithm`      |       | The algorithm used to sign and verify                    |
| `issuer`         | `iss` | Set when sign, and must be the same when verify          |
| `subject`        | `sub` | Set when sign, and must be the same when verify          |
| `audience`       | `aud` | Set when sign, and must be the same when verify          |
| `jwtID`          | `jti` | Set when sign, and must be the same when verify          |
| `expirationTime` | `exp` | Unix timestamp in seconds, set when sign                 |
| `notBefore`      | `nbf` | Unix timestamp in seconds, set when sign                 |
| `issuedAt`       | `iat` | Unix timestamp in seconds, set when sign, default is now |

`expirationTime`, `notBefore` and `issuedAt` are absolute timestamps, not durations.
To make every token expire after a period, set `exp` in the payload.

```typescript
const token = jwt.sign({ uid: 1234, exp: jwt.now + 3600 });
```

### Sign and verify

`sign(payload, options)` accepts `issuer`, `subject`, `audience`, `jwtID`, `expirationTime`, `notBefore` and `issuedAt`.

`verify(token, options)` accepts `issuer`, `subject`, `audience`, `jwtID`, and `currentTime` (in milliseconds, default is `Date.now()`).

The options of the instance take precedence over the options of `sign` / `verify`, and the claims in the payload take precedence over both when sign.
