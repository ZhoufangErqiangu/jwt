import { strictEqual, throws } from "node:assert";
import { describe, test } from "node:test";
import JWT, { JWTError } from "../src";

const SECRET = "a-string-secret-at-least-256-bits-long";

const PRIVATE_KEY = `-----BEGIN PRIVATE KEY-----
MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQC7VJTUt9Us8cKj
MzEfYyjiWA4R4/M2bS1GB4t7NXp98C3SC6dVMvDuictGeurT8jNbvJZHtCSuYEvu
NMoSfm76oqFvAp8Gy0iz5sxjZmSnXyCdPEovGhLa0VzMaQ8s+CLOyS56YyCFGeJZ
qgtzJ6GR3eqoYSW9b9UMvkBpZODSctWSNGj3P7jRFDO5VoTwCQAWbFnOjDfH5Ulg
p2PKSQnSJP3AJLQNFNe7br1XbrhV//eO+t51mIpGSDCUv3E0DDFcWDTH9cXDTTlR
ZVEiR2BwpZOOkE/Z0/BVnhZYL71oZV34bKfWjQIt6V/isSMahdsAASACp4ZTGtwi
VuNd9tybAgMBAAECggEBAKTmjaS6tkK8BlPXClTQ2vpz/N6uxDeS35mXpqasqskV
laAidgg/sWqpjXDbXr93otIMLlWsM+X0CqMDgSXKejLS2jx4GDjI1ZTXg++0AMJ8
sJ74pWzVDOfmCEQ/7wXs3+cbnXhKriO8Z036q92Qc1+N87SI38nkGa0ABH9CN83H
mQqt4fB7UdHzuIRe/me2PGhIq5ZBzj6h3BpoPGzEP+x3l9YmK8t/1cN0pqI+dQwY
dgfGjackLu/2qH80MCF7IyQaseZUOJyKrCLtSD/Iixv/hzDEUPfOCjFDgTpzf3cw
ta8+oE4wHCo1iI1/4TlPkwmXx4qSXtmw4aQPz7IDQvECgYEA8KNThCO2gsC2I9PQ
DM/8Cw0O983WCDY+oi+7JPiNAJwv5DYBqEZB1QYdj06YD16XlC/HAZMsMku1na2T
N0driwenQQWzoev3g2S7gRDoS/FCJSI3jJ+kjgtaA7Qmzlgk1TxODN+G1H91HW7t
0l7VnL27IWyYo2qRRK3jzxqUiPUCgYEAx0oQs2reBQGMVZnApD1jeq7n4MvNLcPv
t8b/eU9iUv6Y4Mj0Suo/AU8lYZXm8ubbqAlwz2VSVunD2tOplHyMUrtCtObAfVDU
AhCndKaA9gApgfb3xw1IKbuQ1u4IF1FJl3VtumfQn//LiH1B3rXhcdyo3/vIttEk
48RakUKClU8CgYEAzV7W3COOlDDcQd935DdtKBFRAPRPAlspQUnzMi5eSHMD/ISL
DY5IiQHbIH83D4bvXq0X7qQoSBSNP7Dvv3HYuqMhf0DaegrlBuJllFVVq9qPVRnK
xt1Il2HgxOBvbhOT+9in1BzA+YJ99UzC85O0Qz06A+CmtHEy4aZ2kj5hHjECgYEA
mNS4+A8Fkss8Js1RieK2LniBxMgmYml3pfVLKGnzmng7H2+cwPLhPIzIuwytXywh
2bzbsYEfYx3EoEVgMEpPhoarQnYPukrJO4gwE2o5Te6T5mJSZGlQJQj9q4ZB2Dfz
et6INsK0oG8XVGXSpQvQh3RUYekCZQkBBFcpqWpbIEsCgYAnM3DQf3FJoSnXaMhr
VBIovic5l0xFkEHskAjFTevO86Fsz1C2aSeRKSqGFoOQ0tmJzBEs1R6KqnHInicD
TQrKhArgLXX4v3CddjfTRJkFWDbE/CkvKZNOrcf1nhaGCPspRJj2KUkj1Fhl9Cnc
dn/RsYEONbwQSjIfMPkvxF+8HQ==
-----END PRIVATE KEY-----`;
const PUBLIC_KEY = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAu1SU1LfVLPHCozMxH2Mo
4lgOEePzNm0tRgeLezV6ffAt0gunVTLw7onLRnrq0/IzW7yWR7QkrmBL7jTKEn5u
+qKhbwKfBstIs+bMY2Zkp18gnTxKLxoS2tFczGkPLPgizskuemMghRniWaoLcyeh
kd3qqGElvW/VDL5AaWTg0nLVkjRo9z+40RQzuVaE8AkAFmxZzow3x+VJYKdjykkJ
0iT9wCS0DRTXu269V264Vf/3jvredZiKRkgwlL9xNAwxXFg0x/XFw005UWVRIkdg
cKWTjpBP2dPwVZ4WWC+9aGVd+Gyn1o0CLelf4rEjGoXbAAEgAqeGUxrcIlbjXfbc
mwIDAQAB
-----END PUBLIC KEY-----`;

describe("encode unit test", () => {
  test("should encode right", () => {
    const s = JWT.encode({ alg: "HS256", typ: "JWT" });
    strictEqual(
      s,
      "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
      "Encoded header should be eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
    );
  });

  test("should encode right", () => {
    const s = JWT.encode({
      sub: "1234567890",
      name: "John Doe",
      admin: true,
      iat: 1516239022,
    });
    strictEqual(
      s,
      "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0",
      "Encoded header should be eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0",
    );
  });
});

describe("decode unit test", () => {
  test("should decode right", () => {
    const d = JWT.decode<{ alg: string; typ: string }>(
      "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
    );
    strictEqual(d.alg, "HS256", "Algorithm should be `HS256`");
    strictEqual(d.typ, "JWT", "Type should be `JWT`");
  });

  test("should decode right", () => {
    const d = JWT.decode<{
      sub: string;
      name: string;
      admin: boolean;
      iat: number;
    }>(
      "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0",
    );
    strictEqual(d.sub, "1234567890", "Subject should be `1234567890`");
    strictEqual(d.name, "John Doe", "name should be `John Doe`");
    strictEqual(d.admin, true, "admin should be `true`");
    strictEqual(d.iat, 1516239022, "Issue at should be `1516239022`");
  });
});

describe("parse unit test", () => {
  test("should parse right", () => {
    const r = JWT.parse(
      "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
    );
    strictEqual(r.length, 3, "Token parts length must be 3");
    strictEqual(
      r[0],
      "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
      "Token header is not right",
    );
    strictEqual(
      r[1],
      "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ",
      "Token header is not right",
    );
    strictEqual(
      r[2],
      "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
      "Token header is not right",
    );
  });
});

describe("JWT unit test", () => {
  test("should be right algorithm", () => {
    const jwt = new JWT(SECRET);
    strictEqual(jwt.algorithm, "HS256", "Algorithm should be HS256");
  });
  test("should be right algorithm", () => {
    const jwt = new JWT(SECRET, { algorithm: "HS512" });
    strictEqual(jwt.algorithm, "HS512", "Algorithm should be HS512");
  });
  test("should be right static registered claims", () => {
    const jwt = new JWT(SECRET, { issuer: "test" });
    strictEqual(jwt.issuer, "test", "Issuer should be test");
  });
});

describe("JWT integration test HS256", () => {
  test("should be right token", () => {
    const jwt = new JWT(SECRET);
    const token = jwt.sign({
      sub: "1234567890",
      iat: 1516239022,
      name: "John Doe",
      admin: true,
    });
    strictEqual(
      token,
      "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwiaWF0IjoxNTE2MjM5MDIyLCJuYW1lIjoiSm9obiBEb2UiLCJhZG1pbiI6dHJ1ZX0._-A3B6dTUb8NrJi2SlUH_9jxmaU3plM2sxf-OyXnWiw",
      "Token should be right",
    );
  });

  test("should be right payload", () => {
    const jwt = new JWT(SECRET);
    const payload = jwt.verify(
      "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwiaWF0IjoxNTE2MjM5MDIyLCJuYW1lIjoiSm9obiBEb2UiLCJhZG1pbiI6dHJ1ZX0._-A3B6dTUb8NrJi2SlUH_9jxmaU3plM2sxf-OyXnWiw",
    );
    strictEqual(payload.sub, "1234567890", "Subject should be `1234567890`");
    strictEqual(payload.name, "John Doe", "Name should be `John Doe`");
    strictEqual(payload.admin, true, "Name should be `true`");
    strictEqual(payload.iat, 1516239022, "Issued at should be 1516239022");
  });

  test("should throw", () => {
    const jwt = new JWT(SECRET);
    throws(() => {
      jwt.verify(
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwiaWF0IjoxNTE2MjM5MDIyLCJuYW1lIjoiSm9obiBEb2UiLCJhZG1pbiI6dHJ1ZX0._-A3B6dTUb8NrJi2SlUH_9jxmaU3plM2sxf-OyXnWi",
      );
    }, JWTError);
  });
});

describe("JWT integration test RS256", () => {
  test("should be right token", () => {
    const jwt = new JWT({ privateKey: PRIVATE_KEY }, { algorithm: "RS256" });
    const token = jwt.sign({
      sub: "1234567890",
      iat: 1516239022,
      name: "John Doe",
      admin: true,
    });
    strictEqual(
      token,
      "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwiaWF0IjoxNTE2MjM5MDIyLCJuYW1lIjoiSm9obiBEb2UiLCJhZG1pbiI6dHJ1ZX0.PX5gLGkSpyBHOl3Ko5gGWhP-vqm9PnujkA0Wfg7rOFXsxG1olol7kamQmpfVo6u3bV7O-s7cOGdLpqJjv0ZD3CYbORXsHpYZzn1psIsRkSnUlS2OdP0QFTy7Ofx8HsaUO3-mG7d504kFd7BN5YM94YdpnHLsk_JM-0GqpfWA0qj8b6WKmCf86PgacaMum7f1eRdE4oSbCY8zYFH2iJC73X9xMOZYFegeuG70LEmB9OXrSbOD4hSUV7XZgTfhclyM8sFg4GdYwxvuWryEelKBfnY3vwwGNnBcQ8XJIzlG04j5-q7cUFw1uJOBLo1xiCFvRB4jf3sRD71gdJMpCsMSHQ",
      "Token should be right",
    );
  });

  test("should be right payload", () => {
    const jwt = new JWT({ publicKey: PUBLIC_KEY }, { algorithm: "RS256" });
    const payload = jwt.verify(
      "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.NHVaYe26MbtOYhSKkoKYdFVomg4i8ZJd8_-RU8VNbftc4TSMb4bXP3l3YlNWACwyXPGffz5aXHc6lty1Y2t4SWRqGteragsVdZufDn5BlnJl9pdR_kdVFUsra2rWKEofkZeIC4yWytE58sMIihvo9H1ScmmVwBcQP6XETqYd0aSHp1gOa9RdUPDvoXQ5oqygTqVtxaDr6wUFKrKItgBMzWIdNZ6y7O9E0DhEPTbE9rfBo6KTFsHAZnMg4k68CDp2woYIaXbmYTWcvbzIuHO7_37GT79XdIwkm95QJ7hYC9RiwrV7mesbY4PAahERJawntho0my942XheVLmGwLMBkQ",
    );
    strictEqual(payload.sub, "1234567890", "Subject should be `1234567890`");
    strictEqual(payload.name, "John Doe", "Name should be `John Doe`");
    strictEqual(payload.admin, true, "Name should be `true`");
    strictEqual(payload.iat, 1516239022, "Issued at should be 1516239022");
  });
});
