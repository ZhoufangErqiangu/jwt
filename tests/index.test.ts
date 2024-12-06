import assert, { strictEqual } from "node:assert";
import { describe, test } from "node:test";
import JWT from "../src";
import { decode } from "../src/decode";
import { encode } from "../src/encode";
import { now } from "../src/now";

const SECRET = "your-256-bit-secret";

describe("now unit test", () => {
  test("should be right now", () => {
    const n = now();
    const d = Date.now();
    assert(Math.abs(n - d / 1000.0) < 2, "Now should be right");
  });
});

describe("encode unit test", () => {
  test("should encode right", () => {
    const s = encode({ alg: "HS256", typ: "JWT" });
    strictEqual(
      s,
      "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
      "Encoded header should be eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
    );
  });
});

describe("decode unit test", () => {
  test("should decode right", () => {
    const d = decode<{ alg: string; typ: string }>(
      "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
    );
    strictEqual(d.alg, "HS256", "Algorithm should be HS256");
    strictEqual(d.typ, "JWT", "Type should be JWT");
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
  test("should be right header", () => {
    const jwt = new JWT(SECRET);
    const h = jwt.buildHeader();
    strictEqual(h.alg, "HS256", "Algorithm should be HS256");
    strictEqual(h.typ, "JWT", "Type should be JWT");
  });
  test("should be right static registered claims", () => {
    const jwt = new JWT(SECRET, { registeredClaims: { iss: "test" } });
    strictEqual(jwt.registeredClaims.iss, "test", "Issuer should be test");
  });
  test("should be right payload", () => {
    const jwt = new JWT(SECRET);
    const p = jwt.buildPayload({ test: "test" });
    strictEqual(p.test, "test", "Test should be test");
  });
  test("should be right payload with static registered claims", () => {
    const jwt = new JWT(SECRET, { registeredClaims: { iss: "test" } });
    const p = jwt.buildPayload({ test: "test" });
    strictEqual(p.test, "test", "Test should be test");
    strictEqual(p.iss, "test", "Issuer should be test isser");
  });
  test("should be right signature", () => {
    const jwt = new JWT(SECRET);
    const s = jwt.buildSignature(
      "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ",
    );
    strictEqual(
      s,
      "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
      "Signature should be SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
    );
  });
});
