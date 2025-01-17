import { strictEqual, throws } from "node:assert";
import { describe, test } from "node:test";
import JWT from "../src";
import { decode } from "../src/decode";
import { encode } from "../src/encode";

const SECRET = "your-256-bit-secret";

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
    const jwt = new JWT(SECRET, { issuer: "test" });
    strictEqual(jwt.issuer, "test", "Issuer should be test");
  });
  test("should be right payload", () => {
    const jwt = new JWT(SECRET);
    const p = jwt.buildPayload({ test: "test" });
    strictEqual(p.test, "test", "Test should be test");
  });
  test("should be right payload with static registered claims", () => {
    const jwt = new JWT(SECRET, { issuer: "test" });
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

describe("JWT integration test", () => {
  test("should be right token", () => {
    const jwt = new JWT(SECRET);
    const token = jwt.sign({
      sub: "1234567890",
      name: "John Doe",
      iat: 1516239022,
    });
    strictEqual(
      token,
      "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwiaWF0IjoxNTE2MjM5MDIyLCJuYW1lIjoiSm9obiBEb2UifQ.LWG7yvgEiiKDUA2PmykvKGKMedYPyLWsLCcJR5pn-Kw",
      "Token should be right",
    );
  });
  test("should be right payload", () => {
    const jwt = new JWT(SECRET);
    const payload = jwt.verify(
      "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
    );
    strictEqual(payload.sub, "1234567890", "Subject should be 1234567890");
    strictEqual(payload.name, "John Doe", "Name should be John Doe");
    strictEqual(payload.iat, 1516239022, "Issued at should be 1516239022");
  });
  test("should throw", () => {
    const jwt = new JWT(SECRET);
    throws(() => {
      jwt.verify(
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5d",
      );
    }, /^Error: Invalid signature/);
  });
});

describe("JWT integration test with static registered claims", () => {
  test("should be right token", () => {
    const jwt = new JWT(SECRET, {
      subject: "1234567890",
      issuedAt: 1516239022000,
    });
    const token = jwt.sign({
      name: "John Doe",
    });
    strictEqual(
      token,
      "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwiaWF0IjoxNTE2MjM5MDIyLCJuYW1lIjoiSm9obiBEb2UifQ.LWG7yvgEiiKDUA2PmykvKGKMedYPyLWsLCcJR5pn-Kw",
      "Token should be right",
    );
  });
  test("should be right payload", () => {
    const jwt = new JWT(SECRET, {
      subject: "1234567890",
      issuedAt: 1516239022000,
    });
    const payload = jwt.verify(
      "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwiaWF0IjoxNTE2MjM5MDIyLCJuYW1lIjoiSm9obiBEb2UifQ.LWG7yvgEiiKDUA2PmykvKGKMedYPyLWsLCcJR5pn-Kw",
    );
    strictEqual(payload.sub, "1234567890", "Subject should be 1234567890");
    strictEqual(payload.name, "John Doe", "Name should be John Doe");
    strictEqual(payload.iat, 1516239022, "Issued at should be 1516239022");
  });
  test("should throw expiration time", () => {
    const jwt = new JWT(SECRET, { expirationTime: 1516239022000 });
    throws(() => {
      jwt.verify(
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiZXhwIjoxNTE2MjM5MDIyfQ.E9bQ6QAil4HpH825QC5PtjNGEDQTtMpcj0SO2W8vmag",
        { currentTime: 1516239023000 },
      );
    }, /^Error: Token expired at/);
  });
});
