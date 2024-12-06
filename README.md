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
