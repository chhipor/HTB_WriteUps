# HTB Web (Easy) – Secure Notes: Writeup

> **Status:** Partial. The source review below confirms a NoSQL injection in `/update`, but I could not find a complete path from that bug to `/flag` in the provided code. Section 5 lists what is missing. The challenge description (not provided) or a live instance may close that gap.

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

## 3. Vulnerability: NoSQL operator injection in `/update`

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
2. **The whole `req.body` is used as the update document.** Mongoose's strict mode removes fields that are not in the schema, so only `title` and `content` survive. The body can still set those two fields on whichever note the filter matches.

Because `/create` validates types and `/update` does not, `/update` is the sink.

### Proof of concept (expected behavior, not yet run)

Return every note in the database:

```bash
curl -s -X POST http://localhost:1337/update \
  -H 'Content-Type: application/json' \
  -d '{"noteId": {"$ne": null}}'
```

`findByIdAndUpdate` builds the filter `{ _id: { $ne: null } }`, which matches a note. The final `Note.find({ _id: { $ne: null } })` returns the whole collection, so the response leaks every note's `_id`, `title`, and `content`.

Overwrite the content of an arbitrary note:

```bash
curl -s -X POST http://localhost:1337/update \
  -H 'Content-Type: application/json' \
  -d '{"noteId": {"$ne": null}, "content": "pwned"}'
```

Here the first note matched by the filter gets its `content` replaced. Targeting a specific note works the same way with a different operator, for example `{"$in": ["<id1>", "<id2>"]}`.

## 4. Why this is not enough for the flag

`/flag` checks the TCP peer address, not any user input. The request must come from inside the container's loopback interface.

- **Direct access is blocked.** With `docker run -p 1337:3000`, requests from the host arrive from the Docker bridge or proxy address, not `127.0.0.1`. `curl http://localhost:1337/flag` returns `403`.
- **NoSQL injection does not read the flag.** `FLAG` is an environment variable, not stored in MongoDB. Leaking notes does not reveal it.
- **Mass assignment does not help.** Strict mode drops everything except `title` and `content`. I checked this against the schema, not by running it.

## 5. What is missing

Reaching `/flag` needs a request that the server (or a process inside the container) sends to `127.0.0.1:3000`. In the code provided, I checked these and found no way to make that happen:

- **SSRF:** The server makes no outbound HTTP requests.
- **XSS:** The sinks in `index.html` (`innerHTML` for note previews) run through `escapeHtml`, and `update.html` sets only `.value`. I found no injectable path.
- **CSRF:** `express.json()` only parses `application/json`. A cross-origin page cannot send that without a CORS preflight, which this app does not allow.
- **Prototype pollution:** Possible in principle through `req.body` (`__proto__` keys), but I found no property that `/flag` reads.
- **Admin bot:** No bot or headless browser is in the repository.

If the challenge includes an admin bot that visits a URL you supply, the intended chain is probably an XSS in the notes app, or an injection that runs script in the bot's browser. The bot's browser would then request `http://127.0.0.1:3000/flag` and send the response back. That still needs a working XSS, which I did not find.

Next steps to settle it:

1. Read the challenge description for mentions of a bot or a report feature.
2. Start the Docker daemon (it was not running here), run `./build-docker.sh`, and test the PoCs above against `localhost:1337`.
3. Look at any frontend behavior that renders note data in a way I did not test in a live browser.

## 6. Verification status

- Source review: done (`app.js`, `index.html`, `update.html`, `package-lock.json`).
- Container build: not run. The Docker daemon was not running, so `./build-docker.sh` could not start.
- PoCs: not run against a live instance. They are based on Mongoose semantics and need confirmation.
