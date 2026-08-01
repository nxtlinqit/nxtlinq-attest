# Authorization model

This standalone Lean 4 project proves one intentionally small specification:
a protected action is permitted only when the manifest is verified, covered
artifacts are verified, and the requested capability is in the signed scope.

`Nxtlinq/Authorization.lean` proves that invalid signatures, altered artifacts,
and out-of-scope capabilities cannot authorize execution. It also proves that
permitted execution implies all three required conditions. The proofs use no
custom axioms or unsafe assumptions.

The runtime conformance vectors in
`../test/fixtures/authorization.json` correspond directly to the fields in this
model and drive the TypeScript execution tests. Lean verifies the specification;
the vectors check that the runtime follows the same decision table. This is not
a proof of the entire TypeScript implementation, identity, agent reasoning,
sandbox containment, ACP or protocol security, or blockchain guarantees.

## Build

```bash
lake build
```

Lean is the only proof authority for this model. OpenGauss is optional and may
assist contributors while authoring proofs, but it is not a dependency and
does not establish correctness. Any generated proof is accepted only after
Lean verifies it.
