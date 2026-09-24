# The provider registry and the simulation mandate

Every provider is declared once, in `crates/day2-capabilities/src/registry.rs`, and
every provider must have a simulation. Both are enforced by the compiler.

## One declaration

```rust
Slack {
    kind: SlackChannel,
    actions: {
        SlackRead => "slack.read.v1" (read),
        SlackPost => "slack.post.v1" (write),
    },
},
```

From that table the `providers!` macro generates the `Provider`, `ResourceKind` and
`Action` enums, `Action::{kind, capability, is_write, destroys_data, provider, ALL}`,
`Provider::{kind, world, name, ALL}`, `provider_matches`, and the `READS`, `WRITES`
and `LOCAL_PROVIDER_DATABASES` lists.

Those were five parallel tables before, with nothing tying them together. A new
provider could satisfy the compiler while falling through the `matches!` that
decided whether its calls counted as writes — and a write admitted as a read is
admitted without a write budget. `resources.rs` re-exports the generated types, so
nothing outside the registry changed.

`read` or `write` is declared per action rather than inferred from the name.

There is a third mode, `destroys`, for an action that removes data
irrecoverably. It implies `write`, and `resources::authorize` refuses every
destroying action outright: nothing an application invokes destroys anything,
whatever its grant says. Declaring it in the table rather than beside it is what
stops a new destroying action defaulting into being harmless. Today
`object_store.delete.v1` is the only one. See [DELETION.md](DELETION.md).

## The mandate

`crates/day2/src/simulations.rs` binds each provider to its simulation in one
exhaustive match. Two mistakes are compile errors:

| Mistake | Result |
| --- | --- |
| Adding a provider without answering for it | `non-exhaustive patterns: Provider::X not covered` |
| Adding a provider that declares no world | `every provider must declare a world that matches its simulation` |

There is no way to answer "none". `simulation()` returns a world, not an option, so
the type has no representation for a provider without one. A `Grandfathered` answer
existed briefly while three providers still lacked simulations; all three now have
them, and the hatch was deleted rather than left empty for someone to reach for.

A further const assertion checks that the registry's declared `world:` and the
simulation bound here name the same file, so the two cannot drift into disagreeing
about where a provider commits its state.

## The world belongs to the provider

`SimulatedProvider::WORLD` is declared per provider, not per direction of travel. A
provider that both makes calls and receives them — Slack posts messages and
receives interactions about them — commits to one store. That makes
*post a message, then receive the callback referring to it* expressible in the
deterministic campaign, which two separate worlds would make impossible.

## What this does not do

It forces a simulation to **exist**. It cannot force one to be **faithful**: a
simulation that lies passes everything here, and a `todo!()` passes too.

That is the job of the gates that remain:

- **Parity suite** — one conformance suite per provider, run against the simulation
  always and against the live provider in the credential-gated lane, mirroring
  [PROVIDER-CONFORMANCE.md](PROVIDER-CONFORMANCE.md).
- **Coverage assertion** — every `Action::ALL` entry and every `AdapterError`
  variant must be exercised, so a stub cannot pass.
- **Saboteur test** — a deliberately broken simulation and a deliberately drifted
  contract, which the gate must reject. Without it the gate rots silently.

## Outstanding

Every provider now has a simulation. `Slack`, `Snowflake` and `OpenAi` — the three
admitted live-first — are served by `integrations::simulated` at the transport seam,
so the offline lane and the live lane differ only in the socket.

**One hole remains, and it is the reason the coverage gate is not optional.**
Declaring a world and binding it proves a *name* exists, not that anything serves
it. A provider can declare `world: "stripe.simulated.sqlite"` with nothing behind
it and compile — verified by adding exactly that and watching it build. Closing it
is the coverage assertion's job: every provider's world must actually be exercised.
Until then the compiler guarantees a simulation is *declared*, not that it *runs*.
