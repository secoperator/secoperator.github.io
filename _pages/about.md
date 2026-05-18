---
layout: about
title: about
permalink: /
subtitle: <strong>Vulnerability research</strong> · browser internals · exploit development

profile:
  align: right
  image: prof_pic.jpg
  image_circular: false
  more_info: >
    <p>Notes from the trenches of</p>
    <p>JavaScript engine internals,</p>
    <p>memory corruption & sandboxing.</p>

selected_papers: false
social: true

announcements:
  enabled: false
  scrollable: true
  limit: 5

latest_posts:
  enabled: true
  scrollable: true
  limit: 3
---

This site is a public lab notebook on **offensive security research**, with a heavy bias toward what runs JavaScript in your browser: **V8**, its sandbox, its trust boundaries and the tooling around it.

You will find notes on:

- **JIT compilers and runtime internals** — TurboFan, Maglev, Sparkplug, deoptimization, speculative optimization bugs.
- **Modern memory models** — the V8 heap cage, pointer compression, the trusted space and the V8 sandbox attacker model.
- **Lab tooling** — building `d8` from source, useful runtime flags, tracing optimization, capturing logs and reproducers.
- **Exploit primitives** — addrof / fakeobj, arbitrary read/write, sandbox escapes via WebAssembly, JIT spraying, and renderer → broker pivots.
- **Fuzzing infrastructure** — coverage-guided JS fuzzers, grammar-based generation, differential testing.

Everything here is intended for **defensive research, CTF play and educational purposes**. Pointers to upstream commits, CVE writeups and trusted external references are preferred over hand-waving.
