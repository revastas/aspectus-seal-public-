# Aspectus Seal

A standalone, dependency-free, deterministic **certificate seal** renderer — the verifiable trust layer for [ProofOfWhen](https://github.com/revastas/proofofwhen) certificates and part of the [Aspectus Lab](https://aspectuslab.com) hash-to-art project.

## Why this exists

An OpenTimestamps proof is trustless — anyone can verify a hash against Bitcoin without trusting a server. But the human-facing *certificate* that presents that proof still requires some trust in how it was rendered and packaged. This seal closes part of that gap: it's a **pure function of one hash**. Given the same hash, this exact file always draws the same seal, on any machine, with no network call and no hidden state. That means a seal on a certificate is an independently checkable claim, not a design decision you have to trust — anyone suspicious of a certificate can take the hash straight off it, run this file themselves, and confirm the seal matches.

## Contents

- **`aspectus-seal.js`** — the reference implementation. No dependencies, no build step. Works in the browser (`<canvas>`) or server-side (Node.js + the `canvas` npm package), and also exports an SVG renderer for print/PDF use.
- **`aspectus-seal-test-vectors.md`** — a human-readable algorithm summary plus worked examples (Genesis Block and several recent Bitcoin blocks), so a from-scratch reimplementation in another language can check itself against known-correct outputs without trusting this JS file at all.
- **`test-vectors.json`** — the same vectors in machine-readable form.

## Usage

```js
// browser
renderSeal(ctx, { hex: fileHashHex, size: 240 });

// Node.js (server-side, with the `canvas` npm package)
const { createCanvas } = require("canvas");
const canvas = createCanvas(240, 240);
renderSeal(canvas.getContext("2d"), { hex: fileHashHex, size: 240 });
const pngBuffer = canvas.toBuffer("image/png");
```

`renderSealSVG(opts)` returns a self-contained SVG string instead, for print/PDF pipelines.

## Verifying independently

Two seals "match" if and only if their `computeSealPlan()` output matches structurally (same node positions, same connections, same palette) — not if two rendered images look pixel-alike (anti-aliasing and renderer differences make pixel-diffing unreliable). See the algorithm summary in `aspectus-seal-test-vectors.md` for the exact, renderer-agnostic spec.

## License

TBD — private for now pending Aspectus Lab's formal IP/licensing decision.
