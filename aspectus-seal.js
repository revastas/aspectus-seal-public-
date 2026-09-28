/*
 * Aspectus Lab — Certificate Seal Renderer
 * ------------------------------------------------------------------
 * A standalone, dependency-free port of the same deterministic
 * hash-to-art engine behind "One Block, One Piece" and "Block in
 * Block" (claude.ai artifacts), sized down and simplified into a
 * "seal": a compact mark meant to sit on a document — a ProofOfWhen
 * certificate, in particular — rather than fill a full canvas.
 *
 * WHY THIS FILE EXISTS (the trust story):
 * A OpenTimestamps proof is trustless — anyone can verify a hash
 * against Bitcoin without trusting ProofOfWhen's servers. But the
 * human-facing CERTIFICATE that presents that proof still requires
 * some trust in how it was rendered and packaged (Hop 4). This seal
 * closes part of that gap: it is a PURE function of one hash. Given
 * the same hash, this exact file always draws the same seal, on any
 * machine, with no network call and no hidden state. That means a
 * seal on a certificate is an independently checkable claim, not a
 * design decision to trust — anyone suspicious of a certificate can
 * take the hash straight off it, run this file themselves, and
 * confirm the seal matches.
 *
 * WHAT DRIVES THE SEAL:
 * Pass the FILE's own hash (the thing actually being proven) as the
 * primary seal — unique per document, so two certificates for two
 * different files visibly differ at a glance. The Bitcoin block hash
 * the proof anchors into can optionally drive a secondary/border
 * accent (see `blockHex` below) — same block, same accent, across
 * every certificate anchored in it, more like a wax-seal "minted in
 * this era" mark than a per-document fingerprint.
 *
 * WHY A SEAL LOOKS DIFFERENT FROM THE FULL PIECES:
 * "One Block, One Piece" draws every connection in its candidate
 * edge list (hundreds, for density and richness at full canvas
 * size). At certificate-seal size (a few hundred px, often smaller
 * once printed), that same density reads as mud. This renderer draws
 * only the first `sealConnCount` connections of the SAME edge list
 * the full piece would draw — an ordered PREFIX, the identical
 * technique "Block in Block" already uses to relate its own tube
 * count back to the 2D piece's full chord count. So a seal isn't a
 * different picture invented for this purpose; it's a legible,
 * sparser crop of the exact same deterministic geometry.
 *
 * USAGE — browser (an HTML5 canvas 2D context):
 *   renderSeal(ctx, { hex: fileHashHex, size: 240 });
 *
 * USAGE — Node.js server-side (with the `canvas` npm package):
 *   const { createCanvas } = require("canvas");
 *   const canvas = createCanvas(240, 240);
 *   renderSeal(canvas.getContext("2d"), { hex: fileHashHex, size: 240 });
 *   const pngBuffer = canvas.toBuffer("image/png");
 *
 * Both work because this file only ever touches the standard
 * CanvasRenderingContext2D surface (arc, moveTo, quadraticCurveTo,
 * fillRect, etc.) — no DOM, no `window`, no browser-only API.
 *
 * This file has no dependencies and no build step. Copy it into the
 * ProofOfWhen codebase as-is (or npm-package it later if it should
 * be shared/published independently so third parties can verify
 * seals without needing the rest of either project).
 * ------------------------------------------------------------------
 */

(function (root, factory) {
  "use strict";
  if (typeof module === "object" && module.exports) {
    module.exports = factory();
  } else {
    root.AspectusSeal = factory();
  }
})(typeof self !== "undefined" ? self : this, function () {
  "use strict";

  // ---- seeded PRNG (identical to both published Aspectus Lab pieces) ----
  function mulberry32(seed) {
    return function () {
      seed |= 0; seed = (seed + 0x6D2B79F5) | 0;
      var t = Math.imul(seed ^ (seed >>> 15), 1 | seed);
      t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
      return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
    };
  }

  function hexByte(hex, byteIndex) {
    var i = byteIndex * 2;
    var v = parseInt(hex.substr(i, 2), 16);
    return isNaN(v) ? 0 : v;
  }

  // ---- real SHA-256 (same implementation as both published pieces) ----
  function sha256(bytes) {
    var K = [
      0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
      0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
      0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
      0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
      0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
      0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
      0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
      0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
    ];
    var H = [0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19];
    var len = bytes.length;
    var msg = bytes.concat([0x80]);
    while ((msg.length % 64) !== 56) msg.push(0);
    var bitLenHi = Math.floor(len / 0x20000000);
    var bitLenLo = (len * 8) >>> 0;
    msg.push((bitLenHi >>> 24) & 0xff, (bitLenHi >>> 16) & 0xff, (bitLenHi >>> 8) & 0xff, bitLenHi & 0xff);
    msg.push((bitLenLo >>> 24) & 0xff, (bitLenLo >>> 16) & 0xff, (bitLenLo >>> 8) & 0xff, bitLenLo & 0xff);
    function rotr(x, n) { return (x >>> n) | (x << (32 - n)); }
    for (var chunk = 0; chunk < msg.length; chunk += 64) {
      var w = new Array(64), i;
      for (i = 0; i < 16; i++) {
        var o = chunk + i * 4;
        w[i] = ((msg[o] << 24) | (msg[o + 1] << 16) | (msg[o + 2] << 8) | msg[o + 3]) >>> 0;
      }
      for (i = 16; i < 64; i++) {
        var s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >>> 3);
        var s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >>> 10);
        w[i] = (w[i - 16] + s0 + w[i - 7] + s1) >>> 0;
      }
      var a = H[0], b = H[1], c = H[2], d = H[3], e = H[4], f = H[5], g = H[6], h = H[7];
      for (i = 0; i < 64; i++) {
        var S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
        var ch = (e & f) ^ (~e & g);
        var temp1 = (h + S1 + ch + K[i] + w[i]) >>> 0;
        var S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
        var maj = (a & b) ^ (a & c) ^ (b & c);
        var temp2 = (S0 + maj) >>> 0;
        h = g; g = f; f = e; e = (d + temp1) >>> 0;
        d = c; c = b; b = a; a = (temp1 + temp2) >>> 0;
      }
      H[0] = (H[0] + a) >>> 0; H[1] = (H[1] + b) >>> 0; H[2] = (H[2] + c) >>> 0; H[3] = (H[3] + d) >>> 0;
      H[4] = (H[4] + e) >>> 0; H[5] = (H[5] + f) >>> 0; H[6] = (H[6] + g) >>> 0; H[7] = (H[7] + h) >>> 0;
    }
    return H;
  }

  function hexToBytes(hex) {
    var bytes = [];
    for (var i = 0; i + 1 < hex.length; i += 2) bytes.push(hexByte(hex, i / 2));
    return bytes;
  }

  function sha256WordsToHex(H) {
    var out = "";
    for (var i = 0; i < 8; i++) {
      var word = (H[i] >>> 0).toString(16);
      while (word.length < 8) word = "0" + word;
      out += word;
    }
    return out;
  }

  function sha256HexOfHash(hex) { return sha256WordsToHex(sha256(hexToBytes(hex))); }
  function seedFromHash(hex) { return parseInt(sha256HexOfHash(hex).substr(0, 8), 16) >>> 0; }

  // ---- palette (identical to both published pieces) ----
  var PALETTE_START_BYTE = 6;

  function paletteFromHash(hex) {
    var count = 2 + (hexByte(hex, PALETTE_START_BYTE) % 5); // 2-6 stops
    var slot = 360 / count;
    var jitterSpan = slot * 0.5;
    var startHue = ((hexByte(hex, PALETTE_START_BYTE + 1) << 8) | hexByte(hex, PALETTE_START_BYTE + 2)) % 360;
    var hues = [];
    for (var i = 0; i < count; i++) {
      var off = PALETTE_START_BYTE + 3 + i * 2;
      var jitterRaw = ((hexByte(hex, off) << 8) | hexByte(hex, off + 1)) % 1000;
      var jitter = (jitterRaw / 999 - 0.5) * jitterSpan;
      hues.push((startHue + i * slot + jitter + 360) % 360);
    }
    var sweepByte = hexByte(hex, PALETTE_START_BYTE + 3 + count * 2);
    var sweepTurns = 0.5 + (sweepByte / 255) * 2.5;
    return { hues: hues, count: count, sweepTurns: sweepTurns };
  }

  function lerpHueShort(a, b, t) {
    var diff = ((b - a + 540) % 360) - 180;
    return (a + diff * t + 360) % 360;
  }

  function paletteHueAtDepth(palette, depth) {
    var hues = palette.hues, n = hues.length;
    if (n === 1) return hues[0];
    var p = depth * palette.sweepTurns * n;
    var i = Math.floor(p) % n;
    if (i < 0) i += n;
    var next = (i + 1) % n;
    var t = p - Math.floor(p);
    return lerpHueShort(hues[i], hues[next], t);
  }

  // ---- the shared geometry engine (identical logic to both published
  // pieces' buildGeometry3 — same node positions, same candidate edge
  // list, for a given hash) ----
  var GEOMETRY_EXTENT = 0.85;

  function buildGeometry3(hex, meta) {
    meta = meta || {};
    var rand = mulberry32(seedFromHash(hex));
    var hashOfHashHex = sha256HexOfHash(hex);
    var palette = paletteFromHash(hashOfHashHex);

    var baseCount;
    if (meta.isGenesis) {
      baseCount = 2;
    } else {
      var b1 = hexByte(hashOfHashHex, 4), b2 = hexByte(hashOfHashHex, 5);
      var normalized = ((b1 << 8) | b2) / 0xffff;
      baseCount = Math.max(2, Math.min(220, Math.round(2 + normalized * 218)));
    }
    var minNodes = baseCount;
    var spreadN = Math.max(1, Math.round(baseCount * 0.25));
    var density = Math.max(1, Math.round(baseCount * 2.4));
    var sparse = density <= 8;
    var nodeCount = minNodes + Math.floor(rand() * spreadN);

    var extent = GEOMETRY_EXTENT;
    var nodes = [];
    for (var i = 0; i < nodeCount; i++) {
      nodes.push({
        x: (rand() * 2 - 1) * extent,
        y: (rand() * 2 - 1) * extent,
        z: (rand() * 2 - 1) * extent
      });
    }

    var edges = [];
    for (var c = 0; c < density; c++) {
      edges.push({ a: Math.floor(rand() * nodeCount), b: Math.floor(rand() * nodeCount) });
    }

    return { palette: palette, nodes: nodes, edges: edges, nodeCount: nodeCount, density: density, sparse: sparse, extent: extent };
  }

  // ---- the seal plan ----
  //
  // computeSealPlan() is the ONE place that turns a hash into "what to
  // draw" — every concrete color, coordinate, radius and stroke width a
  // seal is made of, with no canvas or SVG calls in it at all. Both
  // renderSeal() (canvas) and renderSealSVG() (SVG string) below call
  // this and then just paint the plan in their own API — they cannot
  // drift apart from each other, because neither one contains any of the
  // actual geometry/color decisions itself. This function is also the
  // right one to point at if you want a third renderer (a PDF library, a
  // print pipeline, a from-scratch reimplementation to check this one
  // against) — its output is the full, unambiguous spec of a seal.
  //
  // VERIFICATION CONTRACT: two seals "match" iff their computeSealPlan()
  // output matches (structurally equal node/connection/ring data) — NOT
  // iff two rendered images look alike. Diffing rendered pixels or SVG
  // markup bytes invites false mismatches from anti-aliasing and
  // renderer differences between a server and a browser; the plan is the
  // renderer-agnostic ground truth and is what any "recompute & compare"
  // check should actually diff. (For a from-scratch reimplementation
  // that doesn't share this code at all, use the test vectors in
  // aspectus-seal-test-vectors.md instead — matching hex/nodeCount/
  // edgeCount/palette numbers is the equivalent bar.)
  //
  // A seal is a deliberately sparser crop of the full-piece geometry:
  // only the first `maxConnections` edges of the candidate list are
  // drawn (an ordered prefix — the same technique "Block in Block" uses
  // for its own tube count), plus every node. Defaults are tuned to stay
  // legible from ~120px up through print size.
  function computeSealPlan(opts) {
    opts = opts || {};
    var hex = opts.hex;
    if (!hex || hex.length < 8) throw new Error("AspectusSeal: opts.hex (a hex string) is required");

    var size = opts.size || 240;
    var isGenesis = !!opts.isGenesis;
    var background = opts.background !== undefined ? opts.background : "#05070a";
    var maxConnections = opts.maxConnections || 60;
    var circleClip = opts.circleClip !== false; // default true: a coin/wax-seal silhouette
    var ringHex = opts.blockHex || null; // optional: a thin outer ring driven by a second hash (e.g. the anchoring block)

    var geo = buildGeometry3(hex, { isGenesis: isGenesis });
    var palette = geo.palette;
    var extent = geo.extent;

    var cx = size / 2, cy = size / 2;
    var margin = size * 0.12;
    var half = (size - margin * 2) / 2;

    // project the shared 3D node positions into 2D seal space (x,y for
    // position, z reused as a subtle depth cue — same approach the 2D
    // piece uses)
    var nodes = geo.nodes.map(function (p) {
      return {
        x: cx + (p.x / extent) * half,
        y: cy + (p.y / extent) * half,
        z: p.z / extent
      };
    });

    var connCount = Math.min(maxConnections, geo.edges.length);
    var nodeRadius = geo.sparse ? size * 0.018 : size * 0.008;

    var connections = [];
    for (var c = 0; c < connCount; c++) {
      var e = geo.edges[c];
      if (e.a === e.b) continue;
      var na = nodes[e.a], nb = nodes[e.b];
      var mx = (na.x + nb.x) / 2 + (cx - (na.x + nb.x) / 2) * 0.14;
      var my = (na.y + nb.y) / 2 + (cy - (na.y + nb.y) / 2) * 0.14;

      var depth = c / connCount;
      connections.push({
        ax: na.x, ay: na.y, bx: nb.x, by: nb.y, mx: mx, my: my,
        hue: paletteHueAtDepth(palette, depth),
        sat: 62,
        light: 42 + depth * 24,
        alpha: 0.28 + depth * 0.5,
        width: Math.max(0.6, size * 0.0022) * (0.6 + depth * 1.1)
      });
    }

    var nodeDots = nodes.map(function (n, i) {
      var depthBoost = 1 + n.z * 0.35;
      return {
        x: n.x, y: n.y,
        r: nodeRadius * Math.max(0.55, depthBoost),
        hue: paletteHueAtDepth(palette, nodes.length <= 1 ? 0 : i / (nodes.length - 1)),
        sat: 55,
        light: 66,
        alpha: Math.min(1, 0.55 * Math.max(0.65, depthBoost))
      };
    });

    var ring = null;
    if (ringHex) {
      var ringPalette = paletteFromHash(sha256HexOfHash(ringHex));
      ring = {
        cx: cx, cy: cy,
        r: size / 2 - size * 0.02,
        hue: ringPalette.hues[0],
        sat: 55, light: 60, alpha: 0.75,
        width: size * 0.02
      };
    }

    return {
      hex: hex,
      blockHex: ringHex,
      size: size,
      background: background,
      circleClip: circleClip,
      nodeCount: geo.nodeCount,
      connectionsDrawn: connections.length,
      connectionsAvailable: geo.edges.length,
      palette: palette.hues.slice(),
      nodes: nodeDots,
      connections: connections,
      ring: ring
    };
  }

  function hsla(hue, sat, light, alpha) {
    return "hsla(" + hue + "," + sat + "%," + light + "%," + alpha + ")";
  }

  // ---- canvas renderer ----
  // Draws a seal into any standard CanvasRenderingContext2D (browser
  // <canvas>, or node-canvas server-side). Returns the same summary
  // object computeSealPlan() produces, minus the raw draw instructions,
  // so callers can log/display node & connection counts without needing
  // the plan itself.
  function renderSeal(ctx, opts) {
    var plan = computeSealPlan(opts);

    ctx.save();
    ctx.clearRect(0, 0, plan.size, plan.size);

    if (plan.circleClip) {
      ctx.beginPath();
      ctx.arc(plan.size / 2, plan.size / 2, plan.size / 2, 0, Math.PI * 2);
      ctx.clip();
    }

    if (plan.background) {
      ctx.fillStyle = plan.background;
      ctx.fillRect(0, 0, plan.size, plan.size);
    }

    // connections first, so nodes sit on top and read clearly
    plan.connections.forEach(function (l) {
      ctx.beginPath();
      ctx.moveTo(l.ax, l.ay);
      ctx.quadraticCurveTo(l.mx, l.my, l.bx, l.by);
      ctx.strokeStyle = hsla(l.hue, l.sat, l.light, l.alpha);
      ctx.lineWidth = l.width;
      ctx.stroke();
    });

    plan.nodes.forEach(function (n) {
      ctx.beginPath();
      ctx.arc(n.x, n.y, n.r, 0, Math.PI * 2);
      ctx.fillStyle = hsla(n.hue, n.sat, n.light, n.alpha);
      ctx.fill();
    });

    if (plan.ring) {
      var r = plan.ring;
      ctx.beginPath();
      ctx.arc(r.cx, r.cy, r.r, 0, Math.PI * 2);
      ctx.strokeStyle = hsla(r.hue, r.sat, r.light, r.alpha);
      ctx.lineWidth = r.width;
      ctx.stroke();
    }

    ctx.restore();

    return {
      hex: plan.hex,
      nodeCount: plan.nodeCount,
      connectionsDrawn: plan.connectionsDrawn,
      connectionsAvailable: plan.connectionsAvailable,
      palette: plan.palette
    };
  }

  // ---- SVG renderer ----
  // Returns a self-contained SVG document string — no canvas, no DOM, no
  // node-canvas dependency. Works identically in the browser or in plain
  // Node.js (`fs.writeFileSync("seal.svg", AspectusSeal.renderSealSVG(...))`),
  // and is the right format for the certificate PDF (crisp at any print
  // size, and its path/circle data can be diffed programmatically against
  // an independently-regenerated seal — see the header comment for why
  // that matters for the Hop-4 trust story).
  function svgEscape(s) {
    return String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
  }

  function renderSealSVG(opts) {
    var plan = computeSealPlan(opts);
    var parts = [];

    parts.push(
      '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ' + plan.size + ' ' + plan.size + '" ' +
      'width="' + plan.size + '" height="' + plan.size + '" role="img" ' +
      'aria-label="Aspectus seal for hash ' + svgEscape(plan.hex) + '">'
    );

    if (plan.circleClip) {
      var clipId = "aspectus-seal-clip";
      parts.push('<clipPath id="' + clipId + '"><circle cx="' + plan.size / 2 + '" cy="' + plan.size / 2 + '" r="' + plan.size / 2 + '"/></clipPath>');
      parts.push('<g clip-path="url(#' + clipId + ')">');
    } else {
      parts.push('<g>');
    }

    if (plan.background) {
      parts.push('<rect x="0" y="0" width="' + plan.size + '" height="' + plan.size + '" fill="' + plan.background + '"/>');
    }

    plan.connections.forEach(function (l) {
      parts.push(
        '<path d="M ' + l.ax.toFixed(2) + ' ' + l.ay.toFixed(2) +
        ' Q ' + l.mx.toFixed(2) + ' ' + l.my.toFixed(2) + ' ' + l.bx.toFixed(2) + ' ' + l.by.toFixed(2) + '" ' +
        'fill="none" stroke="' + hsla(l.hue, l.sat, l.light, l.alpha) + '" stroke-width="' + l.width.toFixed(3) + '"/>'
      );
    });

    plan.nodes.forEach(function (n) {
      parts.push(
        '<circle cx="' + n.x.toFixed(2) + '" cy="' + n.y.toFixed(2) + '" r="' + n.r.toFixed(3) + '" ' +
        'fill="' + hsla(n.hue, n.sat, n.light, n.alpha) + '"/>'
      );
    });

    if (plan.ring) {
      var r = plan.ring;
      parts.push(
        '<circle cx="' + r.cx + '" cy="' + r.cy + '" r="' + r.r.toFixed(3) + '" fill="none" ' +
        'stroke="' + hsla(r.hue, r.sat, r.light, r.alpha) + '" stroke-width="' + r.width.toFixed(3) + '"/>'
      );
    }

    parts.push('</g></svg>');
    return parts.join("");
  }

  // ---- personal sigils ----
  //
  // A seal answers "what was proven, when" (per-document, or per-block via
  // the ring). A sigil answers a different question: "who submitted it" —
  // one mark per ACCOUNT, reused across every certificate that account
  // produces. That reuse is the whole point of a sigil (a recognizable
  // personal mark, the way a signature looks the same across documents)
  // but it is also a linkability feature: anyone who sees two
  // certificates with the same sigil can tell they came from the same
  // person, even if the documents are unrelated. Treat sigils as opt-in,
  // never derived from raw PII (email, username) — derive them from a
  // public key or an opaque account id, so nobody can compute a person's
  // sigil just by guessing their email. See aspectus-lab-x-proofofwhen.md
  // for the fuller discussion; this is the rendering half only.
  //
  // Sigils intentionally do NOT reuse buildGeometry3's node/edge counts
  // (tuned for a full piece or a certificate seal, up to 220+ nodes) —
  // a personal mark has to read clearly at avatar sizes (a dashboard row,
  // a list of past submissions), so this generator is tuned separately:
  // far fewer nodes, every edge drawn (no prefix-cropping needed, there
  // isn't enough of a list to crop), bolder strokes.
  function computeSigilGeometry(hex) {
    var rand = mulberry32(seedFromHash(hex));
    var hashOfHashHex = sha256HexOfHash(hex);
    var palette = paletteFromHash(hashOfHashHex);

    var b1 = hexByte(hashOfHashHex, 4), b2 = hexByte(hashOfHashHex, 5);
    var normalized = ((b1 << 8) | b2) / 0xffff;
    var nodeCount = Math.max(6, Math.min(16, Math.round(6 + normalized * 10)));

    var extent = GEOMETRY_EXTENT;
    var nodes = [];
    for (var i = 0; i < nodeCount; i++) {
      nodes.push({
        x: (rand() * 2 - 1) * extent,
        y: (rand() * 2 - 1) * extent,
        z: (rand() * 2 - 1) * extent
      });
    }

    var edgeCount = Math.max(nodeCount, Math.round(nodeCount * 1.4));
    var edges = [];
    for (var c = 0; c < edgeCount; c++) {
      edges.push({ a: Math.floor(rand() * nodeCount), b: Math.floor(rand() * nodeCount) });
    }

    return { palette: palette, nodes: nodes, edges: edges, nodeCount: nodeCount, extent: extent };
  }

  // Same "one function computes the plan, every renderer just paints it"
  // structure as computeSealPlan — see that function's comment for why.
  function computeSigilPlan(opts) {
    opts = opts || {};
    var hex = opts.hex;
    if (!hex || hex.length < 8) throw new Error("AspectusSeal: opts.hex (a hex string) is required");

    var size = opts.size || 120;
    var background = opts.background !== undefined ? opts.background : "#05070a";
    var cornerRadius = opts.cornerRadius !== undefined ? opts.cornerRadius : size * 0.16; // rounded-square silhouette, deliberately NOT a circle — keeps sigils (who) visually distinct from seals (what/when) at a glance

    var geo = computeSigilGeometry(hex);
    var palette = geo.palette;
    var extent = geo.extent;

    var cx = size / 2, cy = size / 2;
    var margin = size * 0.16;
    var half = (size - margin * 2) / 2;

    var nodes = geo.nodes.map(function (p) {
      return {
        x: cx + (p.x / extent) * half,
        y: cy + (p.y / extent) * half,
        z: p.z / extent
      };
    });

    var nodeRadius = size * 0.05; // bolder than a seal's nodes — has to read small

    var connections = geo.edges.map(function (e, i) {
      var na = nodes[e.a], nb = nodes[e.b];
      var mx = (na.x + nb.x) / 2 + (cx - (na.x + nb.x) / 2) * 0.16;
      var my = (na.y + nb.y) / 2 + (cy - (na.y + nb.y) / 2) * 0.16;
      var depth = geo.edges.length <= 1 ? 0 : i / (geo.edges.length - 1);
      return {
        ax: na.x, ay: na.y, bx: nb.x, by: nb.y, mx: mx, my: my,
        hue: paletteHueAtDepth(palette, depth),
        sat: 65, light: 50 + depth * 20,
        alpha: 0.55 + depth * 0.35,
        width: size * 0.018
      };
    }).filter(function (l, i) { return geo.edges[i].a !== geo.edges[i].b; });

    var nodeDots = nodes.map(function (n, i) {
      var depthBoost = 1 + n.z * 0.3;
      return {
        x: n.x, y: n.y,
        r: nodeRadius * Math.max(0.7, depthBoost),
        hue: paletteHueAtDepth(palette, nodes.length <= 1 ? 0 : i / (nodes.length - 1)),
        sat: 60, light: 68,
        alpha: 1
      };
    });

    return {
      hex: hex,
      size: size,
      background: background,
      cornerRadius: cornerRadius,
      nodeCount: geo.nodeCount,
      connectionsDrawn: connections.length,
      palette: palette.hues.slice(),
      nodes: nodeDots,
      connections: connections
    };
  }

  function roundedRectPath(ctxOrParts, x, y, w, h, r, isSvg) {
    if (isSvg) {
      return 'M ' + (x + r) + ' ' + y +
        ' H ' + (x + w - r) + ' A ' + r + ' ' + r + ' 0 0 1 ' + (x + w) + ' ' + (y + r) +
        ' V ' + (y + h - r) + ' A ' + r + ' ' + r + ' 0 0 1 ' + (x + w - r) + ' ' + (y + h) +
        ' H ' + (x + r) + ' A ' + r + ' ' + r + ' 0 0 1 ' + x + ' ' + (y + h - r) +
        ' V ' + (y + r) + ' A ' + r + ' ' + r + ' 0 0 1 ' + (x + r) + ' ' + y + ' Z';
    }
  }

  function renderSigil(ctx, opts) {
    var plan = computeSigilPlan(opts);

    ctx.save();
    ctx.clearRect(0, 0, plan.size, plan.size);

    ctx.beginPath();
    if (ctx.roundRect) {
      ctx.roundRect(0, 0, plan.size, plan.size, plan.cornerRadius);
    } else {
      // roundRect isn't universally available (older node-canvas builds) —
      // fall back to a plain square clip rather than failing
      ctx.rect(0, 0, plan.size, plan.size);
    }
    ctx.clip();

    if (plan.background) {
      ctx.fillStyle = plan.background;
      ctx.fillRect(0, 0, plan.size, plan.size);
    }

    plan.connections.forEach(function (l) {
      ctx.beginPath();
      ctx.moveTo(l.ax, l.ay);
      ctx.quadraticCurveTo(l.mx, l.my, l.bx, l.by);
      ctx.strokeStyle = hsla(l.hue, l.sat, l.light, l.alpha);
      ctx.lineWidth = l.width;
      ctx.stroke();
    });

    plan.nodes.forEach(function (n) {
      ctx.beginPath();
      ctx.arc(n.x, n.y, n.r, 0, Math.PI * 2);
      ctx.fillStyle = hsla(n.hue, n.sat, n.light, n.alpha);
      ctx.fill();
    });

    ctx.restore();

    return {
      hex: plan.hex,
      nodeCount: plan.nodeCount,
      connectionsDrawn: plan.connectionsDrawn,
      palette: plan.palette
    };
  }

  function renderSigilSVG(opts) {
    var plan = computeSigilPlan(opts);
    var parts = [];
    var clipId = "aspectus-sigil-clip";

    parts.push(
      '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ' + plan.size + ' ' + plan.size + '" ' +
      'width="' + plan.size + '" height="' + plan.size + '" role="img" ' +
      'aria-label="Aspectus personal sigil">'
    );
    parts.push('<clipPath id="' + clipId + '"><path d="' + roundedRectPath(null, 0, 0, plan.size, plan.size, plan.cornerRadius, true) + '"/></clipPath>');
    parts.push('<g clip-path="url(#' + clipId + ')">');

    if (plan.background) {
      parts.push('<rect x="0" y="0" width="' + plan.size + '" height="' + plan.size + '" fill="' + plan.background + '"/>');
    }

    plan.connections.forEach(function (l) {
      parts.push(
        '<path d="M ' + l.ax.toFixed(2) + ' ' + l.ay.toFixed(2) +
        ' Q ' + l.mx.toFixed(2) + ' ' + l.my.toFixed(2) + ' ' + l.bx.toFixed(2) + ' ' + l.by.toFixed(2) + '" ' +
        'fill="none" stroke="' + hsla(l.hue, l.sat, l.light, l.alpha) + '" stroke-width="' + l.width.toFixed(3) + '"/>'
      );
    });

    plan.nodes.forEach(function (n) {
      parts.push(
        '<circle cx="' + n.x.toFixed(2) + '" cy="' + n.y.toFixed(2) + '" r="' + n.r.toFixed(3) + '" ' +
        'fill="' + hsla(n.hue, n.sat, n.light, n.alpha) + '"/>'
      );
    });

    parts.push('</g></svg>');
    return parts.join("");
  }

  return {
    renderSeal: renderSeal,
    renderSealSVG: renderSealSVG,
    computeSealPlan: computeSealPlan, // the full unambiguous spec of a seal — the right thing to check a from-scratch reimplementation against
    renderSigil: renderSigil,
    renderSigilSVG: renderSigilSVG,
    computeSigilPlan: computeSigilPlan,
    buildGeometry3: buildGeometry3, // exposed for anyone who wants raw geometry, not just a drawn seal
    sha256HexOfHash: sha256HexOfHash,
    seedFromHash: seedFromHash
  };
});
