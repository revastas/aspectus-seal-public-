# Aspectus Seal — Reference Test Vectors

These vectors let a from-scratch, independent reimplementation of the
Aspectus Seal algorithm verify itself against the reference
implementation (`aspectus-seal.js`) without trusting that file at all —
run your own SHA-256 + PRNG + geometry code against the hashes below and
check you land on the same numbers. This is what actually makes the
"regenerate and compare" trust story real, rather than just trusting a
second copy of the same JS file.

## Algorithm summary

1. **Seed:** `seed = first 32 bits of SHA-256(SHA-256(hex-decode(hash)))`, read as a big-endian uint32 of the first 8 hex chars of that double-SHA-256 digest.
2. **PRNG:** `mulberry32(seed)` — a specific, standard 32-bit PRNG (implementation in `aspectus-seal.js`); every value below is consumed from this single stream, in order.
3. **Node count:** unless `isGenesis` (pinned to `nodeCount = 2`), a `baseCount` in [2,220] is read from bytes 4–5 of the *hash-of-hash* (not the seed bytes), then `nodeCount = baseCount + floor(rand() * round(baseCount * 0.25))`.
4. **Nodes:** `nodeCount` triplets, each `{x,y,z} = (rand()*2-1) * 0.85`, three `rand()` draws per node, in order.
5. **Edges:** `density = round(baseCount * 2.4)` pairs, each `{a,b} = {floor(rand()*nodeCount), floor(rand()*nodeCount)}`, two `rand()` draws per edge, in order — drawn immediately after all nodes, from the same stream.
6. **Palette:** `paletteFromHash(hash-of-hash)` — 2–6 hues, slot-spaced around the color wheel with bounded jitter, all read from hash-of-hash bytes starting at byte 6 (see source for exact byte layout).
7. **Seal crop:** a seal draws every node but only the first `min(maxConnections, edges.length)` edges — an ordered prefix of the list above, default `maxConnections = 60`.

`hash-of-hash` = `SHA-256(hex-decode(hash))`, hex-encoded — i.e. SHA-256 run a second time over the raw bytes the input hash decodes to.

## Vectors

### Genesis Block (height 0)

| field | value |
|---|---|
| `hash` | `000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26` |
| `hash-of-hash` | `7bfe26c2629cdddaa7fc9d96612c14c9930948af75b3390686dcbf265fc3ea47` |
| `seed` (uint32) | `2080253634` |
| `nodeCount` | `2` |
| `edgeCount` | `5` |
| first 3 nodes | `[{"x":-0.599317,"y":-0.586225,"z":-0.582312},{"x":-0.847594,"y":0.402759,"z":-0.677763}]` |
| first 3 edges | `[{"a":1,"b":1},{"a":1,"b":1},{"a":0,"b":0}]` |
| palette hues (deg) | `[185.1802,294.8498,42.0571]` |
| seal connections drawn (240px default) | `0` |

### Block 968,331

| field | value |
|---|---|
| `hash` | `000000000000000000021c8815dfc8cc150b179e0b6cfd7d664db072d9a62d69` |
| `hash-of-hash` | `3eb196cfbf6f5ed72a1dd71f3384df2b2fcae62e017db5574fbb16a8a193bad2` |
| `seed` (uint32) | `1051825871` |
| `nodeCount` | `183` |
| `edgeCount` | `396` |
| first 3 nodes | `[{"x":0.428387,"y":0.128463,"z":-0.344727},{"x":0.158545,"y":0.058271,"z":0.182678},{"x":-0.79837,"y":0.326216,"z":-0.528796}]` |
| first 3 edges | `[{"a":122,"b":63},{"a":55,"b":35},{"a":166,"b":53}]` |
| palette hues (deg) | `[6.1892,76.6396,107.4505,168.6517,255.2883,310.3333]` |
| seal connections drawn (240px default) | `60` |
| first connection color (h,s,l) | `{"hue":6.1892,"sat":62,"light":42}` |

### Block 968,332

| field | value |
|---|---|
| `hash` | `0000000000000000000002109164aaa860965bdb479e02f00a9a182b3169a89f` |
| `hash-of-hash` | `b22669be795322962c7d9f23bf4afca5eda727e5a7f763f724f15eb1b91dd2b6` |
| `seed` (uint32) | `2988861886` |
| `nodeCount` | `111` |
| `edgeCount` | `252` |
| first 3 nodes | `[{"x":0.279355,"y":-0.671938,"z":0.813935},{"x":0.467301,"y":-0.021195,"z":-0.29118},{"x":0.443173,"y":-0.094385,"z":-0.409169}]` |
| first 3 edges | `[{"a":46,"b":89},{"a":71,"b":49},{"a":90,"b":31}]` |
| palette hues (deg) | `[273.7748,333.5345,34.8859,103.3243,172.7538,232.7538]` |
| seal connections drawn (240px default) | `60` |
| first connection color (h,s,l) | `{"hue":273.7748,"sat":62,"light":42}` |

### Block 968,333

| field | value |
|---|---|
| `hash` | `0000000000000000000114cac286c6226a127ead565e24378cde3c98a42e6724` |
| `hash-of-hash` | `b7c722f81214d7390298682ad464bfe13770c2db61b55c17874ad0220a641659` |
| `seed` (uint32) | `3083281144` |
| `nodeCount` | `18` |
| `edgeCount` | `41` |
| first 3 nodes | `[{"x":0.251837,"y":0.401287,"z":0.268396},{"x":0.440791,"y":-0.068818,"z":-0.342073},{"x":0.68207,"y":0.139798,"z":-0.449744}]` |
| first 3 edges | `[{"a":1,"b":5},{"a":2,"b":10},{"a":8,"b":2}]` |
| palette hues (deg) | `[150.4414,55.8468]` |
| seal connections drawn (240px default) | `37` |
| first connection color (h,s,l) | `{"hue":150.4414,"sat":62,"light":42}` |

### Block 968,334

| field | value |
|---|---|
| `hash` | `000000000000000000016b14226e00ccddd84886b1a754c05b0330a3065db31b` |
| `hash-of-hash` | `c24b8be9cf826dcc50602327b4af9c6daedc4602deec5afe611c6c766076f934` |
| `seed` (uint32) | `3259730921` |
| `nodeCount` | `220` |
| `edgeCount` | `430` |
| first 3 nodes | `[{"x":-0.147224,"y":-0.101058,"z":0.429761},{"x":0.493279,"y":-0.421227,"z":0.799393},{"x":0.210734,"y":0.544874,"z":-0.58571}]` |
| first 3 edges | `[{"a":40,"b":198},{"a":214,"b":92},{"a":84,"b":9}]` |
| palette hues (deg) | `[107.3483,153.9249,237.7087,271.3423,340.7117,51.042]` |
| seal connections drawn (240px default) | `60` |
| first connection color (h,s,l) | `{"hue":107.3483,"sat":62,"light":42}` |

### Block 968,335

| field | value |
|---|---|
| `hash` | `000000000000000000017bc179400a757883077f72465c9837e6f79040e94eb8` |
| `hash-of-hash` | `a882c76b5437ac93df3bef51db9515264ef1d38dbeb9f0cd1be4f5e1c4fb2d64` |
| `seed` (uint32) | `2827143019` |
| `nodeCount` | `75` |
| `edgeCount` | `178` |
| first 3 nodes | `[{"x":0.603503,"y":0.846219,"z":0.780987},{"x":-0.271571,"y":0.338569,"z":0.359988},{"x":-0.527625,"y":-0.485425,"z":-0.569529}]` |
| first 3 edges | `[{"a":66,"b":32},{"a":11,"b":33},{"a":55,"b":72}]` |
| palette hues (deg) | `[47.9505,165.518,219.9324,338.8063]` |
| seal connections drawn (240px default) | `59` |
| first connection color (h,s,l) | `{"hue":47.9505,"sat":62,"light":42}` |

### Block 968,336

| field | value |
|---|---|
| `hash` | `0000000000000000000007d1ebb6dd7630f07038e130cfba5f854b9e8cbd1c01` |
| `hash-of-hash` | `18d122b6c4d46f23d0db33cb21afb66742009b5f4671707e2bbaeae668786f3b` |
| `seed` (uint32) | `416359094` |
| `nodeCount` | `208` |
| `edgeCount` | `408` |
| first 3 nodes | `[{"x":-0.832311,"y":0.080865,"z":-0.063403},{"x":-0.241394,"y":-0.330074,"z":0.697333},{"x":-0.469017,"y":0.203831,"z":-0.134997}]` |
| first 3 edges | `[{"a":14,"b":148},{"a":54,"b":41},{"a":161,"b":49}]` |
| palette hues (deg) | `[144.9069,258.0601,76.979]` |
| seal connections drawn (240px default) | `60` |
| first connection color (h,s,l) | `{"hue":144.9069,"sat":62,"light":42}` |

### Block 968,337

| field | value |
|---|---|
| `hash` | `00000000000000000001db77a1f76367b2bafc8479760532840f4e3b2e8fc02e` |
| `hash-of-hash` | `dc30cfc58e752096e29995b05672259244b131007b017ee26347a291cabecc83` |
| `seed` (uint32) | `3694186437` |
| `nodeCount` | `133` |
| `edgeCount` | `295` |
| first 3 nodes | `[{"x":-0.284072,"y":0.116997,"z":0.533403},{"x":0.0751,"y":-0.280123,"z":-0.17659},{"x":0.615323,"y":-0.791564,"z":0.25793}]` |
| first 3 edges | `[{"a":19,"b":18},{"a":53,"b":52},{"a":6,"b":3}]` |
| palette hues (deg) | `[97.7793,179.8964,273.455,13.5]` |
| seal connections drawn (240px default) | `59` |
| first connection color (h,s,l) | `{"hue":97.7793,"sat":62,"light":42}` |

### Block 968,338

| field | value |
|---|---|
| `hash` | `0000000000000000000211a8057995c423a8e8d87882d30c325ee474668ebd0f` |
| `hash-of-hash` | `7e368f4cedd938716f7c5e64aa2c6721069b808da1b5ae20e5517f31e7761e36` |
| `seed` (uint32) | `2117504844` |
| `nodeCount` | `215` |
| `edgeCount` | `492` |
| first 3 nodes | `[{"x":0.553904,"y":-0.568134,"z":0.321683},{"x":0.642907,"y":-0.663491,"z":0.024243},{"x":0.2565,"y":0.235484,"z":0.158695}]` |
| first 3 edges | `[{"a":30,"b":7},{"a":101,"b":188},{"a":143,"b":138}]` |
| palette hues (deg) | `[259.3303,15.2462,111.042]` |
| seal connections drawn (240px default) | `60` |
| first connection color (h,s,l) | `{"hue":259.3303,"sat":62,"light":42}` |

