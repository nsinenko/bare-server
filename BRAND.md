# bare server — brand & usage guide

One idea, taken seriously — the identity follows the software. This is what you
need to put the mark into the repository correctly, and the rules for what not
to do with it.

## The mark

**One buffer.** Brackets closed around a solid block, split once: header and
body, contiguous, one write. The mark draws the server's central design
decision, not a picture of a machine.

Everything sits on a 64-unit grid. All geometry is orthogonal, all terminals are
square, and there is exactly one stroke weight per size.

| | |
| --- | --- |
| grid | 64 × 64 |
| stroke | 5 units, square cap, no join radius |
| bracket | 8 → 17 return, 9 → 55 stem |
| header | 24,23 · 9 × 18 |
| body | 35,23 · 15 × 18 (2-unit gap) |

The accent is optional and never load-bearing. Use it on dark backgrounds and in
the CLI banner, where the header block earns emphasis. Everywhere else —
favicons, docs, print, anything under 32 px — the mark is one ink.

## Lockup and clear space

Horizontal is the default; stacked exists only for square spaces.

| | |
| --- | --- |
| clear space | 0.4 × mark height, all four sides |
| mark : type | mark height = 1.9 × wordmark cap height |
| min width | 96 px — below that, mark only |

The gap between mark and wordmark is 0.4 × the mark height, and the wordmark's
cap height aligns to the block, not to the bracket.

## Size ladder

**Redrawn, not scaled.** Each step thickens the stroke and gives back interior
space, because a 5-unit stroke scaled to 16 px is 1.25 px and lands on a
half-pixel. At 16 px the two blocks merge into one slab — the split is the first
thing to go, the brackets are the last.

| Size | Stroke | Treatment |
| --- | --- | --- |
| ≥ 48 px | 5 | full geometry, accent allowed |
| 32 px | 6 | split held, one ink |
| 24 px | 8 | brackets pulled in 1 unit |
| 16 px | 10 | blocks merged, no accent |

Never below 16 px — use the wordmark instead.

## Colour

**Ink, paper, one ember.** Two neutrals do the work; the accent appears once per
surface at most. No gradients, no second accent, no tints of the accent.

| Token | Value | Use |
| --- | --- | --- |
| **ink** | `#0B0D0F` | Mark, wordmark, dark surfaces, terminal ground |
| **paper** | `#FCFBF8` | Light surfaces. Reverse mark uses `#F2F0EA` on ink |
| **ember** | `#C4451E` light / `#E0521F` dark | Header block, one badge, `ready` in the banner, links |
| **canvas** | `#E8E5DE` | Page ground |
| **muted** | `#8B857A` (`#6C6860` on ink) | Labels, secondary log lines |
| **rule** | `#D5D1C6` | Hairlines |

## Typography and naming

**Monospace for the product, grotesque for prose.**

| | |
| --- | --- |
| product face | JetBrains Mono — 500 wordmark, 400 code |
| tracking | −0.035em wordmark, 0 in code |
| case | always lowercase — never `Bare Server` |
| fallback | `ui-monospace, SFMono-Regular, Menlo, monospace` |

Monospace covers the wordmark, all UI and doc labels, badges, config, and every
line of terminal output.

| | |
| --- | --- |
| prose face | Space Grotesk — 600 headings, 400 body |
| sizes | 30 / 17 / 16 / 12.5 px, line-height 1.55 |
| fallback | `system-ui, -apple-system, sans-serif` |

Prose only: docs pages, the social preview description, release notes. Never the
wordmark.

### Naming

**bare server** in prose and in the logotype. **bare-server** for the crate, the
binary, the config path, the Docker image, and the repo — anywhere a machine
reads it. Never `BareServer`, `Bare-Server`, or `BARE SERVER`.

### Voice

Flat declaratives, real numbers, named trade-offs. State what it does not do as
plainly as what it does. No superlatives, no "blazingly", no exclamation marks —
the benchmark table is the marketing.

## The CLI banner

**Four lines, on stderr, only for a human.** The banner is a courtesy, not
output. It prints to stderr once at boot, only when stderr is a TTY, and never
when `--quiet` is set — a server with no request logging should not be the
noisiest thing in a systemd journal.

```
 ┌──     ──┐
 │         │ bare server 0.1.0
 │  ██ ███ │ rustls · brotli q11 · storage=memory
 │         │ MIT · github.com/nsinenko/bare-server
 └──     ──┘
```

On a non-UTF-8 locale it degrades to one ASCII line rather than emitting
mojibake:

```
[ ## ### ] bare server 0.1.0
```

And the one-line form, for `--version`, logs and CI:

```
bare-server 0.1.0 (aarch64-unknown-linux-musl)
```

Colour is gated on the same TTY check plus `NO_COLOR` being unset, and there are
two tones:

- The **header block** carries the ember accent (`\x1b[38;5;166m`), once. This
  is the whole accent budget for the surface.
- The **brackets** drop back to the muted tone (`\x1b[38;5;245m`), the terminal
  equivalent of `#8B857A`. They are structure, not content, and muting them lets
  the blocks read as the subject. A neutral, so it does not spend the accent.

The body block is deliberately left at the terminal's own foreground rather than
pinned to paper, so it stays legible on a light profile as well as a dark one.

The implementation is [`src/banner.rs`](src/banner.rs): no dependencies, no
colour when piped. It reports the storage backend and compression settings the
process actually loaded, so the banner never claims a configuration the server
is not in.

## README and badges

The header replaces the H1: the centred horizontal lockup at 340 px, the
one-sentence description, then the badge row. **Three badges maximum** — CI,
licence, Rust version.

The lockup is served through a `<picture>` element so it follows the reader's
GitHub theme — `lockup-reverse.svg` on dark, where the ember header block is
allowed, and `lockup.svg` on light, where the mark is one ink. A single
hardcoded `lockup.svg` would be nearly invisible against GitHub's dark ground.

Because the lockup already carries the wordmark, the README has no separate
`<h1>`; the image's `alt` text supplies the name.

Badge colours are pinned to the palette: neutral badges `0B0D0F`, the one accent
badge `C4451E`. Do not add `for-the-badge` styling or a fourth badge.

## GitHub assets

The avatar is exported at 460 × 460 with the mark at 46% of the canvas — GitHub
crops it to a circle, so the brackets must clear the corners. The social preview
is 1280 × 640 on ink ground, with 64 px safe margins and four facts, no logos of
dependencies.

## Misuse

Six ways to break it:

- No rounding — the terminals are square.
- Never rotate.
- No gradients.
- Do not thin the stroke.
- Not title case, not sans — `Bare Server` is wrong twice over.
- Ink or paper grounds only.

Also: do not add a container shape around the mark, do not use the accent for
the brackets, do not stretch the lockup to fill a width, and do not set the
wordmark in the mark's place at small sizes — below 96 px the mark goes alone.

## File manifest

| File | What it is |
| --- | --- |
| [`assets/brand/mark.svg`](assets/brand/mark.svg) | 64 grid, ink, one colour |
| [`assets/brand/mark-reverse.svg`](assets/brand/mark-reverse.svg) | Paper strokes, ember header |
| [`assets/brand/mark-16.svg`](assets/brand/mark-16.svg) | Merged-block drawing for 16 px |
| [`assets/brand/lockup.svg`](assets/brand/lockup.svg) | Horizontal, ink |
| [`assets/brand/lockup-reverse.svg`](assets/brand/lockup-reverse.svg) | Horizontal, on ink |
| [`assets/brand/favicon.svg`](assets/brand/favicon.svg) | Theme-aware; also ships in `www/` |
| [`src/banner.rs`](src/banner.rs) | Boot banner, stderr + TTY only |
| `BRAND.md` | This guide |

Every source file is hand-written SVG under 1 KB — they are the one set of
assets this project ships that a reader might open in a text editor. Use
`currentColor` when inlining the mark into a docs page so it inherits light and
dark themes; use literal hex in files GitHub renders standalone.

For inlining:

```svg
<svg viewBox="0 0 64 64" width="32" height="32" fill="none" aria-label="bare server">
  <path d="M17 9H8V55H17M47 9H56V55H47" stroke="currentColor" stroke-width="6" stroke-linecap="square"/>
  <rect x="24" y="23" width="9" height="18" fill="currentColor"/>
  <rect x="35" y="23" width="15" height="18" fill="currentColor"/>
</svg>
```

`favicon.svg` also belongs in `www/` so the example site serves it and the boot
log proves it was baked.

### Not yet produced

The raster exports in the guide are not in the repo: `favicon.ico` (16 + 32),
`avatar-460.png`, and `social-preview-1280.png`. They are derived from the SVGs
above and need to be exported and uploaded through GitHub's settings.

---

bare server · brand & usage guide · MIT, same as the code.
