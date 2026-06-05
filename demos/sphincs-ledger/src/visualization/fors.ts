// FORS visualization — digest split + k reduced trees with selected leaves.
// All structure here is the pedagogical model from crypto/fors.ts; real k/a/t
// values come from noble PARAMS. Reductions are labeled inline.

import { bytesToHex } from '../crypto/hash';
import type { ForsResult } from '../crypto/fors';

const SVGNS = 'http://www.w3.org/2000/svg';

function isLightTheme(): boolean {
  return document.documentElement.getAttribute('data-theme') === 'light';
}

// One reduced FORS tree as a small SVG glyph, selected leaf highlighted.
function renderTreeGlyph(tree: ForsResult['trees'][number], t: number): SVGSVGElement {
  const light = isLightTheme();
  const levels = tree.reducedHeight;          // aDisplay
  const leaves = 2 ** levels;
  const leafW = 14;
  const gap = 4;
  const width = leaves * (leafW + gap) + 10;
  const height = (levels + 1) * 22 + 34;

  const svg = document.createElementNS(SVGNS, 'svg');
  svg.setAttribute('width', String(width));
  svg.setAttribute('height', String(height));
  svg.setAttribute('viewBox', `0 0 ${width} ${height}`);

  // node positions per level, bottom (leaves) at y = levels*22 + 6
  const yOf = (lvl: number) => 6 + (levels - lvl) * 22;
  const xOfLeaf = (j: number) => 5 + j * (leafW + gap) + leafW / 2;

  // edges
  for (let lvl = 0; lvl < levels; lvl++) {
    const count = 2 ** (levels - lvl);
    for (let j = 0; j < count; j += 2) {
      const px = (xAtLevel(lvl, j, leafW, gap) + xAtLevel(lvl, j + 1, leafW, gap)) / 2;
      const py = yOf(lvl + 1);
      for (const child of [j, j + 1]) {
        const line = document.createElementNS(SVGNS, 'line');
        line.setAttribute('x1', String(px));
        line.setAttribute('y1', String(py));
        line.setAttribute('x2', String(xAtLevel(lvl, child, leafW, gap)));
        line.setAttribute('y2', String(yOf(lvl)));
        line.setAttribute('stroke', light ? '#cbd5e1' : '#3a3a4f');
        line.setAttribute('stroke-width', '1');
        svg.appendChild(line);
      }
    }
  }

  // leaves
  for (let j = 0; j < leaves; j++) {
    const selected = j === tree.reducedLeafIndex;
    const rect = document.createElementNS(SVGNS, 'rect');
    rect.setAttribute('x', String(xOfLeaf(j) - leafW / 2));
    rect.setAttribute('y', String(yOf(0) - 6));
    rect.setAttribute('width', String(leafW));
    rect.setAttribute('height', '12');
    rect.setAttribute('rx', '2');
    rect.setAttribute('fill', selected ? '#f59e0b' : (light ? '#cbd5e1' : '#2d2d3f'));
    rect.setAttribute('stroke', light ? '#94a3b8' : '#555');
    rect.setAttribute('stroke-width', '0.75');
    if (selected) {
      const ttl = document.createElementNS(SVGNS, 'title');
      ttl.textContent = `Revealed FORS secret · real leaf ${tree.leafIndex} of ${t}\n${bytesToHex(tree.secret)}`;
      rect.appendChild(ttl);
    }
    svg.appendChild(rect);
  }

  // internal + root nodes (small dots)
  for (let lvl = 1; lvl <= levels; lvl++) {
    const count = 2 ** (levels - lvl);
    for (let j = 0; j < count; j++) {
      const dot = document.createElementNS(SVGNS, 'circle');
      dot.setAttribute('cx', String(xAtLevel(lvl, j, leafW, gap)));
      dot.setAttribute('cy', String(yOf(lvl)));
      dot.setAttribute('r', lvl === levels ? '4' : '3');
      dot.setAttribute('fill', lvl === levels ? '#16a34a' : (light ? '#94a3b8' : '#555'));
      svg.appendChild(dot);
    }
  }

  // label
  const label = document.createElementNS(SVGNS, 'text');
  label.setAttribute('x', String(width / 2));
  label.setAttribute('y', String(height - 16));
  label.setAttribute('text-anchor', 'middle');
  label.setAttribute('font-size', '9');
  label.setAttribute('font-family', 'monospace');
  label.setAttribute('fill', light ? '#475569' : '#94a3b8');
  label.textContent = `T${tree.treeIndex}`;
  svg.appendChild(label);

  const idxLabel = document.createElementNS(SVGNS, 'text');
  idxLabel.setAttribute('x', String(width / 2));
  idxLabel.setAttribute('y', String(height - 4));
  idxLabel.setAttribute('text-anchor', 'middle');
  idxLabel.setAttribute('font-size', '8');
  idxLabel.setAttribute('font-family', 'monospace');
  idxLabel.setAttribute('fill', light ? '#b45309' : '#fcd34d');
  idxLabel.textContent = `${tree.leafIndex}/${t}`;
  svg.appendChild(idxLabel);

  return svg;
}

// x of a node at (level lvl, position j) in the reduced binary tree drawing
function xAtLevel(lvl: number, j: number, leafW: number, gap: number): number {
  const span = 2 ** lvl;
  const firstLeaf = j * span;
  const leafX = (k: number) => 5 + k * (leafW + gap) + leafW / 2;
  return (leafX(firstLeaf) + leafX(firstLeaf + span - 1)) / 2;
}

export function renderFors(
  container: HTMLElement,
  result: ForsResult,
  params: { k: number; a: number; t: number; forsMdBytes: number; set: string }
): void {
  container.innerHTML = '';
  const light = isLightTheme();

  // ── digest panel ──
  const digestPanel = document.createElement('div');
  digestPanel.className = 'output';
  digestPanel.style.whiteSpace = 'normal';
  digestPanel.innerHTML =
    `<strong>Step 1 — randomized message digest (pedagogical H_msg = MGF1-SHA-256)</strong>\n` +
    `<span class="muted">SHA-256(R ‖ message) → expanded to ${params.forsMdBytes} bytes ` +
    `(⌈k·a/8⌉ = ⌈${params.k}·${params.a}/8⌉):</span>\n` +
    `<code style="word-break:break-all">${bytesToHex(result.digest.mdBytes)}</code>\n\n` +
    `<strong>Step 2 — base_2b split (FIPS 205 Alg 4):</strong> ` +
    `<span class="muted">${params.forsMdBytes} bytes → k=${params.k} fields of a=${params.a} bits ` +
    `→ k indices, each in [0, t=${params.t.toLocaleString()})</span>`;
  container.appendChild(digestPanel);

  // index chips
  const chipWrap = document.createElement('div');
  chipWrap.style.display = 'flex';
  chipWrap.style.flexWrap = 'wrap';
  chipWrap.style.gap = '4px';
  chipWrap.style.margin = '10px 0';
  result.digest.indices.forEach((idx, i) => {
    const chip = document.createElement('span');
    chip.className = 'badge';
    chip.style.background = light ? '#fef3c7' : '#422006';
    chip.style.color = light ? '#92400e' : '#fcd34d';
    chip.style.fontFamily = 'monospace';
    chip.textContent = `T${i}:${idx}`;
    chip.title = `Tree ${i} selects leaf ${idx} of ${params.t}`;
    chipWrap.appendChild(chip);
  });
  container.appendChild(chipWrap);

  // ── trees ──
  const treesHeading = document.createElement('p');
  treesHeading.className = 'muted';
  treesHeading.style.marginTop = '8px';
  treesHeading.innerHTML =
    `<strong>Step 3 — reveal selected leaf + auth path per tree, recompute k roots.</strong> ` +
    `Trees drawn at reduced height ${result.reducedHeight} ` +
    `(real a=${params.a}, t=${params.t.toLocaleString()} — too many leaves to draw literally; ` +
    `the amber leaf's label shows its REAL index/t).`;
  container.appendChild(treesHeading);

  const grid = document.createElement('div');
  grid.style.display = 'flex';
  grid.style.flexWrap = 'wrap';
  grid.style.gap = '10px';
  grid.style.margin = '10px 0';
  grid.style.justifyContent = 'center';
  result.trees.forEach((tree) => grid.appendChild(renderTreeGlyph(tree, params.t)));
  container.appendChild(grid);

  // ── FORS public key ──
  const pkPanel = document.createElement('div');
  pkPanel.className = 'output';
  pkPanel.style.whiteSpace = 'normal';
  pkPanel.innerHTML =
    `<strong>Step 4 — FORS public key</strong> = SHA-256(root₀ ‖ … ‖ root₍ₖ₋₁₎):\n` +
    `<code style="word-break:break-all">${bytesToHex(result.publicKey)}</code>\n\n` +
    `<span class="muted">This FORS public key is the message signed by the bottom-layer ` +
    `XMSS/WOTS+ leaf of the hypertree (see the Hypertree tab).</span>`;
  container.appendChild(pkPanel);
}
