// Hypertree visualization — d stacked XMSS layers, one path highlighted.
// d, h, h' come from real noble PARAMS (params.ts). Each XMSS tree is drawn as a
// schematic triangle (its 2^h' leaves are too many to draw literally for most
// sets); the active leaf position and root are marked and the real leaf count is
// labeled. This is an illustrative structure, not a read-out of noble internals.

import type { SphincsStructuralParams } from '../crypto/params';

const SVGNS = 'http://www.w3.org/2000/svg';

function isLightTheme(): boolean {
  return document.documentElement.getAttribute('data-theme') === 'light';
}

export function renderHypertree(
  container: HTMLElement,
  params: SphincsStructuralParams,
  set: string,
  activeLeafFrac = 0.42 // where on each layer the highlighted path sits (illustrative)
): void {
  container.innerHTML = '';
  const light = isLightTheme();

  const layerH = 64;
  const triW = 220;
  const triH = 40;
  const padX = 110;
  const width = triW + padX * 2;
  const height = params.d * layerH + 90;

  const svg = document.createElementNS(SVGNS, 'svg');
  svg.setAttribute('width', String(width));
  svg.setAttribute('height', String(height));
  svg.setAttribute('viewBox', `0 0 ${width} ${height}`);
  svg.style.display = 'block';
  svg.style.margin = '0 auto';
  svg.setAttribute('role', 'img');
  svg.setAttribute('aria-label',
    `Hypertree for ${set}: ${params.d} stacked XMSS layers of height ${params.hPrime}, ` +
    `each root signed by a WOTS+ leaf in the layer above, climbing to the top root which is the public key. ` +
    `A bottom-layer leaf signs the FORS public key.`);

  const cx = width / 2;
  // layer index ell: d-1 (top) .. 0 (bottom). Row 0 drawn at top.
  const rowY = (rowFromTop: number) => 40 + rowFromTop * layerH;
  const leafX = cx - triW / 2 + activeLeafFrac * triW;

  for (let row = 0; row < params.d; row++) {
    const ell = params.d - 1 - row;       // actual layer index
    const topY = rowY(row);
    const baseY = topY + triH;
    const isTop = ell === params.d - 1;
    const isBottom = ell === 0;

    // triangle (XMSS tree)
    const tri = document.createElementNS(SVGNS, 'polygon');
    tri.setAttribute('points', `${cx},${topY} ${cx - triW / 2},${baseY} ${cx + triW / 2},${baseY}`);
    tri.setAttribute('fill', light ? '#e2e8f0' : '#222238');
    tri.setAttribute('stroke', light ? '#94a3b8' : '#3a3a4f');
    tri.setAttribute('stroke-width', '1');
    svg.appendChild(tri);

    // highlighted path edge inside the triangle (leaf -> root)
    const pathLine = document.createElementNS(SVGNS, 'line');
    pathLine.setAttribute('x1', String(leafX));
    pathLine.setAttribute('y1', String(baseY));
    pathLine.setAttribute('x2', String(cx));
    pathLine.setAttribute('y2', String(topY));
    pathLine.setAttribute('stroke', '#f59e0b');
    pathLine.setAttribute('stroke-width', '2');
    svg.appendChild(pathLine);

    // root dot
    const root = document.createElementNS(SVGNS, 'circle');
    root.setAttribute('cx', String(cx));
    root.setAttribute('cy', String(topY));
    root.setAttribute('r', '5');
    root.setAttribute('fill', isTop ? '#16a34a' : '#6366f1');
    const rootTtl = document.createElementNS(SVGNS, 'title');
    rootTtl.textContent = isTop
      ? `Top root = SLH-DSA public key`
      : `XMSS root, layer ${ell}`;
    root.appendChild(rootTtl);
    svg.appendChild(root);

    // active leaf marker
    const leaf = document.createElementNS(SVGNS, 'rect');
    leaf.setAttribute('x', String(leafX - 5));
    leaf.setAttribute('y', String(baseY - 5));
    leaf.setAttribute('width', '10');
    leaf.setAttribute('height', '10');
    leaf.setAttribute('rx', '2');
    leaf.setAttribute('fill', '#f59e0b');
    const leafTtl = document.createElementNS(SVGNS, 'title');
    leafTtl.textContent = `WOTS+ leaf (1 of 2^h' = ${params.leavesPerLayer.toLocaleString()}) — signs the root below`;
    leaf.appendChild(leafTtl);
    svg.appendChild(leaf);

    // layer label (left)
    const lab = document.createElementNS(SVGNS, 'text');
    lab.setAttribute('x', '8');
    lab.setAttribute('y', String((topY + baseY) / 2));
    lab.setAttribute('font-size', '10');
    lab.setAttribute('font-family', 'monospace');
    lab.setAttribute('fill', light ? '#475569' : '#94a3b8');
    lab.textContent = `layer ${ell}`;
    svg.appendChild(lab);

    // per-layer leaf count (right)
    const cnt = document.createElementNS(SVGNS, 'text');
    cnt.setAttribute('x', String(width - 8));
    cnt.setAttribute('y', String((topY + baseY) / 2));
    cnt.setAttribute('text-anchor', 'end');
    cnt.setAttribute('font-size', '9');
    cnt.setAttribute('font-family', 'monospace');
    cnt.setAttribute('fill', light ? '#64748b' : '#64748b');
    cnt.textContent = `2^${params.hPrime}=${params.leavesPerLayer.toLocaleString()} leaves`;
    svg.appendChild(cnt);

    // "signs" arrow between layers (root of lower layer -> leaf of this layer)
    if (!isBottom) {
      const nextBaseY = rowY(row + 1);
      const arrow = document.createElementNS(SVGNS, 'line');
      arrow.setAttribute('x1', String(leafX));
      arrow.setAttribute('y1', String(baseY));
      arrow.setAttribute('x2', String(cx));
      arrow.setAttribute('y2', String(nextBaseY));
      arrow.setAttribute('stroke', light ? '#cbd5e1' : '#3a3a4f');
      arrow.setAttribute('stroke-width', '1');
      arrow.setAttribute('stroke-dasharray', '3 3');
      svg.appendChild(arrow);
    }
  }

  // FORS anchor at the very bottom
  const forsY = rowY(params.d - 1) + triH + 26;
  const fors = document.createElementNS(SVGNS, 'rect');
  fors.setAttribute('x', String(leafX - 40));
  fors.setAttribute('y', String(forsY - 12));
  fors.setAttribute('width', '80');
  fors.setAttribute('height', '20');
  fors.setAttribute('rx', '3');
  fors.setAttribute('fill', light ? '#fef3c7' : '#422006');
  fors.setAttribute('stroke', '#f59e0b');
  svg.appendChild(fors);
  const forsTxt = document.createElementNS(SVGNS, 'text');
  forsTxt.setAttribute('x', String(leafX));
  forsTxt.setAttribute('y', String(forsY + 2));
  forsTxt.setAttribute('text-anchor', 'middle');
  forsTxt.setAttribute('font-size', '9');
  forsTxt.setAttribute('font-family', 'monospace');
  forsTxt.setAttribute('fill', light ? '#92400e' : '#fcd34d');
  forsTxt.textContent = 'FORS pubkey';
  svg.appendChild(forsTxt);

  const forsArrow = document.createElementNS(SVGNS, 'line');
  forsArrow.setAttribute('x1', String(leafX));
  forsArrow.setAttribute('y1', String(forsY - 12));
  forsArrow.setAttribute('x2', String(leafX));
  forsArrow.setAttribute('y2', String(rowY(params.d - 1) + triH));
  forsArrow.setAttribute('stroke', '#f59e0b');
  forsArrow.setAttribute('stroke-width', '1.5');
  forsArrow.setAttribute('stroke-dasharray', '3 3');
  svg.appendChild(forsArrow);

  container.appendChild(svg);
}
