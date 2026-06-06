// WOTS+ chain visualization — renders horizontal hash chain as SVG boxes

import { bytesToHex } from '../crypto/hash';
import type { WotsChain, WotsSignatureResult } from '../crypto/wots';

const BOX_WIDTH = 72;
const BOX_HEIGHT = 36;
const BOX_GAP = 8;
const CHAIN_Y = 40;

export function renderWotsChain(
  container: HTMLElement,
  chain: WotsChain,
  sigResult?: WotsSignatureResult,
  revealedIndices?: Set<number>,
): void {
  container.innerHTML = '';

  const totalWidth = (chain.chainLength + 1) * (BOX_WIDTH + BOX_GAP) + 40;
  const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
  svg.setAttribute('width', String(Math.min(totalWidth, 900)));
  svg.setAttribute('height', '120');
  svg.setAttribute('viewBox', `0 0 ${totalWidth} 120`);
  svg.style.display = 'block';
  svg.style.margin = '8px auto';

  const isLight = document.documentElement.getAttribute('data-theme') === 'light';

  for (let i = 0; i <= chain.chainLength; i++) {
    const x = 20 + i * (BOX_WIDTH + BOX_GAP);
    const isPrivate = i === 0;
    const isPublic = i === chain.chainLength;
    const isRevealed = sigResult && i === sigResult.revealedStep;
    const isExposed = revealedIndices && revealedIndices.has(i);

    let fill = isLight ? '#cbd5e1' : '#2d2d3f';
    if (isPrivate) fill = '#dc2626';
    else if (isPublic) fill = '#16a34a';
    else if (isRevealed) fill = '#f59e0b';
    else if (isExposed) fill = '#ea580c';

    const group = document.createElementNS('http://www.w3.org/2000/svg', 'g');
    group.style.cursor = 'pointer';

    const rect = document.createElementNS('http://www.w3.org/2000/svg', 'rect');
    rect.setAttribute('x', String(x));
    rect.setAttribute('y', String(CHAIN_Y));
    rect.setAttribute('width', String(BOX_WIDTH));
    rect.setAttribute('height', String(BOX_HEIGHT));
    rect.setAttribute('rx', '4');
    rect.setAttribute('fill', fill);
    rect.setAttribute('stroke', isLight ? '#94a3b8' : '#555');
    rect.setAttribute('stroke-width', '1');

    const text = document.createElementNS('http://www.w3.org/2000/svg', 'text');
    text.setAttribute('x', String(x + BOX_WIDTH / 2));
    text.setAttribute('y', String(CHAIN_Y + BOX_HEIGHT / 2 + 4));
    text.setAttribute('text-anchor', 'middle');
    text.setAttribute('fill', isLight ? '#0f172a' : '#e2e8f0');
    text.setAttribute('font-size', '9');
    text.setAttribute('font-family', 'monospace');

    const hexVal = bytesToHex(chain.chainValues[i]);
    text.textContent = hexVal.substring(0, 8);

    const title = document.createElementNS('http://www.w3.org/2000/svg', 'title');
    title.textContent = hexVal;
    group.appendChild(title);

    // Label
    const label = document.createElementNS('http://www.w3.org/2000/svg', 'text');
    label.setAttribute('x', String(x + BOX_WIDTH / 2));
    label.setAttribute('y', String(CHAIN_Y - 8));
    label.setAttribute('text-anchor', 'middle');
    label.setAttribute('fill', isLight ? '#475569' : '#94a3b8');
    label.setAttribute('font-size', '9');
    label.setAttribute('font-family', 'sans-serif');
    if (isPrivate) { label.textContent = 'Private'; label.setAttribute('fill', isLight ? '#b91c1c' : '#fca5a5'); }
    else if (isPublic) { label.textContent = 'Public'; label.setAttribute('fill', isLight ? '#15803d' : '#86efac'); }
    else if (isRevealed) { label.textContent = 'Sig'; label.setAttribute('fill', isLight ? '#b45309' : '#fcd34d'); }
    else label.textContent = `H^${i}`;

    // Arrow to next
    if (i < chain.chainLength) {
      const arrowX = x + BOX_WIDTH;
      const arrowY = CHAIN_Y + BOX_HEIGHT / 2;
      const arrowLine = document.createElementNS('http://www.w3.org/2000/svg', 'line');
      arrowLine.setAttribute('x1', String(arrowX));
      arrowLine.setAttribute('y1', String(arrowY));
      arrowLine.setAttribute('x2', String(arrowX + BOX_GAP));
      arrowLine.setAttribute('y2', String(arrowY));
      arrowLine.setAttribute('stroke', isLight ? '#94a3b8' : '#555');
      arrowLine.setAttribute('stroke-width', '1');
      arrowLine.setAttribute('marker-end', 'url(#arrowhead)');
      svg.appendChild(arrowLine);
    }

    // Bottom label — step number
    const stepLabel = document.createElementNS('http://www.w3.org/2000/svg', 'text');
    stepLabel.setAttribute('x', String(x + BOX_WIDTH / 2));
    stepLabel.setAttribute('y', String(CHAIN_Y + BOX_HEIGHT + 16));
    stepLabel.setAttribute('text-anchor', 'middle');
    stepLabel.setAttribute('fill', isLight ? '#475569' : '#64748b');
    stepLabel.setAttribute('font-size', '8');
    stepLabel.setAttribute('font-family', 'monospace');
    stepLabel.textContent = `step ${i}`;

    group.appendChild(rect);
    group.appendChild(text);
    group.appendChild(label);
    group.appendChild(stepLabel);
    svg.appendChild(group);
  }

  // Arrow marker definition
  const defs = document.createElementNS('http://www.w3.org/2000/svg', 'defs');
  const marker = document.createElementNS('http://www.w3.org/2000/svg', 'marker');
  marker.setAttribute('id', 'arrowhead');
  marker.setAttribute('markerWidth', '6');
  marker.setAttribute('markerHeight', '4');
  marker.setAttribute('refX', '6');
  marker.setAttribute('refY', '2');
  marker.setAttribute('orient', 'auto');
  const polygon = document.createElementNS('http://www.w3.org/2000/svg', 'polygon');
  polygon.setAttribute('points', '0 0, 6 2, 0 4');
  polygon.setAttribute('fill', isLight ? '#94a3b8' : '#555');
  marker.appendChild(polygon);
  defs.appendChild(marker);
  svg.insertBefore(defs, svg.firstChild);

  container.appendChild(svg);
}
