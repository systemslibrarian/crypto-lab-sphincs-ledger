import './styles.css';
import {
  generateKeyPair,
  sign,
  verify,
  PARAM_SIZES,
  type SphincsParamSet,
  type SphincsKeyPair,
} from './crypto/sphincs';
import { bytesToHex, sha256Hex } from './crypto/hash';
import { buildMerkleTree, getAuthPath, verifyAuthPath } from './crypto/merkle';
import { renderMerkleTree, walkAuthPath } from './visualization/tree';
import {
  generateWotsKeyPair,
  wotsSign,
  wotsVerify,
  wotsForge,
  checkReuseWarning,
  type WotsKeyPair,
  type WotsSignatureResult,
} from './crypto/wots';
import { renderWotsChain, animateForge } from './visualization/wots-chain';
import { getStructuralParams } from './crypto/params';
import { computeForsIndices, buildFors, illustrativeForgeryProbability } from './crypto/fors';
import { renderFors } from './visualization/fors';
import { renderHypertree } from './visualization/hypertree';
import { Ledger } from './ledger/ledger';

type ThemeMode = 'dark' | 'light';

const documentRoot = document.documentElement;
const themeToggle = document.getElementById('theme-toggle') as HTMLButtonElement | null;
const themeColorMeta = document.querySelector('meta[name="theme-color"]');

function getCurrentTheme(): ThemeMode {
  return documentRoot.getAttribute('data-theme') === 'light' ? 'light' : 'dark';
}

function syncThemeToggle(theme: ThemeMode) {
  if (themeToggle) {
    themeToggle.textContent = theme === 'dark' ? '🌙' : '☀️';
    themeToggle.setAttribute('aria-label', theme === 'dark' ? 'Switch to light mode' : 'Switch to dark mode');
  }

  const background = getComputedStyle(documentRoot).getPropertyValue('--bg').trim();
  if (themeColorMeta && background) {
    themeColorMeta.setAttribute('content', background);
  }
}

function setTheme(theme: ThemeMode) {
  documentRoot.setAttribute('data-theme', theme);
  localStorage.setItem('theme', theme);
  syncThemeToggle(theme);
}

if (!documentRoot.getAttribute('data-theme')) {
  documentRoot.setAttribute('data-theme', 'dark');
}
syncThemeToggle(getCurrentTheme());

themeToggle?.addEventListener('click', () => {
  setTheme(getCurrentTheme() === 'dark' ? 'light' : 'dark');
});

// ─── Speed tracking ───
const speedRecords: Record<string, number[]> = {};

function recordSpeed(paramSet: string, ms: number) {
  if (!speedRecords[paramSet]) speedRecords[paramSet] = [];
  speedRecords[paramSet].push(ms);
  renderSpeedChart();
}

// ─── Tab switching ───
const allTabs = Array.from(document.querySelectorAll<HTMLButtonElement>('.tab'));

function activateTab(btn: HTMLButtonElement) {
  allTabs.forEach((t) => {
    t.classList.remove('active');
    t.setAttribute('aria-selected', 'false');
    t.setAttribute('tabindex', '-1');
  });
  document.querySelectorAll('.tab-panel').forEach((p) => {
    p.classList.remove('active');
    p.classList.add('hidden');
  });
  btn.classList.add('active');
  btn.setAttribute('aria-selected', 'true');
  btn.setAttribute('tabindex', '0');
  btn.focus();
  const panel = document.getElementById(`tab-${btn.dataset.tab}`);
  if (panel) {
    panel.classList.add('active');
    panel.classList.remove('hidden');
  }
}

allTabs.forEach((btn) => btn.addEventListener('click', () => activateTab(btn)));

// Jump to a tab by its data-tab name (used by the guided learn-path steps and the
// "See the X tab" links inside the Peek-inside pipeline).
function gotoTab(tabName: string) {
  const btn = allTabs.find((t) => t.dataset.tab === tabName);
  if (btn) {
    activateTab(btn);
    btn.scrollIntoView({ block: 'nearest', behavior: 'smooth' });
  }
}
// Delegated so it also catches the Peek-inside links injected after page load.
document.body.addEventListener('click', (e) => {
  const target = (e.target as HTMLElement).closest<HTMLElement>('[data-goto]');
  if (target) {
    e.preventDefault();
    gotoTab(target.dataset.goto!);
  }
});

// Keyboard arrow navigation for tablist (WCAG)
document.querySelector('.tabs')?.addEventListener('keydown', (e) => {
  const ev = e as KeyboardEvent;
  const idx = allTabs.indexOf(document.activeElement as HTMLButtonElement);
  if (idx === -1) return;
  let next = -1;
  if (ev.key === 'ArrowRight' || ev.key === 'ArrowDown') {
    next = (idx + 1) % allTabs.length;
  } else if (ev.key === 'ArrowLeft' || ev.key === 'ArrowUp') {
    next = (idx - 1 + allTabs.length) % allTabs.length;
  } else if (ev.key === 'Home') {
    next = 0;
  } else if (ev.key === 'End') {
    next = allTabs.length - 1;
  }
  if (next >= 0) {
    ev.preventDefault();
    activateTab(allTabs[next]);
  }
});

// Set initial tabindex state
allTabs.forEach((btn) => {
  btn.setAttribute('tabindex', btn.classList.contains('active') ? '0' : '-1');
});

// ─── TAB 1: Sign & Verify ───
const paramSelect = document.getElementById('param-select') as HTMLSelectElement;
const paramInfo = document.getElementById('param-info')!;
const messageInput = document.getElementById('message-input') as HTMLTextAreaElement;
const btnGenerate = document.getElementById('btn-generate') as HTMLButtonElement;
const signSpinner = document.getElementById('sign-spinner')!;
const signOutput = document.getElementById('sign-output')!;
const btnVerify = document.getElementById('btn-verify') as HTMLButtonElement;
const verifyOutput = document.getElementById('verify-output')!;
const btnTamperSig = document.getElementById('btn-tamper-sig') as HTMLButtonElement;
const btnTamperMsg = document.getElementById('btn-tamper-msg') as HTMLButtonElement;
const tamperOutput = document.getElementById('tamper-output')!;

const peekCard = document.getElementById('peek-card')!;
const btnPeek = document.getElementById('btn-peek') as HTMLButtonElement;
const peekBody = document.getElementById('peek-body')!;
const peekSchematic = document.getElementById('peek-schematic')!;
const peekSteps = document.getElementById('peek-steps')!;

let currentKeyPair: SphincsKeyPair | null = null;
let currentSignature: Uint8Array | null = null;
let currentMessage: Uint8Array | null = null;
let currentParamSet: SphincsParamSet = 'sha2-128f';

// Bridge the opaque hex blob to the mechanism tabs: render the same amber-path
// hypertree schematic and a plain-language pipeline the signature actually walks.
function renderPeek() {
  const p = getStructuralParams(currentParamSet);
  renderHypertree(peekSchematic, p, currentParamSet);
  peekSteps.innerHTML =
    peekStep(1, `Your message (plus a random value) is hashed. Part of that hash picks <strong>${p.k} FORS leaves</strong> — one per FORS tree.`, 'fors') +
    peekStep(2, `Those leaves form a <strong>FORS public key</strong> (the amber box at the bottom). FORS is a <em>few-time</em> signature, so reuse degrades gracefully.`, 'fors') +
    peekStep(3, `A single <strong>WOTS+ leaf</strong> in the bottom XMSS tree signs that FORS public key. WOTS+ is <em>one-time</em> — the hypertree guarantees each is used once.`, 'wots') +
    peekStep(4, `The path then <strong>climbs ${p.d} XMSS layers</strong>: each tree's root is signed by a leaf of the tree above, following the amber line.`, 'hypertree') +
    peekStep(5, `The <strong>top root is your public key</strong>. The whole climb — FORS sig + ${p.d} × (WOTS+ sig + auth path) — is the ${PARAM_SIZES[currentParamSet].signature.toLocaleString()}-byte signature.`, 'hypertree');
}

function peekStep(n: number, text: string, tab: string): string {
  return `<div class="peek-step" role="listitem"><span class="peek-step-num" aria-hidden="true">${n}</span>` +
    `<span>${text} <a href="#" data-goto="${tab}">See the ${tab === 'fors' ? 'FORS' : tab === 'wots' ? 'WOTS+' : 'Hypertree'} tab →</a></span></div>`;
}

btnPeek.addEventListener('click', () => {
  const open = peekBody.hasAttribute('hidden');
  if (open) {
    renderPeek();
    peekBody.removeAttribute('hidden');
    btnPeek.setAttribute('aria-expanded', 'true');
    btnPeek.textContent = 'Hide the mechanism';
  } else {
    peekBody.setAttribute('hidden', '');
    btnPeek.setAttribute('aria-expanded', 'false');
    btnPeek.textContent = 'Show the mechanism';
  }
});

function updateParamInfo() {
  currentParamSet = paramSelect.value as SphincsParamSet;
  const p = PARAM_SIZES[currentParamSet];
  paramInfo.innerHTML = `
    <span class="label">Public key</span><span class="value">${p.publicKey} bytes</span>
    <span class="label">Private key</span><span class="value">${p.privateKey} bytes</span>
    <span class="label">Signature</span><span class="value">${p.signature.toLocaleString()} bytes</span>
    <span class="label">Security level</span><span class="value">${p.security}-bit</span>
  `;
}
paramSelect.addEventListener('change', updateParamInfo);
updateParamInfo();

btnGenerate.addEventListener('click', async () => {
  const params = paramSelect.value as SphincsParamSet;
  currentParamSet = params;
  const msg = new TextEncoder().encode(messageInput.value);

  signSpinner.classList.remove('hidden');
  signOutput.classList.add('hidden');
  btnGenerate.disabled = true;

  try {
    const t0 = performance.now();
    const keyPair = await generateKeyPair(params);
    const tKeygen = performance.now() - t0;

    const t1 = performance.now();
    const sig = await sign(keyPair.privateKey, msg, params);
    const tSign = performance.now() - t1;

    currentKeyPair = keyPair;
    currentSignature = sig;
    currentMessage = msg;

    recordSpeed(params, tSign);

    signOutput.innerHTML =
      `<strong>Keygen:</strong> ${tKeygen.toFixed(1)} ms\n` +
      `<strong>Signing:</strong> ${tSign.toFixed(1)} ms\n\n` +
      `<strong>Public key (${keyPair.publicKey.length} B):</strong>\n${bytesToHex(keyPair.publicKey).substring(0, 64)}…\n\n` +
      `<strong>Private key (${keyPair.privateKey.length} B):</strong> <span class="text-danger">[never transmitted]</span>\n${bytesToHex(keyPair.privateKey).substring(0, 64)}…\n\n` +
      `<strong>Signature (${sig.length.toLocaleString()} B):</strong>\n${bytesToHex(sig).substring(0, 80)}…`;
    signOutput.classList.remove('hidden');

    btnVerify.disabled = false;
    btnTamperSig.disabled = false;
    btnTamperMsg.disabled = false;
    verifyOutput.classList.add('hidden');
    tamperOutput.classList.add('hidden');

    // Reveal the mechanism bridge; refresh it if the learner already opened it.
    peekCard.removeAttribute('hidden');
    if (!peekBody.hasAttribute('hidden')) renderPeek();
  } catch (e: unknown) {
    const msg2 = e instanceof Error ? e.message : String(e);
    signOutput.innerHTML = `<span class="text-danger">Error: ${msg2}</span>`;
    signOutput.classList.remove('hidden');
  } finally {
    signSpinner.classList.add('hidden');
    btnGenerate.disabled = false;
  }
});

btnVerify.addEventListener('click', async () => {
  if (!currentKeyPair || !currentSignature || !currentMessage) return;
  const t0 = performance.now();
  const valid = await verify(currentKeyPair.publicKey, currentMessage, currentSignature, currentParamSet);
  const elapsed = performance.now() - t0;
  verifyOutput.innerHTML = valid
    ? `<span class="badge badge-valid">VERIFIED</span> in ${elapsed.toFixed(1)} ms — the signature is authentic.`
    : `<span class="badge badge-invalid">FAILED</span> in ${elapsed.toFixed(1)} ms — verification rejected.`;
  verifyOutput.classList.remove('hidden');
});

btnTamperSig.addEventListener('click', async () => {
  if (!currentKeyPair || !currentSignature || !currentMessage) return;
  const tampered = new Uint8Array(currentSignature);
  tampered[0] ^= 0x01; // flip one bit of the first byte
  const valid = await verify(currentKeyPair.publicKey, currentMessage, tampered, currentParamSet);
  tamperOutput.innerHTML = valid
    ? `<span class="badge badge-valid">VERIFIED</span> — unexpected!`
    : `<span class="badge badge-invalid">REJECTED</span> — flipped 1 byte in signature (byte[0] XOR 0x01). SHA-256 digest mismatch causes SPHINCS+ verification to fail.`;
  tamperOutput.classList.remove('hidden');
});

btnTamperMsg.addEventListener('click', async () => {
  if (!currentKeyPair || !currentSignature || !currentMessage) return;
  const tampered = new Uint8Array(currentMessage);
  tampered[0] ^= 0x01;
  const valid = await verify(currentKeyPair.publicKey, tampered, currentSignature!, currentParamSet);
  tamperOutput.innerHTML = valid
    ? `<span class="badge badge-valid">VERIFIED</span> — unexpected!`
    : `<span class="badge badge-invalid">REJECTED</span> — flipped 1 byte in message (byte[0] XOR 0x01). The modified message hashes to a different SHA-256 digest, which does not match the signed digest.`;
  tamperOutput.classList.remove('hidden');
});

// ─── TAB 2: Merkle Tree ───
const treeLeavesSelect = document.getElementById('tree-leaves') as HTMLSelectElement;
const btnBuildTree = document.getElementById('btn-build-tree') as HTMLButtonElement;
const leafSelect = document.getElementById('leaf-select') as HTMLSelectElement;
const btnVerifyLeaf = document.getElementById('btn-verify-leaf') as HTMLButtonElement;
const treeContainer = document.getElementById('tree-container')!;
const treeVerifyOutput = document.getElementById('tree-verify-output')!;
const treeCaption = document.getElementById('tree-caption')!;

let treeLeaves: Uint8Array[] = [];
let treeRoot: Awaited<ReturnType<typeof buildMerkleTree>> | null = null;

btnBuildTree.addEventListener('click', async () => {
  const count = parseInt(treeLeavesSelect.value);
  treeLeaves = [];
  for (let i = 0; i < count; i++) {
    treeLeaves.push(crypto.getRandomValues(new Uint8Array(32)));
  }
  treeRoot = await buildMerkleTree(treeLeaves);
  renderMerkleTree(treeContainer, treeRoot);

  // Populate leaf selector
  leafSelect.innerHTML = '';
  for (let i = 0; i < count; i++) {
    const opt = document.createElement('option');
    opt.value = String(i);
    opt.textContent = `Leaf ${i}`;
    leafSelect.appendChild(opt);
  }
  btnVerifyLeaf.disabled = false;
  treeVerifyOutput.classList.add('hidden');
});

btnVerifyLeaf.addEventListener('click', async () => {
  if (!treeRoot || treeLeaves.length === 0) return;
  const leafIdx = parseInt(leafSelect.value);
  const authPath = await getAuthPath(treeLeaves, leafIdx);
  const leafHash = await sha256Hex(treeLeaves[leafIdx]);
  const { valid, intermediates } = await verifyAuthPath(leafHash, leafIdx, authPath, treeRoot.hash);

  // Followable, narrated single-path walk: static tree, one edge lit per level,
  // with the running computed hash shown next to the highlight.
  btnVerifyLeaf.disabled = true;
  treeCaption.hidden = false;
  treeCaption.innerHTML =
    `<strong>Climbing from leaf ${leafIdx}.</strong> Each level combines the current node with its ` +
    `authentication-path sibling to compute the parent — repeat until we reach the root.`;
  await walkAuthPath(treeContainer, treeRoot, authPath, leafIdx, intermediates, (step) => {
    treeCaption.innerHTML =
      `<strong>${step.isRoot ? 'Final level' : 'Level ' + step.level}:</strong> ` +
      `SHA-256( ${step.siblingIsRight ? 'node ‖ sibling' : 'sibling ‖ node'} ) → ` +
      `<span class="caption-hash">${step.parentHash.substring(0, 24)}…</span>` +
      (step.isRoot ? '  — this is the computed root.' : '');
  });
  btnVerifyLeaf.disabled = false;

  let html = `<strong>Leaf ${leafIdx} verification: </strong>`;
  html += valid
    ? `<span class="badge badge-valid">ROOT MATCHES</span>`
    : `<span class="badge badge-invalid">MISMATCH</span>`;
  html += `\n\n<strong>Authentication path (sibling hashes):</strong>\n`;
  authPath.forEach((h, i) => { html += `  Level ${i}: ${h.substring(0, 16)}…\n`; });
  html += `\n<strong>Intermediate computations:</strong>\n`;
  intermediates.forEach((h, i) => { html += `  Step ${i}: ${h.substring(0, 16)}…\n`; });
  html += `\n<strong>Computed root:</strong> ${intermediates[intermediates.length - 1].substring(0, 32)}…`;
  html += `\n<strong>Expected root:</strong> ${treeRoot.hash.substring(0, 32)}…`;

  treeVerifyOutput.innerHTML = html;
  treeVerifyOutput.classList.remove('hidden');
});

// ─── TAB 3: WOTS+ ───
const btnGenWots = document.getElementById('btn-gen-wots') as HTMLButtonElement;
const wotsChainContainer = document.getElementById('wots-chains')!;
const wotsSignControls = document.getElementById('wots-sign-controls')!;
const wotsNibble = document.getElementById('wots-nibble') as HTMLInputElement;
const wotsChainIdx = document.getElementById('wots-chain-idx') as HTMLInputElement;
const btnWotsSign = document.getElementById('btn-wots-sign') as HTMLButtonElement;
const btnWotsVerify = document.getElementById('btn-wots-verify') as HTMLButtonElement;
const wotsReuseWarning = document.getElementById('wots-reuse-warning')!;
const wotsOutput = document.getElementById('wots-output')!;
const wotsForgeControls = document.getElementById('wots-forge-controls')!;
const wotsForgeChain = document.getElementById('wots-forge-chain') as HTMLInputElement;
const wotsForgeStep = document.getElementById('wots-forge-step') as HTMLInputElement;
const btnWotsForge = document.getElementById('btn-wots-forge') as HTMLButtonElement;
const wotsForgeOutput = document.getElementById('wots-forge-output')!;
const wotsForgeCaption = document.getElementById('wots-forge-caption')!;

let wotsKeyPair: WotsKeyPair | null = null;
let wotsLastSig: WotsSignatureResult | null = null;
let wotsSignCount = 0;

// Re-render a chain showing the current signature step (amber) plus every step
// ever revealed on it (orange) — activates the previously-dead revealedIndices hook.
function rerenderWotsChain(chainIdx: number, sig?: WotsSignatureResult) {
  if (!wotsKeyPair) return;
  const div = document.getElementById(`wots-chain-${chainIdx}`)!;
  renderWotsChain(div, wotsKeyPair.chains[chainIdx], sig, wotsKeyPair.chains[chainIdx].revealedSteps);
}

btnGenWots.addEventListener('click', async () => {
  wotsKeyPair = await generateWotsKeyPair(4);
  wotsSignCount = 0;
  wotsLastSig = null;
  wotsReuseWarning.classList.add('hidden');
  wotsOutput.classList.add('hidden');
  wotsForgeControls.style.display = 'none';
  wotsForgeOutput.classList.add('hidden');

  wotsChainContainer.innerHTML = '';
  for (let i = 0; i < wotsKeyPair.chains.length; i++) {
    const div = document.createElement('div');
    div.id = `wots-chain-${i}`;
    const label = document.createElement('div');
    label.className = 'muted';
    label.style.marginTop = '8px';
    label.textContent = `Chain ${i}`;
    wotsChainContainer.appendChild(label);
    wotsChainContainer.appendChild(div);
    renderWotsChain(div, wotsKeyPair.chains[i]);
  }

  wotsSignControls.style.display = 'flex';
  btnWotsVerify.disabled = true;
});

btnWotsSign.addEventListener('click', () => {
  if (!wotsKeyPair) return;
  const nibble = parseInt(wotsNibble.value);
  const chainIdx = parseInt(wotsChainIdx.value);
  // Guard out-of-range / empty inputs (the HTML max attribute does not block
  // typed or empty values, which would otherwise crash with an undefined chain).
  if (!Number.isInteger(nibble) || nibble < 0 || nibble > 15 ||
      !Number.isInteger(chainIdx) || chainIdx < 0 || chainIdx >= wotsKeyPair.chains.length) {
    wotsOutput.innerHTML = `<span class="badge badge-invalid">INVALID</span> Enter nibble 0–15 and chain 0–${wotsKeyPair.chains.length - 1}.`;
    wotsOutput.classList.remove('hidden');
    return;
  }
  const chain = wotsKeyPair.chains[chainIdx];

  wotsLastSig = wotsSign(wotsKeyPair, nibble, chainIdx);

  // Accumulate the revealed step on THIS chain (persists across signatures).
  chain.revealedSteps.add(wotsLastSig.revealedStep);
  wotsKeyPair.signedMessages.push(`nibble-${nibble}-chain-${chainIdx}`);
  wotsSignCount++;

  // Honest, per-chain reuse detection (driven by actual revealed steps).
  const reuse = checkReuseWarning(wotsKeyPair);
  if (reuse.isReuse) {
    wotsReuseWarning.textContent = reuse.warning;
    wotsReuseWarning.classList.remove('hidden');
  } else {
    wotsReuseWarning.classList.add('hidden');
  }

  // Re-render with the current step (amber) + all accumulated reveals (orange).
  rerenderWotsChain(chainIdx, wotsLastSig);

  const revealedList = [...chain.revealedSteps].sort((a, b) => a - b).join(', ');
  wotsOutput.innerHTML =
    `<strong>Signed:</strong> nibble=${nibble}, chain=${chainIdx}\n` +
    `<strong>Revealed step:</strong> ${wotsLastSig.revealedStep} of ${chain.chainLength}\n` +
    `<strong>Steps to public key:</strong> ${wotsLastSig.stepsToPublicKey}\n` +
    `<strong>Revealed value:</strong> ${bytesToHex(wotsLastSig.revealedValue).substring(0, 32)}…\n` +
    `<strong>All steps revealed on chain ${chainIdx}:</strong> [${revealedList}]` +
    (chain.revealedSteps.size >= 2
      ? `  ← lowest = ${Math.min(...chain.revealedSteps)}; every step above it is now forgeable.`
      : '');
  wotsOutput.classList.remove('hidden');
  btnWotsVerify.disabled = false;

  // Enable forgery once any point is revealed; default the forge target sensibly.
  wotsForgeControls.style.display = 'flex';
  wotsForgeChain.value = String(chainIdx);
});

btnWotsForge.addEventListener('click', async () => {
  if (!wotsKeyPair) return;
  const chainIdx = parseInt(wotsForgeChain.value);
  const targetStep = parseInt(wotsForgeStep.value);
  const chain = wotsKeyPair.chains[chainIdx];
  if (!chain) {
    wotsForgeOutput.innerHTML = `<span class="badge badge-invalid">INVALID</span> Chain index must be 0–${wotsKeyPair.chains.length - 1}.`;
    wotsForgeOutput.classList.remove('hidden');
    return;
  }

  const result = await wotsForge(chain, chainIdx, targetStep);
  if ('error' in result) {
    wotsForgeCaption.hidden = true;
    wotsForgeOutput.innerHTML = `<span class="badge badge-invalid">CANNOT FORGE</span> ${result.error}`;
    wotsForgeOutput.classList.remove('hidden');
    return;
  }

  // Re-render this chain fresh (private=red, revealed=orange) then animate the
  // attacker hashing forward from the lowest revealed box to the target step.
  const chainDiv = document.getElementById(`wots-chain-${chainIdx}`);
  if (chainDiv) {
    renderWotsChain(chainDiv, chain, undefined, chain.revealedSteps);
    btnWotsForge.disabled = true;
    wotsForgeCaption.hidden = false;
    wotsForgeCaption.innerHTML =
      `<strong>Attacker starts at the lowest revealed box (step ${result.basisStep}).</strong> ` +
      `It never touches the red Private box — it only hashes forward.`;
    await animateForge(chainDiv, result.basisStep, result.targetStep, (from, to, isFinal) => {
      if (from === to) {
        wotsForgeCaption.innerHTML =
          `<strong>Grabbing the revealed value at step ${from}.</strong> ` +
          `The red Private box (step 0) stays untouched.`;
      } else {
        wotsForgeCaption.innerHTML =
          `SHA-256 forward: step ${from} → step ${to}` +
          (isFinal
            ? `. <strong>The forged value snaps into place at step ${to}</strong> — identical to the honest signer's box, so it verifies.`
            : ` (${to - result.basisStep}× from the start).`);
      }
    });
    btnWotsForge.disabled = false;
  }

  // Verify the forged signature against the genuine public key.
  const valid = await wotsVerify(chain.publicKey, {
    chainIndex: chainIdx,
    revealedStep: result.targetStep,
    revealedValue: result.forgedValue,
    stepsToPublicKey: result.stepsToPublicKey,
  });

  wotsForgeOutput.innerHTML =
    `<strong>Forgery on chain ${chainIdx}, target step ${result.targetStep}</strong>\n` +
    `Attacker started from the LOWEST revealed step (${result.basisStep}) and hashed forward ` +
    `${result.targetStep - result.basisStep}× — never touching the private seed.\n` +
    `<strong>Forged value:</strong> ${bytesToHex(result.forgedValue).substring(0, 32)}…\n` +
    `<strong>Equals honest signer's value at step ${result.targetStep}:</strong> ` +
    (result.matchesReal ? '<span class="badge badge-valid">YES</span>' : '<span class="badge badge-invalid">no</span>') + '\n' +
    `<strong>Verifies against public key:</strong> ` +
    (valid
      ? `<span class="badge badge-invalid">VALID FORGERY</span> — this is the catastrophic WOTS+ reuse failure.`
      : `<span class="badge badge-valid">rejected</span>`);
  wotsForgeOutput.classList.remove('hidden');
});

btnWotsVerify.addEventListener('click', async () => {
  if (!wotsKeyPair || !wotsLastSig) return;
  const chainIdx = wotsLastSig.chainIndex;
  const valid = await wotsVerify(wotsKeyPair.chains[chainIdx].publicKey, wotsLastSig);
  wotsOutput.innerHTML +=
    `\n\n<strong>Verification:</strong> ` +
    (valid
      ? `<span class="badge badge-valid">VALID</span> — hashed forward ${wotsLastSig.stepsToPublicKey} times from revealed value and reached the public key.`
      : `<span class="badge badge-invalid">FAILED</span>`);
});

// ─── TAB: FORS ───
const forsParam = document.getElementById('fors-param') as HTMLSelectElement;
const forsMessage = document.getElementById('fors-message') as HTMLInputElement;
const btnForsBuild = document.getElementById('btn-fors-build') as HTMLButtonElement;
const forsParamsCard = document.getElementById('fors-params')!;
const forsOutput = document.getElementById('fors-output')!;

function renderForsParamsCard() {
  const p = getStructuralParams(forsParam.value as SphincsParamSet);
  forsParamsCard.innerHTML = `
    <span class="label">FORS trees (k)</span><span class="value">${p.k}</span>
    <span class="label">Tree height (a)</span><span class="value">${p.a}</span>
    <span class="label">Leaves per tree (t=2^a)</span><span class="value">${p.t.toLocaleString()}</span>
    <span class="label">Digest bytes (⌈k·a/8⌉)</span><span class="value">${p.forsMdBytes} (${p.forsMdBits} bits)</span>
    <span class="label">Hash family</span><span class="value">SHA-2 only</span>
    <span class="label">Source</span><span class="value">noble PARAMS (real)</span>
  `;
}
forsParam.addEventListener('change', renderForsParamsCard);
renderForsParamsCard();

btnForsBuild.addEventListener('click', async () => {
  const set = forsParam.value as SphincsParamSet;
  const p = getStructuralParams(set);
  btnForsBuild.disabled = true;
  try {
    const msg = new TextEncoder().encode(forsMessage.value);
    // Deterministic randomizer + sk seed for reproducibility in the demo.
    const R = new TextEncoder().encode('fors-demo-R');
    const skSeed = await crypto.subtle.digest('SHA-256', new TextEncoder().encode('fors-demo-sk:' + set));
    const digest = await computeForsIndices(msg, R, p.k, p.a);
    const result = await buildFors(digest, new Uint8Array(skSeed), p.a);
    renderFors(forsOutput, result, { k: p.k, a: p.a, t: p.t, forsMdBytes: p.forsMdBytes, set });
  } finally {
    btnForsBuild.disabled = false;
  }
});

// ─── TAB: Hypertree ───
const hypertreeParam = document.getElementById('hypertree-param') as HTMLSelectElement;
const btnHypertreeBuild = document.getElementById('btn-hypertree-build') as HTMLButtonElement;
const hypertreeParamsCard = document.getElementById('hypertree-params')!;
const hypertreeContainer = document.getElementById('hypertree-container')!;
const hypertreeSizeStory = document.getElementById('hypertree-sizestory')!;

function renderHypertreeAll() {
  const set = hypertreeParam.value as SphincsParamSet;
  const p = getStructuralParams(set);
  hypertreeParamsCard.innerHTML = `
    <span class="label">Hypertree layers (d)</span><span class="value">${p.d}</span>
    <span class="label">Total height (h)</span><span class="value">${p.h}</span>
    <span class="label">Per-layer XMSS height (h′=h/d)</span><span class="value">${p.hPrime}</span>
    <span class="label">WOTS+ leaves per layer (2^h′)</span><span class="value">${p.leavesPerLayer.toLocaleString()}</span>
    <span class="label">Total bottom leaves (2^h)</span><span class="value">2^${p.h}</span>
    <span class="label">Source</span><span class="value">noble PARAMS (real)</span>
  `;
  renderHypertree(hypertreeContainer, p, set);
  const sz = PARAM_SIZES[set];
  hypertreeSizeStory.innerHTML =
    `<strong>Why the signature is ${sz.signature.toLocaleString()} bytes:</strong>\n` +
    `signature  =  FORS sig  +  d × (WOTS+ sig + XMSS auth path)\n` +
    `           =  FORS(k=${p.k}, a=${p.a})  +  ${p.d} layers × (WOTS+ + ${p.hPrime}-node auth path)\n\n` +
    `Each of the ${p.d} layers contributes one WOTS+ signature plus an h′=${p.hPrime} authentication ` +
    `path. More layers (f variants, d=${p.d}) → larger, faster signatures; fewer layers (s variants) → ` +
    `smaller, slower. These are the real ${sz.signature.toLocaleString()}-byte sizes you can reproduce in Tab 1.`;
}
hypertreeParam.addEventListener('change', renderHypertreeAll);
btnHypertreeBuild.addEventListener('click', renderHypertreeAll);
renderHypertreeAll();

// ─── TAB: Collision Tolerance ───
const collisionParam = document.getElementById('collision-param') as HTMLSelectElement;
const collisionMsgA = document.getElementById('collision-msg-a') as HTMLInputElement;
const collisionMsgB = document.getElementById('collision-msg-b') as HTMLInputElement;
const btnCollisionCompare = document.getElementById('btn-collision-compare') as HTMLButtonElement;
const collisionOutput = document.getElementById('collision-output')!;
const collisionN = document.getElementById('collision-n') as HTMLInputElement;
const btnCollisionMargin = document.getElementById('btn-collision-margin') as HTMLButtonElement;
const collisionMargin = document.getElementById('collision-margin')!;
const collisionCoverage = document.getElementById('collision-coverage')!;

// Draw k FORS-tree cells that fill as N grows. A tree is "covered" for a fresh
// target once at least one of that tree's needed leaves has already been revealed;
// expected coverage per tree = 1-(1-1/t)^N. The fill creeping toward all-k is the
// erosion of the few-time margin — watched, not just read.
function renderCoverage(n: number, t: number, k: number) {
  const light = document.documentElement.getAttribute('data-theme') === 'light';
  const perTree = 1 - Math.pow(1 - 1 / t, n);
  const expectedCovered = perTree * k;
  const cols = Math.min(k, 16);
  const cell = 20, gap = 4, rows = Math.ceil(k / cols);
  const w = cols * (cell + gap) + 8;
  const h = rows * (cell + gap) + 40;
  const svgns = 'http://www.w3.org/2000/svg';
  const svg = document.createElementNS(svgns, 'svg');
  svg.setAttribute('width', String(w));
  svg.setAttribute('height', String(h));
  svg.setAttribute('viewBox', `0 0 ${w} ${h}`);
  svg.setAttribute('role', 'img');
  svg.setAttribute('aria-label',
    `Of ${k} FORS trees, about ${expectedCovered.toFixed(1)} are expected to be already covered after ${n.toLocaleString()} signatures.`);
  // Fill the first `expectedCovered` cells solid amber; the fractional cell partial.
  for (let i = 0; i < k; i++) {
    const r = Math.floor(i / cols), c = i % cols;
    const x = 4 + c * (cell + gap), y = 4 + r * (cell + gap);
    const bg = document.createElementNS(svgns, 'rect');
    bg.setAttribute('x', String(x)); bg.setAttribute('y', String(y));
    bg.setAttribute('width', String(cell)); bg.setAttribute('height', String(cell));
    bg.setAttribute('rx', '3');
    bg.setAttribute('fill', light ? '#e2e8f0' : '#222238');
    bg.setAttribute('stroke', '#f59e0b');
    bg.setAttribute('stroke-width', '1');
    svg.appendChild(bg);
    const frac = Math.max(0, Math.min(1, expectedCovered - i));
    if (frac > 0) {
      const fill = document.createElementNS(svgns, 'rect');
      fill.setAttribute('x', String(x));
      fill.setAttribute('y', String(y + cell * (1 - frac)));
      fill.setAttribute('width', String(cell));
      fill.setAttribute('height', String(cell * frac));
      fill.setAttribute('rx', '3');
      fill.setAttribute('fill', '#f59e0b');
      svg.appendChild(fill);
    }
  }
  const label = document.createElementNS(svgns, 'text');
  label.setAttribute('x', '4'); label.setAttribute('y', String(h - 10));
  label.setAttribute('font-size', '11');
  label.setAttribute('font-family', 'monospace');
  label.setAttribute('fill', light ? '#475569' : '#94a3b8');
  label.textContent = `~${expectedCovered.toFixed(1)} of ${k} trees covered (all k = forgeable)`;
  svg.appendChild(label);
  collisionCoverage.innerHTML = '';
  collisionCoverage.appendChild(svg);
  collisionCoverage.hidden = false;
}

btnCollisionCompare.addEventListener('click', async () => {
  const set = collisionParam.value as SphincsParamSet;
  const p = getStructuralParams(set);
  btnCollisionCompare.disabled = true;
  try {
    // Same key → deterministic digest (empty R) so the comparison is purely
    // message-driven. Real SLH-DSA randomizes R per signature, which further
    // frustrates collision-targeting; labeled below.
    const R = new Uint8Array(0);
    const a = await computeForsIndices(new TextEncoder().encode(collisionMsgA.value), R, p.k, p.a);
    const b = await computeForsIndices(new TextEncoder().encode(collisionMsgB.value), R, p.k, p.a);

    let collisions = 0;
    let rows = '';
    for (let i = 0; i < p.k; i++) {
      const same = a.indices[i] === b.indices[i];
      if (same) collisions++;
      rows += `<tr${same ? ' style="background:rgba(245,158,11,0.12)"' : ''}>` +
        `<td>T${i}</td><td>${a.indices[i]}</td><td>${b.indices[i]}</td>` +
        `<td>${same ? '<span class="badge badge-invalid">SAME LEAF</span>' : '<span class="badge badge-valid">different</span>'}</td></tr>`;
    }

    collisionOutput.innerHTML =
      `<div class="output" style="white-space:normal">` +
      `<strong>${set}</strong> — k=${p.k} trees, t=${p.t.toLocaleString()} leaves each. ` +
      `<strong>${collisions}</strong> of ${p.k} trees selected the SAME leaf for both messages.\n\n` +
      `On a colliding tree, both signatures reveal the <em>same</em> FORS secret → <strong>no new ` +
      `information leaks</strong>. On a differing tree, a second distinct secret is revealed. Danger ` +
      `accumulates only across MANY signatures (an attacker grafting enough revealed leaves to cover ` +
      `all k trees of a target) — never from a single collision.\n\n` +
      `<strong>Contrast with WOTS+ (Tab 3):</strong> WOTS+ reuse → immediate forgery of higher chain ` +
      `values on use #2 (catastrophic). FORS reuse → graceful degradation. That graceful degradation ` +
      `IS few-time security, and it is why SLH-DSA can be stateless.\n\n` +
      `<span class="muted">Note: deterministic digest (empty randomizer) used here so identical messages ` +
      `map identically; real SLH-DSA randomizes R per signature.</span>` +
      `</div>` +
      `<div class="table-wrap"><table><thead><tr><th>Tree</th><th>Msg A leaf</th><th>Msg B leaf</th><th>Status</th></tr></thead><tbody>${rows}</tbody></table></div>`;
  } finally {
    btnCollisionCompare.disabled = false;
  }
});

btnCollisionMargin.addEventListener('click', () => {
  const p = getStructuralParams(collisionParam.value as SphincsParamSet);
  const n = Math.max(1, parseInt(collisionN.value) || 1);
  const prob = illustrativeForgeryProbability(n, p.t, p.k);
  const log2 = prob > 0 ? Math.log2(prob) : -Infinity;
  renderCoverage(n, p.t, p.k);
  collisionMargin.innerHTML =
    `<strong>Illustrative</strong> (not a proof) — after N=${n.toLocaleString()} signatures with ONE key:\n` +
    `params: k=${p.k}, t=${p.t.toLocaleString()}\n` +
    `P(fresh message already forgeable) ≈ [1 − (1 − 1/t)^N]^k\n` +
    `≈ ${prob.toExponential(3)}` +
    (isFinite(log2) ? `  (≈ 2^${log2.toFixed(1)})` : '') + '\n\n' +
    `<span class="muted">Real SPHINCS+ bounds are tighter and account for randomized H_msg. The point: ` +
    `the margin erodes slowly and predictably as N grows — graceful, not a cliff.</span>`;
  collisionMargin.classList.remove('hidden');
});

// ─── TAB 4: Ledger ───
const ledger = new Ledger();
const btnLedgerAdd = document.getElementById('btn-ledger-add') as HTMLButtonElement;
const btnLedgerVerify = document.getElementById('btn-ledger-verify') as HTMLButtonElement;
const btnLedgerTamper = document.getElementById('btn-ledger-tamper') as HTMLButtonElement;
const btnLedgerClear = document.getElementById('btn-ledger-clear') as HTMLButtonElement;
const ledgerSpinner = document.getElementById('ledger-spinner')!;
const ledgerEntries = document.getElementById('ledger-entries')!;
const ledgerTamperExpl = document.getElementById('ledger-tamper-explanation')!;

function renderLedger() {
  ledgerEntries.innerHTML = '';
  if (ledger.entries.length === 0) {
    ledgerEntries.innerHTML = '<p class="muted">No entries yet. Add one above.</p>';
    btnLedgerTamper.disabled = true;
    return;
  }
  btnLedgerTamper.disabled = false;

  for (const entry of ledger.entries) {
    const div = document.createElement('div');
    div.className = `ledger-entry${entry.valid ? '' : ' invalid'}`;
    div.innerHTML = `
      <div class="entry-header">
        <span class="entry-author">#${entry.id} — ${escapeHtml(entry.author)}</span>
        <span class="badge ${entry.valid ? 'badge-valid' : 'badge-invalid'}">${entry.valid ? 'VALID' : 'INVALID'}</span>
      </div>
      <div class="entry-message">${escapeHtml(entry.message)}</div>
      <div class="entry-meta">
        ${entry.timestamp} · ${entry.paramSet} · sig: ${entry.signature.length.toLocaleString()} B · ${bytesToHex(entry.signature).substring(0, 24)}…
      </div>
    `;
    ledgerEntries.appendChild(div);
  }
}

function escapeHtml(s: string): string {
  const div = document.createElement('div');
  div.textContent = s;
  return div.innerHTML;
}

renderLedger();

btnLedgerAdd.addEventListener('click', async () => {
  const author = (document.getElementById('ledger-author') as HTMLInputElement).value || 'Anonymous';
  const message = (document.getElementById('ledger-message') as HTMLInputElement).value || '(empty)';
  const params = (document.getElementById('ledger-param') as HTMLSelectElement).value as SphincsParamSet;

  ledgerSpinner.classList.remove('hidden');
  btnLedgerAdd.disabled = true;

  try {
    await ledger.addEntry(author, message, params);
    ledgerTamperExpl.classList.add('hidden');
    renderLedger();
  } finally {
    ledgerSpinner.classList.add('hidden');
    btnLedgerAdd.disabled = false;
  }
});

btnLedgerVerify.addEventListener('click', async () => {
  const result = await ledger.verifyAll();
  renderLedger();
  const summary = document.createElement('div');
  summary.className = 'output';
  summary.innerHTML = `<strong>Verification complete:</strong> ${result.valid} valid, ${result.invalid} invalid out of ${result.entries.length} entries.`;
  ledgerEntries.insertBefore(summary, ledgerEntries.firstChild);
});

btnLedgerTamper.addEventListener('click', () => {
  const latest = ledger.entries[ledger.entries.length - 1];
  if (!latest) return;
  ledger.tamperEntry(latest.id, latest.message + ' [TAMPERED]');
  ledgerTamperExpl.textContent =
    'The message content changed after signing. SHA-256 of the new message does not match the digest that was signed. SPHINCS+ verification rejects it.';
  ledgerTamperExpl.classList.remove('hidden');
  renderLedger();
});

btnLedgerClear.addEventListener('click', () => {
  ledger.clearAll();
  ledgerTamperExpl.classList.add('hidden');
  renderLedger();
});

// ─── TAB 5: Security Basis ───
document.getElementById('security-content')!.innerHTML = `
  <div class="security-section">
    <h3>The Hash-Only Security Argument</h3>
    <div class="highlight-box">
      <strong>"If SHA-256 is secure, SPHINCS+ is secure."</strong><br>
      SLH-DSA's security reduces entirely to the collision resistance, second-preimage resistance,
      and PRF properties of its underlying hash function. There are no number-theoretic assumptions
      (factoring, discrete log, lattice problems) that could be independently broken.
    </div>
  </div>

  <div class="security-section">
    <h3>Quantum Impact</h3>
    <div class="table-wrap"><table>
      <thead>
        <tr><th>Scheme</th><th>Assumption</th><th>Quantum Attack</th><th>Status</th></tr>
      </thead>
      <tbody>
        <tr><td>RSA</td><td>Integer factoring</td><td>Shor's algorithm</td><td class="text-danger">Broken</td></tr>
        <tr><td>ECDSA / Ed25519</td><td>Elliptic curve DLP</td><td>Shor's algorithm</td><td class="text-danger">Broken</td></tr>
        <tr><td>ML-DSA (Dilithium)</td><td>Module-LWE (lattice)</td><td>No known efficient attack</td><td class="text-success">Survives</td></tr>
        <tr><td>SLH-DSA (SPHINCS+)</td><td>Hash function only</td><td>Grover reduces to 128-bit</td><td class="text-success">Survives</td></tr>
      </tbody>
    </table></div>
  </div>

  <div class="security-section">
    <h3>Grover's Algorithm Impact</h3>
    <p>Grover's algorithm provides a quadratic speedup for unstructured search, effectively halving
    the security level of symmetric primitives. SHA-256 retains <strong>128-bit post-quantum security</strong>
    under Grover — still computationally infeasible.</p>
  </div>

  <div class="security-section">
    <h3>Assumption Maturity</h3>
    <div class="table-wrap"><table>
      <thead>
        <tr><th>Assumption</th><th>Years Studied</th><th>Used By</th></tr>
      </thead>
      <tbody>
        <tr><td>Integer factoring</td><td>~50 years</td><td>RSA</td></tr>
        <tr><td>Elliptic curve DLP</td><td>~35 years</td><td>ECDSA, Ed25519</td></tr>
        <tr><td>SHA-256 (hash functions)</td><td>~25 years</td><td>SLH-DSA (SPHINCS+)</td></tr>
        <tr><td>LWE (lattices)</td><td>~20 years</td><td>ML-DSA (Dilithium), ML-KEM</td></tr>
      </tbody>
    </table></div>
  </div>

  <div class="security-section">
    <h3>When to Use SPHINCS+</h3>
    <div class="table-wrap"><table>
      <thead>
        <tr><th>Use Case</th><th>Recommended?</th><th>Rationale</th></tr>
      </thead>
      <tbody>
        <tr><td>Long-lived archives</td><td class="text-success">Yes</td><td>Most conservative PQC assumption; signatures remain valid for decades</td></tr>
        <tr><td>Legal documents</td><td class="text-success">Yes</td><td>Minimal attack surface; hash-only foundation is well-understood</td></tr>
        <tr><td>Software signing (offline)</td><td class="text-success">Yes</td><td>Large signatures acceptable; signing speed less critical</td></tr>
        <tr><td>High-frequency TLS handshakes</td><td class="text-danger">No</td><td>Large signatures (7–50 KB) add latency; ML-DSA preferred</td></tr>
        <tr><td>Bandwidth-constrained IoT</td><td class="text-danger">No</td><td>Signature sizes too large for constrained links</td></tr>
      </tbody>
    </table></div>
  </div>
`;

// ─── TAB 6: Comparison ───
document.getElementById('compare-content')!.innerHTML = `
  <div class="table-wrap"><table>
    <thead>
      <tr>
        <th>Scheme</th>
        <th>Public Key</th>
        <th>Signature</th>
        <th>Quantum Safe</th>
        <th>Assumption</th>
      </tr>
    </thead>
    <tbody>
      <tr><td>RSA-2048</td><td>256 B</td><td>256 B</td><td class="text-danger">No</td><td>Factoring</td></tr>
      <tr><td>Ed25519</td><td>32 B</td><td>64 B</td><td class="text-danger">No</td><td>ECDLP</td></tr>
      <tr><td>ML-DSA-44</td><td>1,312 B</td><td>2,420 B</td><td class="text-success">Yes</td><td>LWE (lattice)</td></tr>
      <tr><td>SLH-DSA-128s</td><td>32 B</td><td>7,856 B</td><td class="text-success">Yes</td><td>Hash only</td></tr>
      <tr><td>SLH-DSA-128f</td><td>32 B</td><td>17,088 B</td><td class="text-success">Yes</td><td>Hash only</td></tr>
      <tr><td>SLH-DSA-256s</td><td>64 B</td><td>29,792 B</td><td class="text-success">Yes</td><td>Hash only</td></tr>
      <tr><td>SLH-DSA-256f</td><td>64 B</td><td>49,856 B</td><td class="text-success">Yes</td><td>Hash only</td></tr>
    </tbody>
  </table></div>
`;

// ─── Speed chart ───
function renderSpeedChart() {
  const container = document.getElementById('speed-chart');
  if (!container) return;
  container.innerHTML = '';

  const allTimes = Object.values(speedRecords).flat();
  if (allTimes.length === 0) {
    container.innerHTML = '<p class="muted">No signing operations recorded yet. Sign a message in Tab 1 to populate this chart.</p>';
    return;
  }
  const maxTime = Math.max(...allTimes, 1);

  for (const [paramSet, times] of Object.entries(speedRecords)) {
    const avg = times.reduce((a, b) => a + b, 0) / times.length;
    const pct = Math.max((avg / maxTime) * 100, 3);
    const div = document.createElement('div');
    div.className = 'speed-bar-container';
    div.innerHTML = `
      <div class="speed-bar-label">SLH-DSA-${paramSet} (${times.length} run${times.length > 1 ? 's' : ''})</div>
      <div class="speed-bar-track">
        <div class="speed-bar-fill" style="width:${pct}%">${avg.toFixed(0)} ms</div>
      </div>`;
    container.appendChild(div);
  }
}
