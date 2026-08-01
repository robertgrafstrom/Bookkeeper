// app.js — screens, camera/OCR capture, ledger, backup/import, settings.

const CATEGORIES = ['Sales', 'Office', 'Travel', 'Meals', 'Equipment', 'Software', 'Marketing', 'Rent', 'Other'];
const VAT_RATES = ['25', '12', '6', '0'];
const FIXED_PRF_SALT_LABEL = 'bookkeeping-prf-v1'; // turned into bytes below

let sessionKey = null;     // AES-GCM CryptoKey, memory-only, cleared on lock
let entries = [];          // decrypted entries for the current session
let stream = null;         // camera MediaStream
let capturedImage = null;  // dataURL of last capture
let editingEntryId = null; // set when editing an existing entry
let dirHandle = null;      // remembered export folder (File System Access API)
let ocrWorker = null;      // reused across scans so repeat captures are fast

const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => document.querySelectorAll(sel);

function showView(name) {
  $$('.view').forEach((v) => v.classList.remove('active'));
  $(`#view-${name}`).classList.add('active');
  $$('.nav-btn').forEach((b) => b.classList.toggle('active', b.dataset.view === name));
  const nav = $('.bottom-nav');
  const fullScreenViews = ['capture', 'confirm'];
  nav.style.display = fullScreenViews.includes(name) ? 'none' : 'flex';
}

function uid() {
  return crypto.randomUUID ? crypto.randomUUID() : `${Date.now()}-${Math.random().toString(16).slice(2)}`;
}

function todayISO() {
  return new Date().toISOString().slice(0, 10);
}

function fmtAmount(n) {
  return new Intl.NumberFormat('sv-SE', { minimumFractionDigits: 2, maximumFractionDigits: 2 }).format(n);
}

// ---------------------------------------------------------------------
// Boot
// ---------------------------------------------------------------------

async function init() {
  if ('serviceWorker' in navigator) {
    navigator.serviceWorker.register('./service-worker.js').catch(() => {});
  }
  const auth = await DB.get('meta', 'auth');
  if (auth) {
    showView('unlock');
    const bio = await DB.get('meta', 'biometric');
    if (bio && window.PublicKeyCredential) {
      $('#btn-biometric').style.display = 'flex';
    }
  } else {
    showView('setup');
  }
  bindEvents();
}

function bindEvents() {
  $('#setup-form').addEventListener('submit', onSetupSubmit);
  $('#unlock-form').addEventListener('submit', onUnlockSubmit);
  $('#btn-biometric').addEventListener('click', onBiometricUnlock);

  $$('.nav-btn').forEach((b) => b.addEventListener('click', () => {
    const v = b.dataset.view;
    if (v === 'capture') openCapture(); else showView(v);
  }));

  $('#btn-close-capture').addEventListener('click', closeCapture);
  $('#btn-shutter').addEventListener('click', capturePhoto);
  $('#btn-retake').addEventListener('click', retake);
  $('.camera-wrap').addEventListener('click', (e) => {
    if (e.target.closest('.camera-top-bar, .camera-controls')) return;
    onTapToFocus(e);
  });
  $('#confirm-form').addEventListener('submit', onSaveEntry);
  $('#btn-quick-save').addEventListener('click', () => $('#confirm-form').requestSubmit());
  $('#btn-cancel-confirm').addEventListener('click', () => { capturedImage = null; editingEntryId = null; showView('ledger'); });
  $('#confirm-photo').addEventListener('click', () => $('#confirm-photo').classList.toggle('photo-fullscreen'));
  $('#entry-currency').addEventListener('change', onCurrencyChange);
  $('#entry-foreign-flag-manual').addEventListener('change', (e) => {
    $('#entry-currency').dataset.manualOverride = e.target.checked ? '1' : '';
  });
  $('#btn-delete-entry').addEventListener('click', onDeleteEntry);

  $('#btn-export').addEventListener('click', exportBackup);
  $('#import-file').addEventListener('change', importBackup);
  $('#btn-lock').addEventListener('click', lockApp);
  $('#toggle-biometric').addEventListener('change', onToggleBiometric);
  $('#btn-dismiss-banner').addEventListener('click', dismissBackupBanner);
  $('#btn-backup-now').addEventListener('click', () => { showView('settings'); });

  $('#ledger-search').addEventListener('input', renderLedger);
  $('#ledger-filter').addEventListener('change', renderLedger);
}

// ---------------------------------------------------------------------
// Setup / unlock / lock
// ---------------------------------------------------------------------

async function onSetupSubmit(e) {
  e.preventDefault();
  const p1 = $('#setup-password').value;
  const p2 = $('#setup-password-confirm').value;
  const err = $('#setup-error');
  err.textContent = '';
  if (p1.length < 8) { err.textContent = 'Use at least 8 characters.'; return; }
  if (p1 !== p2) { err.textContent = 'Passwords do not match.'; return; }

  const salt = Crypto.newSalt();
  const key = await Crypto.deriveKey(p1, salt);
  const verify = await Crypto.encryptJSON(key, { check: 'ok' });
  await DB.put('meta', { key: 'auth', salt, verify });
  await DB.put('meta', { key: 'lastBackup', value: null });

  sessionKey = key;
  entries = [];
  await afterUnlock();
}

async function onUnlockSubmit(e) {
  e.preventDefault();
  const pass = $('#unlock-password').value;
  const err = $('#unlock-error');
  err.textContent = '';
  const auth = await DB.get('meta', 'auth');
  try {
    const key = await Crypto.deriveKey(pass, auth.salt);
    const check = await Crypto.decryptJSON(key, auth.verify);
    if (check.check !== 'ok') throw new Error('bad');
    sessionKey = key;
    await afterUnlock();
  } catch {
    err.textContent = 'Incorrect password.';
  }
}

async function onBiometricUnlock() {
  const err = $('#unlock-error');
  err.textContent = '';
  try {
    const bio = await DB.get('meta', 'biometric');
    const auth = await DB.get('meta', 'auth');
    if (!bio || !auth) throw new Error('not set up');

    const prfSalt = Crypto.fromB64(bio.prfSalt);
    const cred = await navigator.credentials.get({
      publicKey: {
        challenge: Crypto.randomBytes(32),
        allowCredentials: [{ id: Crypto.fromB64(bio.credentialId), type: 'public-key' }],
        userVerification: 'required',
        extensions: { prf: { eval: { first: prfSalt } } },
      },
    });
    const results = cred.getClientExtensionResults();
    const prfBits = results.prf && results.prf.results && results.prf.results.first;
    if (!prfBits) throw new Error('PRF unavailable');

    const prfKey = await crypto.subtle.importKey('raw', prfBits, { name: 'AES-GCM' }, false, ['decrypt']);
    const rawKeyBits = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: Crypto.fromB64(bio.wrapIv) },
      prfKey,
      Crypto.fromB64(bio.wrapData)
    );
    const key = await crypto.subtle.importKey('raw', rawKeyBits, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);

    // sanity-check the recovered key against the password verifier
    const check = await Crypto.decryptJSON(key, auth.verify);
    if (check.check !== 'ok') throw new Error('mismatch');

    sessionKey = key;
    await afterUnlock();
  } catch (ex) {
    err.textContent = 'Biometric unlock failed — use your password.';
  }
}

async function afterUnlock() {
  $('#setup-password').value = '';
  $('#unlock-password').value = '';
  await loadEntries();
  showView('ledger');
  checkBackupReminder();
}

function lockApp() {
  sessionKey = null;
  entries = [];
  if (stream) { stream.getTracks().forEach((t) => t.stop()); stream = null; }
  if (ocrWorker) { ocrWorker.terminate().catch(() => {}); ocrWorker = null; }
  $('#unlock-password').value = '';
  showView('unlock');
}

// ---------------------------------------------------------------------
// Biometric enrollment (Settings toggle) — experimental, feature-detected
// ---------------------------------------------------------------------

async function onToggleBiometric(e) {
  const checked = e.target.checked;
  const status = $('#biometric-status');
  if (!checked) {
    const v = await DB.get('meta', 'biometric');
    if (v) await DB.del('meta', 'biometric');
    status.textContent = 'Biometric unlock is off.';
    return;
  }
  status.textContent = 'Setting up…';
  try {
    if (!window.PublicKeyCredential) throw new Error('unsupported');

    // Fail fast if this browser can report in advance that it doesn't
    // support PRF, instead of prompting for a fingerprint twice for nothing.
    if (PublicKeyCredential.getClientCapabilities) {
      let caps = null;
      try { caps = await PublicKeyCredential.getClientCapabilities(); } catch { /* capability check itself unsupported */ }
      if (caps && caps['extension:prf'] === false) {
        throw new Error('PRF not supported on this device/browser yet.');
      }
    }

    const prfSaltBytes = new TextEncoder().encode(FIXED_PRF_SALT_LABEL).slice(0, 32);
    const userId = Crypto.randomBytes(16);

    const created = await navigator.credentials.create({
      publicKey: {
        challenge: Crypto.randomBytes(32),
        rp: { name: 'Bookkeeping' },
        user: { id: userId, name: 'owner', displayName: 'Bookkeeping owner' },
        pubKeyCredParams: [{ type: 'public-key', alg: -7 }, { type: 'public-key', alg: -257 }],
        authenticatorSelection: { authenticatorAttachment: 'platform', userVerification: 'required' },
        extensions: { prf: {} },
        timeout: 60000,
      },
    });

    // Immediately do a get() to retrieve the actual PRF secret.
    const assertion = await navigator.credentials.get({
      publicKey: {
        challenge: Crypto.randomBytes(32),
        allowCredentials: [{ id: created.rawId, type: 'public-key' }],
        userVerification: 'required',
        extensions: { prf: { eval: { first: prfSaltBytes } } },
      },
    });
    const results = assertion.getClientExtensionResults();
    const prfBits = results.prf && results.prf.results && results.prf.results.first;
    if (!prfBits) throw new Error('This phone/browser does not support biometric-bound keys (PRF).');

    const prfKey = await crypto.subtle.importKey('raw', prfBits, { name: 'AES-GCM' }, false, ['encrypt']);
    const rawKeyBits = await crypto.subtle.exportKey('raw', sessionKey);
    const iv = Crypto.randomBytes(12);
    const wrapped = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, prfKey, rawKeyBits);

    await DB.put('meta', {
      key: 'biometric',
      credentialId: Crypto.toB64(new Uint8Array(created.rawId)),
      prfSalt: Crypto.toB64(prfSaltBytes),
      wrapIv: Crypto.toB64(iv),
      wrapData: Crypto.toB64(new Uint8Array(wrapped)),
    });
    status.textContent = 'Biometric unlock is on.';
  } catch (ex) {
    e.target.checked = false;
    status.textContent = 'Not available on this phone/browser — password unlock still works fine.';
  }
}

// ---------------------------------------------------------------------
// Note: sessionKey must be extractable for the biometric wrap above to
// work. Both deriveKey() calls in crypto.js create extractable keys.
// ---------------------------------------------------------------------

// ---------------------------------------------------------------------
// Ledger
// ---------------------------------------------------------------------

async function loadEntries() {
  const rows = await DB.getAll('entries');
  entries = [];
  for (const row of rows) {
    try {
      const plain = await Crypto.decryptJSON(sessionKey, row);
      entries.push({ id: row.id, ...plain });
    } catch { /* skip corrupt row */ }
  }
  entries.sort((a, b) => (a.date < b.date ? 1 : -1));
  renderLedger();
}

function renderLedger() {
  const list = $('#ledger-list');
  const search = $('#ledger-search').value.trim().toLowerCase();
  const filter = $('#ledger-filter').value;

  let filtered = entries.filter((en) => {
    if (filter === 'income' && en.type !== 'income') return false;
    if (filter === 'expense' && en.type !== 'expense') return false;
    if (filter === 'flagged' && !en.foreignFlag) return false;
    if (search) {
      const hay = `${en.vendor} ${en.category} ${en.notes || ''}`.toLowerCase();
      if (!hay.includes(search)) return false;
    }
    return true;
  });

  let income = 0, expense = 0;
  entries.forEach((en) => { if (en.type === 'income') income += en.amount; else expense += en.amount; });
  $('#total-income').textContent = fmtAmount(income) + ' kr';
  $('#total-expense').textContent = fmtAmount(expense) + ' kr';
  $('#total-net').textContent = fmtAmount(income - expense) + ' kr';

  list.innerHTML = '';
  if (filtered.length === 0) {
    list.innerHTML = '<div class="empty-state">No entries yet.<br>Tap the camera tab to scan your first receipt.</div>';
    return;
  }

  let lastMonth = '';
  for (const en of filtered) {
    const month = en.date.slice(0, 7);
    if (month !== lastMonth) {
      lastMonth = month;
      const h = document.createElement('div');
      h.className = 'month-heading';
      h.textContent = new Date(en.date + 'T00:00:00').toLocaleDateString('en-GB', { month: 'long', year: 'numeric' });
      list.appendChild(h);
    }
    const card = document.createElement('div');
    card.className = 'entry-card';
    card.innerHTML = `
      ${en.photo ? `<img class="entry-thumb" src="${en.photo}" alt="">` : `<div class="entry-thumb"></div>`}
      <div class="entry-main">
        <div class="entry-vendor">${escapeHtml(en.vendor || 'Untitled')}${en.foreignFlag ? '<span class="flag-pill">check FX</span>' : ''}</div>
        <div class="entry-meta">${en.date} · ${escapeHtml(en.category)} · VAT ${en.vat}%</div>
      </div>
      <div class="entry-amount ${en.type}">${en.type === 'expense' ? '−' : '+'}${fmtAmount(en.amount)} ${en.currency}</div>
    `;
    card.addEventListener('click', () => openEditEntry(en.id));
    list.appendChild(card);
  }
}

function escapeHtml(s) {
  const d = document.createElement('div');
  d.textContent = s || '';
  return d.innerHTML;
}

// ---------------------------------------------------------------------
// Camera capture + OCR
// ---------------------------------------------------------------------

async function openCapture() {
  editingEntryId = null;
  showView('capture');
  $('#camera-video').style.display = 'block';
  $('#captured-canvas').style.display = 'none';
  $('#btn-shutter').style.display = 'flex';
  $('#btn-retake').style.display = 'none';
  try {
    stream = await navigator.mediaDevices.getUserMedia({
      video: {
        facingMode: 'environment',
        width: { ideal: 1920 },
        height: { ideal: 1080 },
      },
      audio: false,
    });
    $('#camera-video').srcObject = stream;
    await enableContinuousFocus();
  } catch (ex) {
    $('#ocr-status').textContent = 'Camera unavailable — check permissions.';
    $('#ocr-status').classList.add('show');
  }
}

async function enableContinuousFocus() {
  try {
    const track = stream.getVideoTracks()[0];
    const caps = track.getCapabilities ? track.getCapabilities() : {};
    if (caps.focusMode && caps.focusMode.includes('continuous')) {
      await track.applyConstraints({ advanced: [{ focusMode: 'continuous' }] });
    }
  } catch { /* this phone/browser doesn't expose focus control — that's fine */ }
}

async function onTapToFocus(e) {
  const wrap = $('.camera-wrap');
  const rect = wrap.getBoundingClientRect();
  const x = (e.clientX - rect.left) / rect.width;
  const y = (e.clientY - rect.top) / rect.height;
  showFocusRing(e.clientX - rect.left, e.clientY - rect.top);

  if (!stream) return;
  try {
    const track = stream.getVideoTracks()[0];
    const caps = track.getCapabilities ? track.getCapabilities() : {};
    if (caps.pointsOfInterest) {
      const advanced = [{ pointsOfInterest: [{ x, y }] }];
      if (caps.focusMode && caps.focusMode.includes('single-shot')) advanced[0].focusMode = 'single-shot';
      await track.applyConstraints({ advanced });
    }
  } catch { /* no hardware focus-point support on this device */ }
}

function showFocusRing(x, y) {
  const wrap = $('.camera-wrap');
  const ring = document.createElement('div');
  ring.className = 'focus-ring';
  ring.style.left = `${x}px`;
  ring.style.top = `${y}px`;
  wrap.appendChild(ring);
  ring.addEventListener('animationend', () => ring.remove());
}

function closeCapture() {
  if (stream) { stream.getTracks().forEach((t) => t.stop()); stream = null; }
  showView('ledger');
}

async function capturePhoto() {
  const video = $('#camera-video');
  const canvas = $('#captured-canvas');
  canvas.width = video.videoWidth;
  canvas.height = video.videoHeight;
  const ctx = canvas.getContext('2d');
  ctx.drawImage(video, 0, 0);
  capturedImage = canvas.toDataURL('image/jpeg', 0.82);

  video.style.display = 'none';
  canvas.style.display = 'block';
  $('#btn-shutter').style.display = 'none';
  $('#btn-retake').style.display = 'flex';
  if (stream) { stream.getTracks().forEach((t) => t.stop()); stream = null; }

  await runOCR(capturedImage);
}

function retake() {
  capturedImage = null;
  openCapture();
}

async function getOcrWorker() {
  if (ocrWorker) return ocrWorker;
  ocrWorker = await Tesseract.createWorker(['eng', 'swe'], 1, {
    logger: (m) => {
      if (m.status === 'recognizing text') {
        $('#ocr-status').textContent = `Reading receipt… ${Math.round((m.progress || 0) * 100)}%`;
      }
    },
  });
  return ocrWorker;
}

async function runOCR(imageDataUrl) {
  const status = $('#ocr-status');
  status.classList.add('show');
  status.textContent = 'Warming up the text reader…';
  try {
    const worker = await getOcrWorker();
    status.textContent = 'Reading receipt…';
    const { data } = await worker.recognize(imageDataUrl);
    const text = data.text || '';
    status.classList.remove('show');
    openConfirm(parseReceiptText(text), imageDataUrl);
  } catch (ex) {
    status.textContent = 'Could not read the photo automatically — fill it in below.';
    setTimeout(() => status.classList.remove('show'), 2200);
    openConfirm(parseReceiptText(''), imageDataUrl);
  }
}

function parseReceiptText(text) {
  const lines = text.split('\n').map((l) => l.trim()).filter(Boolean);
  const guess = { vendor: '', date: todayISO(), amount: '', currency: 'SEK' };

  if (lines.length) guess.vendor = lines[0].slice(0, 60);

  // Date: look for common formats
  const dateRe = /(\d{4})[-./](\d{1,2})[-./](\d{1,2})|(\d{1,2})[-./](\d{1,2})[-./](\d{2,4})/;
  for (const line of lines) {
    const m = line.match(dateRe);
    if (m) {
      try {
        let iso;
        if (m[1]) {
          iso = `${m[1]}-${m[2].padStart(2, '0')}-${m[3].padStart(2, '0')}`;
        } else {
          let yr = m[6].length === 2 ? `20${m[6]}` : m[6];
          iso = `${yr}-${m[5].padStart(2, '0')}-${m[4].padStart(2, '0')}`;
        }
        if (!isNaN(new Date(iso).getTime())) { guess.date = iso; break; }
      } catch { /* ignore */ }
    }
  }

  // Amount: prefer a line containing a total keyword, else the largest number found
  const totalKeywords = /(summa|total|att betala|belopp att betala|to pay|amount due)/i;
  const numRe = /(\d{1,3}(?:[ .]?\d{3})*(?:[.,]\d{2}))/g;
  let bestFromKeyword = null;
  let largest = 0;
  for (const line of lines) {
    const nums = [...line.matchAll(numRe)].map((m) => parseFloat(m[1].replace(/\s/g, '').replace(',', '.')));
    if (!nums.length) continue;
    const maxOnLine = Math.max(...nums);
    if (totalKeywords.test(line) && bestFromKeyword === null) bestFromKeyword = maxOnLine;
    if (maxOnLine > largest) largest = maxOnLine;
  }
  const chosen = bestFromKeyword !== null ? bestFromKeyword : largest;
  guess.amount = chosen ? chosen.toFixed(2) : '';

  // Currency
  if (/€|eur\b/i.test(text)) guess.currency = 'EUR';
  else if (/\$|usd\b/i.test(text)) guess.currency = 'USD';
  else guess.currency = 'SEK';

  return guess;
}

// ---------------------------------------------------------------------
// Confirm / edit entry
// ---------------------------------------------------------------------

function openConfirm(guess, imageDataUrl) {
  $('#entry-currency').dataset.manualOverride = '';
  $('#confirm-title').textContent = 'Confirm receipt';
  $('#entry-vendor').value = guess.vendor || '';
  $('#entry-date').value = guess.date || todayISO();
  $('#entry-amount').value = guess.amount || '';
  $('#entry-currency').value = guess.currency || 'SEK';
  $('#entry-type').value = 'expense';
  $('#entry-vat').value = '25';
  $('#entry-category').value = 'Other';
  $('#entry-notes').value = '';
  $('#entry-foreign-flag-manual').checked = guess.currency !== 'SEK';
  $('#confirm-photo').src = imageDataUrl || '';
  $('#confirm-photo').style.display = imageDataUrl ? 'block' : 'none';
  $('#btn-delete-entry').style.display = 'none';
  showView('confirm');
}

function openEditEntry(id) {
  const en = entries.find((e) => e.id === id);
  if (!en) return;
  editingEntryId = id;
  capturedImage = en.photo || null;
  $('#entry-currency').dataset.manualOverride = '1';
  $('#confirm-title').textContent = 'Edit entry';
  $('#entry-vendor').value = en.vendor || '';
  $('#entry-date').value = en.date;
  $('#entry-amount').value = en.amount;
  $('#entry-currency').value = en.currency;
  $('#entry-type').value = en.type;
  $('#entry-vat').value = en.vat;
  $('#entry-category').value = en.category;
  $('#entry-notes').value = en.notes || '';
  $('#entry-foreign-flag-manual').checked = en.foreignFlag;
  $('#confirm-photo').src = en.photo || '';
  $('#confirm-photo').style.display = en.photo ? 'block' : 'none';
  $('#btn-delete-entry').style.display = 'block';
  showView('confirm');
}

function onCurrencyChange(e) {
  if (!e.target.dataset.manualOverride) {
    $('#entry-foreign-flag-manual').checked = e.target.value !== 'SEK';
  }
}

async function onSaveEntry(e) {
  e.preventDefault();
  const entry = {
    vendor: $('#entry-vendor').value.trim(),
    date: $('#entry-date').value || todayISO(),
    amount: parseFloat($('#entry-amount').value) || 0,
    currency: $('#entry-currency').value,
    type: $('#entry-type').value,
    vat: $('#entry-vat').value,
    category: $('#entry-category').value,
    notes: $('#entry-notes').value.trim(),
    foreignFlag: $('#entry-foreign-flag-manual').checked,
    photo: capturedImage,
    createdAt: new Date().toISOString(),
  };
  const id = editingEntryId || uid();
  const enc = await Crypto.encryptJSON(sessionKey, entry);
  await DB.put('entries', { id, iv: enc.iv, data: enc.data });

  editingEntryId = null;
  capturedImage = null;
  await loadEntries();
  showView('ledger');
  showStamp(entry.date);
}

async function onDeleteEntry() {
  if (!editingEntryId) return;
  await DB.del('entries', editingEntryId);
  editingEntryId = null;
  capturedImage = null;
  await loadEntries();
  showView('ledger');
}

function showStamp(dateStr) {
  const overlay = $('#stamp-overlay');
  $('#stamp-date').textContent = dateStr;
  overlay.classList.add('show');
  overlay.querySelector('.stamp').style.animation = 'none';
  void overlay.offsetWidth;
  overlay.querySelector('.stamp').style.animation = '';
  setTimeout(() => overlay.classList.remove('show'), 900);
}

// ---------------------------------------------------------------------
// Backup export / import
// ---------------------------------------------------------------------

async function exportBackup() {
  const rows = await DB.getAll('entries');
  const auth = await DB.get('meta', 'auth');
  const payload = {
    app: 'bookkeeping-backup',
    version: 1,
    exportedAt: new Date().toISOString(),
    salt: auth.salt,
    verify: auth.verify,
    entries: rows,
  };
  const blob = new Blob([JSON.stringify(payload)], { type: 'application/json' });
  const filename = `bookkeeping-backup-${todayISO()}.json`;

  try {
    if (!dirHandle && window.showDirectoryPicker) {
      dirHandle = await window.showDirectoryPicker({ id: 'bookkeeping-folder', mode: 'readwrite' });
    }
    if (dirHandle) {
      const fileHandle = await dirHandle.getFileHandle(filename, { create: true });
      const writable = await fileHandle.createWritable();
      await writable.write(blob);
      await writable.close();
      $('#export-status').textContent = `Saved ${filename} to your chosen folder.`;
    } else {
      throw new Error('no picker');
    }
  } catch {
    // Fallback: plain download into Downloads/Bookkeeping (browser-dependent)
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = `Bookkeeping/${filename}`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    $('#export-status').textContent = `Downloaded ${filename} — move it into a "Bookkeeping" folder if it landed in Downloads.`;
  }

  await DB.put('meta', { key: 'lastBackup', value: new Date().toISOString() });
  dismissBackupBanner();
}

async function importBackup(e) {
  const file = e.target.files[0];
  if (!file) return;
  const status = $('#import-status');
  status.textContent = 'Importing…';
  try {
    const text = await file.text();
    const payload = JSON.parse(text);
    if (payload.app !== 'bookkeeping-backup') throw new Error('not a backup file');

    // If this is a fresh device with no account yet, adopt the backup's auth.
    const auth = await DB.get('meta', 'auth');
    if (!auth) {
      await DB.put('meta', { key: 'auth', salt: payload.salt, verify: payload.verify });
    }

    let added = 0, skipped = 0;
    for (const row of payload.entries) {
      const existing = await DB.get('entries', row.id);
      if (existing) { skipped++; continue; }
      await DB.put('entries', row);
      added++;
    }
    status.textContent = `Imported ${added} new entries (${skipped} already present).`;
    if (sessionKey) await loadEntries();
  } catch (ex) {
    status.textContent = 'Could not import this file — is it a Bookkeeping backup?';
  }
  e.target.value = '';
}

// ---------------------------------------------------------------------
// Weekly backup reminder (in-app banner — see note in chat about limits
// of true offline push notifications)
// ---------------------------------------------------------------------

async function checkBackupReminder() {
  const meta = await DB.get('meta', 'lastBackup');
  const last = meta && meta.value ? new Date(meta.value) : null;
  const days = last ? (Date.now() - last.getTime()) / 86400000 : Infinity;
  const banner = $('#backup-banner');
  if (days >= 7) {
    $('#backup-banner-text').textContent = last
      ? `It's been ${Math.floor(days)} days since your last backup.`
      : "You haven't backed up yet.";
    banner.classList.add('show');
  } else {
    banner.classList.remove('show');
  }
}

function dismissBackupBanner() {
  $('#backup-banner').classList.remove('show');
}

document.addEventListener('DOMContentLoaded', init);
