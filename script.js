const $ = id => document.getElementById(id); //[cite: 1]

// Adapted Caesar Shift from reference[cite: 1]
function shiftChar(c, n) {
  let x = c.charCodeAt(0);
  if (x >= 65 && x <= 90) return String.fromCharCode((x - 65 + n + 2600) % 26 + 65);
  if (x >= 97 && x <= 122) return String.fromCharCode((x - 97 + n + 2600) % 26 + 97);
  return c;
}

// Adapted Hex routines from reference[cite: 1]
function hexEncode(s) {
  return [...new TextEncoder().encode(s)].map(b => b.toString(16).padStart(2, '0').toUpperCase()).join(' ');
}
function hexDecode(s) {
  let z = s.trim().replace(/[\s,:-]/g, '');
  if (!z) return "";
  if (z.length % 2 || !/^[0-9a-f]+$/i.test(z)) throw new Error('Invalid hexadecimal format.');
  return new TextDecoder('utf-8', { fatal: true }).decode(new Uint8Array(z.match(/.{2}/g).map(v => parseInt(v, 16))));
}

// AES-GCM Implementation (Web Crypto API)
async function deriveKey(password, salt) {
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    "raw", enc.encode(password), { name: "PBKDF2" }, false, ["deriveKey"]
  );
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt: salt, iterations: 100000, hash: "SHA-256" },
    keyMaterial,
    { name: "AES-GCM", length: 256 },
    false, ["encrypt", "decrypt"]
  );
}

// Algorithms Library
const Algos = {
  caesar: {
    name: "Caesar Cipher",
    config: [{ key: "shift", label: "Shift", type: "number", default: 14 }], // Default +14 requested
    encrypt: async (text, cfg) => [...text].map(c => shiftChar(c, parseInt(cfg.shift))).join(''),
    decrypt: async (text, cfg) => [...text].map(c => shiftChar(c, -parseInt(cfg.shift))).join('')
  },
  atbash: {
    name: "Atbash Cipher",
    config: [],
    encrypt: async (text) => [...text].map(c => {
      let x = c.charCodeAt(0);
      if (x >= 65 && x <= 90) return String.fromCharCode(155 - x);
      if (x >= 97 && x <= 122) return String.fromCharCode(219 - x);
      return c;
    }).join(''),
    decrypt: async function(text, cfg) { return this.encrypt(text, cfg); }
  },
  vigenere: {
    name: "Vigenère Cipher",
    config: [{ key: "keyword", label: "Keyword", type: "text", default: "OBSCURA" }],
    encrypt: async (text, cfg) => vigenereCore(text, cfg.keyword, false),
    decrypt: async (text, cfg) => vigenereCore(text, cfg.keyword, true)
  },
  hex: {
    name: "Hexadecimal",
    config: [],
    encrypt: async (text) => hexEncode(text),
    decrypt: async (text) => hexDecode(text)
  },
  binary: {
    name: "Binary",
    config: [],
    encrypt: async (text) => [...new TextEncoder().encode(text)].map(b => b.toString(2).padStart(8, '0')).join(' '),
    decrypt: async (text) => {
      let z = text.trim().replace(/\s+/g, '');
      if(!z) return "";
      if (z.length % 8 !== 0 || !/^[01]+$/.test(z)) throw new Error("Invalid binary format.");
      let arr = new Uint8Array(z.length / 8);
      for (let i=0; i<z.length/8; i++) arr[i] = parseInt(z.substr(i*8, 8), 2);
      return new TextDecoder().decode(arr);
    }
  },
  base64: {
    name: "Base64",
    config: [],
    encrypt: async (text) => btoa(String.fromCharCode.apply(null, new TextEncoder().encode(text))),
    decrypt: async (text) => new TextDecoder().decode(new Uint8Array([...atob(text)].map(c => c.charCodeAt(0))))
  },
  aes: {
    name: "AES-GCM",
    config: [{ key: "password", label: "Password", type: "text", default: "secret" }],
    encrypt: async (text, cfg) => {
      const salt = crypto.getRandomValues(new Uint8Array(16));
      const iv = crypto.getRandomValues(new Uint8Array(12));
      const key = await deriveKey(cfg.password, salt);
      const encBuffer = await crypto.subtle.encrypt({ name: "AES-GCM", iv: iv }, key, new TextEncoder().encode(text));
      // Bundle: salt(16) + iv(12) + ciphertext
      const bundle = new Uint8Array(16 + 12 + encBuffer.byteLength);
      bundle.set(salt, 0); bundle.set(iv, 16); bundle.set(new Uint8Array(encBuffer), 28);
      return btoa(String.fromCharCode.apply(null, bundle));
    },
    decrypt: async (text, cfg) => {
      const raw = Uint8Array.from(atob(text), c => c.charCodeAt(0));
      if (raw.length < 28) throw new Error("Invalid AES payload.");
      const salt = raw.slice(0, 16), iv = raw.slice(16, 28), data = raw.slice(28);
      const key = await deriveKey(cfg.password, salt);
      try {
        const decBuffer = await crypto.subtle.decrypt({ name: "AES-GCM", iv: iv }, key, data);
        return new TextDecoder().decode(decBuffer);
      } catch (e) { throw new Error("Decryption failed. Bad password or tampered data."); }
    }
  },
  sha256: {
    name: "SHA-256 Hash",
    config: [],
    encrypt: async (text) => {
      const hashBuffer = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text));
      return Array.from(new Uint8Array(hashBuffer)).map(b => b.toString(16).padStart(2, '0')).join('');
    },
    decrypt: async () => { throw new Error("SHA-256 is a one-way hash and cannot be decrypted."); }
  }
};

function vigenereCore(text, key, isDecrypt) {
  key = key.toUpperCase().replace(/[^A-Z]/g, '');
  if (!key) throw new Error("Vigenère requires a valid alphabetic keyword.");
  let keyIndex = 0, res = "";
  for (let c of text) {
    let x = c.charCodeAt(0);
    let isUpper = (x >= 65 && x <= 90), isLower = (x >= 97 && x <= 122);
    if (isUpper || isLower) {
      let offset = key.charCodeAt(keyIndex % key.length) - 65;
      if (isDecrypt) offset = -offset;
      res += shiftChar(c, offset);
      keyIndex++;
    } else {
      res += c;
    }
  }
  return res;
}

// Pipeline State Management
let pipeline = [];

// UI Setup
function init() {
  const select = $('algoSelect');
  for (const [id, algo] of Object.entries(Algos)) {
    let opt = document.createElement('option');
    opt.value = id; opt.textContent = algo.name;
    select.appendChild(opt);
  }
  
  $('addLayerBtn').onclick = () => addLayer($('algoSelect').value);
  $('encryptBtn').onclick = () => processPipeline(true);
  $('decryptBtn').onclick = () => processPipeline(false);
  
  $('copyBtn').onclick = async () => {
    try {
      await navigator.clipboard.writeText($('outputText').value);
      setStatus("Copied to clipboard!");
    } catch { setStatus("Failed to copy."); }
  };

  $('presetSelect').onchange = (e) => loadPreset(e.target.value);
  loadPreset('obscura5'); // Load OBSCURA-5 by default
}

function addLayer(id, configValues = null) {
  const algo = Algos[id];
  const layerId = Math.random().toString(36).substr(2, 9);
  const cfg = {};
  algo.config.forEach(c => cfg[c.key] = configValues && configValues[c.key] !== undefined ? configValues[c.key] : c.default);
  pipeline.push({ id, layerId, config: cfg });
  renderPipeline();
}

function removeLayer(layerId) {
  pipeline = pipeline.filter(l => l.layerId !== layerId);
  renderPipeline();
}

function moveLayer(layerId, dir) {
  const idx = pipeline.findIndex(l => l.layerId === layerId);
  if (idx < 0 || (dir === -1 && idx === 0) || (dir === 1 && idx === pipeline.length - 1)) return;
  const temp = pipeline[idx];
  pipeline[idx] = pipeline[idx + dir];
  pipeline[idx + dir] = temp;
  renderPipeline();
}

function updateConfig(layerId, key, val) {
  const layer = pipeline.find(l => l.layerId === layerId);
  if (layer) layer.config[key] = val;
}

function renderPipeline() {
  const container = $('pipelineContainer');
  container.innerHTML = '';
  pipeline.forEach((layer, idx) => {
    const algo = Algos[layer.id];
    const div = document.createElement('div');
    div.className = 'layer';
    
    let configHtml = algo.config.map(c => 
      `<label>${c.label}: <input type="${c.type}" value="${layer.config[c.key]}" onchange="updateConfig('${layer.layerId}', '${c.key}', this.value)"></label>`
    ).join('');

    div.innerHTML = `
      <div class="layer-header">
        <span>${idx + 1}. ${algo.name}</span>
        <div class="layer-actions">
          <button onclick="moveLayer('${layer.layerId}', -1)">▲</button>
          <button onclick="moveLayer('${layer.layerId}', 1)">▼</button>
          <button class="remove-btn" onclick="removeLayer('${layer.layerId}')">X</button>
        </div>
      </div>
      <div class="layer-config">${configHtml}</div>
    `;
    container.appendChild(div);
  });
}

function setStatus(msg, isError = false) {
  const note = $('statusNote');
  note.textContent = msg;
  note.style.color = isError ? "#ef4444" : "var(--peach)";
}

async function processPipeline(isEncrypt) {
  let text = $('inputText').value;
  setStatus("Processing...");
  $('outputText').value = "";
  
  if (!text) { setStatus("Input is empty.", true); return; }
  
  // Encrypt goes 0 to N. Decrypt goes N to 0.
  const layers = isEncrypt ? pipeline : [...pipeline].reverse();
  
  try {
    for (let i = 0; i < layers.length; i++) {
      const layer = layers[i];
      const algo = Algos[layer.id];
      text = isEncrypt ? await algo.encrypt(text, layer.config) : await algo.decrypt(text, layer.config);
    }
    $('outputText').value = text;
    setStatus(isEncrypt ? "Encryption complete." : "Decryption complete.");
  } catch (err) {
    $('outputText').value = "";
    setStatus(`Error: ${err.message}`, true);
  }
}

function loadPreset(preset) {
  pipeline = [];
  if (preset === 'obscura5') {
    addLayer('vigenere', { keyword: 'OBSCURA' });
    addLayer('caesar', { shift: 14 });
    addLayer('hex');
    addLayer('binary');
    addLayer('base64');
  } else if (preset === 'classic') {
    addLayer('atbash');
    addLayer('caesar', { shift: 3 });
    addLayer('vigenere', { keyword: 'SECRET' });
  } else if (preset === 'digital') {
    addLayer('hex');
    addLayer('binary');
    addLayer('base64');
  } else if (preset === 'transposition') {
    addLayer('caesar', {shift: 5}); // Placeholder for transposition demo
  } else if (preset === 'secure') {
    addLayer('aes', { password: 'MyStrongPassword123!' });
  }
  renderPipeline();
}

window.onload = init;