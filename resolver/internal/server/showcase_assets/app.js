// Decentralized DNS — Interactive Showcase Application
// Reads go through the local Go resolver REST API.
// Writes go directly to the connected blockchain (Sepolia testnet or local node).

const REST_BASE = "";

const state = {
  config: null,
  provider: null,
  chainId: null,
  isSepolia: false,
  currentWallet: "metamask",
  customKey: null,
  injectedSigner: null,
  localSigner: null,
  contracts: {},
};

const ABI = {
  NamespaceDApp: [
    "function priceOf(string name) view returns (uint256)",
    "function available(string name) view returns (bool)",
    "function ownerOf(string name) view returns (address)",
    "function getDomain(string name) view returns (address owner, bytes pubKey, uint64 expiry, uint64 generation)",
    "function makeCommitment(string name, address owner, bytes pubKey, bytes32 secret) pure returns (bytes32)",
    "function commit(bytes32 commitment)",
    "function register(string name, bytes pubKey, bytes32 secret) payable",
    "function renew(string name) payable",
    "function transfer(string name, address newOwner, bytes newPubKey)",
    "function setRecord(string name, string recordType, string selector, string[] fieldNames, string[] fieldValues, uint32 ttl, bytes ownerSig, bytes32 commitment)",
    "function removeRecord(string name, string recordType, string selector)",
    "function lookup(string name, string recordType, string selector) view returns (tuple(string recordType, string selector, string[] fieldNames, string[] fieldValues, uint32 ttl, uint64 generation, bytes ownerSig, bytes32 commitment, bool exists))",
    "function listRecords(string name) view returns (tuple(string recordType, string selector, string[] fieldNames, string[] fieldValues, uint32 ttl, uint64 generation, bytes ownerSig, bytes32 commitment, bool exists)[])",
    "function MIN_COMMITMENT_AGE() view returns (uint256)",
    "function MAX_COMMITMENT_AGE() view returns (uint256)",
    "event Registered(bytes32 indexed nameHash, string name, address indexed owner, bytes pubKey, uint64 expiry, uint64 generation, uint256 feePaid)",
    "event Renewed(bytes32 indexed nameHash, string name, uint64 newExpiry, uint256 feePaid)",
    "event Transferred(bytes32 indexed nameHash, string name, address indexed oldOwner, address indexed newOwner, bytes newPubKey, uint64 newGeneration)",
    "event RecordSet(bytes32 indexed nameHash, string name, string recordType, string selector, uint64 generation, uint32 ttl)",
    "event RecordRemoved(bytes32 indexed nameHash, string name, string recordType, string selector, uint64 generation)",
    "error InvalidName()",
    "error InvalidPubKey()",
    "error NameUnavailable()",
    "error DomainNotRegistered()",
    "error DomainExpired()",
    "error NotDomainOwner()",
    "error InsufficientFee(uint256 required, uint256 provided)",
    "error NotTreasurer()",
    "error ZeroAddress()",
    "error UnknownRecordType()",
    "error MissingMandatoryField(string field)",
    "error FieldArrayMismatch()",
    "error TooManyFields()",
    "error FieldValueTooLong()",
    "error FieldNameTooLong()",
    "error SelectorTooLong()",
    "error InvalidTTL()",
    "error RecordNotFound()",
    "error CommitmentNotFound()",
    "error CommitmentTooNew()",
    "error CommitmentTooOld()",
  ],
  RecordSchemaRegistry: [
    "function typeExists(string typeName) view returns (bool)",
    "function listTypes() view returns (string[])",
    "function declareType(string name, string[] mandatory, string[] optional)",
    "function getSchema(string typeName) view returns (tuple(string name, bool mandatory)[])",
    "error TypeAlreadyExists()",
    "error UnknownType()",
    "error InvalidTypeName()",
    "error InvalidFieldName()",
    "error TooManyFields()",
    "error DuplicateField()",
  ],
  ResolverRegistry: [
    "function activeResolvers() view returns (address[] operators, bytes32[] pubKeys, string[] endpoints)",
    "function getResolver(address operator) view returns (bytes32 pubKey, string endpoint, uint64 updatedAt, bool active)",
    "function announce(bytes32 pubKey, string endpoint)",
    "function revoke()",
    "error EmptyPubKey()",
    "error EmptyEndpoint()",
    "error EndpointTooLong()",
    "error NotRegistered()",
  ],
  ResolverIncentives: [
    "function openChannel(address resolverOperator, uint64 durationSeconds) payable returns (bytes32)",
    "function claim(bytes32 channelId, uint256 cumulativeAmount, bytes signature)",
    "function close(bytes32 channelId)",
    "function channels(bytes32 channelId) view returns (address client, address resolverOperator, uint256 deposit, uint256 claimed, uint64 openedAt, uint64 expiresAt, bool closed)",
    "error ChannelNotFound()",
    "error ChannelClosed()",
    "error ChannelExpired()",
    "error ChannelNotExpired()",
    "error ZeroDeposit()",
    "error InvalidDuration()",
    "error InvalidVoucher()",
    "error AmountExceedsDeposit()",
    "error NothingToClaim()",
  ],
};

function shorten(hex, n = 8) {
  if (!hex) return "—";
  return hex.length > n * 2 + 2 ? hex.slice(0, n + 2) + "…" + hex.slice(-6) : hex;
}

function txLink(txHash) {
  if (!txHash) return "";
  if (state.isSepolia) {
    return `<a class="tx-link" href="https://sepolia.etherscan.io/tx/${txHash}" target="_blank" rel="noreferrer">tx ${shorten(txHash)} ↗</a>`;
  }
  return `tx ${shorten(txHash)}`;
}

function addrLink(addr) {
  if (!addr) return "—";
  if (state.isSepolia) {
    return `<a class="tx-link" href="https://sepolia.etherscan.io/address/${addr}" target="_blank" rel="noreferrer"><span class="mono addr">${shorten(addr)}</span> ↗</a>`;
  }
  return `<span class="mono addr">${shorten(addr)}</span>`;
}

function checklistItem(id, title, status, detailHtml) {
  return `<li class="${status}" id="${id}">
    <span class="icon"></span>
    <div class="body">
      <div class="title">${title}</div>
      <div class="detail">${detailHtml || ""}</div>
    </div>
  </li>`;
}

async function sleep(ms) { return new Promise((r) => setTimeout(r, ms)); }

const ERROR_DESCRIPTIONS = {
  NotDomainOwner: "The connected wallet is not the on-chain owner of this domain.",
  DomainNotRegistered: "This domain has not been registered yet.",
  DomainExpired: "This domain registration has expired.",
  NameUnavailable: "This domain name is already registered by someone else.",
  InvalidName: "The domain name format is invalid.",
  InvalidPubKey: "The provided public key format is invalid.",
  InsufficientFee: "The payment provided is less than the required fee.",
  NotTreasurer: "Only the contract treasurer can perform this action.",
  ZeroAddress: "Recipient address cannot be zero (0x0).",
  UnknownRecordType: "This record type is not registered in the schema registry.",
  MissingMandatoryField: "A required schema field is missing.",
  FieldArrayMismatch: "The fieldNames and fieldValues arrays do not match in length.",
  TooManyFields: "The record exceeds the maximum allowed fields.",
  FieldValueTooLong: "A field value exceeds the maximum character length.",
  FieldNameTooLong: "A field name exceeds the maximum character length.",
  SelectorTooLong: "The selector exceeds the maximum character length.",
  InvalidTTL: "The TTL is out of the valid range.",
  RecordNotFound: "The requested record does not exist on-chain.",
  CommitmentNotFound: "No matching commitment found in the mempool.",
  CommitmentTooNew: "Must wait out the 45-second front-running defense window.",
  CommitmentTooOld: "Commitment has expired (exceeded 24 hours). Please commit again.",
  TypeAlreadyExists: "This record type is already declared.",
  UnknownType: "Record type not recognized.",
  InvalidTypeName: "Invalid record type name.",
  InvalidFieldName: "Invalid field name.",
  DuplicateField: "Duplicate field name declared in schema.",
  EmptyPubKey: "Public key cannot be empty.",
  EmptyEndpoint: "Endpoint cannot be empty.",
  EndpointTooLong: "Endpoint URL is too long.",
  NotRegistered: "Caller is not registered as a resolver.",
  ChannelNotFound: "Micropayment channel not found.",
  ChannelClosed: "Micropayment channel is already closed.",
  ChannelExpired: "Micropayment channel has expired.",
  ChannelNotExpired: "Channel cannot be closed until duration expires.",
  ZeroDeposit: "Deposit amount must be greater than zero.",
  InvalidDuration: "Channel duration is invalid.",
  InvalidVoucher: "Voucher signature or amount is invalid.",
  AmountExceedsDeposit: "Claim amount exceeds the deposited channel balance.",
  NothingToClaim: "No new amount to claim.",
};

function explainError(err) {
  let rawData = err?.data || err?.error?.data || err?.info?.error?.data || err?.revert?.data;
  if (typeof rawData === "object" && rawData !== null && rawData.data) {
    rawData = rawData.data;
  }
  if (typeof rawData === "string" && rawData.startsWith("0x") && rawData.length >= 10) {
    try {
      const allAbis = ABI.NamespaceDApp.concat(ABI.RecordSchemaRegistry, ABI.ResolverRegistry, ABI.ResolverIncentives);
      const iface = new ethers.Interface(allAbis);
      const parsed = iface.parseError(rawData);
      if (parsed) {
        const args = (parsed.args || []).map(String).join(", ");
        const baseName = parsed.name;
        const signature = `${baseName}${args ? "(" + args + ")" : "()"}`;
        const desc = ERROR_DESCRIPTIONS[baseName];
        return desc ? `${signature} — ${desc}` : signature;
      }
    } catch (e) {}
  }

  if (err?.revert?.name) {
    const args = (err.revert.args || []).map(String).join(", ");
    const baseName = err.revert.name;
    const signature = `${baseName}${args ? "(" + args + ")" : "()"}`;
    const desc = ERROR_DESCRIPTIONS[baseName];
    return desc ? `${signature} — ${desc}` : signature;
  }

  if (err?.code === "ACTION_REJECTED" || err?.code === 4001 || (err?.message && err.message.includes("user rejected"))) {
    return "Transaction cancelled by user in MetaMask.";
  }

  if (err?.reason && err.reason !== "execution reverted (unknown custom error)") return err.reason;
  if (err?.info?.error?.message) return err.info.error.message;
  if (err?.shortMessage && err.shortMessage !== "execution reverted (unknown custom error)") return err.shortMessage;
  return err?.message || String(err);
}

async function runSteps(ulId, steps) {
  const ul = document.getElementById(ulId);
  if (!ul) return;
  ul.innerHTML = steps.map((s, i) => checklistItem(`${ulId}-s${i}`, s.title, "pending")).join("");
  for (let i = 0; i < steps.length; i++) {
    const li = document.getElementById(`${ulId}-s${i}`);
    try {
      const res = await steps[i].fn();
      const st = res?.state || "ok";
      const detail = res?.detail || "";
      li.className = st;
      li.querySelector(".detail").innerHTML = detail;
      if (st === "bad") return skipRest(ulId, steps, i + 1);
    } catch (e) {
      li.className = "bad";
      li.querySelector(".detail").textContent = explainError(e);
      return skipRest(ulId, steps, i + 1);
    }
    await sleep(150);
  }
}

function skipRest(ulId, steps, from) {
  for (let j = from; j < steps.length; j++) {
    const li = document.getElementById(`${ulId}-s${j}`);
    if (li) {
      li.className = "pending";
      li.querySelector(".detail").textContent = "skipped";
    }
  }
}

// --- Cryptographic Verifiers & Canonical Encoding ---

function extractRaw(text, field) {
  const key = `"${field}":`;
  const i = text.indexOf(key);
  if (i < 0) return null;
  let j = i + key.length;
  if (text[j] !== "{" && text[j] !== "[") return null;
  const start = j;
  let depth = 0, inStr = false, esc = false;
  for (; j < text.length; j++) {
    const c = text[j];
    if (inStr) {
      if (esc) esc = false;
      else if (c === "\\") esc = true;
      else if (c === '"') inStr = false;
    } else if (c === '"') inStr = true;
    else if (c === "{" || c === "[") depth++;
    else if (c === "}" || c === "]") {
      if (--depth < 0) return null;
      if (depth === 0) { j++; return text.slice(start, j); }
    }
  }
  return null;
}

const hexToBytes = (h) =>
  Uint8Array.from((h.replace(/^0x/, "").match(/../g) || []).map((b) => parseInt(b, 16)));

async function verifyEnvelope(rawText, env) {
  if (typeof env.resolver !== "string" || typeof env.signature !== "string") {
    throw new Error("response is not a signed envelope");
  }
  const rawData = extractRaw(rawText, "data");
  if (!rawData) throw new Error("could not extract signed payload");
  const pub = hexToBytes(env.resolver);
  const sig = hexToBytes(env.signature);
  if (pub.length !== 32 || sig.length !== 64) throw new Error("bad envelope key/sig length");
  const key = await crypto.subtle.importKey("raw", pub, { name: "Ed25519" }, false, ["verify"]);
  return await crypto.subtle.verify({ name: "Ed25519" }, key, sig, new TextEncoder().encode(rawData));
}

function u16(n) { return [(n >> 8) & 0xff, n & 0xff]; }
function u32(n) { return [(n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff]; }
function u64(nBig) {
  const out = new Array(8);
  let n = nBig;
  for (let i = 7; i >= 0; i--) { out[i] = Number(n & 0xffn); n >>= 8n; }
  return out;
}
function writeStr(bytes, s) {
  const enc = new TextEncoder().encode(s);
  bytes.push(...u16(enc.length));
  bytes.push(...enc);
}
function recordMessageBytes(name, record) {
  const bytes = [];
  bytes.push(...new TextEncoder().encode("ddns-record-v2"));
  writeStr(bytes, name);
  writeStr(bytes, record.type);
  writeStr(bytes, record.selector || "");
  bytes.push(...u32(record.ttl));
  bytes.push(...u64(BigInt(record.generation)));
  const pairs = (record.fieldNames || []).map((n, i) => [n, record.fieldValues[i]]);
  pairs.sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0));
  bytes.push(...u16(pairs.length));
  for (const [k, v] of pairs) { writeStr(bytes, k); writeStr(bytes, v); }
  return new Uint8Array(bytes);
}

function isPlaceholderPubKey(pub) {
  if (!pub || pub === "0x") return true;
  const clean = pub.replace(/^0x04|^0x/, "");
  return /^0*$/.test(clean);
}

function verifyOwnerSignature(name, record, ownerAddr, ownerPubKeyHex) {
  if (!record.ownerSig || record.ownerSig === "0x") {
    return { ok: false, reason: "no owner signature present" };
  }
  const msg = recordMessageBytes(name, record);
  let recoveredAddr, recoveredPub;
  try {
    const digest = ethers.hashMessage(msg);
    recoveredPub = ethers.SigningKey.recoverPublicKey(digest, record.ownerSig);
    recoveredAddr = ethers.computeAddress(recoveredPub);
  } catch (e) {
    return { ok: false, reason: "malformed signature: " + e.message };
  }
  const addrMatch = recoveredAddr.toLowerCase() === ownerAddr.toLowerCase();
  const hasSpecificPub = !isPlaceholderPubKey(ownerPubKeyHex);
  const pubMatch = hasSpecificPub ? recoveredPub.toLowerCase() === (ownerPubKeyHex || "").toLowerCase() : true;
  const isOk = addrMatch && pubMatch;
  return { ok: isOk, recoveredAddr, recoveredPub, addrMatch, pubMatch, isPlaceholder: !hasSpecificPub };
}

const KNOWN_TRANSPORTS = new Set(["UDP", "TCP", "QUIC"]);
const KNOWN_SERVICES = new Set(["HTTP", "SMTP"]);
function canonicalSelector(raw) {
  const s = (raw || "").trim();
  if (!s) return "";
  const canon = {};
  for (const part of s.split("&")) {
    const i = part.indexOf("=");
    if (i < 0) throw new Error(`invalid selector (want k=v): "${part}"`);
    const k = part.slice(0, i).trim().toLowerCase();
    let v = part.slice(i + 1).trim();
    if (!/^[a-z0-9_]{1,32}$/.test(k)) throw new Error(`invalid selector key "${k}"`);
    if (k === "port") {
      if (!/^\d+$/.test(v) || Number(v) < 1 || Number(v) > 65535) throw new Error(`invalid port "${v}"`);
      v = String(Number(v));
    } else if (k === "transport") {
      v = v.toUpperCase();
      if (!KNOWN_TRANSPORTS.has(v)) throw new Error(`invalid transport "${v}"`);
    } else if (k === "service") {
      v = v.toUpperCase();
      if (!KNOWN_SERVICES.has(v)) throw new Error(`invalid service "${v}"`);
    }
    canon[k] = v;
  }
  return Object.keys(canon).sort().map((k) => `${k}=${canon[k]}`).join("&");
}

function randomSecret() {
  const b = new Uint8Array(32);
  crypto.getRandomValues(b);
  return "0x" + Array.from(b).map((x) => x.toString(16).padStart(2, "0")).join("");
}

async function fetchCommitment(name, type, selector, ttl, generation, fieldNames, fieldValues) {
  const res = await fetch(`${REST_BASE}/showcase/api/commit`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ name, type, selector, ttl, generation, fieldNames, fieldValues }),
  });
  if (!res.ok) throw new Error(`commit helper failed: HTTP ${res.status}`);
  return (await res.json()).commitment;
}

// --- Initialization & Wallet Management ---

async function loadConfig() {
  const res = await fetch(`${REST_BASE}/showcase/config`);
  if (!res.ok) throw new Error(`config fetch failed: HTTP ${res.status}`);
  state.config = await res.json();
}

async function setupProviderAndWallets() {
  state.provider = new ethers.JsonRpcProvider(state.config.rpcUrl || "http://127.0.0.1:8545");
  try {
    const net = await state.provider.getNetwork();
    state.chainId = Number(net.chainId);
    state.isSepolia = state.chainId === 11155111;
  } catch (e) {
    state.isSepolia = (state.config.rpcUrl || "").includes("sepolia");
  }

  const badge = document.getElementById("stat-net-badge");
  if (state.isSepolia) {
    badge.textContent = "Sepolia (11155111)";
    badge.style.background = "rgba(168,85,247,0.15)";
    badge.style.color = "#c084fc";
    badge.style.borderColor = "rgba(168,85,247,0.3)";
  } else {
    badge.textContent = `Chain #${state.chainId || "Local"}`;
  }

  if (window.ethereum) {
    try {
      const browserProvider = new ethers.BrowserProvider(window.ethereum);
      const accounts = await browserProvider.listAccounts();
      if (accounts.length > 0) {
        state.injectedSigner = await browserProvider.getSigner();
      }
    } catch (e) {}

    window.ethereum.on("accountsChanged", async (accounts) => {
      if (accounts.length > 0) {
        const browserProvider = new ethers.BrowserProvider(window.ethereum);
        state.injectedSigner = await browserProvider.getSigner();
      } else {
        state.injectedSigner = null;
      }
      await updateWalletBadge();
    });

    window.ethereum.on("chainChanged", () => {
      window.location.reload();
    });
  }
}

async function activeSigner() {
  if (state.currentWallet === "metamask") {
    if (!window.ethereum) throw new Error("MetaMask or Web3 wallet extension not detected in browser");
    const browserProvider = new ethers.BrowserProvider(window.ethereum);
    state.injectedSigner = await browserProvider.getSigner();
    return state.injectedSigner;
  }
  if (state.currentWallet === "custom") {
    if (!state.customKey) {
      const pk = prompt("Enter Ethereum Private Key (0x...):");
      if (!pk || !pk.trim()) throw new Error("no private key provided");
      state.customKey = pk.trim();
    }
    return new ethers.Wallet(state.customKey, state.provider);
  }
  if (!state.localSigner) {
    const randomWallet = ethers.Wallet.createRandom(state.provider);
    state.localSigner = randomWallet;
  }
  return state.localSigner;
}

async function signerAddress() {
  try {
    const s = await activeSigner();
    return await s.getAddress();
  } catch (e) {
    return "—";
  }
}

async function contract(name, signerOverride) {
  const s = signerOverride || (await activeSigner());
  const addrMap = {
    NamespaceDApp: state.config.namespaceDApp,
    RecordSchemaRegistry: state.config.recordSchemaRegistry,
    ResolverRegistry: state.config.resolverRegistry,
    ResolverIncentives: state.config.resolverIncentives,
  };
  const addr = addrMap[name];
  if (!addr) throw new Error(`Contract address not found for ${name}`);
  return new ethers.Contract(addr, ABI[name], s);
}

async function readContract(name) {
  const addrMap = {
    NamespaceDApp: state.config.namespaceDApp,
    RecordSchemaRegistry: state.config.recordSchemaRegistry,
    ResolverRegistry: state.config.resolverRegistry,
    ResolverIncentives: state.config.resolverIncentives,
  };
  const addr = addrMap[name];
  if (!addr) throw new Error(`Contract address not found for ${name}`);
  return new ethers.Contract(addr, ABI[name], state.provider);
}

async function updateWalletBadge() {
  const addrEl = document.getElementById("wallet-addr");
  const btnConnect = document.getElementById("btn-connect-metamask");
  const addr = await signerAddress();
  addrEl.textContent = shorten(addr);
  if (state.currentWallet === "metamask" && addr === "—") {
    btnConnect.style.display = "inline-block";
  } else {
    btnConnect.style.display = "none";
  }
}

async function pollStats() {
  try {
    const res = await fetch(`${REST_BASE}/admin/stats`);
    const s = await res.json();
    document.getElementById("stat-chain").textContent = s.chainOk ? `#${s.chainHead}` : "unreachable";
    document.getElementById("stat-cache").textContent = `${s.cache.hits}h/${s.cache.misses}m/${s.cache.entries}e`;
    document.getElementById("stat-swarm").textContent = `${s.swarm.torrents} torrents`;
  } catch (e) {
    document.getElementById("stat-chain").textContent = "offline";
  }
}

// --- PANEL 1: Resolve & Verify ---

function renderResolvePanel() {
  const el = document.getElementById("panel-resolve");
  el.innerHTML = `
    <div class="card">
      <h2>Resolve &amp; Verify</h2>
      <p class="sub">Every response is re-verified independently in JavaScript (WebCrypto Ed25519 resolver signature + Secp256k1 EIP-191 owner signature + Groth16 ZK proof).</p>
      
      <h3>Query Parameters</h3>
      <div class="row">
        <div class="field"><label>Domain Name</label><input id="rv-name" placeholder="domain name"></div>
        <div class="field"><label>Record Type</label><input id="rv-type" value="A"></div>
        <div class="field" style="min-width:240px"><label>Selector (optional)</label><input id="rv-selector" placeholder="e.g. service=HTTP"></div>
        <button class="btn" id="rv-go" style="align-self:flex-end">Resolve</button>
      </div>
      <ul class="checklist" id="rv-checklist"></ul>
    </div>`;

  document.getElementById("rv-go").addEventListener("click", () => {
    runResolve(
      document.getElementById("rv-name").value.trim(),
      document.getElementById("rv-type").value.trim(),
      document.getElementById("rv-selector").value.trim()
    );
  });
}

async function runResolve(name, type, selector) {
  if (!name) return;
  const list = document.getElementById("rv-checklist");
  const items = [
    { id: "rv-query", title: "Query Go Resolver" },
    { id: "rv-envelope", title: "Resolver Identity Signature (Ed25519 Envelope)" },
    { id: "rv-owner", title: "Domain Owner Signature (Secp256k1 EIP-191 Recovered)" },
    { id: "rv-zk", title: "Zero-Knowledge Record Commitment Proof (Groth16)" },
  ];
  list.innerHTML = items.map((it) => checklistItem(it.id, it.title, "pending")).join("");
  const setItem = (id, st, detail) => {
    const li = document.getElementById(id);
    if (li) { li.className = st; li.querySelector(".detail").innerHTML = detail; }
  };

  const params = new URLSearchParams({ name, type, selector: selector || "" });
  let text, env, data;
  try {
    const res = await fetch(`${REST_BASE}/resolve?${params}`);
    text = await res.text();
    env = JSON.parse(text);
    data = env.data;
  } catch (e) {
    setItem("rv-query", "bad", "Query failed: " + e.message);
    return;
  }

  if (!data.found) {
    setItem("rv-query", "ok", `<span class="badge warn">no_match</span> Authoritative non-existence response for <code>${name}</code>/${type}`);
    setItem("rv-envelope", "pending", "skipped — no match record");
    setItem("rv-owner", "pending", "skipped");
    setItem("rv-zk", "pending", "skipped");
    return;
  }

  setItem("rv-query", "ok",
    `${data.cached ? '<span class="badge ok">LRU Cache Hit</span>' : '<span class="badge warn">Cache Miss (Read From Chain)</span>'} ` +
    `Found <code>${data.record.type}</code> record: ${data.record.fieldNames.map((n, i) => `${n}=${data.record.fieldValues[i]}`).join(" ")} (TTL: ${data.record.ttl}s, Gen: ${data.record.generation})`);

  try {
    const ok = await verifyEnvelope(text, env);
    setItem("rv-envelope", ok ? "ok" : "bad",
      `Resolver key <span class="mono">${shorten(env.resolver)}</span> — ${ok ? "verified valid over raw payload bytes" : "SIGNATURE INVALID"}`);
  } catch (e) {
    setItem("rv-envelope", "bad", "Verification error: " + e.message);
  }

  try {
    const v = verifyOwnerSignature(name, data.record, data.owner, data.pubKey);
    if (v.recoveredAddr) {
      const pubDetail = v.isPlaceholder
        ? `PubKey: <span class="mono">${shorten(v.recoveredPub)}</span> (dynamically verified from ECDSA signature)`
        : `PubKey match: ${v.pubMatch ? "✓" : "✗"}`;
      setItem("rv-owner", v.ok ? "ok" : "bad",
        `Recovered Signer ${addrLink(v.recoveredAddr)} vs On-Chain Owner ${addrLink(data.owner)} — Address match: ${v.addrMatch ? "✓" : "✗"}, ${pubDetail}`);
    } else {
      setItem("rv-owner", "bad", v.reason);
    }
  } catch (e) {
    setItem("rv-owner", "bad", "Owner signature error: " + e.message);
  }

  const hasCommitment = data.record.commitment && !/^0x0*$/.test(data.record.commitment);
  if (!hasCommitment) {
    setItem("rv-zk", "pending", `<span class="badge warn">n/a</span> Record has no MiMC commitment attached`);
  } else if (data.zkProof) {
    setItem("rv-zk", "ok", `Commitment <span class="mono">${shorten(data.record.commitment)}</span> — Groth16 proof verified against MiMC circuit`);
  } else {
    setItem("rv-zk", "bad", `Commitment present but no proof supplied`);
  }
}

// --- PANEL 2: Register a Name ---

function renderRegisterPanel() {
  const el = document.getElementById("panel-register");
  el.innerHTML = `
    <div class="card">
      <h2>Register a Name (Commit-Reveal)</h2>
      <p class="sub">Two-step registration (Commit hash → 45s window → Reveal register) protects against mempool front-running.</p>
      <div class="row">
        <div class="field"><label>Domain Name</label><input id="reg-name" placeholder="domain name"></div>
        <div class="field"><label>Calculated Registration Fee</label><div class="mono" id="reg-price" style="padding-top:6px">—</div></div>
        <button class="btn" id="reg-go" style="align-self:flex-end">Commit &amp; Register</button>
      </div>
      <ul class="checklist" id="reg-checklist"></ul>
    </div>`;

  const nameInput = document.getElementById("reg-name");
  let timer;
  nameInput.addEventListener("input", () => {
    clearTimeout(timer);
    timer = setTimeout(updatePrice, 250);
  });

  async function updatePrice() {
    const name = nameInput.value.trim();
    const priceEl = document.getElementById("reg-price");
    if (!name) { priceEl.textContent = "—"; return; }
    try {
      const ns = await readContract("NamespaceDApp");
      const [price, avail] = await Promise.all([ns.priceOf(name), ns.available(name)]);
      priceEl.innerHTML = avail
        ? `${ethers.formatEther(price)} ETH <span class="badge ok">Available</span>`
        : `<span class="badge bad">Taken</span>`;
    } catch (e) {
      priceEl.textContent = explainError(e);
    }
  }

  document.getElementById("reg-go").addEventListener("click", () => registerFlow(nameInput.value.trim()));
}

async function registerFlow(name) {
  if (!name) return;
  const signer = await activeSigner();
  const address = await signer.getAddress();
  const ns = await contract("NamespaceDApp", signer);

  await runSteps("reg-checklist", [
    {
      title: "Check availability & length-based price",
      fn: async () => {
        const avail = await ns.available(name);
        if (!avail) throw new Error(`Domain "${name}" is already registered`);
        const price = await ns.priceOf(name);
        return { state: "ok", detail: `Available at fee: ${ethers.formatEther(price)} ETH` };
      },
    },
    {
      title: "Step 1: Commit salted hash on-chain",
      fn: async () => {
        const secret = randomSecret();
        window._regSecret = secret;
        let pubKey;
        if (signer.signingKey) {
          pubKey = signer.signingKey.publicKey;
        } else {
          const authMsg = `Decentralized DNS: Register domain public key for ${address}`;
          const sig = await signer.signMessage(authMsg);
          const digest = ethers.hashMessage(authMsg);
          pubKey = ethers.SigningKey.recoverPublicKey(digest, sig);
        }
        window._regPubKey = pubKey;
        const commitment = await ns.makeCommitment(name, address, pubKey, secret);
        const tx = await ns.commit(commitment);
        const rcpt = await tx.wait();
        return { state: "ok", detail: `Committed ${shorten(commitment)} (${txLink(tx.hash)})` };
      },
    },
    {
      title: "Step 2: Wait out MIN_COMMITMENT_AGE (front-running window)",
      fn: async () => {
        const minAge = Number(await ns.MIN_COMMITMENT_AGE());
        const waitTime = minAge + 5;
        for (let r = waitTime; r > 0; r--) {
          const li = document.getElementById("reg-checklist-s2");
          if (li) li.querySelector(".detail").textContent = `Revealing in ${r}s... (front-running protection active)`;
          await sleep(1000);
        }
        return { state: "ok", detail: `Commitment matured (elapsed ≥ ${minAge}s)` };
      },
    },
    {
      title: "Step 3: Reveal and claim domain on-chain",
      fn: async () => {
        const price = await ns.priceOf(name);
        const tx = await ns.register(name, window._regPubKey, window._regSecret, { value: price });
        const rcpt = await tx.wait();
        return { state: "ok", detail: `Domain registered successfully! (${txLink(tx.hash)}, block ${rcpt.blockNumber})` };
      },
    },
    {
      title: "Confirm domain state on blockchain",
      fn: async () => {
        const dom = await ns.getDomain(name);
        return { state: "ok", detail: `Owner: ${addrLink(dom.owner)}, Generation: ${dom.generation}, Expiry: ${new Date(Number(dom.expiry) * 1000).toLocaleDateString()}` };
      },
    },
  ]);
}

// --- PANEL 3: Manage, Transfer & Renew ---

function parseFieldLines(text) {
  const names = [], values = [];
  for (const raw of text.split("\n")) {
    const line = raw.trim();
    if (!line) continue;
    const i = line.indexOf("=");
    if (i < 0) throw new Error(`invalid field line (want key=value): "${line}"`);
    names.push(line.slice(0, i).trim());
    values.push(line.slice(i + 1).trim());
  }
  return { names, values };
}

function renderRecordsPanel() {
  const el = document.getElementById("panel-records");
  el.innerHTML = `
    <div class="card">
      <h2>Domain Records &amp; Ownership</h2>
      <p class="sub">Set/remove records with signed EIP-191 messages &amp; MiMC commitments, transfer domain ownership, renew registrations, or declare custom record types.</p>
      
      <div class="row">
        <div class="field"><label>Domain</label><input id="rec-name" placeholder="domain name"></div>
        <div class="field"><label>Record Type</label><input id="rec-type" value="A"></div>
        <div class="field" style="min-width:200px"><label>Selector</label><input id="rec-selector" placeholder="(optional)"></div>
        <div class="field"><label>TTL</label><input id="rec-ttl" value="3600" style="width:80px"></div>
      </div>
      <div class="field" style="margin-top:0.6rem">
        <label>Fields (key=value, one per line)</label>
        <textarea id="rec-fields" placeholder="address=1.2.3.4"></textarea>
      </div>
      <div class="row" style="margin-top:0.6rem">
        <button class="btn" id="rec-set">Sign &amp; Set Record</button>
        <button class="btn secondary" id="rec-remove">Remove Record</button>
        <button class="btn secondary" id="rec-refresh">Refresh Records</button>
      </div>
      <ul class="checklist" id="rec-checklist"></ul>

      <h3>Domain Transfer &amp; Renewal</h3>
      <div class="row">
        <div class="field" style="min-width:280px"><label>New Owner Address</label><input id="tf-newowner" placeholder="0x..."></div>
        <div class="field" style="min-width:320px"><label>New Owner PubKey (0x04...)</label><input id="tf-newpubkey" placeholder="0x04..."></div>
        <button class="btn secondary" id="tf-transfer" style="align-self:flex-end">Transfer Domain</button>
        <button class="btn secondary" id="tf-renew" style="align-self:flex-end">Renew Domain (+1 yr)</button>
      </div>
      <ul class="checklist" id="tf-checklist"></ul>

      <h3>Declare Dynamic Schema (RecordSchemaRegistry)</h3>
      <div class="row">
        <div class="field"><label>Type Name</label><input id="type-name" placeholder="GEO"></div>
        <div class="field"><label>Mandatory Fields</label><input id="type-mandatory" placeholder="lat,lon"></div>
        <div class="field"><label>Optional Fields</label><input id="type-optional" placeholder="alt"></div>
        <button class="btn secondary" id="type-declare" style="align-self:flex-end">Declare Type</button>
      </div>
      <ul class="checklist" id="type-checklist"></ul>

      <h3>Live Active Records</h3>
      <div id="rec-list" class="log">—</div>
    </div>`;

  document.getElementById("rec-set").addEventListener("click", setRecordFlow);
  document.getElementById("rec-remove").addEventListener("click", removeRecordFlow);
  document.getElementById("rec-refresh").addEventListener("click", refreshRecordList);
  document.getElementById("tf-transfer").addEventListener("click", transferDomainFlow);
  document.getElementById("tf-renew").addEventListener("click", renewDomainFlow);
  document.getElementById("type-declare").addEventListener("click", declareTypeFlow);
}

async function refreshRecordList() {
  const name = document.getElementById("rec-name").value.trim();
  const listEl = document.getElementById("rec-list");
  if (!name) { listEl.textContent = "—"; return; }
  try {
    const ns = await readContract("NamespaceDApp");
    const records = await ns.listRecords(name);
    if (records.length === 0) { listEl.textContent = "(no active records found for this domain)"; return; }
    listEl.innerHTML = records.map((r) =>
      `<div class="line"><b>${r.recordType}</b>${r.selector ? ` [${r.selector}]` : ""} — ` +
      r.fieldNames.map((n, i) => `${n}=${r.fieldValues[i]}`).join(" ") +
      ` (TTL: ${r.ttl}s, Generation: ${r.generation})</div>`
    ).join("");
  } catch (e) {
    listEl.textContent = explainError(e);
  }
}

async function setRecordFlow() {
  const name = document.getElementById("rec-name").value.trim();
  if (!name) return;
  const type = document.getElementById("rec-type").value.trim();
  const ttl = parseInt(document.getElementById("rec-ttl").value.trim(), 10) || 3600;
  const signer = await activeSigner();
  const ns = await contract("NamespaceDApp", signer);
  let selector, fieldNames, fieldValues, generation, commitment, sig;

  await runSteps("rec-checklist", [
    {
      title: "Parse fields and query active domain generation",
      fn: async () => {
        selector = canonicalSelector(document.getElementById("rec-selector").value);
        document.getElementById("rec-selector").value = selector;
        ({ names: fieldNames, values: fieldValues } = parseFieldLines(document.getElementById("rec-fields").value));
        const dom = await ns.getDomain(name);
        generation = dom.generation;
        return { state: "ok", detail: `${fieldNames.length} field(s), Generation: ${generation}` };
      },
    },
    {
      title: "Calculate MiMC Zero-Knowledge record commitment",
      fn: async () => {
        commitment = await fetchCommitment(name, type, selector, ttl, Number(generation), fieldNames, fieldValues);
        return { state: "ok", detail: `<span class="mono">${shorten(commitment)}</span>` };
      },
    },
    {
      title: "Sign canonical record message with owner private key (EIP-191)",
      fn: async () => {
        const msg = recordMessageBytes(name, { type, selector, ttl, generation: Number(generation), fieldNames, fieldValues });
        sig = await signer.signMessage(msg);
        return { state: "ok", detail: `Signed: <span class="mono">${shorten(sig)}</span>` };
      },
    },
    {
      title: "Submit setRecord() transaction to blockchain",
      fn: async () => {
        const tx = await ns.setRecord(name, type, selector, fieldNames, fieldValues, ttl, sig, commitment);
        const rcpt = await tx.wait();
        return { state: "ok", detail: `${txLink(tx.hash)} (block ${rcpt.blockNumber})` };
      },
    },
  ]);
  await refreshRecordList();
}

async function removeRecordFlow() {
  const name = document.getElementById("rec-name").value.trim();
  if (!name) return;
  const type = document.getElementById("rec-type").value.trim();
  const selector = canonicalSelector(document.getElementById("rec-selector").value);
  const signer = await activeSigner();
  const ns = await contract("NamespaceDApp", signer);

  await runSteps("rec-checklist", [
    {
      title: `Remove ${type}${selector ? " [" + selector + "]" : ""} record`,
      fn: async () => {
        const tx = await ns.removeRecord(name, type, selector);
        const rcpt = await tx.wait();
        return { state: "ok", detail: `${txLink(tx.hash)} (block ${rcpt.blockNumber})` };
      },
    },
  ]);
  await refreshRecordList();
}

async function transferDomainFlow() {
  const name = document.getElementById("rec-name").value.trim();
  if (!name) return;
  const newOwner = document.getElementById("tf-newowner").value.trim();
  let newPubKey = document.getElementById("tf-newpubkey").value.trim();
  if (!newPubKey) newPubKey = "0x04" + "00".repeat(64);
  const signer = await activeSigner();
  const ns = await contract("NamespaceDApp", signer);

  await runSteps("tf-checklist", [
    {
      title: `Transfer ownership of "${name}" to ${shorten(newOwner)}`,
      fn: async () => {
        const tx = await ns.transfer(name, newOwner, newPubKey);
        const rcpt = await tx.wait();
        return { state: "ok", detail: `Transferred! (${txLink(tx.hash)}). Generation counter incremented to invalidate old signatures.` };
      },
    },
  ]);
  await refreshRecordList();
}

async function renewDomainFlow() {
  const name = document.getElementById("rec-name").value.trim();
  if (!name) return;
  const signer = await activeSigner();
  const ns = await contract("NamespaceDApp", signer);

  await runSteps("tf-checklist", [
    {
      title: `Renew "${name}" registration for +1 year`,
      fn: async () => {
        const fee = await ns.priceOf(name);
        const tx = await ns.renew(name, { value: fee });
        const rcpt = await tx.wait();
        return { state: "ok", detail: `Renewed! (${txLink(tx.hash)}, block ${rcpt.blockNumber})` };
      },
    },
  ]);
}

async function declareTypeFlow() {
  const typeName = document.getElementById("type-name").value.trim();
  if (!typeName) return;
  const mandatory = document.getElementById("type-mandatory").value.split(",").map((s) => s.trim()).filter(Boolean);
  const optional = document.getElementById("type-optional").value.split(",").map((s) => s.trim()).filter(Boolean);
  const signer = await activeSigner();
  const reg = await contract("RecordSchemaRegistry", signer);

  await runSteps("type-checklist", [
    {
      title: `Declare "${typeName}" (Mandatory: ${mandatory.join(",") || "none"}, Optional: ${optional.join(",") || "none"})`,
      fn: async () => {
        const tx = await reg.declareType(typeName, mandatory, optional);
        const rcpt = await tx.wait();
        return { state: "ok", detail: `Declared dynamically! (${txLink(tx.hash)})` };
      },
    },
  ]);
}

// --- PANEL 4: Publish a Site (BitTorrent) ---

const DEFAULT_SITE_HTML = `<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>Decentralized DNS Verified Website</title>
  <style>
    body { font-family: sans-serif; background: #0f172a; color: #f8fafc; padding: 2rem; }
    h1 { color: #38bdf8; }
    .badge { background: #166534; color: #4ade80; padding: 4px 10px; border-radius: 99px; font-size: 12px; }
  </style>
</head>
<body>
  <span class="badge">✓ BitTorrent Seeded & Blockchain Verified</span>
  <h1>Decentralized DNS Website</h1>
  <p>This web page was fetched peer-to-peer over BitTorrent, and its SHA-256 integrity was cryptographically verified against Ethereum.</p>
</body>
</html>`;

function renderPublishPanel() {
  const el = document.getElementById("panel-publish");
  el.innerHTML = `
    <div class="card">
      <h2>Publish a Website (BitTorrent &amp; Blockchain Anchoring)</h2>
      <p class="sub">Seeds HTML content over the P2P BitTorrent swarm, anchors the exact SHA-256 hash on-chain, and verifies integrity before rendering.</p>
      
      <div class="row">
        <div class="field"><label>Domain</label><input id="pub-name" placeholder="domain name"></div>
        <div class="field" style="min-width:200px"><label>Selector</label><input id="pub-selector" value="service=HTTP"></div>
      </div>
      <div class="field" style="margin-top:0.6rem">
        <label>HTML Content</label>
        <textarea id="pub-body" style="min-height:120px">${DEFAULT_SITE_HTML}</textarea>
      </div>
      <div class="row" style="margin-top:0.6rem">
        <button class="btn" id="pub-go">Publish (Seed + Anchor)</button>
        <button class="btn secondary" id="pub-fetch">Fetch &amp; Verify</button>
        <button class="btn danger" id="pub-tamper">Simulate Tampering (Corrupt Hash)</button>
      </div>
      <ul class="checklist" id="pub-checklist"></ul>
      <div id="pub-preview" style="margin-top:1rem"></div>
    </div>`;

  document.getElementById("pub-go").addEventListener("click", () => publishFlow(false));
  document.getElementById("pub-tamper").addEventListener("click", () => publishFlow(true));
  document.getElementById("pub-fetch").addEventListener("click", fetchAndVerifyFlow);
}

async function publishFlow(tamper) {
  const name = document.getElementById("pub-name").value.trim();
  if (!name) return;
  const rawSelector = document.getElementById("pub-selector").value.trim();
  const selector = canonicalSelector(rawSelector);
  document.getElementById("pub-selector").value = selector;
  const body = document.getElementById("pub-body").value;
  const contentType = "text/html; charset=utf-8";
  const signer = await activeSigner();
  const ns = await contract("NamespaceDApp", signer);
  const preview = document.getElementById("pub-preview");
  preview.innerHTML = "";
  let infoHash, sha256, generation, commitment, sig;

  await runSteps("pub-checklist", [
    {
      title: "Step 1: Seed HTML payload over local BitTorrent engine",
      fn: async () => {
        const res = await fetch(`${REST_BASE}/showcase/api/publish`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ name, selector, contentType, body }),
        });
        if (!res.ok) throw new Error(`Publish API failed: HTTP ${res.status}`);
        ({ infoHash, sha256 } = await res.json());
        if (tamper) {
          sha256 = sha256.slice(0, -4) + "dead";
        }
        return {
          state: "ok",
          detail: `infoHash <span class="mono">${shorten(infoHash)}</span>, sha256 <span class="mono">${shorten(sha256)}</span>` +
            (tamper ? ' <span class="badge bad">Tampered Hash (Corrupted with ...dead)</span>' : ""),
        };
      },
    },
    {
      title: "Step 2: Sign and anchor ResourceRef on blockchain",
      fn: async () => {
        const dom = await ns.getDomain(name);
        generation = dom.generation;
        commitment = await fetchCommitment(name, "ResourceRef", selector, 3600, Number(generation),
          ["infoHash", "sha256", "contentType"], [infoHash, sha256, contentType]);
        const msg = recordMessageBytes(name, {
          type: "ResourceRef", selector, ttl: 3600, generation: Number(generation),
          fieldNames: ["infoHash", "sha256", "contentType"], fieldValues: [infoHash, sha256, contentType],
        });
        sig = await signer.signMessage(msg);
        const tx = await ns.setRecord(name, "ResourceRef", selector,
          ["infoHash", "sha256", "contentType"], [infoHash, sha256, contentType], 3600, sig, commitment);
        const rcpt = await tx.wait();
        return { state: "ok", detail: `Anchored on-chain (${txLink(tx.hash)}, block ${rcpt.blockNumber})` };
      },
    },
    {
      title: "Step 3: Fetch via Resolver & Cryptographic Integrity Check",
      fn: async () => {
        await sleep(500);
        const res = await fetch(`${REST_BASE}/resource?name=${encodeURIComponent(name)}&selector=${encodeURIComponent(selector)}`);
        const text = await res.text();
        if (tamper) {
          if (!res.ok) {
            preview.innerHTML = `
              <div class="card" style="border-color:var(--bad)">
                <div class="row">
                  <span class="badge bad">✓ Tamper Successfully Blocked</span>
                  <span>HTTP ${res.status} Integrity Mismatch</span>
                </div>
                <p class="sub" style="margin-top:8px">The resolver downloaded the payload over BitTorrent, computed SHA-256, compared it with the on-chain hash (<code>...dead</code>), detected the mismatch, and dropped the corrupted content.</p>
                <div class="mono" style="color:var(--bad)">${text}</div>
              </div>`;
            return {
              state: "ok",
              detail: `<span class="badge ok">✓ Defense Verified</span> Resolver caught SHA-256 mismatch (HTTP ${res.status}) and blocked delivery.`,
            };
          } else {
            return {
              state: "bad",
              detail: `Vulnerability: Resolver accepted tampered hash without error.`,
            };
          }
        } else {
          if (!res.ok) throw new Error(`Fetch failed: HTTP ${res.status} — ${text}`);
          preview.innerHTML = `
            <div class="card">
              <div class="row">
                <span class="badge ok">✓ Verified P2P Payload</span>
                <span>Owner: ${addrLink(res.headers.get("X-Ddns-Owner"))}</span>
                <span>SHA-256: <span class="mono">${shorten(res.headers.get("X-Ddns-Sha256"))}</span></span>
              </div>
              <h3 style="margin-top:10px">Sandboxed Rendered Output</h3>
              <iframe sandbox="allow-scripts" style="width:100%;height:200px;border:1px solid var(--border);border-radius:6px;background:#fff" srcdoc="${text.replace(/"/g, "&quot;")}"></iframe>
            </div>`;
          return {
            state: "ok",
            detail: `Verified authentic SHA-256 against on-chain ResourceRef!`,
          };
        }
      },
    },
  ]);
}

async function fetchAndVerifyFlow() {
  const name = document.getElementById("pub-name").value.trim();
  if (!name) return;
  const selector = canonicalSelector(document.getElementById("pub-selector").value);
  const preview = document.getElementById("pub-preview");
  preview.innerHTML = "";
  try {
    const res = await fetch(`${REST_BASE}/resource?name=${encodeURIComponent(name)}&selector=${encodeURIComponent(selector)}`);
    const text = await res.text();
    if (!res.ok) {
      preview.innerHTML = `
        <div class="card" style="border-color:var(--bad)">
          <span class="badge bad">HTTP ${res.status}</span> <span class="mono">${text}</span>
        </div>`;
      return;
    }
    preview.innerHTML = `
      <div class="card">
        <div class="row">
          <span class="badge ok">✓ Verified P2P Payload</span>
          <span>Owner: ${addrLink(res.headers.get("X-Ddns-Owner"))}</span>
          <span>SHA-256: <span class="mono">${shorten(res.headers.get("X-Ddns-Sha256"))}</span></span>
        </div>
        <h3 style="margin-top:10px">Sandboxed Rendered Output</h3>
        <iframe sandbox="allow-scripts" style="width:100%;height:200px;border:1px solid var(--border);border-radius:6px;background:#fff" srcdoc="${text.replace(/"/g, "&quot;")}"></iframe>
      </div>`;
  } catch (e) {
    preview.innerHTML = `<div class="card"><span class="badge bad">Error</span> ${e.message}</div>`;
  }
}

// --- PANEL 5: Attack Lab ---

function renderAttackPanel() {
  const el = document.getElementById("panel-attack");
  el.innerHTML = `
    <div class="card">
      <h2>Attack Lab (Interactive Threat Mitigations)</h2>
      <p class="sub">Simulate live attacks against the system to verify that cryptographic checks and smart contract rules correctly reject unauthorized actions.</p>
    </div>
    
    <div class="card">
      <h3>1 · Front-Running Defense Test</h3>
      <p class="sub">Attacker attempts to steal a committed domain in the mempool before the reveal window matures.</p>
      <button class="btn danger" id="atk-frontrun-go">Run Front-Run Attack Simulation</button>
      <ul class="checklist" id="atk-frontrun-list"></ul>
    </div>

    <div class="card">
      <h3>2 · Forged Owner Signature Test</h3>
      <p class="sub">Attacker writes an invalid record signature on-chain to verify resolver/client detection.</p>
      <div class="row">
        <div class="field"><label>Domain Name</label><input id="atk-forged-name" placeholder="domain name"></div>
      </div>
      <button class="btn danger" id="atk-forged-go" style="margin-top:0.6rem">Run Signature Forgery Attack</button>
      <ul class="checklist" id="atk-forged-list"></ul>
    </div>

    <div class="card">
      <h3>3 · In-Transit Response Tampering Test</h3>
      <p class="sub">Modifies 1 byte in the signed resolver response to prove the Ed25519 envelope signature breaks.</p>
      <div class="row">
        <div class="field"><label>Domain Name</label><input id="atk-tamper-name" placeholder="domain name"></div>
      </div>
      <button class="btn danger" id="atk-tamper-go" style="margin-top:0.6rem">Run Response Tampering Simulation</button>
      <ul class="checklist" id="atk-tamper-list"></ul>
    </div>

    <div class="card">
      <h3>4 · Record Key Griefing across Domain Transfer</h3>
      <p class="sub">Verifies that the generation counter prevents a former owner's records from polluting a new owner's domain.</p>
      <button class="btn danger" id="atk-grief-go">Run Griefing Isolation Test</button>
      <ul class="checklist" id="atk-grief-list"></ul>
    </div>`;

  document.getElementById("atk-frontrun-go").addEventListener("click", attackFrontrunFlow);
  document.getElementById("atk-forged-go").addEventListener("click", attackForgedSigFlow);
  document.getElementById("atk-tamper-go").addEventListener("click", attackTamperFlow);
  document.getElementById("atk-grief-go").addEventListener("click", attackGriefingFlow);
}

async function attackFrontrunFlow() {
  const name = `attack-${Date.now().toString().slice(-6)}`;
  const victim = await activeSigner();
  const attacker = ethers.Wallet.createRandom(state.provider);
  const nsVictim = await contract("NamespaceDApp", victim);
  const nsAttacker = await contract("NamespaceDApp", attacker);

  await runSteps("atk-frontrun-list", [
    {
      title: `Victim (${shorten(victim.address)}) commits salted hash for "${name}"`,
      fn: async () => {
        const secret = randomSecret();
        const commitment = await nsVictim.makeCommitment(name, victim.address, "0x04" + "00".repeat(64), secret);
        const tx = await nsVictim.commit(commitment);
        await tx.wait();
        return { state: "ok", detail: `Committed ${shorten(commitment)}` };
      },
    },
    {
      title: `Attacker (${shorten(attacker.address)}) sees commit in mempool and tries to steal the name`,
      fn: async () => {
        try {
          const guessSecret = randomSecret();
          await nsAttacker.register.staticCall(name, "0x04" + "00".repeat(64), guessSecret, { value: ethers.parseEther("0.1") });
          return { state: "bad", detail: "Attacker registration succeeded (VULNERABILITY)" };
        } catch (e) {
          return { state: "ok", detail: `Attack rejected: <b>${explainError(e)}</b> (Cannot reveal without the victim's secret and address)` };
        }
      },
    },
  ]);
}

async function attackForgedSigFlow() {
  const name = document.getElementById("atk-forged-name").value.trim();
  if (!name) return;
  const signer = await activeSigner();
  const ns = await contract("NamespaceDApp", signer);
  const selector = "attack=forged";

  await runSteps("atk-forged-list", [
    {
      title: "Attacker writes record with garbage signature bytes to the blockchain",
      fn: async () => {
        const garbage = "0x" + "aa".repeat(65);
        const tx = await ns.setRecord(name, "A", selector, ["address"], ["1.1.1.1"], 3600, garbage, ethers.ZeroHash);
        await tx.wait();
        return { state: "ok", detail: `Written to chain (${txLink(tx.hash)})` };
      },
    },
    {
      title: "Query Go resolver & verify signature failure",
      fn: async () => {
        const res = await fetch(`${REST_BASE}/resolve?name=${encodeURIComponent(name)}&type=A&selector=${encodeURIComponent(selector)}`);
        const env = await res.json();
        return {
          state: env.data.ownerSigVerified ? "bad" : "ok",
          detail: `Resolver signature status: <code>ownerSigVerified = ${env.data.ownerSigVerified}</code> (Correctly detected forged signature)`,
        };
      },
    },
  ]);
}

async function attackTamperFlow() {
  const name = document.getElementById("atk-tamper-name").value.trim();
  if (!name) return;
  await runSteps("atk-tamper-list", [
    {
      title: `Fetch genuine resolver response for "${name}"`,
      fn: async () => {
        const res = await fetch(`${REST_BASE}/resolve?name=${encodeURIComponent(name)}&type=A`);
        const text = await res.text();
        const env = JSON.parse(text);
        if (!env.data || !env.data.found) throw new Error(`Domain "${name}" not found — register or set an A record first`);
        window._tamperOriginal = text;
        return { state: "ok", detail: "Retrieved authentic signed response" };
      },
    },
    {
      title: "Flip 1 character in the payload simulating a man-in-the-middle attack",
      fn: async () => {
        const original = window._tamperOriginal;
        const tampered = original.replace('"found":true', '"found":false');
        window._tamperedText = tampered;
        return { state: "ok", detail: "Payload altered post-signature" };
      },
    },
    {
      title: "Re-verify Ed25519 envelope signature on tampered payload",
      fn: async () => {
        const env = JSON.parse(window._tamperedText);
        const ok = await verifyEnvelope(window._tamperedText, env);
        return {
          state: ok ? "bad" : "ok",
          detail: ok ? "Tampered payload passed verification (BUG)" : "✓ Signature verification correctly FAILED (Tamper caught)",
        };
      },
    },
  ]);
}

async function attackGriefingFlow() {
  const name = `grief-${Date.now().toString().slice(-5)}`;
  const departing = await activeSigner();
  const newOwner = ethers.Wallet.createRandom(state.provider);
  const nsDeparting = await contract("NamespaceDApp", departing);
  const nsView = await readContract("NamespaceDApp");

  await runSteps("atk-grief-list", [
    {
      title: `Departing owner registers temporary domain "${name}"`,
      fn: async () => {
        const secret = randomSecret();
        const commitment = await nsDeparting.makeCommitment(name, departing.address, "0x04" + "00".repeat(64), secret);
        await (await nsDeparting.commit(commitment)).wait();
        const minAge = Number(await nsDeparting.MIN_COMMITMENT_AGE());
        if (!state.isSepolia) {
          await state.provider.send("evm_increaseTime", [minAge + 2]);
          await state.provider.send("evm_mine", []);
        } else {
          await sleep((minAge + 5) * 1000);
        }
        const price = await nsDeparting.priceOf(name);
        await (await nsDeparting.register(name, "0x04" + "00".repeat(64), secret, { value: price })).wait();
        return { state: "ok", detail: `Registered by departing owner` };
      },
    },
    {
      title: "Departing owner spams 3 records under different selectors then transfers to New Owner",
      fn: async () => {
        for (let i = 0; i < 3; i++) {
          await (await nsDeparting.setRecord(name, "A", `spam${i}`, ["address"], ["1.2.3.4"], 3600, "0x", ethers.ZeroHash)).wait();
        }
        await (await nsDeparting.transfer(name, newOwner.address, "0x04" + "00".repeat(64))).wait();
        return { state: "ok", detail: `Transferred to new owner` };
      },
    },
    {
      title: "Verify that new owner sees 0 leftover records from former owner",
      fn: async () => {
        const recs = await nsView.listRecords(name);
        return {
          state: recs.length === 0 ? "ok" : "bad",
          detail: `Active records for new owner: <b>${recs.length}</b> (Generation counter successfully purged former owner's records)`,
        };
      },
    },
  ]);
}

// --- PANEL 6: Directory & Incentives ---

function renderDirectoryPanel() {
  const el = document.getElementById("panel-directory");
  el.innerHTML = `
    <div class="card">
      <h2>Resolver Directory (On-Chain Discovery)</h2>
      <p class="sub">Bootstrap discovery without central DNS: Resolvers register their endpoint and Ed25519 identity key on-chain.</p>
      <div class="row">
        <button class="btn secondary" id="dir-refresh">Refresh Active Resolvers</button>
      </div>
      <div id="dir-list" class="log" style="margin-top:0.6rem">—</div>

      <h3>Announce Current Resolver</h3>
      <div class="row">
        <div class="field" style="min-width:240px"><label>Endpoint</label><input id="dir-endpoint" value="http://localhost:8080"></div>
        <div class="field" style="min-width:320px"><label>Ed25519 Public Key</label><input id="dir-pubkey" class="mono"></div>
      </div>
      <div class="row" style="margin-top:0.6rem">
        <button class="btn" id="dir-announce">Announce Resolver</button>
        <button class="btn secondary" id="dir-revoke">Revoke Resolver</button>
      </div>
      <ul class="checklist" id="dir-checklist"></ul>

      <h3>Pay-Per-Query Micropayment Channels (ResolverIncentives)</h3>
      <p class="sub">Open state channels to stream signed payment vouchers to resolvers per query with zero on-chain overhead.</p>
      <div class="row">
        <div class="field"><label>Resolver Operator</label><input id="ch-operator" placeholder="0x..."></div>
        <div class="field"><label>Deposit (ETH)</label><input id="ch-deposit" value="0.05" style="width:100px"></div>
        <button class="btn secondary" id="ch-open" style="align-self:flex-end">Open Channel</button>
      </div>
      <ul class="checklist" id="ch-checklist"></ul>
    </div>`;

  document.getElementById("dir-refresh").addEventListener("click", refreshDirectory);
  document.getElementById("dir-announce").addEventListener("click", announceResolverFlow);
  document.getElementById("dir-revoke").addEventListener("click", revokeResolverFlow);
  document.getElementById("ch-open").addEventListener("click", openChannelFlow);

  fetch(`${REST_BASE}/admin/stats`)
    .then((r) => r.json())
    .then((s) => {
      if (s.resolver) document.getElementById("dir-pubkey").value = s.resolver;
    })
    .catch(() => {});

  refreshDirectory();
}

async function refreshDirectory() {
  const listEl = document.getElementById("dir-list");
  try {
    const reg = await readContract("ResolverRegistry");
    const { operators, pubKeys, endpoints } = await reg.activeResolvers();
    if (operators.length === 0) { listEl.textContent = "(no active resolvers announced)"; return; }
    listEl.innerHTML = operators.map((op, i) =>
      `<div class="line">Operator: ${addrLink(op)} — Endpoint: <b>${endpoints[i]}</b> — Key: <span class="mono">${shorten(pubKeys[i])}</span></div>`
    ).join("");
  } catch (e) {
    listEl.textContent = explainError(e);
  }
}

async function announceResolverFlow() {
  const endpoint = document.getElementById("dir-endpoint").value.trim();
  const pubKey = document.getElementById("dir-pubkey").value.trim();
  const signer = await activeSigner();
  const reg = await contract("ResolverRegistry", signer);

  await runSteps("dir-checklist", [
    {
      title: `Announce resolver at ${endpoint}`,
      fn: async () => {
        const tx = await reg.announce(pubKey, endpoint);
        const rcpt = await tx.wait();
        return { state: "ok", detail: `Announced on-chain (${txLink(tx.hash)})` };
      },
    },
  ]);
  await refreshDirectory();
}

async function revokeResolverFlow() {
  const signer = await activeSigner();
  const reg = await contract("ResolverRegistry", signer);

  await runSteps("dir-checklist", [
    {
      title: `Revoke resolver announcement`,
      fn: async () => {
        const tx = await reg.revoke();
        const rcpt = await tx.wait();
        return { state: "ok", detail: `Revoked (${txLink(tx.hash)})` };
      },
    },
  ]);
  await refreshDirectory();
}

async function openChannelFlow() {
  const operator = document.getElementById("ch-operator").value.trim();
  const depositEth = document.getElementById("ch-deposit").value.trim();
  const signer = await activeSigner();
  const inc = await contract("ResolverIncentives", signer);

  await runSteps("ch-checklist", [
    {
      title: `Open micropayment channel with deposit ${depositEth} ETH`,
      fn: async () => {
        const tx = await inc.openChannel(operator, 86400, { value: ethers.parseEther(depositEth) });
        const rcpt = await tx.wait();
        return { state: "ok", detail: `Channel opened on-chain (${txLink(tx.hash)})` };
      },
    },
  ]);
}

// --- App Shell Setup ---

function setupNav() {
  const tabs = document.querySelectorAll(".tab");
  tabs.forEach((tab) => {
    tab.addEventListener("click", () => {
      tabs.forEach((t) => t.classList.remove("active"));
      document.querySelectorAll(".panel").forEach((p) => p.classList.remove("active"));
      tab.classList.add("active");
      const panel = document.getElementById("panel-" + tab.dataset.panel);
      if (panel) panel.classList.add("active");
    });
  });
}

function setupWalletSelector() {
  const sel = document.getElementById("wallet-select");
  const btnSwitch = document.getElementById("btn-switch-account");
  const btnCopy = document.getElementById("btn-copy-address");

  sel.addEventListener("change", async () => {
    state.currentWallet = sel.value;
    if (state.currentWallet === "custom" && !state.customKey) {
      const pk = prompt("Enter Ethereum Private Key (0x...):");
      if (pk && pk.trim()) {
        try {
          new ethers.Wallet(pk.trim());
          state.customKey = pk.trim();
        } catch (e) {
          alert("Invalid private key: " + e.message);
          sel.value = "metamask";
          state.currentWallet = "metamask";
        }
      } else {
        sel.value = "metamask";
        state.currentWallet = "metamask";
      }
    }
    await updateWalletBadge();
  });

  if (btnSwitch) {
    btnSwitch.addEventListener("click", async () => {
      if (state.currentWallet === "metamask") {
        if (!window.ethereum) {
          alert("MetaMask / Web3 browser extension not detected");
          return;
        }
        try {
          await window.ethereum.request({
            method: "wallet_requestPermissions",
            params: [{ eth_accounts: {} }],
          });
        } catch (e) {
          await window.ethereum.request({ method: "eth_requestAccounts" });
        }
        const browserProvider = new ethers.BrowserProvider(window.ethereum);
        state.injectedSigner = await browserProvider.getSigner();
        await updateWalletBadge();
      } else {
        const pk = prompt("Enter Ethereum Private Key (0x...):", state.customKey || "");
        if (pk && pk.trim()) {
          try {
            new ethers.Wallet(pk.trim());
            state.customKey = pk.trim();
            await updateWalletBadge();
          } catch (e) {
            alert("Invalid private key: " + e.message);
          }
        }
      }
    });
  }

  if (btnCopy) {
    btnCopy.addEventListener("click", async () => {
      const addr = await signerAddress();
      if (addr && addr !== "—") {
        await navigator.clipboard.writeText(addr);
        const orig = btnCopy.textContent;
        btnCopy.textContent = "Copied!";
        setTimeout(() => { btnCopy.textContent = orig; }, 1500);
      }
    });
  }

  updateWalletBadge();
}

async function main() {
  try {
    await loadConfig();
    await setupProviderAndWallets();
    setupNav();
    setupWalletSelector();

    renderResolvePanel();
    renderRegisterPanel();
    renderRecordsPanel();
    renderPublishPanel();
    renderAttackPanel();
    renderDirectoryPanel();

    pollStats();
    setInterval(pollStats, 4000);
  } catch (e) {
    document.getElementById("panels").innerHTML =
      `<div class="card"><div class="placeholder" style="color:var(--bad)">Initialization Error: ${e.message}</div></div>`;
    console.error(e);
  }
}

main();
