import { useCallback, useEffect, useRef, useState } from 'react';
import * as C from './crypto';
import { kvGet, kvSet, kvDel } from './idb';

const TOKEN_KEY = 'vault-token'; // sessionStorage: each browser tab has its own login
const authFetch = async (path, body) => {
  const r = await fetch(`/api/auth/${path}`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
  const d = await r.json().catch(() => ({}));
  if (!r.ok) throw Object.assign(new Error(d.error || 'Something went wrong. Try again.'), { fields: d.fields });
  return d;
};
const wsUrl = () => `${location.protocol === 'https:' ? 'wss' : 'ws'}://${location.host}/ws`;

/** Owns the socket, keys and message store. UI components only read state and call actions. */
export function useChat() {
  const [status, setStatus] = useState(() => (sessionStorage.getItem(TOKEN_KEY) ? 'restoring' : 'idle')); // restoring | idle | auth | keys | connecting | online | offline
  const [fieldErrors, setFieldErrors] = useState({});
  const [error, setError] = useState('');
  const [me, setMe] = useState(null);
  const [users, setUsers] = useState([]);
  const [messages, setMessages] = useState({});
  const [sessions, setSessions] = useState({});
  const [unread, setUnread] = useState({});
  const [verified, setVerified] = useState({});
  const [keyChanged, setKeyChanged] = useState({});
  const [stolen, setStolen] = useState({});   // attack demo: peer -> { at } while an attacker holds that chat's session key
  const R = useRef({ ws: null, id: null, me: null, users: [], keys: new Map(), stolen: new Map(), msgs: {}, sess: {}, lastHs: {}, active: null, chain: Promise.resolve(), retry: null, manual: false });

  const key = (kind, peer) => `${kind}:${R.current.me.username}:${peer}`;
  const wsSend = (o) => R.current.ws?.readyState === 1 && R.current.ws.send(JSON.stringify(o));

  const push = (peer, msg) => {
    const next = [...(R.current.msgs[peer] || []), msg];
    R.current.msgs[peer] = next;
    setMessages({ ...R.current.msgs });
    kvSet(key('msgs', peer), next);
  };
  const patch = (peer, id, p) => {
    R.current.msgs[peer] = (R.current.msgs[peer] || []).map((m) => (m.id === id ? { ...m, ...p } : m));
    setMessages({ ...R.current.msgs });
    kvSet(key('msgs', peer), R.current.msgs[peer]);
  };
  const system = (peer, text) => push(peer, { id: `sys-${crypto.randomUUID()}`, dir: 'system', ts: Date.now(), text });

  const storeSession = async (peer, keys, initiator) => {
    const s = { ...keys, since: Date.now(), initiator };
    R.current.keys.set(peer, keys);
    R.current.sess[peer] = { since: s.since, initiator };
    setSessions({ ...R.current.sess });
    await kvSet(key('session', peer), s);
  };

  const hydrate = async (peer) => {
    if (R.current.msgs[peer]) return;
    R.current.msgs[peer] = (await kvGet(key('msgs', peer))) || [];
    const s = await kvGet(key('session', peer));
    if (s) { R.current.keys.set(peer, { aes: s.aes, mac: s.mac }); R.current.sess[peer] = { since: s.since, initiator: s.initiator }; }
    const v = await kvGet(key('verified', peer));
    setVerified((o) => ({ ...o, [peer]: !!v }));
    setMessages({ ...R.current.msgs });
    setSessions({ ...R.current.sess });
  };

  const updateUsers = async (list) => {
    const others = list.filter((u) => u.username !== R.current.me.username);
    R.current.users = others;
    setUsers(others);
    const changed = {};
    for (const u of others) {
      await hydrate(u.username);
      const pin = await kvGet(key('pin', u.username));      // trust on first use
      if (!pin) await kvSet(key('pin', u.username), { publicKey: u.publicKey, signKey: u.signKey });
      else if (pin.publicKey !== u.publicKey || pin.signKey !== u.signKey) changed[u.username] = true;
    }
    setKeyChanged(changed);
  };

  const initiate = async (peer) => {
    const u = R.current.users.find((x) => x.username === peer);
    if (!u) throw new Error('unknown peer');
    const { handshake, keys } = await C.createSession(R.current.id, { from: R.current.me.username, to: peer, peerPublicKey: u.publicKey });
    await storeSession(peer, keys, true);
    wsSend({ type: 'handshake', to: peer, ...handshake });
    system(peer, 'Secure session started. Messages are now encrypted on this device.');
  };

  const onHandshake = async (m) => {
    const peer = m.from;
    const u = R.current.users.find((x) => x.username === peer);
    if (!u || R.current.keyChanged?.[peer]) return;
    if (Math.abs(Date.now() - m.ts) > 10 * 60 * 1000 || m.ts <= (R.current.lastHs[peer] || 0)) return; // stale or replayed
    const mine = R.current.sess[peer];
    if (mine?.initiator && Date.now() - mine.since < 5000 && R.current.me.username < peer) return;      // simultaneous start: lower name wins
    try {
      const keys = await C.acceptSession(R.current.id, { ...m, peerSignKey: u.signKey, to: R.current.me.username });
      R.current.lastHs[peer] = m.ts;
      await storeSession(peer, keys, false);
      system(peer, `Secure session started by ${peer}. Handshake signature verified.`);
    } catch {
      system(peer, 'Rejected a handshake with an invalid signature.');
    }
  };

  const onMessage = async (m) => {
    const peer = m.from;
    await hydrate(peer);
    if ((R.current.msgs[peer] || []).some((x) => x.id === m.id)) return; // replay
    const base = { id: m.id, dir: 'in', ts: m.ts, wire: { iv: m.iv, ct: m.ct, tag: m.tag } };
    const keys = R.current.keys.get(peer);
    if (!keys) push(peer, { ...base, status: 'nokey', text: null });
    else {
      try { push(peer, { ...base, status: 'ok', text: await C.decryptMessage(keys, m) }); }
      catch { push(peer, { ...base, status: 'tampered', text: null }); }
    }
    if (R.current.active !== peer) setUnread((u) => ({ ...u, [peer]: (u[peer] || 0) + 1 }));
  };

  const handle = async (m) => {
    switch (m.type) {
      case 'challenge': wsSend({ type: 'challenge_response', nonce: await C.answerChallenge(R.current.id, m.data) }); break;
      case 'ready': setStatus('online'); setError(''); await updateUsers(m.users); break;
      case 'presence': await updateUsers(m.users); break;
      case 'handshake': await onHandshake(m); break;
      case 'message': await onMessage(m); break;
      case 'ack': break;
      case 'error':
        setError(m.message);
        if (m.fatal) {
          R.current.manual = true; R.current.ws?.close(); setStatus('idle');
          if (m.code === 'auth') { sessionStorage.removeItem(TOKEN_KEY); setMe(null); }
        }
        break;
    }
  };

  const connect = useCallback(() => {
    const ws = new WebSocket(wsUrl());
    R.current.ws = ws;
    setStatus('connecting');
    ws.onopen = () => ws.send(JSON.stringify({ type: 'hello', token: sessionStorage.getItem(TOKEN_KEY), publicKey: R.current.me.publicKey, signKey: R.current.me.signKey }));
    ws.onmessage = (e) => {
      let m; try { m = JSON.parse(e.data); } catch { return; }
      R.current.chain = R.current.chain.then(() => handle(m)).catch(console.error);   // process in order
    };
    ws.onclose = () => {
      if (R.current.manual) return;
      setStatus('offline');
      R.current.retry = setTimeout(connect, 2000);
    };
  }, []); // eslint-disable-line

  // After login the browser creates (or loads) this account's encryption keys, then opens the socket.
  const startSession = async (username) => {
    setStatus('keys');
    try {
      let id = await kvGet(`identity:${username}`);
      if (!id) { id = await C.generateIdentity(); await kvSet(`identity:${username}`, id); }
      const pub = await C.exportPublic(id);
      const info = { username, ...pub, fingerprint: await C.fingerprint(pub) };
      Object.assign(R.current, { id, me: info, manual: false, keys: new Map(), stolen: new Map(), msgs: {}, sess: {}, lastHs: {} });
      setStolen({});
      setMe(info);
      connect();
    } catch (e) { console.error(e); setError('Could not create keys. Use https:// or localhost so the browser allows encryption.'); setStatus('idle'); }
  };

  const account = (path) => async (body) => {
    setError(''); setFieldErrors({}); setStatus('auth');
    try {
      const d = await authFetch(path, body);
      sessionStorage.setItem(TOKEN_KEY, d.token);
      await startSession(d.user.username);
    } catch (e) { setError(e.message); setFieldErrors(e.fields || {}); setStatus('idle'); }
  };
  const signup = account('signup');
  const login = account('login');
  const clearError = () => { setError(''); setFieldErrors({}); };

  const leave = () => {
    R.current.manual = true; clearTimeout(R.current.retry); R.current.ws?.close();
    sessionStorage.removeItem(TOKEN_KEY);
    R.current.stolen = new Map(); setStolen({});
    setMe(null); setUsers([]); setMessages({}); setSessions({}); setUnread({}); setStatus('idle'); setError('');
  };

  const send = async (peer, text) => {
    const body = text.trim();
    if (!body || keyChanged[peer]) return;
    if (!R.current.keys.has(peer)) await initiate(peer);
    const online = R.current.users.find((u) => u.username === peer)?.online;
    const env = await C.encryptMessage(R.current.keys.get(peer), { from: R.current.me.username, to: peer, text: body });
    push(peer, { id: env.id, dir: 'out', ts: env.ts, text: body, status: online ? 'sent' : 'queued', wire: { iv: env.iv, ct: env.ct, tag: env.tag } });
    wsSend({ type: 'message', to: peer, ...env });
  };

  const rekey = (peer) => initiate(peer);

  /* Attack demo: "key theft". The attacker gets a copy of this chat's CURRENT session keys (the keys stay non-extractable,
     so it is a working handle, not readable bytes) and has also recorded the relay traffic. It never learns anything else. */
  const stealKey = (peer) => {
    const k = R.current.keys.get(peer);
    if (!k) return;
    R.current.stolen.set(peer, { aes: k.aes, mac: k.mac });
    setStolen((o) => ({ ...o, [peer]: { at: Date.now() } }));
  };
  const releaseKey = (peer) => { R.current.stolen.delete(peer); setStolen(({ [peer]: _gone, ...rest }) => rest); };
  /** What the attacker can read of one recorded message using only the stolen key and the ciphertext from the wire. */
  const attackerRead = async (peer, m) => {
    const k = R.current.stolen.get(peer);
    if (!k || !m.wire) return { ok: false };
    const me = R.current.me.username;
    const env = { from: m.dir === 'out' ? me : peer, to: m.dir === 'out' ? peer : me, id: m.id, ts: m.ts, ...m.wire };
    try { return { ok: true, text: await C.decryptMessage(k, env) }; } catch { return { ok: false }; }
  };
  const setActive = (peer) => { R.current.active = peer; if (peer) setUnread((u) => ({ ...u, [peer]: 0 })); };
  const setPeerVerified = (peer, v) => { setVerified((o) => ({ ...o, [peer]: v })); kvSet(key('verified', peer), v); };
  const trustNewKey = async (peer) => {
    const u = R.current.users.find((x) => x.username === peer);
    await kvSet(key('pin', peer), { publicKey: u.publicKey, signKey: u.signKey });
    await kvDel(key('session', peer)); R.current.keys.delete(peer); delete R.current.sess[peer];
    setSessions({ ...R.current.sess }); setPeerVerified(peer, false);
    setKeyChanged((o) => ({ ...o, [peer]: false }));
    system(peer, `You accepted ${peer}'s new keys. Start a new session by sending a message.`);
  };

  useEffect(() => { R.current.keyChanged = keyChanged; }, [keyChanged]);
  useEffect(() => { // resume this tab's login after a page refresh
    const t = sessionStorage.getItem(TOKEN_KEY);
    if (!t) return;
    let live = true;
    fetch('/api/auth/me', { headers: { Authorization: `Bearer ${t}` } })
      .then((r) => (r.ok ? r.json() : Promise.reject()))
      .then((d) => live && startSession(d.user.username))
      .catch(() => { sessionStorage.removeItem(TOKEN_KEY); live && setStatus('idle'); });
    return () => { live = false; };
  }, []); // eslint-disable-line
  useEffect(() => () => { R.current.manual = true; clearTimeout(R.current.retry); R.current.ws?.close(); }, []);

  return { status, error, fieldErrors, clearError, signup, login, me, users, messages, sessions, unread, verified, keyChanged, stolen, stealKey, releaseKey, attackerRead, leave, send, rekey, setActive, setPeerVerified, trustNewKey };
}
