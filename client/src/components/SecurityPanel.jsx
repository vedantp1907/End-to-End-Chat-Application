import { useEffect, useState } from 'react';
import { X, ShieldCheck, KeyRound, Server, TriangleAlert, RefreshCw, Check, Bug } from 'lucide-react';
import * as C from '../lib/crypto';
import { fmtTime } from './ui';

function ThisChat({ chat, peer }) {
  const user = chat.users.find((u) => u.username === peer);
  const [safety, setSafety] = useState([]);
  const [theirFp, setTheirFp] = useState('');
  useEffect(() => {
    if (!user) return;
    C.safetyNumber(chat.me, user).then(setSafety);
    C.fingerprint(user).then(setTheirFp);
  }, [user?.publicKey, user?.signKey, chat.me]); // eslint-disable-line
  const sess = chat.sessions[peer];
  if (!user) return null;
  return (
    <div className="space-y-6">
      {chat.keyChanged[peer] && (
        <div role="alert" className="alert alert-error alert-soft text-sm flex-col items-start">
          <div className="font-bold flex items-center gap-2"><TriangleAlert size={16} /> Keys changed</div>
          <p>{peer} is now using different keys than when you first connected. Only continue if they confirm they set up a new device.</p>
          <button className="btn btn-error btn-sm" onClick={() => chat.trustNewKey(peer)}>Trust the new keys</button>
        </div>
      )}
      <section>
        <h3 className="font-display font-bold">Safety number</h3>
        <p className="text-sm text-base-content/65 mt-1">Compare this with {peer} in person or over a call. If both of you see the same numbers, nobody swapped your keys.</p>
        <div className="mt-3 grid grid-cols-3 gap-2 font-mono text-lg text-center">
          {safety.map((g, i) => <div key={i} className="rounded-field bg-base-200 py-2">{g}</div>)}
        </div>
        <label className="mt-4 flex items-center gap-3 cursor-pointer">
          <input type="checkbox" className="toggle toggle-success" checked={!!chat.verified[peer]} onChange={(e) => chat.setPeerVerified(peer, e.target.checked)} />
          <span className="text-sm font-medium">The numbers match</span>
        </label>
      </section>

      <section>
        <h3 className="font-display font-bold">Key fingerprints</h3>
        <dl className="mt-2 space-y-3 text-sm">
          <div><dt className="text-base-content/60">{peer}</dt><dd className="font-mono text-xs break-words">{theirFp}</dd></div>
          <div><dt className="text-base-content/60">You</dt><dd className="font-mono text-xs break-words">{chat.me.fingerprint}</dd></div>
        </dl>
      </section>

      <section>
        <h3 className="font-display font-bold">Session</h3>
        {sess ? (
          <>
            <p className="text-sm text-base-content/65 mt-1">Started {fmtTime(sess.since)} by {sess.initiator ? 'you' : peer}. The same key protects every message until you create a new one.</p>
            <ul className="mt-3 text-sm space-y-1.5">
              <li className="flex justify-between"><span className="text-base-content/60">Key exchange</span><span>RSA-OAEP 3072 + signed</span></li>
              <li className="flex justify-between"><span className="text-base-content/60">Encryption</span><span>AES-256-CBC</span></li>
              <li className="flex justify-between"><span className="text-base-content/60">Integrity</span><span>HMAC-SHA256</span></li>
              <li className="flex justify-between"><span className="text-base-content/60">Key derivation</span><span>HKDF-SHA256</span></li>
              <li className="flex justify-between"><span className="text-base-content/60">Transport</span><span>{location.protocol === 'https:' ? 'TLS (wss)' : 'Not encrypted (ws)'}</span></li>
            </ul>
            <button className="btn btn-outline btn-sm mt-4" onClick={() => chat.rekey(peer)}><RefreshCw size={14} /> Create a new session key</button>
          </>
        ) : <p className="text-sm text-base-content/65 mt-1">No session yet. It starts automatically when a message is sent.</p>}
      </section>

      <StolenKey chat={chat} peer={peer} />
    </div>
  );
}

function StolenKey({ chat, peer }) {
  const stolen = chat.stolen[peer];
  const msgs = chat.messages[peer];
  const [rows, setRows] = useState([]);
  useEffect(() => {
    if (!stolen) { setRows([]); return; }
    let live = true;
    Promise.all((msgs || []).filter((m) => m.wire).map(async (m) => ({ m, r: await chat.attackerRead(peer, m) })))
      .then((r) => live && setRows(r));
    return () => { live = false; };
  }, [stolen, msgs]); // eslint-disable-line
  return (
    <section className={`rounded-box p-4 text-sm ${stolen ? 'bg-error/10 border border-error/40' : 'bg-base-200'}`}>
      <h3 className="font-bold flex items-center gap-2"><Bug size={15} /> Try an attack: steal the session key</h3>
      <p className="mt-1 text-base-content/70">
        Pretend malware copied this chat's session key, and an eavesdropper recorded the encrypted traffic. Nothing else is given to the attacker:
        no passwords, no private keys.
      </p>
      {!stolen ? (
        <button className="btn btn-sm mt-3" disabled={!chat.sessions[peer]} onClick={() => chat.stealKey(peer)}>Give the key to the attacker</button>
      ) : (
        <>
          <div className="mt-3 font-bold">What the attacker can read</div>
          <ul className="mt-2 space-y-2">
            {rows.map(({ m, r }) => (
              <li key={m.id} className="rounded-field bg-base-100 border border-base-300 p-2.5">
                <div className="flex justify-between text-xs text-base-content/55">
                  <span>{m.dir === 'out' ? 'You' : peer} · {fmtTime(m.ts)}</span>
                  <span>{m.ts < stolen.at ? 'recorded before the theft' : 'sent after the theft'}</span>
                </div>
                {r.ok ? <div className="mt-1 font-medium text-error break-words">{r.text}</div> : <div className="mt-1 text-base-content/60">Cannot read (different key, or altered).</div>}
              </li>
            ))}
            {rows.length === 0 && <li className="text-base-content/60">No messages in this chat yet. Send one and watch the attacker read it too.</li>}
          </ul>
          <p className="mt-3 text-base-content/70">
            Past and future messages under the same key are all exposed: this is the missing forward secrecy. Creating a new session key locks the attacker
            out of messages sent afterwards, but everything already recorded stays readable.
          </p>
          <button className="btn btn-ghost btn-sm mt-2" onClick={() => chat.releaseKey(peer)}>Stop the simulation</button>
        </>
      )}
    </section>
  );
}

const authHeader = () => ({ Authorization: `Bearer ${sessionStorage.getItem('vault-token')}` });

const ATTACKS = [
  ['corrupt', 'Corrupt the next message', 'The relay flips a bit. The receiver should reject it.'],
  ['drop', 'Drop the next message', 'The relay silently throws it away. See whether anyone notices.'],
  ['delay', 'Delay the next message', 'The relay holds it back, then delivers it unchanged.'],
];

function ServerView() {
  const [data, setData] = useState({ entries: [] });
  const armed = data.armed;
  useEffect(() => {
    let live = true;
    const tick = () => fetch('/api/relay-log', { headers: authHeader() }).then((r) => r.json()).then((d) => live && setData(d)).catch(() => {});
    tick(); const t = setInterval(tick, 1500);
    return () => { live = false; clearInterval(t); };
  }, []);
  const arm = async (mode) => {
    const r = await fetch('/api/tamper', { method: 'POST', headers: { ...authHeader(), 'Content-Type': 'application/json' }, body: JSON.stringify({ mode }) });
    if (r.ok) setData((d) => ({ ...d, armed: mode }));
  };
  return (
    <div className="space-y-5">
      <p className="text-sm text-base-content/70">This is the relay's own log. Look for message text: there is none, only encoded bytes and who talked to whom.</p>
      <div className={`rounded-box p-4 text-sm ${armed ? 'bg-error/10 border border-error/40' : 'bg-base-200'}`}>
        <div className="font-bold flex items-center gap-2"><Bug size={15} /> Try an attack</div>
        <p className="mt-1 text-base-content/70">Make the relay misbehave on the next message you send.</p>
        <div className="mt-3 space-y-2">
          {ATTACKS.map(([mode, label, hint]) => (
            <div key={mode}>
              <button className="btn btn-sm" onClick={() => arm(mode)} disabled={!!armed || data.tamperAllowed === false}>
                {armed === mode ? 'Armed: send a message now' : label}
              </button>
              <span className="ml-2 text-xs text-base-content/60">{mode === 'delay' && data.delayMs ? `Holds it ${data.delayMs / 1000} s, then delivers it unchanged.` : hint}</span>
            </div>
          ))}
        </div>
      </div>
      <ul className="space-y-2">
        {[...data.entries].reverse().map((e, i) => (
          <li key={i} className="rounded-field border border-base-300 p-3 text-xs font-mono">
            <div className="flex justify-between font-sans text-sm"><span><b>{e.from}</b> to <b>{e.to}</b></span><span className="text-base-content/55">{fmtTime(e.t)}</span></div>
            <div className="text-base-content/55 font-sans text-xs mb-1">{e.type === 'handshake' ? 'Key handshake' : 'Message'} · {e.bytes} bytes · {e.note ? <span className="text-error font-medium">{e.note}</span> : e.delivered ? 'delivered' : 'held for offline user'}</div>
            {Object.entries(e.fields).filter(([k]) => ['wrappedKey', 'iv', 'ct', 'tag'].includes(k)).map(([k, v]) => <div key={k} className="break-all"><span className="text-base-content/50">{k} </span>{v}</div>)}
          </li>
        ))}
        {data.entries.length === 0 && <li className="text-sm text-base-content/60">Nothing relayed yet. Send a message to see what the server handles.</li>}
      </ul>
    </div>
  );
}

function Limits() {
  const Row = ({ ok, title, children }) => (
    <li className="flex gap-3">
      <span className={`mt-0.5 shrink-0 size-5 rounded-full grid place-items-center ${ok ? 'bg-success/15 text-success' : 'bg-warning/20 text-warning'}`}>{ok ? <Check size={12} /> : <TriangleAlert size={11} />}</span>
      <div><div className="font-medium">{title}</div><p className="text-sm text-base-content/65">{children}</p></div>
    </li>
  );
  return (
    <div className="space-y-5">
      <ul className="space-y-4">
        <Row ok title="The relay cannot read messages">Text is encrypted before it leaves your device.</Row>
        <Row ok title="Changes are detected">Every message carries an HMAC. A changed message is rejected, not shown.</Row>
        <Row ok title="Identical messages look different">Each message gets a fresh random IV.</Row>
        <Row ok title="Handshakes are signed">The key exchange proves who started it, and your safety number proves whose keys they are.</Row>
        <Row title="No forward secrecy">One key protects the whole chat. If it is ever stolen, every past and future message under it can be read.</Row>
        <Row title="No recovery after a leak">Apps like Signal change keys with every message so a leak heals itself (a ratchet). This app does not.</Row>
        <Row title="Metadata is visible">The relay knows who talks to whom, when, and how long each message is.</Row>
        <Row title="Delivery is not guaranteed">The relay can silently drop or delay messages and neither user is told. Encryption protects what a message says, not whether it arrives.</Row>
      </ul>
      <p className="text-sm text-base-content/65 rounded-box bg-base-200 p-4">Creating a new session key limits the damage of a leak, but you have to do it by hand. A ratchet does it automatically.</p>
    </div>
  );
}

export default function SecurityPanel({ chat, peer, onClose }) {
  const [tab, setTab] = useState(peer ? 'chat' : 'limits');
  const tabs = [...(peer ? [['chat', 'This chat', ShieldCheck]] : []), ['server', "Server's view", Server], ['limits', 'Limits', KeyRound]];
  return (
    <aside className="h-full flex flex-col bg-base-100 border-l border-base-300">
      <header className="flex items-center justify-between px-5 py-4">
        <h2 className="font-display text-lg font-bold">Security</h2>
        <button className="btn btn-ghost btn-sm btn-square" onClick={onClose} aria-label="Close security panel"><X size={18} /></button>
      </header>
      <div role="tablist" className="tabs tabs-border px-3">
        {tabs.map(([id, label]) => <button key={id} role="tab" className={`tab ${tab === id ? 'tab-active' : ''}`} onClick={() => setTab(id)}>{label}</button>)}
      </div>
      <div className="flex-1 overflow-y-auto scroll-thin p-5">
        {tab === 'chat' && peer && <ThisChat chat={chat} peer={peer} />}
        {tab === 'server' && <ServerView />}
        {tab === 'limits' && <Limits />}
      </div>
    </aside>
  );
}
