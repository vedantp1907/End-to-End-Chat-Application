import { useEffect, useRef, useState } from 'react';
import { ArrowLeft, Send, ShieldCheck, ShieldAlert, Lock, Code2, Clock, AlertTriangle } from 'lucide-react';
import { Avatar, fmtTime } from './ui';

function Bubble({ m }) {
  const [wire, setWire] = useState(false);
  if (m.dir === 'system')
    return <div className="my-4 flex items-center justify-center gap-2 text-xs text-base-content/60"><Lock size={12} /> {m.text}</div>;
  const mine = m.dir === 'out';
  const bad = m.status === 'tampered' || m.status === 'nokey';
  return (
    <div className={`flex flex-col ${mine ? 'items-end' : 'items-start'} mb-2`}>
      <div className={`chat-bubble ${mine ? 'chat-bubble-primary' : bad ? 'chat-bubble-error' : 'bg-base-200 text-base-content'}`}>
        {m.status === 'tampered' && <span className="flex items-start gap-2"><AlertTriangle size={16} className="mt-0.5 shrink-0" /> This message was changed on its way here, so it was discarded.</span>}
        {m.status === 'nokey' && <span className="flex items-start gap-2"><AlertTriangle size={16} className="mt-0.5 shrink-0" /> No session key for this message. Ask {m.from || 'them'} to send again or create a new session.</span>}
        {m.text}
      </div>
      <div className="mt-1 flex items-center gap-2 text-xs text-base-content/55">
        <span>{fmtTime(m.ts)}</span>
        {m.status === 'queued' && <span className="flex items-center gap-1"><Clock size={11} /> Waiting for them to come online</span>}
        {m.status === 'ok' && <span className="flex items-center gap-1 text-success"><ShieldCheck size={11} /> Verified</span>}
        <button className="flex items-center gap-1 hover:text-base-content underline-offset-2 hover:underline" onClick={() => setWire(!wire)} aria-expanded={wire}><Code2 size={11} /> {wire ? 'Hide' : 'Show'} what was sent</button>
      </div>
      {wire && (
        <div className="mt-1.5 max-w-[min(34rem,82vw)] w-full rounded-field bg-neutral text-neutral-content p-3 font-mono text-xs space-y-1 break-all">
          <div><span className="text-neutral-content/50">iv  </span>{m.wire.iv}</div>
          <div><span className="text-neutral-content/50">ct  </span>{m.wire.ct}</div>
          <div><span className="text-neutral-content/50">tag </span>{m.wire.tag}</div>
          <div className="pt-1 font-sans text-neutral-content/60">This is everything the relay receives: no readable text.</div>
        </div>
      )}
    </div>
  );
}

export default function ChatPane({ chat, peer, onBack, onSecurity }) {
  const [text, setText] = useState('');
  const end = useRef(null);
  const user = chat.users.find((u) => u.username === peer);
  const list = chat.messages[peer] || [];
  const changed = chat.keyChanged[peer];
  const hasSession = !!chat.sessions[peer];

  useEffect(() => { end.current?.scrollIntoView({ block: 'end' }); }, [list.length, peer]);

  const submit = () => { if (!text.trim()) return; chat.send(peer, text); setText(''); };
  const onKey = (e) => { if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); submit(); } };

  return (
    <section className="flex flex-col h-full min-w-0">
      <header className="flex items-center gap-3 px-4 py-3 border-b border-base-300 bg-base-100">
        <button className="btn btn-ghost btn-sm btn-square lg:hidden" onClick={onBack} aria-label="Back to people"><ArrowLeft size={18} /></button>
        <Avatar name={peer} online={user?.online} />
        <div className="min-w-0 flex-1">
          <div className="font-display font-bold leading-tight">{peer}</div>
          <div className="text-xs text-base-content/60">{user?.online ? 'Online' : 'Offline · messages are held until they return'}</div>
        </div>
        <button onClick={onSecurity} className={`btn btn-sm ${changed ? 'btn-error' : chat.verified[peer] ? 'btn-success btn-soft' : 'btn-ghost'}`}>
          {changed ? <ShieldAlert size={16} /> : <ShieldCheck size={16} />}
          <span className="hidden sm:inline">{changed ? 'Key changed' : chat.verified[peer] ? 'Verified' : 'Verify security'}</span>
        </button>
      </header>

      {changed && (
        <div role="alert" className="alert alert-error rounded-none text-sm">
          <ShieldAlert size={18} />
          <span><b>{peer}'s keys have changed since you first saw them.</b> This could mean a new device, or someone impersonating them. Sending is blocked until you review it.</span>
          <button className="btn btn-sm" onClick={onSecurity}>Review</button>
        </div>
      )}

      <div className="flex-1 overflow-y-auto scroll-thin px-4 sm:px-8 py-4" aria-live="polite">
        {list.length === 0 && (
          <div className="h-full grid place-items-center text-center">
            <div className="max-w-xs">
              <div className="mx-auto mb-4 size-14 rounded-full bg-base-200 grid place-items-center"><Lock className="text-primary" /></div>
              <p className="font-display text-xl font-bold">Say hello to {peer}</p>
              <p className="mt-1 text-sm text-base-content/65">Your first message sets up a shared key with {peer}, then every message is encrypted before it leaves this device.</p>
            </div>
          </div>
        )}
        {list.map((m) => <Bubble key={m.id} m={{ ...m, from: peer }} />)}
        <div ref={end} />
      </div>

      <footer className="border-t border-base-300 p-3 sm:p-4 bg-base-100 pb-[max(0.75rem,env(safe-area-inset-bottom))]">
        <div className="flex items-end gap-2">
          <textarea className="textarea w-full resize-none min-h-11 max-h-36" rows={1} value={text} onChange={(e) => setText(e.target.value)} onKeyDown={onKey} disabled={changed} placeholder={changed ? 'Review the key change to continue' : `Message ${peer}`} aria-label={`Message ${peer}`} />
          <button className="btn btn-primary btn-square" onClick={submit} disabled={!text.trim() || changed} aria-label="Send message"><Send size={18} /></button>
        </div>
        <p className="mt-2 text-xs text-base-content/50 flex items-center gap-1.5"><Lock size={11} /> {hasSession ? 'Encrypted with AES-256 · integrity checked with HMAC-SHA256' : 'A secure session will be created when you send'}</p>
      </footer>
    </section>
  );
}
