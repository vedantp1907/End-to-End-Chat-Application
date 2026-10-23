import { useState } from 'react';
import { Lock, KeyRound, Server, ArrowRight, Eye, EyeOff } from 'lucide-react';

const NAME_RE = /^[A-Za-z0-9_]{2,20}$/;
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;

function Field({ label, error, hint, children }) {
  return (
    <label className="block">
      <span className="mb-1.5 block text-sm font-medium">{label}</span>
      {children}
      {error ? <span role="alert" className="mt-1.5 block text-sm text-error">{error}</span>
        : hint ? <span className="mt-1.5 block text-sm text-base-content/55">{hint}</span> : null}
    </label>
  );
}

export default function Login({ chat }) {
  const [mode, setMode] = useState('login');
  const [f, setF] = useState({ username: '', email: '', identifier: '', password: '' });
  const [local, setLocal] = useState({});
  const [show, setShow] = useState(false);
  const busy = chat.status === 'auth' || chat.status === 'keys';
  const errs = { ...chat.fieldErrors, ...local };
  const signup = mode === 'signup';

  const set = (k) => (e) => { setF({ ...f, [k]: e.target.value }); setLocal({ ...local, [k]: undefined }); chat.clearError(); };
  const switchMode = (m) => { setMode(m); setLocal({}); chat.clearError(); };

  const submit = (e) => {
    e.preventDefault();
    const err = {};
    if (signup) {
      if (!NAME_RE.test(f.username.trim())) err.username = 'Use 2–20 letters, numbers or underscores.';
      if (!EMAIL_RE.test(f.email.trim())) err.email = 'Enter a valid email address.';
      if (f.password.length < 8) err.password = 'Use at least 8 characters.';
    } else {
      if (!f.identifier.trim()) err.identifier = 'Enter your username or email.';
      if (!f.password) err.password = 'Enter your password.';
    }
    setLocal(err);
    if (Object.keys(err).length) return;
    signup
      ? chat.signup({ username: f.username.trim(), email: f.email.trim(), password: f.password })
      : chat.login({ identifier: f.identifier.trim(), password: f.password });
  };
  const cls = (k) => `input w-full ${errs[k] ? 'input-error' : ''}`;

  return (
    <main className="min-h-dvh grid lg:grid-cols-[1.1fr_1fr]">
      <section className="hidden lg:flex flex-col justify-between bg-neutral text-neutral-content p-12">
        <div className="flex items-center gap-2 font-display text-xl font-bold"><Lock size={20} className="text-secondary" /> Vault Chat</div>
        <div className="max-w-lg">
          <h1 className="font-display text-5xl font-bold leading-[1.05]">The server passes your messages along. It cannot read them.</h1>
          <p className="mt-5 text-neutral-content/70 text-lg">Encryption and decryption happen on your device, so the relay in the middle only ever handles scrambled data.</p>
          <div className="mt-10 rounded-box bg-black/25 p-5 space-y-4 font-mono text-sm">
            <div><div className="text-neutral-content/50 text-xs mb-1 font-sans">You type</div><div>See you at 6?</div></div>
            <div className="h-px bg-white/10" />
            <div><div className="text-neutral-content/50 text-xs mb-1 font-sans">The relay sees</div><div className="text-secondary break-all">ct: q3VtL0pXn8Zr+4kT2wY9cA== · tag: 5b1e90c4a7…</div></div>
          </div>
        </div>
        <p className="text-sm text-neutral-content/50">Microproject · Cryptography and Security</p>
      </section>

      <section className="flex items-center justify-center p-6 sm:p-12">
        <form className="w-full max-w-sm" onSubmit={submit} noValidate>
          <div className="lg:hidden flex items-center gap-2 font-display text-xl font-bold mb-8"><Lock size={20} className="text-secondary" /> Vault Chat</div>
          <h2 className="font-display text-3xl font-bold">{signup ? 'Create your account' : 'Welcome back'}</h2>
          <p className="mt-2 text-base-content/70">
            {signup ? 'Your encryption keys are created in this browser and never leave it.' : 'Log in to pick up your conversations on this browser.'}
          </p>

          <div role="tablist" className="tabs tabs-box mt-6">
            <button type="button" role="tab" className={`tab flex-1 ${signup ? 'tab-active' : ''}`} onClick={() => switchMode('signup')}>Sign up</button>
            <button type="button" role="tab" className={`tab flex-1 ${!signup ? 'tab-active' : ''}`} onClick={() => switchMode('login')}>Log in</button>
          </div>

          <div className="mt-6 space-y-4">
            {signup ? (
              <>
                <Field label="Username" error={errs.username} hint="Shown exactly as you type it. Capitals matter: Sam and sam are different accounts.">
                  <input className={cls('username')} value={f.username} onChange={set('username')} placeholder="Vedant" autoComplete="username" spellCheck="false" maxLength={20} autoFocus disabled={busy} />
                </Field>
                <Field label="Email" error={errs.email}>
                  <input className={cls('email')} type="email" value={f.email} onChange={set('email')} placeholder="you@example.com" autoComplete="email" disabled={busy} />
                </Field>
              </>
            ) : (
              <Field label="Username or email" error={errs.identifier} hint="Usernames are case-sensitive.">
                <input className={cls('identifier')} value={f.identifier} onChange={set('identifier')} autoComplete="username" spellCheck="false" autoFocus disabled={busy} />
              </Field>
            )}
            <Field label="Password" error={errs.password} hint={signup ? 'At least 8 characters.' : undefined}>
              <div className="relative">
                <input className={`${cls('password')} pr-11`} type={show ? 'text' : 'password'} value={f.password} onChange={set('password')} autoComplete={signup ? 'new-password' : 'current-password'} disabled={busy} />
                <button type="button" className="absolute right-1 top-1/2 -translate-y-1/2 btn btn-ghost btn-sm btn-square" onClick={() => setShow(!show)} aria-label={show ? 'Hide password' : 'Show password'}>
                  {show ? <EyeOff size={16} /> : <Eye size={16} />}
                </button>
              </div>
            </Field>
          </div>

          {chat.error && !Object.keys(chat.fieldErrors).length && <p role="alert" className="mt-4 rounded-field bg-error/10 px-3 py-2 text-sm text-error">{chat.error}</p>}

          <button className="btn btn-primary btn-lg w-full mt-6" disabled={busy}>
            {busy
              ? <><span className="loading loading-spinner" /> {chat.status === 'keys' ? <span className="cipher-sweep">Creating your keys…</span> : 'Checking…'}</>
              : <>{signup ? 'Create account' : 'Log in'} <ArrowRight size={18} /></>}
          </button>

          <ul className="mt-10 space-y-3 text-sm text-base-content/70">
            <li className="flex gap-3"><KeyRound size={18} className="shrink-0 mt-0.5 text-primary" /> Your password only signs you in. It is never used to encrypt messages.</li>
            <li className="flex gap-3"><Lock size={18} className="shrink-0 mt-0.5 text-primary" /> Each chat uses one shared AES-256 key, with an HMAC on every message.</li>
            <li className="flex gap-3"><Server size={18} className="shrink-0 mt-0.5 text-primary" /> The database stores accounts only. No messages, ever.</li>
          </ul>
        </form>
      </section>
    </main>
  );
}
