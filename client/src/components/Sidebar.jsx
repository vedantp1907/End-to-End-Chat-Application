import { LogOut, ShieldCheck, Users, Moon, Sun } from 'lucide-react';
import { Avatar, fmtTime } from './ui';

export default function Sidebar({ chat, active, onPick }) {
  const { me, users, messages, unread, verified, status } = chat;
  const last = (u) => [...(messages[u] || [])].reverse().find((m) => m.dir !== 'system');
  const sorted = [...users].sort((a, b) => (last(b)?.ts || 0) - (last(a)?.ts || 0) || b.online - a.online);
  const toggleTheme = () => {
    const el = document.documentElement;
    el.dataset.theme = el.dataset.theme === 'vaultnight' ? 'vault' : 'vaultnight';
  };
  return (
    <aside className="flex flex-col h-full bg-base-200 border-r border-base-300 w-full">
      <header className="p-4 flex items-center gap-3">
        <Avatar name={me.username} online={status === 'online'} />
        <div className="min-w-0 flex-1">
          <div className="font-display font-bold truncate">{me.username}</div>
          <div className="text-xs text-base-content/60">{status === 'online' ? 'Connected to relay' : status === 'offline' ? 'Reconnecting…' : 'Connecting…'}</div>
        </div>
        <button className="btn btn-ghost btn-sm btn-square" onClick={toggleTheme} aria-label="Toggle dark mode"><Sun size={16} className="hidden [[data-theme=vaultnight]_&]:block" /><Moon size={16} className="[[data-theme=vaultnight]_&]:hidden" /></button>
        <button className="btn btn-ghost btn-sm btn-square" onClick={chat.leave} aria-label="Sign out"><LogOut size={16} /></button>
      </header>

      <div className="px-4 pb-2 text-sm font-medium text-base-content/70 flex items-center gap-2"><Users size={14} /> People</div>
      <nav className="flex-1 overflow-y-auto scroll-thin px-2 pb-4">
        {sorted.length === 0 && (
          <div className="m-2 p-5 rounded-box border border-dashed border-base-300 text-sm text-base-content/70">
            <p className="font-medium text-base-content">No one else is here yet.</p>
            <p className="mt-1">Open this page in a second window and join with a different username. They will show up here.</p>
          </div>
        )}
        {sorted.map((u) => {
          const l = last(u.username);
          return (
            <button key={u.username} onClick={() => onPick(u.username)} className={`w-full text-left flex items-center gap-3 p-2.5 rounded-field transition-colors ${active === u.username ? 'bg-base-100 shadow-sm' : 'hover:bg-base-100/60'}`}>
              <Avatar name={u.username} online={u.online} />
              <div className="min-w-0 flex-1">
                <div className="flex items-center gap-1.5">
                  <span className="font-medium truncate">{u.username}</span>
                  {verified[u.username] && <ShieldCheck size={14} className="text-success shrink-0" aria-label="Verified" />}
                  {l && <span className="ml-auto text-xs text-base-content/50">{fmtTime(l.ts)}</span>}
                </div>
                <div className="text-sm text-base-content/60 truncate">{l ? (l.text ?? 'Message could not be verified') : u.online ? 'Online' : 'Offline'}</div>
              </div>
              {unread[u.username] > 0 && <span className="badge badge-primary badge-sm">{unread[u.username]}</span>}
            </button>
          );
        })}
      </nav>
    </aside>
  );
}
