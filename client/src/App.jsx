import { useState } from 'react';
import { ShieldCheck, Lock } from 'lucide-react';
import { useChat } from './lib/useChat';
import Login from './components/Login';
import Sidebar from './components/Sidebar';
import ChatPane from './components/ChatPane';
import SecurityPanel from './components/SecurityPanel';

export default function App() {
  const chat = useChat();
  const [peer, setPeer] = useState(null);
  const [panel, setPanel] = useState(false);

  if (chat.status === 'restoring') return <div className="h-dvh grid place-items-center"><span className="loading loading-spinner loading-lg text-primary" aria-label="Signing you back in" /></div>;
  if (!chat.me || ['idle', 'auth', 'keys'].includes(chat.status)) return <Login chat={chat} />;

  const pick = (u) => { setPeer(u); chat.setActive(u); };
  const back = () => { setPeer(null); chat.setActive(null); };

  return (
    <div className="h-dvh flex overflow-hidden">
      <div className={`${peer ? 'hidden lg:block' : 'block'} w-full lg:w-80 shrink-0`}>
        <Sidebar chat={chat} active={peer} onPick={pick} />
      </div>

      <main className={`${peer ? 'flex' : 'hidden lg:flex'} flex-1 min-w-0 flex-col`}>
        {peer ? (
          <ChatPane key={peer} chat={chat} peer={peer} onBack={back} onSecurity={() => setPanel(true)} />
        ) : (
          <div className="h-full grid place-items-center p-8 text-center">
            <div className="max-w-sm">
              <div className="mx-auto mb-5 size-16 rounded-full bg-base-200 grid place-items-center"><Lock className="text-primary" size={26} /></div>
              <h1 className="font-display text-2xl font-bold">Pick someone to talk to</h1>
              <p className="mt-2 text-base-content/65">Messages are encrypted on your device. Not even the server in the middle can read them.</p>
              <button className="btn btn-ghost btn-sm mt-4" onClick={() => setPanel(true)}><ShieldCheck size={16} /> How this is protected</button>
            </div>
          </div>
        )}
      </main>

      {panel && (
        <>
          <div className="fixed inset-0 bg-black/40 xl:hidden z-30" onClick={() => setPanel(false)} />
          <div className="fixed inset-y-0 right-0 w-full max-w-md z-40 xl:static xl:z-auto xl:w-96 xl:shrink-0 shadow-2xl xl:shadow-none">
            <SecurityPanel chat={chat} peer={peer} onClose={() => setPanel(false)} />
          </div>
        </>
      )}
    </div>
  );
}
