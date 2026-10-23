export const hue = (s) => [...s].reduce((h, c) => (h * 31 + c.charCodeAt(0)) % 360, 7);
export const fmtTime = (ts) => new Date(ts).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });

export function Avatar({ name, size = 'w-10 h-10', online }) {
  return (
    <div className="relative shrink-0">
      <div className={`${size} rounded-full grid place-items-center font-display font-bold text-white select-none`} style={{ background: `hsl(${hue(name)} 48% 40%)` }}>
        {name[0]?.toUpperCase()}
      </div>
      {online !== undefined && (
        <span className={`absolute -right-0.5 -bottom-0.5 size-3 rounded-full border-2 border-base-100 ${online ? 'bg-success' : 'bg-base-300'}`} aria-label={online ? 'online' : 'offline'} />
      )}
    </div>
  );
}
