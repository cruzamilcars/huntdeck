import type { ReactNode } from "react";

export function ModulePanel({
  title,
  meta,
  children,
}: {
  title: string;
  meta?: string;
  children: ReactNode;
}) {
  return (
    <section className="muted-panel min-h-[240px]">
      <header className="flex items-center justify-between border-b border-[var(--muted-line)] px-3 py-2">
        <h2 className="text-sm font-black uppercase">{title}</h2>
        {meta ? <span className="text-xs uppercase text-[var(--warning)]">{meta}</span> : null}
      </header>
      <div className="p-3">{children}</div>
    </section>
  );
}

