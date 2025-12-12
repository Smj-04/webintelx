import * as React from "react";

export function Card({ className = "", children }) {
  return (
    <div
      className={`rounded-xl border border-slate-700 bg-slate-800/50 shadow-md ${className}`}
    >
      {children}
    </div>
  );
}

export function CardHeader({ children }) {
  return <div className="p-4 border-b border-slate-700">{children}</div>;
}

export function CardTitle({ children }) {
  return <h3 className="text-lg font-semibold text-white">{children}</h3>;
}

export function CardContent({ children }) {
  return <div className="p-4 text-slate-300">{children}</div>;
}
