import * as React from "react";

export function Tabs({ value, onValueChange, children }) {
  return (
    <div data-value={value} className="w-full">
      {React.Children.map(children, (child) =>
        React.cloneElement(child, { value, onValueChange })
      )}
    </div>
  );
}

export function TabsList({ children }) {
  return <div className="flex rounded-lg overflow-hidden mb-2">{children}</div>;
}

export function TabsTrigger({ children, value, onValueChange }) {
  return (
    <button
      onClick={() => onValueChange(value)}
      className={`flex-1 px-3 py-2 text-sm font-medium ${
        value === onValueChange?.currentValue
          ? "bg-cyan-500 text-white"
          : "bg-slate-700 text-slate-300"
      }`}
    >
      {children}
    </button>
  );
}

export function TabsContent({ children, value, onValueChange }) {
  return value === onValueChange?.currentValue ? (
    <div className="text-slate-300">{children}</div>
  ) : null;
}
