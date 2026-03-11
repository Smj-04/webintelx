// Password-hardener/frontend/src/components/StrengthMeter.jsx
// WHITE THEME VERSION

import React, { useEffect, useState } from "react";

export default function StrengthMeter({ bits, rankColor }) {
  const [width, setWidth] = useState(0);

  useEffect(() => {
    const capped = Math.min(120, Math.max(0, bits));
    const pct = Math.round((capped / 120) * 100);
    const t = setTimeout(() => setWidth(pct), 60);
    return () => clearTimeout(t);
  }, [bits]);

  // Map rankColor neons → white-theme ink colors
  const safeColor = rankColor || "var(--accent)";

  return (
    <div>
      <div className="meter" aria-hidden>
        <div
          className="meter-bar"
          style={{
            width: `${width}%`,
            background: safeColor,
            boxShadow: `0 2px 8px ${safeColor}30`,
          }}
        />
      </div>
      <div className="meter-label">Strength: {bits} bits</div>
    </div>
  );
}