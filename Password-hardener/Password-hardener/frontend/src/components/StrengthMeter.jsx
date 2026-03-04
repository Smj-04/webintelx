import React, { useEffect, useState } from "react";

export default function StrengthMeter({ bits, rankColor }) {
  const [width, setWidth] = useState(0);

  useEffect(() => {
    // map bits (0..120+ ) to 0..100%
    const capped = Math.min(120, Math.max(0, bits));
    const pct = Math.round((capped / 120) * 100);
    // small animation delay
    const t = setTimeout(() => setWidth(pct), 60);
    return () => clearTimeout(t);
  }, [bits]);

  return (
    <div>
      <div className="meter" aria-hidden>
        <div
          className="meter-bar"
          style={{
            width: `${width}%`,
            boxShadow: `0 6px 20px ${rankColor ? rankColor + '22' : 'rgba(11,116,255,0.12)'}`
          }}
        />
      </div>
      <div className="meter-label">Strength: {bits} bits</div>
    </div>
  );
}
