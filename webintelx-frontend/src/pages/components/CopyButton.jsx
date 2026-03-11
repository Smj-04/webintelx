import React from "react";

export default function CopyButton({ text }) {
  async function copy() {
    try {
      await navigator.clipboard.writeText(text);
      const el = document.createElement('div');
      el.textContent = 'Copied!';
      el.style.position = 'fixed';
      el.style.bottom = '24px';
      el.style.left = '50%';
      el.style.transform = 'translateX(-50%)';
      el.style.background = 'rgba(15,23,42,0.9)';
      el.style.color = '#fff';
      el.style.padding = '8px 12px';
      el.style.borderRadius = '8px';
      el.style.zIndex = 9999;
      document.body.appendChild(el);
      setTimeout(()=>document.body.removeChild(el),1200);
    } catch (e) {
      alert('Copy failed - select and copy manually');
    }
  }
  return <button className="copy-btn" onClick={copy}>Copy</button>;
}
