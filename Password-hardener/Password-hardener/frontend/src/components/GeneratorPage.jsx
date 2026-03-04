import { useState } from "react";
import { generatePassword } from "../api";
import CopyButton from "../components/CopyButton";

export default function GeneratorPage() {
  const [primaryWord, setPrimaryWord] = useState("");
  const [secondaryWord, setSecondaryWord] = useState("");
  const [generated, setGenerated] = useState(null);
  const [error, setError] = useState("");

  async function handleGenerate() {
    setError("");
    setGenerated(null);

    if (!primaryWord.trim()) {
      setError("Enter at least one word.");
      return;
    }

    try {
      const res = await generatePassword(
        primaryWord.trim(),
        secondaryWord.trim() || null
      );
      setGenerated(res);
    } catch {
      setError("Generation failed");
    }
  }

  return (
    <div className="page">
      <div className="card">
        <h2>Password Generator</h2>

        <input
          placeholder="Primary word"
          value={primaryWord}
          onChange={(e) => setPrimaryWord(e.target.value)}
        />

        <input
          placeholder="Secondary word (optional)"
          value={secondaryWord}
          onChange={(e) => setSecondaryWord(e.target.value)}
        />

        <button onClick={handleGenerate}>
          Generate Password
        </button>

        {error && <div className="error">{error}</div>}

        {generated && (
          <div className="result">
            <code>{generated.password}</code>
            <CopyButton text={generated.password} />

            <span className="badge">
              {generated.level}
            </span>
          </div>
        )}
      </div>
    </div>
  );
}
