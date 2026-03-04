import { useState } from "react";
import { analyzePassword } from "../api";
import StrengthMeter from "../components/StrengthMeter";

export default function AnalyzerPage() {
  const [password, setPassword] = useState("");
  const [result, setResult] = useState(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const [showPassword, setShowPassword] = useState(false);

  async function handleAnalyze(e) {
    e.preventDefault();
    setError("");
    setResult(null);

    if (!password.trim()) {
      setError("Please enter a password.");
      return;
    }

    try {
      setLoading(true);
      const res = await analyzePassword(password);
      setResult(res);
    } catch {
      setError("Analysis failed");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="page">
      <div className="card">
        <h2>Password Strength Analyzer</h2>

        <form onSubmit={handleAnalyze}>
          <div className="password-wrapper">
            <input
              type={showPassword ? "text" : "password"}
              placeholder="Enter password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
            />
            <span
              className="eye"
              onClick={() => setShowPassword(!showPassword)}
            >
              {showPassword ? "🙈" : "👁️"}
            </span>
          </div>

          <button disabled={loading}>
            {loading ? "Analyzing..." : "Analyze"}
          </button>
        </form>

        {error && <div className="error">{error}</div>}

        {result?.analysis && (
          <div className="result">
            <ul>
              <li>Length: {result.analysis.length}</li>
              <li>Entropy: {result.analysis.entropyBits} bits</li>
              <li>Crack Time: {result.analysis.crackTimeHuman}</li>
            </ul>

            <StrengthMeter bits={result.analysis.entropyBits} />

            <span
              className="badge"
              style={{ background: result.analysis.strength.color }}
            >
              {result.analysis.strength.label}
            </span>
          </div>
        )}
      </div>
    </div>
  );
}
