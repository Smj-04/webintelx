import { useEffect } from "react";

export default function PasswordChecker() {
  useEffect(() => {
    window.open("http://localhost:3001", "_blank"); // opens PH in a new tab
  }, []);

  return (
    <div style={{ padding: "60px", color: "white" }}>
      <p>Opening Password Hardener...</p>
    </div>
  );
}