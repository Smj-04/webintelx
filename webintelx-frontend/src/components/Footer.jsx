export default function Footer() {
  return (
    <footer className="mt-auto bg-gray-950 border-t border-gray-800 text-gray-400">
      <div className="max-w-6xl mx-auto px-6 py-4 flex flex-col md:flex-row items-center justify-between gap-2">
        
        <p className="text-sm">
          © {new Date().getFullYear()} WebIntelX · All rights reserved
        </p>

        <p className="text-sm text-gray-500">
          QuickScan · Educational Security Tool
        </p>

      </div>
    </footer>
  );
}
