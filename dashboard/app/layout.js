import "./globals.css";

export const metadata = {
  title: "Concordia — Evidence-Bound DAO Governance Council",
  description: "A LLM-powered DAO governance workspace with hash-chained evidence and human-governed execution.",
};

export const viewport = {
  width: "device-width",
  initialScale: 1,
  colorScheme: "dark",
  themeColor: "#07111e",
};

export default function RootLayout({ children }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
