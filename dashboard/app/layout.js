import "./globals.css";
import { Chakra_Petch, JetBrains_Mono, Space_Grotesk } from "next/font/google";

const spaceGrotesk = Space_Grotesk({
  subsets: ["latin"],
  weight: ["400", "500", "600", "700"],
  display: "swap",
  variable: "--font-space-grotesk",
});

const chakraPetch = Chakra_Petch({
  subsets: ["latin"],
  weight: ["400", "500", "600", "700"],
  display: "swap",
  variable: "--font-chakra-petch",
});

const jetBrainsMono = JetBrains_Mono({
  subsets: ["latin"],
  weight: ["400", "500", "700"],
  display: "swap",
  variable: "--font-jetbrains-mono",
});

export const metadata = {
  title: "Concordia - Evidence-Bound DAO Governance Council",
  description: "Recorded Casper Testnet governance evidence, bounded agent deliberation, human quorum, and exact approved execution.",
  icons: {
    icon: "/dashboard/concordia-dao-logo-final.png",
    shortcut: "/dashboard/concordia-dao-logo-final.png",
    apple: "/dashboard/concordia-dao-logo-final.png",
  },
};

export const viewport = {
  width: "device-width",
  initialScale: 1,
  colorScheme: "dark",
  themeColor: "#07111e",
};

export default function RootLayout({ children }) {
  return (
    <html lang="en" className={`${spaceGrotesk.variable} ${chakraPetch.variable} ${jetBrainsMono.variable}`}>
      <body>{children}</body>
    </html>
  );
}
