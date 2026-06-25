import type { Metadata } from "next";
import { Space_Grotesk, JetBrains_Mono } from "next/font/google";
import { RootProvider } from "fumadocs-ui/provider/next";
import { ConvexClientProvider } from "./ConvexClientProvider";
import "./globals.css";

// Space Grotesk (geometric, characterful) for UI + display, JetBrains Mono for
// data/metrics — deliberately not the Next.js default Geist, which reads as a starter template.
const displaySans = Space_Grotesk({
  variable: "--font-display",
  subsets: ["latin"],
  weight: ["400", "500", "600", "700"],
});

const dataMono = JetBrains_Mono({
  variable: "--font-data",
  subsets: ["latin"],
  weight: ["400", "500", "700"],
});

export const metadata: Metadata = {
  title: "GhostFilter AI — Scam & Phishing Shield",
  description: "AI-powered scam and phishing message analyzer.",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html
      lang="en"
      className={`${displaySans.variable} ${dataMono.variable} h-full antialiased`}
    >
      <body className="min-h-full flex flex-col">
        <RootProvider theme={{ attribute: "class", forcedTheme: "dark" }}>
          <ConvexClientProvider>{children}</ConvexClientProvider>
        </RootProvider>
      </body>
    </html>
  );
}
