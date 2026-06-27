import type { Metadata } from "next";
import { Space_Grotesk, JetBrains_Mono } from "next/font/google";
import { RootProvider } from "fumadocs-ui/provider/next";
import { ConvexClientProvider } from "./ConvexClientProvider";
import { AuthSessionProvider } from "./AuthSessionProvider";
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
  metadataBase: new URL(process.env.NEXT_PUBLIC_APP_URL ?? "http://localhost:3000"),
  title: {
    default: "GhostFilter AI | Human and Agent Safety Firewall",
    template: "%s | GhostFilter AI",
  },
  description:
    "Detect scams and phishing for people, and block prompt injection before untrusted content reaches AI agents.",
  applicationName: "GhostFilter AI",
  openGraph: {
    title: "GhostFilter AI",
    description: "A safety firewall for people and AI agents.",
    type: "website",
  },
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
          <AuthSessionProvider>
            <ConvexClientProvider>{children}</ConvexClientProvider>
          </AuthSessionProvider>
        </RootProvider>
      </body>
    </html>
  );
}
