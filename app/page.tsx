import type { Metadata } from "next";
import LandingPage from "./LandingPage";

export const metadata: Metadata = {
  title: "GhostFilter AI — Inspect Before You Trust",
  description:
    "Analyze suspicious messages, links, email headers, and attachments before you click, reply, or share sensitive information.",
};

export default function HomePage() {
  return <LandingPage />;
}
