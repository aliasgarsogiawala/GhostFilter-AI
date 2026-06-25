import { DocsLayout } from "fumadocs-ui/layouts/docs";
import { source } from "@/lib/docs-source";

export default function Layout({ children }: { children: React.ReactNode }) {
  return (
    <DocsLayout
      tree={source.pageTree}
      nav={{
        title: <span className="font-semibold">GhostFilter AI</span>,
        url: "/",
      }}
      themeSwitch={{ enabled: false }}
      links={[
        {
          text: "Scanner",
          url: "/dashboard",
        },
        {
          text: "npm",
          url: "https://www.npmjs.com/package/ghostfilter-ai",
          external: true,
        },
        {
          text: "GitHub",
          url: "https://github.com/aliasgarsogiawala/GhostFilter-AI",
          external: true,
        },
      ]}
    >
      {children}
    </DocsLayout>
  );
}
