import { createHash } from "node:crypto";
import type { NextAuthOptions } from "next-auth";
import CredentialsProvider from "next-auth/providers/credentials";
import { createOwnerToken } from "./ownerToken";

function stableUserId(email: string) {
  return `user_${createHash("sha256").update(email.trim().toLowerCase()).digest("hex").slice(0, 32)}`;
}

export const authOptions: NextAuthOptions = {
  session: {
    strategy: "jwt",
    maxAge: 60 * 60 * 24 * 14,
  },
  pages: {
    signIn: "/dashboard",
  },
  providers: [
    CredentialsProvider({
      name: "GhostFilter account",
      credentials: {
        name: { label: "Name", type: "text" },
        email: { label: "Email", type: "email" },
        password: { label: "Access code", type: "password" },
      },
      async authorize(credentials) {
        const email = credentials?.email?.trim().toLowerCase();
        if (!email || !email.includes("@")) return null;

        const configuredPassword = process.env.DEMO_AUTH_PASSWORD;
        if (process.env.NODE_ENV === "production" && !configuredPassword) {
          console.error("DEMO_AUTH_PASSWORD must be configured in production.");
          return null;
        }
        if (configuredPassword && credentials?.password !== configuredPassword) {
          return null;
        }

        return {
          id: stableUserId(email),
          email,
          name: credentials?.name?.trim() || email.split("@")[0] || "GhostFilter user",
        };
      },
    }),
  ],
  callbacks: {
    async jwt({ token, user }) {
      if (user?.id) token.sub = user.id;
      return token;
    },
    async session({ session, token }) {
      if (session.user && token.sub) {
        session.user.id = token.sub;
        session.ownerToken = await createOwnerToken(token.sub);
      }
      return session;
    },
  },
};

export function sessionOwnerId(session: { user?: { id?: string | null } } | null) {
  return session?.user?.id ?? null;
}
