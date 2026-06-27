import { createHash } from "node:crypto";
import type { NextAuthOptions } from "next-auth";
import CredentialsProvider from "next-auth/providers/credentials";
import GithubProvider from "next-auth/providers/github";
import GoogleProvider from "next-auth/providers/google";
import { createOwnerToken } from "./ownerToken";

function stableUserId(email: string) {
  return `user_${createHash("sha256").update(email.trim().toLowerCase()).digest("hex").slice(0, 32)}`;
}

const providers: NextAuthOptions["providers"] = [];

if (process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET) {
  providers.push(
    GoogleProvider({
      clientId: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    })
  );
}

if (process.env.GITHUB_CLIENT_ID && process.env.GITHUB_CLIENT_SECRET) {
  providers.push(
    GithubProvider({
      clientId: process.env.GITHUB_CLIENT_ID,
      clientSecret: process.env.GITHUB_CLIENT_SECRET,
    })
  );
}

if (process.env.NODE_ENV !== "production" || process.env.DEMO_AUTH_PASSWORD) {
  providers.push(
    CredentialsProvider({
      name: "Hackathon access code",
      credentials: {
        name: { label: "Name", type: "text" },
        email: { label: "Email", type: "email" },
        password: { label: "Access code", type: "password" },
      },
      async authorize(credentials) {
        const email = credentials?.email?.trim().toLowerCase();
        if (!email || !email.includes("@")) return null;

        const configuredPassword = process.env.DEMO_AUTH_PASSWORD;
        if (process.env.NODE_ENV === "production" && !configuredPassword) return null;
        if (configuredPassword && credentials?.password !== configuredPassword) return null;

        return {
          id: stableUserId(email),
          email,
          name: credentials?.name?.trim() || email.split("@")[0] || "GhostFilter user",
        };
      },
    })
  );
}

export const authOptions: NextAuthOptions = {
  session: {
    strategy: "jwt",
    maxAge: 60 * 60 * 24 * 14,
  },
  pages: {
    signIn: "/dashboard",
  },
  providers,
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
