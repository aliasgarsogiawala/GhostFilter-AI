import type { NextAuthOptions } from "next-auth";
import CredentialsProvider from "next-auth/providers/credentials";
import { ConvexHttpClient } from "convex/browser";
import { api } from "@/convex/_generated/api";
import { createOwnerToken } from "./ownerToken";

function authServiceSecret() {
  const secret = process.env.AUTH_SERVICE_SECRET;
  if (!secret) throw new Error("AUTH_SERVICE_SECRET is not configured.");
  return secret;
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
        email: { label: "Email", type: "email" },
        password: { label: "Password", type: "password" },
      },
      async authorize(credentials) {
        const email = credentials?.email?.trim().toLowerCase();
        const password = credentials?.password ?? "";
        if (!email || !password) return null;
        const convex = new ConvexHttpClient(process.env.NEXT_PUBLIC_CONVEX_URL!);
        return await convex.action(api.auth.login, {
          serviceSecret: authServiceSecret(),
          email,
          password,
        });
      },
    })
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
