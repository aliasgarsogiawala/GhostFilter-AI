import "next-auth";

declare module "next-auth" {
  interface Session {
    ownerToken?: string;
    user?: {
      id?: string;
      name?: string | null;
      email?: string | null;
      image?: string | null;
    };
  }

  interface User {
    id: string;
  }
}
