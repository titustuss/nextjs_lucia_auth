import { PrismaAdapter } from "@lucia-auth/adapter-prisma";
import { Lucia, Session, User } from "lucia";
import { cookies } from "next/headers";
import { cache } from "react";
import prisma from "@/lib/prisma";

// Initialize the Prisma adapter
const adapter = new PrismaAdapter(prisma.session, prisma.user);

// Initialize Lucia
export const lucia = new Lucia(adapter, {
  sessionCookie: {
    expires: false,
    attributes: {
      secure: process.env.NODE_ENV === "production",
    },
  },
  getUserAttributes(databaseUserAttributes) {
    return {
      id: databaseUserAttributes.id,
      username: databaseUserAttributes.username,
      displayName: databaseUserAttributes.displayName,
      avatarUrl: databaseUserAttributes.avatarUrl,
      googleId: databaseUserAttributes.googleId,
    };
  },
});

// Declare module for TypeScript support
declare module "lucia" {
  interface Register {
    Lucia: typeof lucia;
    DatabaseUserAttributes: DatabaseUserAttributes;
  }
}

// Define user attributes interface
interface DatabaseUserAttributes {
  id: string;
  username: string;
  displayName: string;
  avatarUrl: string | null;
  googleId: string | null;
}

// Validate request function
export const validateRequest = cache(
  async (): Promise<
    { user: User; session: Session } | { user: null; session: null }
  > => {
    // Await the cookies object
    const cookieStore = await cookies();

    // Get the session ID from cookies
    const sessionId = cookieStore.get(lucia.sessionCookieName)?.value ?? null;

    if (!sessionId) {
      return {
        user: null,
        session: null,
      };
    }

    // Validate the session
    const result = await lucia.validateSession(sessionId);

    try {
      if (result.session && result.session.fresh) {
        // Create a new session cookie
        const sessionCookie = lucia.createSessionCookie(result.session.id);

        // Set the session cookie
        cookieStore.set(
          sessionCookie.name,
          sessionCookie.value,
          sessionCookie.attributes
        );
      }

      if (!result.session) {
        // Create a blank session cookie
        const sessionCookie = lucia.createBlankSessionCookie();

        // Set the blank session cookie
        cookieStore.set(
          sessionCookie.name,
          sessionCookie.value,
          sessionCookie.attributes
        );
      }
    } catch (error) {
      console.error("Error setting cookies:", error);
    }

    return result;
  }
);
