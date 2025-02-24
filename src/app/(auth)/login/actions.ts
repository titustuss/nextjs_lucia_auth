"use server";

import { lucia } from "@/app/auth";
import prisma from "@/lib/prisma";
import { loginSchema, LoginValues } from "@/lib/validation";
import { verify } from "@node-rs/argon2";
import { cookies } from "next/headers";
import { redirect } from "next/navigation";

export async function login(
  credentials: LoginValues
): Promise<{ error?: string }> {
  try {
    const { username, password } = loginSchema.parse(credentials);

    // Find the user by username
    const existingUser = await prisma.user.findFirst({
      where: {
        username: {
          equals: username,
          mode: "insensitive",
        },
      },
    });

    if (!existingUser || !existingUser.passwordHash) {
      return {
        error: "Incorrect username or password",
      };
    }

    // Verify the password
    const validPassword = await verify(existingUser.passwordHash, password, {
      memoryCost: 19456,
      timeCost: 2,
      outputLen: 32,
      parallelism: 1,
    });

    if (!validPassword) {
      return {
        error: "Incorrect username or password",
      };
    }

    // Create a session for the user
    const session = await lucia.createSession(existingUser.id, {});

    // Set the session cookie
    const sessionCookie = lucia.createSessionCookie(session.id);
    const cookieStore = await cookies(); // Await the cookies object
    cookieStore.set(
      sessionCookie.name,
      sessionCookie.value,
      sessionCookie.attributes
    );

    // Redirect to the home page
    redirect("/dashboard"); // Call redirect directly without wrapping in return

    return {}; // Optional: Return an empty object on success
  } catch (error) {
    console.error("Error during login:", error);

    // Type guard to check if the error is a redirect error
    if (
      error &&
      typeof error === "object" &&
      "digest" in error &&
      typeof error.digest === "string" &&
      error.digest.startsWith("NEXT_REDIRECT")
    ) {
      throw error; // Re-throw the redirect error
    }

    // Return an error message for other cases
    return {
      error: "Something went wrong. Please try again.",
    };
  }
}
