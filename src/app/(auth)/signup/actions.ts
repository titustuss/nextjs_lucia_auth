"use server";

import { lucia } from "@/app/auth";
import prisma from "@/lib/prisma";
import { signUpSchema, SignUpValues } from "@/lib/validation";
import { hash } from "@node-rs/argon2";
import { generateIdFromEntropySize } from "lucia";
import { cookies } from "next/headers";
import { redirect } from "next/navigation";

export async function signUp(
  credentials: SignUpValues
): Promise<{ error?: string }> {
  try {
    const { username, email, password } = signUpSchema.parse(credentials);

    // Hash the password
    const passwordHash = await hash(password, {
      memoryCost: 19456,
      timeCost: 2,
      outputLen: 32,
      parallelism: 1,
    });

    // Generate a unique user ID
    const userId = generateIdFromEntropySize(10);

    // Check if the username already exists
    const existingUsername = await prisma.user.findFirst({
      where: {
        username: {
          equals: username,
          mode: "insensitive",
        },
      },
    });
    if (existingUsername) {
      return {
        error: "Username already taken",
      };
    }

    // Check if the email already exists
    const existingEmail = await prisma.user.findFirst({
      where: {
        email: {
          equals: email,
          mode: "insensitive",
        },
      },
    });
    if (existingEmail) {
      return {
        error: "Email already taken",
      };
    }

    // Create the user in the database
    await prisma.user.create({
      data: {
        id: userId,
        username,
        displayName: username,
        email,
        passwordHash,
      },
    });

    // Create a session for the user
    const session = await lucia.createSession(userId, {});

    // Set the session cookie
    const sessionCookie = lucia.createSessionCookie(session.id);
    const cookieStore = await cookies();
    cookieStore.set(
      sessionCookie.name,
      sessionCookie.value,
      sessionCookie.attributes
    );

    // Redirect to the home page
    redirect("/dashboard"); // Do not use `return` with `redirect`

    // If the function reaches this point, ensure no value is returned
    return {}; // Optional: Return an empty object on success
  } catch (error) {
    console.error("Error during sign-up:", error);

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
