"use server";
import { cookies } from "next/headers";
import { redirect } from "next/navigation";
import { lucia, validateRequest } from "../auth";

export async function logout() {
  try {
    // Validate the request to get the session
    const { session } = await validateRequest();
    if (!session) {
      throw new Error("Unauthorized");
    }

    // Invalidate the current session
    await lucia.invalidateSession(session.id);

    // Create a blank session cookie
    const sessionCookie = lucia.createBlankSessionCookie();

    // Set the blank session cookie (await cookies())
    const cookieStore = await cookies(); // Await the cookies object
    cookieStore.set(
      sessionCookie.name,
      sessionCookie.value,
      sessionCookie.attributes
    );

    // Redirect to the login page with explicit arguments
    return redirect("/");
  } catch (error) {
    console.error("Error during logout:", error);
    throw error; // Re-throw the error for proper handling
  }
}
