import { expect, test } from "@playwright/test";

test.describe("smoke", () => {
  test("home page loads with the GuardiaBox heading", async ({ page }) => {
    await page.goto("/");
    await expect(page.getByRole("heading", { name: "GuardiaBox" })).toBeVisible();
  });
});
