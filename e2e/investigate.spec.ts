import { expect, test } from "@playwright/test";

test.describe("investigate flow", () => {
  test("renders the tactical report for the default IOC", async ({ page }) => {
    await page.goto("/investigate");

    const input = page.getByLabel(/IOC input/i);
    await expect(input).toHaveValue("8.8.8.8");

    await page.getByRole("button", { name: "Investigate" }).click();

    await expect(page.getByText("Normalized target")).toBeVisible();
    await expect(page.getByText("8.8.8.8", { exact: true }).first()).toBeVisible();
    await expect(page.getByText("Reputation", { exact: true }).first()).toBeVisible();
  });

  test("shows an error state for an invalid IOC", async ({ page }) => {
    await page.goto("/investigate");

    await page.getByLabel(/IOC input/i).fill("not an ioc");
    await page.getByRole("button", { name: "Investigate" }).click();

    await expect(page.getByText(/Unsupported or malformed IOC/i)).toBeVisible();
  });
});