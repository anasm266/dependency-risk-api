import { test, expect } from "@playwright/test";

test("dev login reaches repository dashboard", async ({ page }) => {
  await page.goto("/");
  await page.getByRole("button", { name: "dev login" }).click();
  await expect(page.getByText("repositories")).toBeVisible();
  await expect(page.getByText("anasm266/installsentry")).toBeVisible();
});

test("dashboard is usable on mobile viewport", async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto("/");
  await page.getByRole("button", { name: "dev login" }).click();
  await expect(page.getByText("active repo")).toBeVisible();
  await expect(page.getByRole("button", { name: "scan" })).toBeVisible();
});
