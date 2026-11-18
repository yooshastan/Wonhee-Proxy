package com.yooshastan.wonheeproxy;

/** Pure category checks; no Android context, root or network access. */
public final class AppUseCategoriesTest {
    public static void main(String[] args) {
        if (AppUseCategories.LABELS.length != 8
                || AppUseCategories.EXPLANATIONS.length != 8) {
            throw new AssertionError("Expected eight app categories.");
        }
        String[] expected = {
                "Everyday", "Private", "Regional", "Finance",
                "Home", "Work", "Media", "System"
        };
        for (int i = 0; i < expected.length; i++) {
            if (!AppUseCategories.valid(i)
                    || !expected[i].equals(AppUseCategories.label(i))
                    || AppUseCategories.EXPLANATIONS[i].trim().isEmpty()) {
                throw new AssertionError("Category mismatched: " + i);
            }
        }
        if (AppUseCategories.valid(-1)
                || AppUseCategories.valid(8)
                || AppUseCategories.safe(999) != AppUseCategories.EVERYDAY) {
            throw new AssertionError("Unknown categories must fail safe.");
        }
        String[] valid = {"com.example.app", "org.telegram.messenger",
                "com.mcdonalds.mobileapp", "co.example_app.store_2"};
        for (String s : valid) {
            if (!AppUseCategories.validPackageName(s)) {
                throw new AssertionError("Expected valid package name");
            }
        }
        String[] invalid = {"", "app", "../../private", "a..b",
                "x/secret.key", "x.b\nlog", ".hidden", "x.b;reboot"};
        for (String s : invalid) {
            if (AppUseCategories.validPackageName(s)) {
                throw new AssertionError("Expected invalid package name");
            }
        }
        if (AppUseCategories.validPackageName(null)
                || AppUseCategories.validPackageName("x."+"q".repeat(240))) {
            throw new AssertionError("Invalid package names were accepted.");
        }
        System.out.println("AppUseCategoriesTest passed");
    }
}
