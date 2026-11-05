package com.yooshastan.wonheeproxy;

import java.util.Arrays;

public final class RootDualRoutePolicyTest {
    private static void fails(String expected, String[] home, String[] internet) {
        try {
            RootDualRoutePolicy.validate(Arrays.asList(home), Arrays.asList(internet));
            throw new AssertionError("Expected: " + expected);
        } catch (IllegalArgumentException got) {
            if (!got.getMessage().contains(expected)) throw new AssertionError(got);
        }
    }

    public static void main(String[] ignored) {
        String[] split = {"10.6.0.0/24", "10.0.0.0/24"};
        String[] full = {"0.0.0.0/0", "::/0"};
        RootDualRoutePolicy.validate(Arrays.asList(split), Arrays.asList(full));
        fails("Home must be split", new String[] {"0.0.0.0/0"}, full);
        fails("AirVPN must include", split, new String[] {"0.0.0.0/0"});
        fails("AirVPN must include", split, new String[] {"::/0"});
        fails("need peer routes", new String[] {}, full);
        System.out.println("RootDualRoutePolicyTest passed");
    }
}
