import com.yooshastan.wonheeproxy.core.UltgramPackages;
import java.util.Arrays;
import java.util.HashSet;

public final class UltgramPackagesTest {
    public static void main(String[] args) {
        String[] expected = {
                "com.yooshastan.ultmessenger.foss.beta",
                "com.yooshastan.ultmessenger.foss",
                "com.yooshastan.ultmessenger.beta",
                "com.yooshastan.ultmessenger"
        };
        String[] actual = UltgramPackages.candidates();
        if (!Arrays.equals(expected, actual)) {
            throw new AssertionError("Missing or reordered Ultgram build variants");
        }
        if (new HashSet<>(Arrays.asList(actual)).size() != actual.length) {
            throw new AssertionError("Duplicate Ultgram package variants");
        }
        actual[0] = "untrusted.package";
        if (!UltgramPackages.candidates()[0].equals(expected[0])) {
            throw new AssertionError("Callers must not mutate allowed destinations");
        }
        System.out.println("Ultgram package handoff targets passed");
    }
}
