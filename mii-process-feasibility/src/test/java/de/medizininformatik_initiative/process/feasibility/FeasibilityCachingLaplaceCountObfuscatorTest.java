package de.medizininformatik_initiative.process.feasibility;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.stream.IntStream;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;

public class FeasibilityCachingLaplaceCountObfuscatorTest {

    private static final int RESULT = 490715;
    private FeasibilityCachingLaplaceCountObfuscator obfuscator;

    private static Stream<Integer> resultRange() {
        return IntStream.rangeClosed(-100, 1000).boxed();
    }

    @BeforeEach
    public void setUp() {
        obfuscator = new FeasibilityCachingLaplaceCountObfuscator(1, 0.5);
    }

    @RepeatedTest(100)
    @DisplayName("obfuscated result is rounded to tens")
    public void checkIfObfuscatedResultIsRoundedToTens() {
        var result = 490715;
        var obfuscatedResult = obfuscator.obfuscate(result);

        assertThat(obfuscatedResult % 10).as("obfuscated result is rounded to tens").isEqualTo(0);
    }

    @RepeatedTest(100)
    @DisplayName("for the same result value the obfuscater always returns the same obfuscated result")
    public void obfuscatedResultStaysSameForSameInputValue() {
        Integer resultA = obfuscator.obfuscate(RESULT);
        Integer resultB = obfuscator.obfuscate(RESULT);

        assertThat(resultA).isEqualTo(resultB);
    }

    @ParameterizedTest
    @MethodSource("resultRange")
    @DisplayName("the obfuscated result is always >= 0 for any given result")
    public void nonNegativeObfuscatedResult(Integer result) {
        assertThat(obfuscator.obfuscate(result)).isGreaterThanOrEqualTo(0);
    }
}
