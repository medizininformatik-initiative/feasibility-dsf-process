package de.medizininformatik_initiative.process.feasibility;

import com.fasterxml.jackson.annotation.JsonCreator;

import java.util.Arrays;
import java.util.List;

import static java.util.Arrays.asList;

/**
 * Determines which evaluation strategy to be used within the process.
 */
public enum EvaluationStrategy {

    /**
     * Measures will be evaluated using CQL.
     * Requires a FHIR server capable of handling CQL queries.
     */
    CQL("cql"),

    /**
     * Measures will be evaluated using a clinical cohort definition language query.
     */
    CCDL("ccdl", "structured-query");

    private List<String> strategyRepresentations;

    EvaluationStrategy(String... strategyRepresentation) {
        assert strategyRepresentation.length > 0;
        this.strategyRepresentations = asList(strategyRepresentation);
    }

    /**
     * Gets the string representation of this evaluation strategy.
     *
     * @return The evaluation strategy's string representation.
     */
    @Override
    public String toString() {
        return strategyRepresentations.get(0);
    }

    /**
     * Gets the appropriate evaluation strategy instance for a given representation.
     *
     * @param strategyRepresentation An evaluation strategy's string representation.
     * @return The appropriate evaluation strategy instance.
     * @throws IllegalArgumentException If the given strategy representation is not supported.
     */
    @JsonCreator
    public static EvaluationStrategy fromStrategyRepresentation(String strategyRepresentation) {
        return Arrays.stream(EvaluationStrategy.values())
                .filter(es -> es.strategyRepresentations.stream()
                        .anyMatch(r -> r.equalsIgnoreCase(strategyRepresentation)))
                .findFirst()
                .orElseThrow(() -> new IllegalArgumentException("No known evaluation strategy with the representation: " + strategyRepresentation));
    }
}
