package de.medizininformatik_initiative.process.feasibility;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

public class EvaluationStrategyTest {

    @Test
    public void testFromStrategyRepresentation_UnknownStrategy() {
        assertThrows(IllegalArgumentException.class, () -> EvaluationStrategy.fromStrategyRepresentation("unknown"));
    }

    @Test
    public void testFromStrategyRepresentation_StrategyCaseDoesNotMatter() {
        var evaluationStrategy = EvaluationStrategy.fromStrategyRepresentation("strUCtured-QUerY");
        assertEquals(EvaluationStrategy.CCDL, evaluationStrategy);
    }

    @Test
    public void testFromStrategyRepresentation() {
        var evaluationStrategy = EvaluationStrategy.fromStrategyRepresentation("cql");
        assertEquals(EvaluationStrategy.CQL, evaluationStrategy);
    }
}
