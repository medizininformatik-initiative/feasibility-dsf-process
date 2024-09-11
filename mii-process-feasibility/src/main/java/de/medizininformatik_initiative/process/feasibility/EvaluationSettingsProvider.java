package de.medizininformatik_initiative.process.feasibility;

import java.time.Duration;

/**
 * Provides different settings required for evaluating a measure.
 */
public interface EvaluationSettingsProvider {

    /**
     * Returns the evaluation strategy.
     *
     * @return the evaluation strategy.
     */
    EvaluationStrategy evaluationStrategy();

    /**
     * Returns whether evaluation result obfuscation is enabled.
     *
     * @return True if evaluation result obfuscation is enabled and false otherwise.
     */
    boolean evaluationResultObfuscationEnabled();

    /**
     * Returns the sensitivity value of the Laplace algorithm to be used for obfuscating the feasibility result.
     *
     * @return value of sensitivity used for the result obfuscation Laplace algorithm
     */
    double resultObfuscationLaplaceSensitivity();

    /**
     * Returns the epsilon value of the Laplace algorithm to be used for obfuscating the feasibility result.
     *
     * @return value of epsilon used for the result obfuscation Laplace algorithm
     */

    double resultObfuscationLaplaceEpsilon();

    /**
     * Provides the user specified maximum number of request allowed for the given time interval
     *
     * @return maximum number of allowed requests (>= 0)
     */
    Integer getRateLimitCount();

    /**
     * Provides the time interval duration in which the request rate limit is evaluated
     *
     * @return time duration of rate limit interval
     */
    Duration getRateLimitTimeIntervalDuration();

    /**
     * Returns whether feasibility Distribution is enabled.
     *
     * @return True if feasibility Distribution is enabled and false otherwise.
     */
    boolean feasibilityDistributionEnabled();

    /**
     * Returns the set request organization identifier value (default: "medizininformatik-initiative.de")
     *
     * @return the set organization identifier value
     */
    String requestOrganizationIdentifierValue();

    /**
     * Returns the set execute organization identifier value (default: "medizininformatik-initiative.de")
     *
     * @return the set organization identifier value
     */
    String executeOrganizationIdentifierValue();

    /**
     * Returns whether this instance is a Sub-DIC
     *
     * @return True if this instance is a Sub-DIC
     */
    boolean subDic();
}