package de.medizininformatik_initiative.process.feasibility;

import java.time.Duration;
import java.util.Objects;

import static java.lang.String.format;
import static org.springframework.util.Assert.isTrue;

/**
 * Can provide several information necessary for running the evaluation pipeline step.
 */
public class EvaluationSettingsProviderImpl implements EvaluationSettingsProvider {

    private final EvaluationStrategy evaluationStrategy;
    private final boolean evaluationResultObfuscationEnabled;
    private final double evaluationResultObfuscationLaplaceSensitivity;
    private final double evaluationResultObfuscationLaplaceEpsilon;
    private final Integer rateLimitCount;
    private final Duration rateLimitTimeIntervalDuration;
    private final boolean feasibilityDistributionEnabled;
    private final String requestOrganizationIdentifierValue;
    private final String executeOrganizationIdentifierValue;
    private final boolean subDic;

    public EvaluationSettingsProviderImpl(EvaluationStrategy evaluationStrategy,
                                          Boolean evaluationResultObfuscationEnabled,
                                          Double evaluationResultObfuscationLaplaceSensitivity,
                                          Double evaluationResultObfuscationLaplaceEpsilon,
                                          Integer rateLimitCount,
                                          Duration rateLimitTimeIntervalDuration,
                                          Boolean feasibilityDistributionEnabled,
                                          String requestOrganizationIdentifierValue,
                                          String executeOrganizationIdentifierValue,
                                          Boolean subDic) {
        this.evaluationStrategy = Objects.requireNonNull(evaluationStrategy);
        this.evaluationResultObfuscationEnabled = Objects.requireNonNull(evaluationResultObfuscationEnabled);
        this.evaluationResultObfuscationLaplaceSensitivity = Objects
                .requireNonNull(evaluationResultObfuscationLaplaceSensitivity);
        this.evaluationResultObfuscationLaplaceEpsilon = Objects
                .requireNonNull(evaluationResultObfuscationLaplaceEpsilon);
        this.rateLimitCount = Objects.requireNonNull(rateLimitCount);
        this.rateLimitTimeIntervalDuration = Objects.requireNonNull(rateLimitTimeIntervalDuration);

        isTrue(this.rateLimitCount >= 0, format("given request limit '%d' is not >= 0", this.getRateLimitCount()));
        isTrue(this.rateLimitTimeIntervalDuration.compareTo(Duration.ZERO) > 0,
                format("given request limit time interval '%s' is not > 0", this.rateLimitTimeIntervalDuration));

        this.feasibilityDistributionEnabled = Objects.requireNonNull(feasibilityDistributionEnabled);

        this.subDic = Objects.requireNonNull(subDic);

        this.requestOrganizationIdentifierValue = requestOrganizationIdentifierValue != null ?
                requestOrganizationIdentifierValue : "medizininformatik-initiative.de";

        this.executeOrganizationIdentifierValue = executeOrganizationIdentifierValue != null ?
                executeOrganizationIdentifierValue : "medizininformatik-initiative.de";

    }

    @Override
    public EvaluationStrategy evaluationStrategy() {
        return evaluationStrategy;
    }

    @Override
    public boolean evaluationResultObfuscationEnabled() {
        return evaluationResultObfuscationEnabled;
    }

    @Override
    public double resultObfuscationLaplaceSensitivity() {
        return evaluationResultObfuscationLaplaceSensitivity;
    }

    @Override
    public double resultObfuscationLaplaceEpsilon() {
        return evaluationResultObfuscationLaplaceEpsilon;
    }

    @Override
    public Integer getRateLimitCount() {
        return rateLimitCount;
    }

    @Override
    public Duration getRateLimitTimeIntervalDuration() {
        return rateLimitTimeIntervalDuration;
    }

    @Override
    public boolean feasibilityDistributionEnabled() {
        return feasibilityDistributionEnabled;
    }

    @Override
    public String requestOrganizationIdentifierValue() {
        return requestOrganizationIdentifierValue;
    }

    @Override
    public String executeOrganizationIdentifierValue() {
        return executeOrganizationIdentifierValue;
    }

    @Override
    public boolean subDic() {
        return subDic;
    }
}
