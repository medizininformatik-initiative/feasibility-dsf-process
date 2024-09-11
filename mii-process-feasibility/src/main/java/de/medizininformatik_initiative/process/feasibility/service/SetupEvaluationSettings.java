package de.medizininformatik_initiative.process.feasibility.service;

import de.medizininformatik_initiative.process.feasibility.EvaluationSettingsProvider;
import dev.dsf.bpe.v1.ProcessPluginApi;
import dev.dsf.bpe.v1.activity.AbstractServiceDelegate;
import dev.dsf.bpe.v1.variables.Variables;
import org.camunda.bpm.engine.delegate.DelegateExecution;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.InitializingBean;

import java.util.Objects;

import static de.medizininformatik_initiative.process.feasibility.variables.ConstantsFeasibility.*;

public class SetupEvaluationSettings extends AbstractServiceDelegate
        implements InitializingBean {
    private static final Logger logger = LoggerFactory.getLogger(SetupEvaluationSettings.class);

    private final EvaluationSettingsProvider evaluationSettingsProvider;

    public SetupEvaluationSettings(EvaluationSettingsProvider evaluationSettingsProvider, ProcessPluginApi api) {
        super(api);
        this.evaluationSettingsProvider = evaluationSettingsProvider;
    }

    @Override
    public void afterPropertiesSet() throws Exception {
        super.afterPropertiesSet();
        Objects.requireNonNull(evaluationSettingsProvider, "variablesSettingsProvider");
    }

    @Override
    protected void doExecute(DelegateExecution execution, Variables variables) {
        logger.info("doExecute setup evaluation settings");

        variables.setString(VARIABLE_EVALUATION_STRATEGY,
                evaluationSettingsProvider.evaluationStrategy().toString());
        variables.setBoolean(VARIABLE_EVALUATION_OBFUSCATION,
                evaluationSettingsProvider.evaluationResultObfuscationEnabled());
        variables.setDouble(VARIABLE_EVALUATION_OBFUSCATION_LAPLACE_SENSITIVITY,
                evaluationSettingsProvider.resultObfuscationLaplaceSensitivity());
        variables.setDouble(VARIABLE_EVALUATION_OBFUSCATION_LAPLACE_EPSILON,
                evaluationSettingsProvider.resultObfuscationLaplaceEpsilon());

        variables.setBoolean(VARIABLE_FEASIBILITY_DISTRIBUTION,
                evaluationSettingsProvider.feasibilityDistributionEnabled());
    }
}
