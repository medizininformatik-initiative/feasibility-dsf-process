package de.medizininformatik_initiative.process.feasibility.service;

import de.medizininformatik_initiative.process.feasibility.RateLimit;
import dev.dsf.bpe.v1.ProcessPluginApi;
import dev.dsf.bpe.v1.activity.AbstractServiceDelegate;
import dev.dsf.bpe.v1.variables.Variables;
import org.camunda.bpm.engine.delegate.BpmnError;
import org.camunda.bpm.engine.delegate.DelegateExecution;
import org.springframework.beans.factory.InitializingBean;

import java.util.Map;
import java.util.Optional;

import static de.medizininformatik_initiative.process.feasibility.variables.ConstantsFeasibility.VARIABLE_REQUESTER_PARENT_ORGANIZATION;
import static de.medizininformatik_initiative.process.feasibility.variables.ConstantsFeasibility.VARIABLE_REQUEST_RATE_BELOW_LIMIT;

/**
 * This class implements a rate limiting
 *
 * @author <a href="mailto:math2306@hotmail.com">Mathias Rühle</a>
 */
public class EvaluateRequestRate extends AbstractServiceDelegate implements InitializingBean {

    private Map<String, RateLimit> rateLimits;

    public EvaluateRequestRate(ProcessPluginApi api, Map<String, RateLimit> rateLimits) {
        super(api);
        this.rateLimits = rateLimits;
    }

    @Override
    protected void doExecute(DelegateExecution execution, Variables variables) throws BpmnError, Exception {
        var parentOrganization = variables.getString(VARIABLE_REQUESTER_PARENT_ORGANIZATION);
        variables.setBoolean(VARIABLE_REQUEST_RATE_BELOW_LIMIT,
                Optional.of(rateLimits.get(parentOrganization))
                        .map(r -> r.countRequestAndCheckLimit())
                        .orElseThrow(() -> new IllegalStateException(
                                "No rate limit set for network '%s'.".formatted(parentOrganization))));
    }
}
