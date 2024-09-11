package de.medizininformatik_initiative.process.feasibility.service;

import dev.dsf.bpe.v1.ProcessPluginApi;
import dev.dsf.bpe.v1.activity.AbstractServiceDelegate;
import dev.dsf.bpe.v1.variables.Variables;
import org.camunda.bpm.engine.delegate.BpmnError;
import org.camunda.bpm.engine.delegate.DelegateExecution;
import org.hl7.fhir.r4.model.CodeableConcept;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.InitializingBean;

import static org.hl7.fhir.r4.model.Task.TaskStatus.FAILED;

public class RateLimitExceededTaskRejecter extends AbstractServiceDelegate implements InitializingBean {
    private static final Logger logger = LoggerFactory.getLogger(RateLimitExceededTaskRejecter.class);

    public RateLimitExceededTaskRejecter(ProcessPluginApi api) {
        super(api);
    }

    @Override
    protected void doExecute(DelegateExecution execution, Variables variables) throws BpmnError, Exception {
        logger.info("doExecute reject task");

        var reason = new CodeableConcept().setText("The request rate limit has been exceeded.");
        variables.getStartTask().setStatus(FAILED).setStatusReason(reason);
    }

}
