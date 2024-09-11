package de.medizininformatik_initiative.process.feasibility.service;

import dev.dsf.bpe.v1.ProcessPluginApi;
import dev.dsf.bpe.v1.activity.AbstractServiceDelegate;
import dev.dsf.bpe.v1.variables.Variables;
import org.camunda.bpm.engine.delegate.BpmnError;
import org.camunda.bpm.engine.delegate.DelegateExecution;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class LogReceiveTimeout extends AbstractServiceDelegate {

    private static final Logger logger = LoggerFactory.getLogger(LogReceiveTimeout.class);

    public LogReceiveTimeout(ProcessPluginApi api) {
        super(api);
    }

    @Override
    protected void doExecute(DelegateExecution execution, Variables variables) throws BpmnError, Exception {
        logger.info("doExecute log receive timeout");

        var target = variables.getTarget();
        logger.warn("Timeout while waiting for result from {} (endpoint url: {}).",
                target.getOrganizationIdentifierValue(),
                target.getEndpointUrl());
    }

}
