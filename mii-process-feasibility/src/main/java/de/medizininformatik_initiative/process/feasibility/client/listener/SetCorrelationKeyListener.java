package de.medizininformatik_initiative.process.feasibility.client.listener;

import dev.dsf.bpe.v1.ProcessPluginApi;
import dev.dsf.bpe.v1.constants.BpmnExecutionVariables;
import org.camunda.bpm.engine.delegate.DelegateExecution;
import org.camunda.bpm.engine.delegate.ExecutionListener;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.InitializingBean;

import java.util.Objects;

public class SetCorrelationKeyListener implements ExecutionListener, InitializingBean
{
    private static final Logger logger = LoggerFactory.getLogger(SetCorrelationKeyListener.class);

    private final ProcessPluginApi api;

    public SetCorrelationKeyListener(ProcessPluginApi api) {
        this.api = api;
    }

    @Override
    public void afterPropertiesSet() throws Exception {
        Objects.requireNonNull(api, "api");
    }

    @Override
    public void notify(DelegateExecution execution) throws Exception {
        logger.info("notify Gateway Receive DIC Result");

        var variables = api.getVariables(execution);
        var target = variables.getTarget();

        execution.setVariableLocal(BpmnExecutionVariables.CORRELATION_KEY, target.getCorrelationKey());
    }
}
