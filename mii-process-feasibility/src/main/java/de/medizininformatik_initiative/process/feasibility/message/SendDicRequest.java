package de.medizininformatik_initiative.process.feasibility.message;

import dev.dsf.bpe.v1.ProcessPluginApi;
import dev.dsf.bpe.v1.activity.AbstractTaskMessageSend;
import dev.dsf.bpe.v1.variables.Variables;
import org.camunda.bpm.engine.delegate.DelegateExecution;
import org.camunda.bpm.engine.impl.el.FixedValue;
import org.hl7.fhir.r4.model.Reference;
import org.hl7.fhir.r4.model.Task;
import org.hl7.fhir.r4.model.Task.ParameterComponent;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.stream.Stream;

import static com.google.common.base.Preconditions.checkNotNull;
import static de.medizininformatik_initiative.process.feasibility.variables.ConstantsFeasibility.CODESYSTEM_FEASIBILITY;
import static de.medizininformatik_initiative.process.feasibility.variables.ConstantsFeasibility.CODESYSTEM_FEASIBILITY_VALUE_MEASURE_REFERENCE;

public class SendDicRequest extends AbstractTaskMessageSend {
    private static final Logger logger = LoggerFactory.getLogger(SendDicRequest.class);
    private final FixedValue requestOrganizationIdentifierValue;

    public SendDicRequest(ProcessPluginApi api, String organizationIdentifierValue) {
        super(api);
        this.requestOrganizationIdentifierValue = new FixedValue(organizationIdentifierValue);
    }

    @Override
    protected Stream<ParameterComponent> getAdditionalInputParameters(DelegateExecution execution,
                                                                      Variables variables) {
        logger.info("getAdditionalInputParameters Send DIC Request");

        return Stream.of(api.getTaskHelper().createInput(
                new Reference(checkNotNull(variables.getString("measure-id"),
                        "variable 'measure-id' not set")),
                CODESYSTEM_FEASIBILITY, CODESYSTEM_FEASIBILITY_VALUE_MEASURE_REFERENCE));
    }

    @Override
    protected void handleIntermediateThrowEventError(DelegateExecution execution, Variables variables,
                                                     Exception exception, String errorMessage) {
        execution.setVariableLocal("sendError", true);
    }

    @Override
    protected void addErrorMessage(Task task, String errorMessage) {
    }

    public FixedValue getRequestOrganizationIdentifierValue() {
        return requestOrganizationIdentifierValue;
    }

    @Override
    protected String getInstantiatesCanonical(DelegateExecution execution, Variables variables) {
        String defaultInstantiatesCanonical = super.getInstantiatesCanonical(execution, variables);
        return defaultInstantiatesCanonical;
    }

}
