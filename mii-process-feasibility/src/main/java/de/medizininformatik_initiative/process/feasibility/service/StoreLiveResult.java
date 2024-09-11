package de.medizininformatik_initiative.process.feasibility.service;

import dev.dsf.bpe.v1.ProcessPluginApi;
import dev.dsf.bpe.v1.activity.AbstractServiceDelegate;
import dev.dsf.bpe.v1.variables.Variables;
import org.camunda.bpm.engine.delegate.DelegateExecution;
import org.hl7.fhir.r4.model.IdType;
import org.hl7.fhir.r4.model.MeasureReport;
import org.hl7.fhir.r4.model.Reference;
import org.hl7.fhir.r4.model.Task;
import org.hl7.fhir.r4.model.Task.TaskOutputComponent;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.InitializingBean;

import static de.medizininformatik_initiative.process.feasibility.variables.ConstantsFeasibility.*;
import static dev.dsf.fhir.authorization.read.ReadAccessHelper.READ_ACCESS_TAG_VALUE_LOCAL;

/**
 * The type Store live result.
 */
public class StoreLiveResult extends AbstractServiceDelegate implements InitializingBean {

    private static final Logger logger = LoggerFactory.getLogger(StoreLiveResult.class);

    /**
     * Instantiates a new Store live result.
     *
     * @param api
     * @param clientProvider the client provider
     * @param taskHelper     the task helper
     */
    public StoreLiveResult(ProcessPluginApi api) {
        super(api);
    }

    @Override
    protected void doExecute(DelegateExecution execution, Variables variables) {
        logger.info("doExecute store live result");

        var task = variables.getLatestTask();

        var measureReport = (MeasureReport) execution.getVariableLocal(VARIABLE_MEASURE_REPORT);
        addReadAccessTag(measureReport);

        var storedMeasureReport = storeMeasureReport(measureReport);
        addMeasureReportReferenceToTaskOutput(task, storedMeasureReport.getIdElement());
        logger.info("Added measure report {} to {}", storedMeasureReport.getId(), task.getId());

        variables.setResource("subMeasure_" + variables.getTarget().getCorrelationKey(),
                storedMeasureReport);
    }

    private void addReadAccessTag(MeasureReport measureReport) {
        measureReport.getMeta().getTag().removeIf(t -> !READ_ACCESS_TAG_VALUE_LOCAL.equals(t.getCode()));

        if (!api.getReadAccessHelper().hasLocal(measureReport)) {
            api.getReadAccessHelper().addLocal(measureReport);
        }
    }

    private MeasureReport storeMeasureReport(MeasureReport measureReport) {
        return api.getFhirWebserviceClientProvider().getLocalWebserviceClient()
                .create(measureReport);
    }

    private void addMeasureReportReferenceToTaskOutput(Task task, IdType measureReportId) {
        task.addOutput(createMeasureReportReferenceOutput(measureReportId));
    }

    private TaskOutputComponent createMeasureReportReferenceOutput(IdType measureReportId) {
        return api.getTaskHelper().createOutput(
                new Reference().setReference(createMeasureRef(measureReportId)),
                CODESYSTEM_FEASIBILITY, CODESYSTEM_FEASIBILITY_VALUE_MEASURE_REPORT_REFERENCE);
    }

    private String createMeasureRef(IdType measureReportId) {
        return "MeasureReport/" + measureReportId.getIdPart();
    }
}
