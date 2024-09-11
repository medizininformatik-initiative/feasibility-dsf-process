package de.medizininformatik_initiative.process.feasibility.service;

import dev.dsf.bpe.v1.ProcessPluginApi;
import dev.dsf.bpe.v1.activity.AbstractServiceDelegate;
import dev.dsf.bpe.v1.variables.Variables;
import org.camunda.bpm.engine.delegate.DelegateExecution;
import org.hl7.fhir.r4.model.IdType;
import org.hl7.fhir.r4.model.Measure;
import org.hl7.fhir.r4.model.MeasureReport;
import org.hl7.fhir.r4.model.Task;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.InitializingBean;

import java.util.List;

import static de.medizininformatik_initiative.process.feasibility.variables.ConstantsFeasibility.VARIABLE_MEASURE;
import static de.medizininformatik_initiative.process.feasibility.variables.ConstantsFeasibility.VARIABLE_MEASURE_REPORT;
import static de.medizininformatik_initiative.process.feasibility.variables.ConstantsFeasibility.VARIABLE_MEASURE_REPORT_ID;

public class StoreMeasureReport extends AbstractServiceDelegate implements InitializingBean {
    private static final Logger logger = LoggerFactory.getLogger(StoreMeasureReport.class);

    public StoreMeasureReport(ProcessPluginApi api) {
        super(api);
    }

    @Override
    protected void doExecute(DelegateExecution execution, Variables variables) {
        logger.info("doExecute store measure report");

        var task = variables.getStartTask();

        MeasureReport measureReport = variables.getResource(VARIABLE_MEASURE_REPORT);
        Measure associatedMeasure = variables.getResource(VARIABLE_MEASURE);

        addReadAccessTag(measureReport, task);
        referenceZarsMeasure(measureReport, associatedMeasure);
        stripEvaluatedResources(measureReport);

        var measureReportId = storeMeasureReport(measureReport);
        logger.debug("Stored MeasureReport {}", measureReportId);

        variables.setString(VARIABLE_MEASURE_REPORT_ID, measureReportId.getValue());
    }

    private void addReadAccessTag(MeasureReport measureReport, Task task)
    {
        var identifier = task.getRequester().getIdentifier().getValue();
        api.getReadAccessHelper().addOrganization(measureReport, identifier);
    }

    private void referenceZarsMeasure(MeasureReport measureReport, Measure zarsMeasure) {
        measureReport.setMeasure(zarsMeasure.getUrl());
    }

    private void stripEvaluatedResources(MeasureReport measureReport) {
        measureReport.setEvaluatedResource(List.of());
    }

    private IdType storeMeasureReport(MeasureReport measureReport) {
        return api.getFhirWebserviceClientProvider()
                .getLocalWebserviceClient()
                .withMinimalReturn()
                .create(measureReport);
    }
}
