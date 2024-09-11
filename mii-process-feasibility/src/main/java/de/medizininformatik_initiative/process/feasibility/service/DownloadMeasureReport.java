package de.medizininformatik_initiative.process.feasibility.service;

import de.medizininformatik_initiative.process.feasibility.EnhancedFhirWebserviceClientProvider;
import dev.dsf.bpe.v1.ProcessPluginApi;
import dev.dsf.bpe.v1.activity.AbstractServiceDelegate;
import dev.dsf.bpe.v1.variables.Variables;
import dev.dsf.fhir.client.FhirWebserviceClient;
import org.camunda.bpm.engine.delegate.DelegateExecution;
import org.hl7.fhir.r4.model.IdType;
import org.hl7.fhir.r4.model.MeasureReport;
import org.hl7.fhir.r4.model.Reference;
import org.hl7.fhir.r4.model.Task;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.InitializingBean;

import java.util.Objects;
import java.util.Optional;

import static de.medizininformatik_initiative.process.feasibility.variables.ConstantsFeasibility.CODESYSTEM_FEASIBILITY;
import static de.medizininformatik_initiative.process.feasibility.variables.ConstantsFeasibility.CODESYSTEM_FEASIBILITY_VALUE_MEASURE_REPORT_REFERENCE;
import static de.medizininformatik_initiative.process.feasibility.variables.ConstantsFeasibility.VARIABLE_MEASURE_REPORT;

public class DownloadMeasureReport extends AbstractServiceDelegate implements InitializingBean {

    private static final Logger logger = LoggerFactory.getLogger(DownloadMeasureReport.class);
    private EnhancedFhirWebserviceClientProvider clientProvider;

    public DownloadMeasureReport(EnhancedFhirWebserviceClientProvider clientProvider, ProcessPluginApi api) {
        super(api);
        this.clientProvider = clientProvider;
    }

    @Override
    public void afterPropertiesSet() throws Exception {
        super.afterPropertiesSet();
        Objects.requireNonNull(clientProvider, "clientProvider");
    }

    @Override
    protected void doExecute(DelegateExecution execution, Variables variables) {
        logger.info("doExecute download MeasureReport");

        var task = variables.getLatestTask();
        var measureReportId = getMeasureReportId(task);
        var client = clientProvider
                .getWebserviceClientByReference(measureReportId);
        var measureReport = downloadMeasureReport(client, measureReportId);
        execution.setVariableLocal(VARIABLE_MEASURE_REPORT, measureReport);
    }

    private MeasureReport downloadMeasureReport(FhirWebserviceClient client, IdType measureReportId) {
        logger.debug("Download MeasureReport with ID {} from {}", measureReportId.getIdPart(), client.getBaseUrl());
        return client.read(MeasureReport.class, measureReportId.getIdPart());
    }

    private IdType getMeasureReportId(Task task) {
        Optional<Reference> measureRef = api.getTaskHelper()
                .getFirstInputParameterValue(task, CODESYSTEM_FEASIBILITY,
                        CODESYSTEM_FEASIBILITY_VALUE_MEASURE_REPORT_REFERENCE, Reference.class);
        if (measureRef.isPresent()) {
            return new IdType(measureRef.get().getReference());
        } else {
            logger.error("Task {} is missing the measure report reference.", task.getId());
            throw new RuntimeException("Missing measure report reference.");
        }
    }
}
