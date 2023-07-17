package de.medizininformatik_initiative.feasibility_dsf_process.service;

import ca.uhn.fhir.rest.client.api.IGenericClient;
import dev.dsf.bpe.v1.ProcessPluginApi;
import dev.dsf.bpe.v1.activity.AbstractServiceDelegate;
import dev.dsf.bpe.v1.variables.Variables;
import org.camunda.bpm.engine.delegate.DelegateExecution;
import org.hl7.fhir.r4.model.DateType;
import org.hl7.fhir.r4.model.MeasureReport;
import org.hl7.fhir.r4.model.Parameters;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.InitializingBean;

import java.util.Objects;

import static de.medizininformatik_initiative.feasibility_dsf_process.variables.ConstantsFeasibility.VARIABLE_MEASURE_ID;
import static de.medizininformatik_initiative.feasibility_dsf_process.variables.ConstantsFeasibility.VARIABLE_MEASURE_REPORT;

public class EvaluateCqlMeasure extends AbstractServiceDelegate implements InitializingBean {

    private static final Logger logger = LoggerFactory.getLogger(EvaluateCqlMeasure.class);

    private static final String CODE_SYSTEM_MEASURE_POPULATION = "http://terminology.hl7.org/CodeSystem/measure-population";
    private static final String CODE_INITIAL_POPULATION = "initial-population";

    private final IGenericClient storeClient;

    public EvaluateCqlMeasure(IGenericClient storeClient, ProcessPluginApi api) {
        super(api);

        this.storeClient = storeClient;
    }

    @Override
    public void afterPropertiesSet() throws Exception {
        super.afterPropertiesSet();

        Objects.requireNonNull(storeClient, "storeClient");
    }

    @Override
    protected void doExecute(DelegateExecution execution, Variables variables) {
        String measureId = variables.getString(VARIABLE_MEASURE_ID);

        MeasureReport report = executeEvaluateMeasure(measureId);
        validateMeasureReport(report);

        variables.setResource(VARIABLE_MEASURE_REPORT, report);
    }

    private MeasureReport executeEvaluateMeasure(String measureId) {
        logger.debug("Evaluate measure {}", measureId);
        return storeClient.operation().onInstance("Measure/" + measureId).named("evaluate-measure")
                .withParameter(Parameters.class, "periodStart", new DateType(1900, 1, 1))
                .andParameter("periodEnd", new DateType(2100, 1, 1))
                .useHttpGet()
                .returnResourceType(MeasureReport.class)
                .execute();
    }

    private void validateMeasureReport(MeasureReport report) {
        if (!report.hasGroup()) {
            throw new RuntimeException("Missing MeasureReport group");
        }
        if (!report.getGroupFirstRep().hasPopulation()) {
            throw new RuntimeException("Missing MeasureReport population");
        }
        if (!report.getGroupFirstRep().getPopulationFirstRep().hasCode()) {
            throw new RuntimeException("Missing MeasureReport population code");
        }
        if (!report.getGroupFirstRep().getPopulationFirstRep().getCode().hasCoding(CODE_SYSTEM_MEASURE_POPULATION,
                CODE_INITIAL_POPULATION)) {
            throw new RuntimeException("Missing MeasureReport initial-population code");
        }
        if (!report.getGroupFirstRep().getPopulationFirstRep().hasCount()) {
            throw new RuntimeException("Missing MeasureReport population count");
        }
    }
}
