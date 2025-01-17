package de.medizininformatik_initiative.process.feasibility.service;

import ca.uhn.fhir.rest.client.api.IGenericClient;
import de.medizininformatik_initiative.process.feasibility.variables.ConstantsFeasibility;
import dev.dsf.bpe.v1.ProcessPluginApi;
import dev.dsf.bpe.v1.activity.AbstractServiceDelegate;
import dev.dsf.bpe.v1.variables.Variables;
import org.camunda.bpm.engine.delegate.DelegateExecution;
import org.hl7.fhir.r4.model.DateType;
import org.hl7.fhir.r4.model.MeasureReport;
import org.hl7.fhir.r4.model.Parameters;
import org.hl7.fhir.r4.model.StringType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.InitializingBean;

import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

import static de.medizininformatik_initiative.process.feasibility.variables.ConstantsFeasibility.MEASURE_REPORT_PERIOD_END;
import static de.medizininformatik_initiative.process.feasibility.variables.ConstantsFeasibility.MEASURE_REPORT_PERIOD_START;
import static de.medizininformatik_initiative.process.feasibility.variables.ConstantsFeasibility.MEASURE_REPORT_TYPE_POPULATION;
import static de.medizininformatik_initiative.process.feasibility.variables.ConstantsFeasibility.VARIABLE_MEASURE_ID;
import static de.medizininformatik_initiative.process.feasibility.variables.ConstantsFeasibility.VARIABLE_REQUESTER_PARENT_ORGANIZATION;

public class EvaluateCQLMeasure extends AbstractServiceDelegate implements InitializingBean {

    private static final Logger logger = LoggerFactory.getLogger(EvaluateCQLMeasure.class);

    private static final String MEASURE_POPULATION = "http://terminology.hl7.org/CodeSystem/measure-population";
    private static final String INITIAL_POPULATION = "initial-population";

    private final Map<String, IGenericClient> storeClients;

    private Map<String, Set<String>> networkStores;

    public EvaluateCQLMeasure(Map<String, Set<String>> networkStores, Map<String, IGenericClient> storeClients,
            ProcessPluginApi api) {
        super(api);
        this.networkStores = networkStores;
        this.storeClients = storeClients;
    }

    @Override
    public void afterPropertiesSet() throws Exception {
        super.afterPropertiesSet();

        Objects.requireNonNull(storeClients, "storeClients");
    }

    @Override
    protected void doExecute(DelegateExecution execution, Variables variables) {
        var requesterParentOrganization = variables.getString(VARIABLE_REQUESTER_PARENT_ORGANIZATION);
        variables.setInteger(ConstantsFeasibility.VARIABLE_MEASURE_RESULT_CQL,
                executeEvaluateMeasure(requesterParentOrganization, variables));
    }

    private int executeEvaluateMeasure(String requesterParentOrganization, Variables variables) {
        var errorsAndResults = Optional.ofNullable(networkStores.get(requesterParentOrganization))
                .orElse(Set.of())
                .stream()
                .filter(storeId -> storeClients.containsKey(storeId))
                .collect(Collectors.toMap(id -> id, id -> storeClients.get(id)))
                .entrySet()
                .parallelStream()
                .map(e -> executeMeasure(e.getKey(), e.getValue(),
                        variables.getString("%s_%s".formatted(VARIABLE_MEASURE_ID, e.getKey()))))
                .collect(Collectors.partitioningBy(r -> validateMeasureReport(r)));

        if (errorsAndResults.getOrDefault(false, List.of()).isEmpty()) {
            return errorsAndResults.getOrDefault(true, List.of())
                    .stream()
                    .map(r -> r.getGroupFirstRep().getPopulationFirstRep().getCount())
                    .reduce(0, (a, b) -> a + b);
        } else {
            throw new IllegalStateException("Invalid measure report(s).");
        }
    }

    private MeasureReport executeMeasure(String storeId, IGenericClient client, String measureId) {
        if (measureId == null || measureId.isBlank()) {
            throw new IllegalStateException(
                    "No measure id to execute for store '%s' found in execution variables.".formatted(storeId));
        } else {
            logger.debug("Evaluate measure {}", measureId);

            return client.operation().onInstance("Measure/" + measureId).named("evaluate-measure")
                    .withParameter(Parameters.class, "periodStart", new DateType(MEASURE_REPORT_PERIOD_START))
                    .andParameter("periodEnd", new DateType(MEASURE_REPORT_PERIOD_END))
                    .andParameter("reportType", new StringType(MEASURE_REPORT_TYPE_POPULATION))
                    .useHttpGet()
                    .returnResourceType(MeasureReport.class)
                    .execute();
        }
    }

    private boolean validateMeasureReport(MeasureReport report) {
        if (!report.hasGroup()) {
            logger.error("Missing group for MeasureReport(id: '{}').", report.getId());
            return false;
        }
        if (!report.getGroupFirstRep().hasPopulation()) {
            logger.error("Missing population for MeasureReport(id: '{}').", report.getId());
            return false;
        }
        if (!report.getGroupFirstRep().getPopulationFirstRep().hasCode()) {
            logger.error("Missing population code for MeasureReport(id: '{}').", report.getId());
            return false;
        }
        if (!report.getGroupFirstRep().getPopulationFirstRep().getCode().hasCoding(MEASURE_POPULATION,
                INITIAL_POPULATION)) {
            logger.error("Missing initial-population code for MeasureReport(id: '{}').", report.getId());
            return false;
        }
        if (!report.getGroupFirstRep().getPopulationFirstRep().hasCount()) {
            logger.error("Missing population count for MeasureReport(id: '{}').", report.getId());
            return false;
        }
        return true;
    }
}
