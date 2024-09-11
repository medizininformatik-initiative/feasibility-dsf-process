package de.medizininformatik_initiative.process.feasibility.service;

import de.medizininformatik_initiative.process.feasibility.EnhancedFhirWebserviceClientProvider;
import de.medizininformatik_initiative.process.feasibility.variables.ConstantsFeasibility;
import dev.dsf.bpe.v1.ProcessPluginApi;
import dev.dsf.bpe.v1.activity.AbstractServiceDelegate;
import dev.dsf.bpe.v1.variables.Variables;
import dev.dsf.fhir.client.FhirWebserviceClient;
import org.camunda.bpm.engine.delegate.DelegateExecution;
import org.hl7.fhir.r4.model.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.InitializingBean;

import java.util.Collections;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

import static de.medizininformatik_initiative.process.feasibility.variables.ConstantsFeasibility.CODESYSTEM_FEASIBILITY;
import static de.medizininformatik_initiative.process.feasibility.variables.ConstantsFeasibility.CODESYSTEM_FEASIBILITY_VALUE_MEASURE_REFERENCE;

public class DownloadFeasibilityResources extends AbstractServiceDelegate
        implements InitializingBean {

    private static final Logger logger = LoggerFactory.getLogger(DownloadFeasibilityResources.class);
    private EnhancedFhirWebserviceClientProvider clientProvider;

    public DownloadFeasibilityResources(EnhancedFhirWebserviceClientProvider clientProvider, ProcessPluginApi api) {
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
        logger.info("doExecute download feasibility resources");

        var task = variables.getStartTask();

        var measureId = getMeasureId(task);
        var client = clientProvider.getWebserviceClientByReference(measureId);
        var bundle = getMeasureAndLibrary(measureId, client);

        variables.setResource(ConstantsFeasibility.VARIABLE_MEASURE, bundle.getEntry().get(0).getResource());
        variables.setResource(ConstantsFeasibility.VARIABLE_LIBRARY, bundle.getEntry().get(1).getResource());
    }

    private IdType getMeasureId(Task task) {
        Optional<Reference> measureRef = api.getTaskHelper()
                .getFirstInputParameterValue(task, CODESYSTEM_FEASIBILITY,
                        CODESYSTEM_FEASIBILITY_VALUE_MEASURE_REFERENCE, Reference.class);
        if (measureRef.isPresent() && measureRef.get().getReference() != null) {
            return new IdType(measureRef.get().getReference());
        } else {
            logger.error("Task {} is missing the measure reference.", task.getId());
            throw new RuntimeException("Missing measure reference.");
        }
    }

    private Bundle getMeasureAndLibrary(IdType measureId, FhirWebserviceClient client) {
        try {
            var bundle = client.searchWithStrictHandling(Measure.class,
                    Map.of("_id", Collections.singletonList(measureId.getIdPart()),
                            "_include", Collections.singletonList("Measure:depends-on")));

            if (bundle.getEntry().size() < 2) {
                throw new RuntimeException("Returned search-set contained less then two entries");
            } else if (!bundle.getEntry().get(0).hasResource() ||
                    !(bundle.getEntry().get(0).getResource() instanceof Measure)) {
                throw new RuntimeException("Returned search-set did not contain Measure at index 0");
            } else if (!bundle.getEntry().get(1).hasResource() ||
                    !(bundle.getEntry().get(1).getResource() instanceof Library)) {
                throw new RuntimeException("Returned search-set did not contain Library at index 1");
            }

            return bundle;
        } catch (Exception e) {
            logger.warn("Error while reading Measure with id {} including its Library from {}: {}",
                    measureId.getIdPart(), client.getBaseUrl(), e.getMessage());
            throw e;
        }
    }
}
