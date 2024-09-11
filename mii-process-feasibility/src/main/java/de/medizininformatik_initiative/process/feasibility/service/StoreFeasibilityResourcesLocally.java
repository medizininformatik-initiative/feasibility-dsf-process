package de.medizininformatik_initiative.process.feasibility.service;

import de.medizininformatik_initiative.process.feasibility.StoreBundleProvider;
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

import java.util.List;
import java.util.UUID;

public class StoreFeasibilityResourcesLocally extends AbstractServiceDelegate implements InitializingBean, StoreBundleProvider {

    private static final Logger logger = LoggerFactory.getLogger(StoreFeasibilityResourcesLocally.class);

    private FhirWebserviceClient localWebserviceClient;

    public StoreFeasibilityResourcesLocally(ProcessPluginApi api) {
        super(api);
        this.localWebserviceClient = api.getFhirWebserviceClientProvider().getLocalWebserviceClient();
    }

    @Override
    protected void doExecute(DelegateExecution delegateExecution, Variables variables) {
        logger.info("doExecute store feasibility resource for distribution");

        Measure measureFromRequest = variables.getResource(ConstantsFeasibility.VARIABLE_MEASURE);
        Library libraryFromRequest = variables.getResource(ConstantsFeasibility.VARIABLE_LIBRARY);

        fixCanonical(measureFromRequest, libraryFromRequest);

        var transactionResponse = storeTransactionBundle(measureFromRequest, libraryFromRequest);

        String newMeasureId =
                findIdPartInFirstBundleResourceType(transactionResponse, ResourceType.Measure);

        fixMeasureInTaskLocal(newMeasureId, variables.getLatestTask());
    }

    private void fixMeasureInTaskLocal(String newMeasureId, Task task) {
        String measureRef = "Measure/" + newMeasureId;
        try {
            task.getInput().stream().filter(e ->
                    ConstantsFeasibility.CODESYSTEM_FEASIBILITY.equals(e.getType().getCoding().get(0).getSystem())
            ).findFirst().ifPresent(e ->
                    e.setValue(new Reference(measureRef)));
        } catch (Exception e) {
            logger.error("Can`t create Task with measure reference {}.", measureRef);
            throw e;
        }
    }

    @Override
    public Bundle storeBundle(Bundle bundle) {
        fixRequest(bundle.getEntry());
        return localWebserviceClient.postBundle(bundle);
    }

    private void fixRequest(List<Bundle.BundleEntryComponent> entry) {
        for (Bundle.BundleEntryComponent eb : entry) {
            eb.getResource().setId((String) null);
            eb.setFullUrl(URL_UUID_PREFIX + UUID.randomUUID());
        }
    }

}
