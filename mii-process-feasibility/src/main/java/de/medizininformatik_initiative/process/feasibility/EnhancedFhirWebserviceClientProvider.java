package de.medizininformatik_initiative.process.feasibility;

import dev.dsf.bpe.v1.service.FhirWebserviceClientProvider;
import dev.dsf.fhir.client.FhirWebserviceClient;
import org.hl7.fhir.r4.model.IdType;

public interface EnhancedFhirWebserviceClientProvider extends FhirWebserviceClientProvider {

    /**
     * Gets a {@link FhirWebserviceClient} for local or remote use based on the given reference.
     *
     * If the reference points to a local resource then a local webservice client gets returned.
     * A remote webservice client gets returned if the reference points to a remote resource.
     *
     * @param reference A FHIR ID Type that points either to a local or a remote resource.
     * @return A FHIR webservice client.
     */
    FhirWebserviceClient getWebserviceClientByReference(IdType reference);
}
