package de.medizininformatik_initiative.process.feasibility.service;

import de.medizininformatik_initiative.process.feasibility.client.flare.FlareWebserviceClient;
import de.medizininformatik_initiative.process.feasibility.variables.ConstantsFeasibility;
import dev.dsf.bpe.v1.ProcessPluginApi;
import dev.dsf.bpe.v1.activity.AbstractServiceDelegate;
import dev.dsf.bpe.v1.variables.Variables;
import org.camunda.bpm.engine.delegate.DelegateExecution;
import org.hl7.fhir.r4.model.Library;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.InitializingBean;

import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

import static de.medizininformatik_initiative.process.feasibility.variables.ConstantsFeasibility.VARIABLE_LIBRARY;
import static de.medizininformatik_initiative.process.feasibility.variables.ConstantsFeasibility.VARIABLE_REQUESTER_PARENT_ORGANIZATION;

public class EvaluateCCDLMeasure extends AbstractServiceDelegate implements InitializingBean {

    private static final Logger logger = LoggerFactory.getLogger(EvaluateCCDLMeasure.class);
    private static final String STRUCTURED_QUERY_CONTENT_TYPE = "application/json";

    private final Map<String, FlareWebserviceClient> flareClients;
    private Map<String, Set<String>> networkStores;

    public EvaluateCCDLMeasure(Map<String, Set<String>> networkStores,
            Map<String, FlareWebserviceClient> flareClients, ProcessPluginApi api) {
        super(api);
        this.networkStores = networkStores;
        this.flareClients = flareClients;
    }

    @Override
    public void afterPropertiesSet() throws Exception {
        super.afterPropertiesSet();
        Objects.requireNonNull(flareClients, "flareClients");
    }

    @Override
    protected void doExecute(DelegateExecution execution, Variables variables)
            throws IOException, InterruptedException {
        var library = (Library) variables.getResource(VARIABLE_LIBRARY);
        var requesterPartentOrganization = variables.getString(VARIABLE_REQUESTER_PARENT_ORGANIZATION);


        var structuredQuery = getStructuredQuery(library);
        var feasibility = getFeasibility(requesterPartentOrganization, structuredQuery);

        variables.setInteger(ConstantsFeasibility.VARIABLE_MEASURE_RESULT_CCDL, feasibility);
    }

    private byte[] getStructuredQuery(Library library) {
        return library.getContent().stream()
                .filter(c -> c.getContentType().equalsIgnoreCase(STRUCTURED_QUERY_CONTENT_TYPE))
                .findFirst()
                .orElseThrow(() -> new IllegalStateException("query is missing content of type " + STRUCTURED_QUERY_CONTENT_TYPE))
                .getData();
    }

    private int getFeasibility(String requesterParentOrganization, byte[] structuredQuery)
            throws IOException, InterruptedException {
        Map<Boolean, List<Integer>> results = Optional.ofNullable(networkStores.get(requesterParentOrganization))
                .orElse(Set.of())
                .stream()
                .filter(storeId -> flareClients.containsKey(storeId))
                .collect(Collectors.toMap(id -> id, id -> flareClients.get(id)))
                .entrySet()
                .parallelStream()
                .map(c -> {
                    try {
                        return c.getValue().requestFeasibility(structuredQuery);
                    } catch (IOException | InterruptedException e) {
                        logger.error("Error at feasibility request from FHIR store '%s' with flare base url '%s'."
                                .formatted(c.getKey(), c.getValue().getFlareBaseUrl()), e);
                        return -1;
                    }
                })
                .collect(Collectors.partitioningBy(r -> r >= 0));
        if (results.getOrDefault(false, List.of()).isEmpty()) {
            return results.getOrDefault(true, List.of()).stream().reduce(0, (a, b) -> a + b);
        } else {
            throw new IllegalStateException("Error(s) executing feasibility query.");
        }
    }
}
