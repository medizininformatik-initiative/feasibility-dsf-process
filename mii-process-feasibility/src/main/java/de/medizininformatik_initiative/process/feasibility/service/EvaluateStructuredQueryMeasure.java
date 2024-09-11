package de.medizininformatik_initiative.process.feasibility.service;

import de.medizininformatik_initiative.process.feasibility.MeasureReportGenerator;
import de.medizininformatik_initiative.process.feasibility.client.flare.FlareWebserviceClient;
import dev.dsf.bpe.v1.ProcessPluginApi;
import dev.dsf.bpe.v1.activity.AbstractServiceDelegate;
import dev.dsf.bpe.v1.variables.Variables;
import org.camunda.bpm.engine.delegate.DelegateExecution;
import org.hl7.fhir.r4.model.Library;
import org.hl7.fhir.r4.model.Measure;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.InitializingBean;

import java.io.IOException;
import java.util.Objects;

import static de.medizininformatik_initiative.process.feasibility.variables.ConstantsFeasibility.*;

public class EvaluateStructuredQueryMeasure extends AbstractServiceDelegate implements InitializingBean, MeasureReportGenerator {
    private static final Logger logger = LoggerFactory.getLogger(EvaluateStructuredQueryMeasure.class);

    private static final String STRUCTURED_QUERY_CONTENT_TYPE = "application/json";

    private final FlareWebserviceClient flareClient;

    public EvaluateStructuredQueryMeasure(FlareWebserviceClient flareClient, ProcessPluginApi api) {
        super(api);
        this.flareClient = flareClient;
    }

    @Override
    public void afterPropertiesSet() throws Exception {
        super.afterPropertiesSet();
        Objects.requireNonNull(flareClient, "flareClient");
    }

    @Override
    protected void doExecute(DelegateExecution execution, Variables variables)
            throws IOException, InterruptedException {
        logger.info("doExecute evaluate Structured Query measure");

        var library = (Library) variables.getResource(VARIABLE_LIBRARY);
        var measure = (Measure) variables.getResource(VARIABLE_MEASURE);

        var structuredQuery = getStructuredQuery(library);
        var feasibility = getFeasibility(structuredQuery);
        var measureReport = buildMeasureReport(measure.getUrl(), feasibility);

        variables.setResource(VARIABLE_MEASURE_REPORT, measureReport);
    }

    private byte[] getStructuredQuery(Library library) {
        return library.getContent().stream()
                .filter(c -> c.getContentType().equalsIgnoreCase(STRUCTURED_QUERY_CONTENT_TYPE))
                .findFirst()
                .orElseThrow(() -> new IllegalStateException("query is missing content of type " + STRUCTURED_QUERY_CONTENT_TYPE))
                .getData();
    }

    private int getFeasibility(byte[] structuredQuery) throws IOException, InterruptedException {
        return flareClient.requestFeasibility(structuredQuery);
    }

}
