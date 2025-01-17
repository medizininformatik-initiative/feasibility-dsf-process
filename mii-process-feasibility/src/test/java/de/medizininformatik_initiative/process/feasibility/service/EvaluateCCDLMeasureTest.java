package de.medizininformatik_initiative.process.feasibility.service;

import de.medizininformatik_initiative.process.feasibility.client.flare.FlareWebserviceClient;
import de.medizininformatik_initiative.process.feasibility.variables.ConstantsFeasibility;
import dev.dsf.bpe.v1.ProcessPluginApi;
import dev.dsf.bpe.v1.variables.Variables;
import org.camunda.bpm.engine.delegate.DelegateExecution;
import org.hl7.fhir.r4.model.Attachment;
import org.hl7.fhir.r4.model.Library;
import org.hl7.fhir.r4.model.Measure;
import org.hl7.fhir.r4.model.MeasureReport;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static de.medizininformatik_initiative.process.feasibility.variables.ConstantsFeasibility.VARIABLE_LIBRARY;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
public class EvaluateCCDLMeasureTest {

    private static final String PARENT_ORGANIZATION = "foo.bar";
    private static final String STORE_ID = "foo";

    @Captor ArgumentCaptor<MeasureReport> measureReportCaptor;

    @Mock private FlareWebserviceClient flareWebserviceClient;
    @Mock private DelegateExecution execution;
    @Mock private ProcessPluginApi api;
    @Mock private Variables variables;

    private EvaluateCCDLMeasure service;

    @BeforeEach
    public void setup() {
        service = new EvaluateCCDLMeasure(Map.of(PARENT_ORGANIZATION, Set.of(STORE_ID)),
                Map.of(STORE_ID, flareWebserviceClient), api);
        when(variables.getString(ConstantsFeasibility.VARIABLE_REQUESTER_PARENT_ORGANIZATION))
                .thenReturn(PARENT_ORGANIZATION);
    }

    @Test
    public void testDoExecute_FailsIfStructuredQueryContentIsMissing() {
        var library = new Library();
        when(variables.getResource(VARIABLE_LIBRARY)).thenReturn(library);
        assertThrows(IllegalStateException.class, () -> service.doExecute(execution, variables));
    }

    @Test
    public void testDoExecute_FailsIfFeasibilityCannotBeRequested() throws IOException, InterruptedException {
        var structuredQuery = STORE_ID.getBytes();

        var measure = new Measure();
        measure.setUrl("https://my-zars/Measure/a9d981ed-58dd-4213-9abf-cb86ab757162");
        var library = new Library();
        library.setContent(List.of(new Attachment()
                .setContentType("application/json")
                .setData(structuredQuery)));

        when(variables.getResource(VARIABLE_LIBRARY)).thenReturn(library);
        when(flareWebserviceClient.requestFeasibility(structuredQuery)).thenThrow(IOException.class);

        assertThrows(IllegalStateException.class, () -> service.doExecute(execution, variables));
    }

    @Test
    public void testDoExecute_FailsIfLibraryDoesNotContainStructuredQuery() {
        var structuredQuery = STORE_ID.getBytes();

        var measure = new Measure();
        measure.setUrl("https://my-zars/Measure/a9d981ed-58dd-4213-9abf-cb86ab757162");
        var library = new Library();
        library.setContent(List.of(new Attachment()
                .setContentType("text/plain")
                .setData(structuredQuery)));

        when(variables.getResource(VARIABLE_LIBRARY)).thenReturn(library);

        assertThrows(IllegalStateException.class, () -> service.doExecute(execution, variables));
    }

    @Test
    public void testDoExecute() throws IOException, InterruptedException {
        var structuredQuery = STORE_ID.getBytes();
        var measureRef = "https://my-zars/Measure/a9d981ed-58dd-4213-9abf-cb86ab757162";

        var measure = new Measure();
        measure.setUrl(measureRef);
        var library = new Library();
        library.setContent(List.of(new Attachment()
                .setContentType("application/json")
                .setData(structuredQuery)));
        var feasibility = 10;

        when(variables.getResource(VARIABLE_LIBRARY)).thenReturn(library);
        when(flareWebserviceClient.requestFeasibility(structuredQuery)).thenReturn(feasibility);

        service.doExecute(execution, variables);

        verify(variables).setInteger(ConstantsFeasibility.VARIABLE_MEASURE_RESULT_CCDL, feasibility);
    }
}
