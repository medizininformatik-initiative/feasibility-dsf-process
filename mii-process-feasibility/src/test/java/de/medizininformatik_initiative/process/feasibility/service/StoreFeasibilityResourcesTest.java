package de.medizininformatik_initiative.process.feasibility.service;

import ca.uhn.fhir.rest.client.api.IGenericClient;
import dev.dsf.bpe.v1.ProcessPluginApi;
import dev.dsf.bpe.v1.variables.Variables;
import org.camunda.bpm.engine.delegate.DelegateExecution;
import org.hl7.fhir.r4.model.Bundle;
import org.hl7.fhir.r4.model.Library;
import org.hl7.fhir.r4.model.Measure;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Answers;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Map;
import java.util.Set;

import static de.medizininformatik_initiative.process.feasibility.Assertions.assertThat;
import static de.medizininformatik_initiative.process.feasibility.variables.ConstantsFeasibility.VARIABLE_LIBRARY;
import static de.medizininformatik_initiative.process.feasibility.variables.ConstantsFeasibility.VARIABLE_MEASURE;
import static de.medizininformatik_initiative.process.feasibility.variables.ConstantsFeasibility.VARIABLE_MEASURE_ID;
import static de.medizininformatik_initiative.process.feasibility.variables.ConstantsFeasibility.VARIABLE_REQUESTER_PARENT_ORGANIZATION;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.assertj.core.api.Assertions.assertThat;
import static org.hl7.fhir.r4.model.Bundle.HTTPVerb.POST;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
public class StoreFeasibilityResourcesTest {

    private static final String STORE_ID = "foo";
    private static final String NETWORK_ID = "foo.bar";
    public static final String LIBRARY_ID = "library-id-173603";
    public static final String MEASURE_ID = "measure-id-173603";

    @Mock(answer = Answers.RETURNS_DEEP_STUBS) private IGenericClient storeClient;
    @Mock private FeasibilityResourceCleaner cleaner;
    @Mock private DelegateExecution execution;
    @Mock private ProcessPluginApi api;
    @Mock private Variables variables;

    @Captor private ArgumentCaptor<Bundle> transactionBundleCaptor;


    private StoreFeasibilityResources service;

    @BeforeEach
    public void setup() {
        service = new StoreFeasibilityResources(Map.of(NETWORK_ID, Set.of(STORE_ID)), Map.of(STORE_ID, storeClient),
                api, cleaner);
    }

    // Creates a Measure like the Feasibility Backend will do.
    private static Measure inputMeasure() {
        return new Measure()
                .setUrl("https://foo.de/Measure/9308b842-2bee-418b-b3bf-cc347541c1c3")
                .addLibrary("urn:uuid:7942465b-513a-4812-a078-e72dfea97f43");
    }

    // Creates a Library like the Feasibility Backend will do.
    private static Library inputLibrary() {
        var library = new Library()
                .setUrl("urn:uuid:7942465b-513a-4812-a078-e72dfea97f43")
                .setName("Retrieve");
        library.addContent().setContentType("text/cql").setData("""
                library Retrieve version '1.0.0'
                using FHIR version '4.0.0'
                include FHIRHelpers version '4.0.0'
                """.getBytes(UTF_8));
        return library;
    }

    private static Measure outputMeasure() {
        return new Measure()
                .setUrl("https://foo.de/Measure/9308b842-2bee-418b-b3bf-cc347541c1c3")
                .addLibrary("https://foo.de/Library/7942465b-513a-4812-a078-e72dfea97f43");
    }

    private static Library outputLibrary() {
        var library = new Library()
                .setUrl("https://foo.de/Library/7942465b-513a-4812-a078-e72dfea97f43")
                .setName("7942465b-513a-4812-a078-e72dfea97f43")
                .setVersion("1.0.0");
        library.addContent().setContentType("text/cql").setData("""
                library "7942465b-513a-4812-a078-e72dfea97f43" version '1.0.0'
                using FHIR version '4.0.0'
                include FHIRHelpers version '4.0.0'
                """.getBytes(UTF_8));
        return library;
    }

    @Test
    public void testDoExecute() {
        var inputMeasure = inputMeasure();
        var inputLibrary = inputLibrary();
        var transactionResponse = new Bundle();
        transactionResponse.addEntry().getResponse().setLocation("Measure/" + MEASURE_ID);
        inputLibrary.getContentFirstRep().setContentType("text/cql");
        when(variables.getResource(VARIABLE_MEASURE)).thenReturn(inputMeasure);
        when(variables.getResource(VARIABLE_LIBRARY)).thenReturn(inputLibrary);
        when(variables.getString(VARIABLE_REQUESTER_PARENT_ORGANIZATION)).thenReturn(NETWORK_ID);
        when(storeClient.transaction().withBundle(transactionBundleCaptor.capture()).execute()).thenReturn(transactionResponse);

        service.doExecute(execution, variables);

        verify(cleaner, never()).cleanLibrary(inputLibrary);
        verify(cleaner).cleanLibrary(any(Library.class));
        verify(cleaner, never()).cleanMeasure(inputMeasure);
        verify(cleaner).cleanMeasure(any(Measure.class));
        assertThat(transactionBundleCaptor.getValue()).hasType("transaction");
        assertThat(transactionBundleCaptor.getValue().getEntry()).hasSize(2);
        assertThat(transactionBundleCaptor.getValue().getEntry().get(0).getResource())
                .isDeepEqualTo(outputMeasure());
        assertThat(transactionBundleCaptor.getValue().getEntry().get(0).getRequest())
                .hasMethod(POST)
                .hasUrl("Measure");
        assertThat(transactionBundleCaptor.getValue().getEntry().get(1).getResource())
                .isDeepEqualTo(outputLibrary());
        assertThat(transactionBundleCaptor.getValue().getEntry().get(1).getRequest())
                .hasMethod(POST)
                .hasUrl("Library");
        verify(variables).setString("%s_%s".formatted(VARIABLE_MEASURE_ID, STORE_ID), MEASURE_ID);
    }
}
