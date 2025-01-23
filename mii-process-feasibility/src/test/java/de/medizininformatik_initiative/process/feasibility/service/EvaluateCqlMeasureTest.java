package de.medizininformatik_initiative.process.feasibility.service;

import ca.uhn.fhir.rest.client.api.IGenericClient;
import ca.uhn.fhir.rest.gclient.IOperationUntypedWithInput;
import dev.dsf.bpe.v1.variables.Variables;
import org.camunda.bpm.engine.delegate.DelegateExecution;
import org.hl7.fhir.r4.model.Bundle;
import org.hl7.fhir.r4.model.CodeableConcept;
import org.hl7.fhir.r4.model.DateType;
import org.hl7.fhir.r4.model.Identifier;
import org.hl7.fhir.r4.model.MeasureReport;
import org.hl7.fhir.r4.model.Medication;
import org.hl7.fhir.r4.model.OperationOutcome;
import org.hl7.fhir.r4.model.Parameters;
import org.hl7.fhir.r4.model.Parameters.ParametersParameterComponent;
import org.hl7.fhir.r4.model.StringType;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Answers;
import org.mockito.ArgumentCaptor;
import org.mockito.ArgumentMatchers;
import org.mockito.Captor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.List;

import static de.medizininformatik_initiative.process.feasibility.variables.ConstantsFeasibility.HEADER_PREFER;
import static de.medizininformatik_initiative.process.feasibility.variables.ConstantsFeasibility.HEADER_PREFER_RESPOND_ASYNC;
import static de.medizininformatik_initiative.process.feasibility.variables.ConstantsFeasibility.MEASURE_REPORT_TYPE_POPULATION;
import static de.medizininformatik_initiative.process.feasibility.variables.ConstantsFeasibility.VARIABLE_MEASURE_ID;
import static de.medizininformatik_initiative.process.feasibility.variables.ConstantsFeasibility.VARIABLE_MEASURE_REPORT;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
public class EvaluateCqlMeasureTest {

    private static final String MEASURE_POPULATION = "http://terminology.hl7.org/CodeSystem/measure-population";
    private static final String INITIAL_POPULATION = "initial-population";
    private static final String MEASURE_ID = "id-145128";

    @Captor ArgumentCaptor<StringType> stringTypeCaptor;

    @Mock(answer = Answers.RETURNS_DEEP_STUBS) private IGenericClient storeClient;
    @Mock private DelegateExecution execution;
    @Mock private Variables variables;
    @Mock private IOperationUntypedWithInput<Parameters> operation;

    @InjectMocks private EvaluateCqlMeasure service;

    @BeforeEach
    public void setUp() {
        var report = new MeasureReport();
        var code = new CodeableConcept();
        var coding = code.getCodingFirstRep();
        coding.setSystem(MEASURE_POPULATION);
        coding.setCode(INITIAL_POPULATION);
        report.getGroupFirstRep().getPopulationFirstRep().setCode(code);
        when(storeClient.operation()
                .onInstance("Measure/" + MEASURE_ID)
                .named("evaluate-measure")
                .withParameter(ArgumentMatchers.<Class<org.hl7.fhir.r4.model.Parameters>>any(), eq("periodStart"),
                        any(DateType.class))
                .andParameter(eq("periodEnd"), any(DateType.class))
                .andParameter(eq("reportType"), stringTypeCaptor.capture())
                .useHttpGet()
                .preferResponseTypes(eq(List.of(MeasureReport.class, Bundle.class, OperationOutcome.class))))
                        .thenReturn(operation);
        when(operation.withAdditionalHeader(eq(HEADER_PREFER), eq(HEADER_PREFER_RESPOND_ASYNC))).thenReturn(operation);
        when(variables.getString(VARIABLE_MEASURE_ID)).thenReturn(MEASURE_ID);
    }

    @Test
    void testDoExecuteReturnsMeasureReport() {
        var report = new MeasureReport();
        var code = new CodeableConcept();
        var coding = code.getCodingFirstRep();
        coding.setSystem(MEASURE_POPULATION);
        coding.setCode(INITIAL_POPULATION);
        report.getGroupFirstRep().getPopulationFirstRep().setCode(code).setCount(0);
        when(operation.execute())
                .thenReturn(new Parameters().addParameter(new ParametersParameterComponent().setResource(report)));

        service.doExecute(execution, variables);

        verify(variables).setResource(VARIABLE_MEASURE_REPORT, report);
        assertThat(stringTypeCaptor.getValue()).isNotNull();
        assertThat(stringTypeCaptor.getValue().getValue()).isEqualTo(MEASURE_REPORT_TYPE_POPULATION);
    }

    @Test
    void testFailsOnEmptyMeasureReport() {
        MeasureReport report = new MeasureReport().setIdentifier(List.of(new Identifier().setValue("foo")));
        when(operation.execute())
                .thenReturn(new Parameters()
                        .addParameter(new ParametersParameterComponent()
                                .setName("foo")
                                .setResource(report)));

        assertThatThrownBy(() -> service.doExecute(execution, variables))
                .hasMessage("Missing MeasureReport group");
    }

    @Test
    void testFailsOnMissingPopulation() {
        var report = new MeasureReport().setIdentifier(List.of(new Identifier().setValue("foo")));
        report.getGroupFirstRep().setCode(new CodeableConcept().setText("foo"));
        when(operation.execute())
                .thenReturn(new Parameters().addParameter(new ParametersParameterComponent().setResource(report)));

        assertThatThrownBy(() -> service.doExecute(execution, variables))
                .hasMessage("Missing MeasureReport population");
    }

    @Test
    void testFailsOnMissingPopulationCode() {
        var report = new MeasureReport().setIdentifier(List.of(new Identifier().setValue("foo")));
        report.getGroupFirstRep().getPopulationFirstRep().setCount(0);
        when(operation.execute())
                .thenReturn(new Parameters().addParameter(new ParametersParameterComponent().setResource(report)));

        assertThatThrownBy(() -> service.doExecute(execution, variables))
                .hasMessage("Missing MeasureReport population code");
    }

    @Test
    void testFailsOnWrongPopulationCode() {
        var report = new MeasureReport().setIdentifier(List.of(new Identifier().setValue("foo")));
        report.getGroupFirstRep().getPopulationFirstRep().setCode(new CodeableConcept().setText("foo"));
        when(operation.execute())
                .thenReturn(new Parameters().addParameter(new ParametersParameterComponent().setResource(report)));

        assertThatThrownBy(() -> service.doExecute(execution, variables))
                .hasMessage("Missing MeasureReport initial-population code");
    }

    @Test
    void testFailsOnMissingPopulationCount() {
        var report = new MeasureReport().setIdentifier(List.of(new Identifier().setValue("foo")));
        var code = new CodeableConcept();
        var coding = code.getCodingFirstRep();
        coding.setSystem(MEASURE_POPULATION);
        coding.setCode(INITIAL_POPULATION);
        report.getGroupFirstRep().getPopulationFirstRep().setCode(code);
        when(operation.execute())
                .thenReturn(new Parameters().addParameter(new ParametersParameterComponent().setResource(report)));

        assertThatThrownBy(() -> service.doExecute(execution, variables))
                .hasMessage("Missing MeasureReport population count");
    }

    @Test
    void testDoExecuteReturnsBundleContainingMeasureReport() {
        var report = new MeasureReport();
        var code = new CodeableConcept();
        var coding = code.getCodingFirstRep();
        coding.setSystem(MEASURE_POPULATION);
        coding.setCode(INITIAL_POPULATION);
        report.getGroupFirstRep().getPopulationFirstRep().setCode(code).setCount(0);
        var bundle = new Bundle().addEntry(new Bundle.BundleEntryComponent().setResource(report));
        when(operation.execute())
                .thenReturn(new Parameters().addParameter(new ParametersParameterComponent().setResource(bundle)));

        service.doExecute(execution, variables);

        verify(variables).setResource(VARIABLE_MEASURE_REPORT, report);
        assertThat(stringTypeCaptor.getValue()).isNotNull();
        assertThat(stringTypeCaptor.getValue().getValue()).isEqualTo(MEASURE_REPORT_TYPE_POPULATION);
    }

    @Test
    void testFailsOnBundleIsEmpty() {
        var bundle = new Bundle();
        when(operation.execute())
                .thenReturn(new Parameters().addParameter(new ParametersParameterComponent().setResource(bundle)));

        assertThatThrownBy(() -> service.doExecute(execution, variables))
                .hasMessage("Failed to extract MeasureReport from response");
    }

    @Test
    void testFailsOnBundleContainingNonMeasureReportResource() {
        var resource = new Medication().setIdentifier(List.of(new Identifier().setValue("foo")));
        var bundle = new Bundle().addEntry(new Bundle.BundleEntryComponent().setResource(resource));
        when(operation.execute())
                .thenReturn(new Parameters().addParameter(new ParametersParameterComponent().setResource(bundle)));

        assertThatThrownBy(() -> service.doExecute(execution, variables))
                .hasMessage("Failed to extract MeasureReport from response");
    }

    @Test
    void testFailsOnNonMeasureReportResource() {
        var resource = new Medication().setIdentifier(List.of(new Identifier().setValue("foo")));
        when(operation.execute())
                .thenReturn(new Parameters()
                        .addParameter(new ParametersParameterComponent().setResource(resource)));

        assertThatThrownBy(() -> service.doExecute(execution, variables))
                .hasMessage("Failed to extract MeasureReport from response");
    }
}
