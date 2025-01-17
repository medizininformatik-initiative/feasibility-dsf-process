package de.medizininformatik_initiative.process.feasibility.service;

import de.medizininformatik_initiative.process.feasibility.Obfuscator;
import dev.dsf.bpe.v1.ProcessPluginApi;
import dev.dsf.bpe.v1.variables.Variables;
import org.camunda.bpm.engine.delegate.DelegateExecution;
import org.hl7.fhir.r4.model.CodeableConcept;
import org.hl7.fhir.r4.model.Coding;
import org.hl7.fhir.r4.model.MeasureReport;
import org.hl7.fhir.r4.model.MeasureReport.MeasureReportGroupComponent;
import org.hl7.fhir.r4.model.MeasureReport.MeasureReportGroupPopulationComponent;
import org.hl7.fhir.r4.model.Period;
import org.joda.time.LocalDate;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Date;
import java.util.List;

import static de.medizininformatik_initiative.process.feasibility.variables.ConstantsFeasibility.CODESYSTEM_MEASURE_POPULATION;
import static de.medizininformatik_initiative.process.feasibility.variables.ConstantsFeasibility.CODESYSTEM_MEASURE_POPULATION_VALUE_INITIAL_POPULATION;
import static de.medizininformatik_initiative.process.feasibility.variables.ConstantsFeasibility.MEASURE_REPORT_PERIOD_END;
import static de.medizininformatik_initiative.process.feasibility.variables.ConstantsFeasibility.MEASURE_REPORT_PERIOD_START;
import static de.medizininformatik_initiative.process.feasibility.variables.ConstantsFeasibility.VARIABLE_MEASURE_REPORT;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.hl7.fhir.r4.model.MeasureReport.MeasureReportStatus.COMPLETE;
import static org.hl7.fhir.r4.model.MeasureReport.MeasureReportStatus.PENDING;
import static org.hl7.fhir.r4.model.MeasureReport.MeasureReportType.SUMMARY;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
public class ObfuscateEvaluationResultTest {

    @Captor private ArgumentCaptor<MeasureReport> measureReportCaptor;

    @Mock private DelegateExecution execution;
    @Mock private ProcessPluginApi api;
    @Mock private Variables variables;

    private ObfuscateEvaluationResult service;

    @BeforeEach
    public void setUp() {
        var incrementFeasibilityCountObfuscator = (Obfuscator<Integer>) value -> value + 1;
        service = new ObfuscateEvaluationResult(incrementFeasibilityCountObfuscator, api);
    }

    @Test
    @DisplayName("execution succeeds on measure report containing single population with single coding '"
            + CODESYSTEM_MEASURE_POPULATION_VALUE_INITIAL_POPULATION + "'")
    public void doExecuteSucceedsSinglePopulationSingleCoding() throws Exception {
        var feasibilityCount = 5;
        var reportDate = new Date();
        var measureUrl = "http://localhost/fhir/Measure/123456";
        var measureReport = new MeasureReport()
                .setStatus(COMPLETE)
                .setType(SUMMARY)
                .setMeasure(measureUrl)
                .setDate(reportDate)
                .setPeriod(new Period()
                        .setStart(new LocalDate(1312, 4, 9).toDate())
                        .setEnd(new LocalDate(1314, 1, 8).toDate()));
        var populationGroup = new MeasureReportGroupPopulationComponent()
                .setCode(new CodeableConcept()
                        .addCoding(new Coding()
                                .setSystem(CODESYSTEM_MEASURE_POPULATION)
                                .setCode(CODESYSTEM_MEASURE_POPULATION_VALUE_INITIAL_POPULATION)))
                .setCount(feasibilityCount);
        measureReport.getGroup()
                .add(new MeasureReportGroupComponent()
                        .setPopulation(List.of(populationGroup)));

        when(api.getVariables(execution)).thenReturn(variables);
        when(variables.getResource(VARIABLE_MEASURE_REPORT)).thenReturn(measureReport);

        service.execute(execution);
        verify(variables).setResource(eq(VARIABLE_MEASURE_REPORT), measureReportCaptor.capture());

        var expectedFeasibilityCount = feasibilityCount + 1;

        var obfuscatedMeasureReport = measureReportCaptor.getValue();
        var reportPopulation = obfuscatedMeasureReport.getGroupFirstRep().getPopulationFirstRep();
        assertThat(obfuscatedMeasureReport.getStatus()).isEqualTo(COMPLETE);
        assertThat(obfuscatedMeasureReport.getType()).isEqualTo(SUMMARY);
        assertThat(obfuscatedMeasureReport.getMeasure()).isEqualTo(measureUrl);
        assertThat(obfuscatedMeasureReport.hasDate()).isFalse();
        assertThat(obfuscatedMeasureReport.getPeriod().getStart()).isEqualTo(MEASURE_REPORT_PERIOD_START);
        assertThat(obfuscatedMeasureReport.getPeriod().getEnd()).isEqualTo(MEASURE_REPORT_PERIOD_END);
        assertThat(reportPopulation.getCode().getCodingFirstRep().getSystem())
                .isEqualTo(CODESYSTEM_MEASURE_POPULATION);
        assertThat(reportPopulation.getCode().getCodingFirstRep().getCode())
                .isEqualTo(CODESYSTEM_MEASURE_POPULATION_VALUE_INITIAL_POPULATION);
        assertEquals(expectedFeasibilityCount, reportPopulation.getCount());
    }

    @Test
    @DisplayName("execution succeeds on measure report containing multiple populations with one having single coding '"
            + CODESYSTEM_MEASURE_POPULATION_VALUE_INITIAL_POPULATION + "'")
    public void doExecuteSucceedsMultiplePopulationsSingleCoding() throws Exception {
        var feasibilityCount = 5;
        var reportDate = new Date();
        var measureUrl = "http://localhost/fhir/Measure/123456";
        var measureReport = new MeasureReport()
                .setStatus(COMPLETE)
                .setType(SUMMARY)
                .setMeasure(measureUrl)
                .setDate(reportDate)
                .setPeriod(new Period()
                        .setStart(new LocalDate(1316, 4, 9).toDate())
                        .setEnd(new LocalDate(1317, 11, 18).toDate()));
        var fooPopulationGroup = new MeasureReportGroupPopulationComponent()
                .setCode(new CodeableConcept()
                        .addCoding(new Coding()
                                .setSystem(CODESYSTEM_MEASURE_POPULATION)
                                .setCode("measure-population")))
                .setCount(134430);
        var initialPopulationGroup = new MeasureReportGroupPopulationComponent()
                .setCode(new CodeableConcept()
                        .addCoding(new Coding()
                                .setSystem(CODESYSTEM_MEASURE_POPULATION)
                                .setCode(CODESYSTEM_MEASURE_POPULATION_VALUE_INITIAL_POPULATION)))
                .setCount(feasibilityCount);
        measureReport.getGroup()
                .add(new MeasureReportGroupComponent()
                        .setPopulation(List.of(fooPopulationGroup, initialPopulationGroup)));
        when(api.getVariables(execution)).thenReturn(variables);
        when(variables.getResource(VARIABLE_MEASURE_REPORT)).thenReturn(measureReport);

        service.execute(execution);

        verify(variables).setResource(eq(VARIABLE_MEASURE_REPORT), measureReportCaptor.capture());
        assertThat(measureReportCaptor.getValue().getGroupFirstRep().getPopulationFirstRep().getCount())
                .isEqualTo(feasibilityCount + 1);
    }

    @Test
    @DisplayName("execution succeeds on measure report containing single population with multiple codings including '"
            + CODESYSTEM_MEASURE_POPULATION_VALUE_INITIAL_POPULATION + "'")
    public void doExecuteSucceedsSinglePopulationsMultipleCodings() throws Exception {
        var feasibilityCount = 5;
        var reportDate = new Date();
        var measureUrl = "http://localhost/fhir/Measure/123456";
        var measureReport = new MeasureReport()
                .setStatus(COMPLETE)
                .setType(SUMMARY)
                .setMeasure(measureUrl)
                .setDate(reportDate)
                .setPeriod(new Period()
                        .setStart(new LocalDate(1312, 4, 9).toDate())
                        .setEnd(new LocalDate(1314, 1, 8).toDate()));
        var initialPopulationGroup = new MeasureReportGroupPopulationComponent()
                .setCode(new CodeableConcept()
                        .addCoding(new Coding()
                                .setSystem(CODESYSTEM_MEASURE_POPULATION)
                                .setCode("measure-population"))
                        .addCoding(new Coding()
                                .setSystem(CODESYSTEM_MEASURE_POPULATION)
                                .setCode(CODESYSTEM_MEASURE_POPULATION_VALUE_INITIAL_POPULATION)))
                .setCount(feasibilityCount);
        measureReport.getGroup()
                .add(new MeasureReportGroupComponent()
                        .setPopulation(List.of(initialPopulationGroup)));

        when(api.getVariables(execution)).thenReturn(variables);
        when(variables.getResource(VARIABLE_MEASURE_REPORT)).thenReturn(measureReport);

        service.execute(execution);

        verify(variables).setResource(eq(VARIABLE_MEASURE_REPORT), measureReportCaptor.capture());
        assertThat(measureReportCaptor.getValue().getGroupFirstRep().getPopulationFirstRep().getCount())
                .isEqualTo(feasibilityCount + 1);
    }

    @Test
    @DisplayName("execution fails on measure report containing single population with missing coding '"
            + CODESYSTEM_MEASURE_POPULATION_VALUE_INITIAL_POPULATION + "'")
    void doExecuteFailsOnMissingInitialPopulationInMeasureReport() throws Exception {
        var feasibilityCount = 5;
        var reportDate = new Date();
        var measureUrl = "http://localhost/fhir/Measure/123456";
        var measureReport = new MeasureReport()
                .setStatus(COMPLETE)
                .setType(SUMMARY)
                .setMeasure(measureUrl)
                .setDate(reportDate)
                .setPeriod(new Period()
                        .setStart(new LocalDate(1312, 4, 9).toDate())
                        .setEnd(new LocalDate(1314, 1, 8).toDate()));
        var reportId = "id-205925";
        measureReport.setId(reportId);
        var populationGroup = new MeasureReportGroupPopulationComponent()
                .setCode(new CodeableConcept()
                        .addCoding(new Coding()
                                .setSystem(CODESYSTEM_MEASURE_POPULATION)
                                .setCode("measure-population")))
                .setCount(feasibilityCount);
        measureReport.getGroup()
                .add(new MeasureReportGroupComponent()
                        .setPopulation(List.of(populationGroup)));
        when(variables.getResource(VARIABLE_MEASURE_REPORT)).thenReturn(measureReport);

        assertThatThrownBy(() -> {
            service.doExecute(execution, variables);
        }).hasMessage("Missing population with coding '%s' in measure report (id '%s').",
                        CODESYSTEM_MEASURE_POPULATION_VALUE_INITIAL_POPULATION, reportId);
    }

    @Test
    @DisplayName("execution fails on measure report containing no population")
    void doExecuteFailsOnNoPopulationInMeasureReport() throws Exception {
        var reportDate = new Date();
        var measureUrl = "http://localhost/fhir/Measure/123456";
        var reportId = "id-205435";
        var measureReport = new MeasureReport()
                .setStatus(COMPLETE)
                .setType(SUMMARY)
                .setMeasure(measureUrl)
                .setDate(reportDate)
                .setPeriod(new Period()
                        .setStart(new LocalDate(1312, 4, 9).toDate())
                        .setEnd(new LocalDate(1314, 1, 8).toDate()))
                .setId(reportId);
        when(variables.getResource(VARIABLE_MEASURE_REPORT)).thenReturn(measureReport);

        assertThatThrownBy(() -> {
            service.doExecute(execution, variables);
        }).hasMessage("Missing population with coding '%s' in measure report (id '%s').",
                        CODESYSTEM_MEASURE_POPULATION_VALUE_INITIAL_POPULATION, reportId);
    }

    @Test
    @DisplayName("execution fails on incomplete measure report")
    void doExecuteFailsOnWrongMeasureReportStatus() throws Exception {
        var reportDate = new Date();
        var measureUrl = "http://localhost/fhir/Measure/123456";
        var reportId = "id-181407";
        var measureReport = new MeasureReport()
                .setStatus(PENDING)
                .setType(SUMMARY)
                .setMeasure(measureUrl)
                .setDate(reportDate)
                .setPeriod(new Period()
                        .setStart(new LocalDate(1312, 4, 9).toDate())
                        .setEnd(new LocalDate(1314, 1, 8).toDate()))
                .setId(reportId);
        when(variables.getResource(VARIABLE_MEASURE_REPORT)).thenReturn(measureReport);

        assertThatThrownBy(() -> {
            service.doExecute(execution, variables);
        }).hasMessage("Expected status '%s' but actually is '%s' for measure report (id '%s').",
                COMPLETE, PENDING, reportId);
    }
}
