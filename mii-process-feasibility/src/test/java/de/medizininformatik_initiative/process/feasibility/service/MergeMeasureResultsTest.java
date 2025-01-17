package de.medizininformatik_initiative.process.feasibility.service;

import dev.dsf.bpe.v1.ProcessPluginApi;
import dev.dsf.bpe.v1.variables.Variables;
import org.camunda.bpm.engine.delegate.DelegateExecution;
import org.hl7.fhir.r4.model.Measure;
import org.hl7.fhir.r4.model.MeasureReport;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static de.medizininformatik_initiative.process.feasibility.variables.ConstantsFeasibility.VARIABLE_MEASURE;
import static de.medizininformatik_initiative.process.feasibility.variables.ConstantsFeasibility.VARIABLE_MEASURE_REPORT;
import static de.medizininformatik_initiative.process.feasibility.variables.ConstantsFeasibility.VARIABLE_MEASURE_RESULT_CCDL;
import static de.medizininformatik_initiative.process.feasibility.variables.ConstantsFeasibility.VARIABLE_MEASURE_RESULT_CQL;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class MergeMeasureResultsTest {

    @Captor private ArgumentCaptor<MeasureReport> reportCaptor;

    @Mock private ProcessPluginApi api;
    @Mock private DelegateExecution execution;
    @Mock private Variables variables;

    @InjectMocks private MergeMeasureResults service;

    @BeforeEach
    void setup() {
        when(api.getVariables(execution)).thenReturn(variables);
    }

    @Test
    void multipleResultsAreMerged() throws Exception {
        var measureRef = "http://foo.bar";
        var measure = new Measure().setUrl(measureRef);
        var cqlResultCount = 23600;
        var ccdlResultCount = 23645;

        when(variables.getResource(VARIABLE_MEASURE)).thenReturn(measure);
        when(variables.getInteger(VARIABLE_MEASURE_RESULT_CQL)).thenReturn(cqlResultCount);
        when(variables.getInteger(VARIABLE_MEASURE_RESULT_CCDL)).thenReturn(ccdlResultCount);

        service.execute(execution);

        verify(variables).setResource(eq(VARIABLE_MEASURE_REPORT), reportCaptor.capture());
        assertThat(reportCaptor.getValue()).isNotNull();
        assertThat(reportCaptor.getValue().getMeasure()).isEqualTo(measureRef);
        assertThat(reportCaptor.getValue().getGroup()).hasSize(1);
        assertThat(reportCaptor.getValue().getGroupFirstRep().getPopulation()).hasSize(1);
        assertThat(reportCaptor.getValue().getGroupFirstRep().getPopulationFirstRep().getCount())
                .isEqualTo(cqlResultCount + ccdlResultCount);

    }

    @Test
    void NoCCDLResultHasOnlyCQLResultIsInReport() throws Exception {
        var measureRef = "http://foo.bar";
        var measure = new Measure().setUrl(measureRef);
        var cqlResultCount = 25922;

        when(variables.getResource(VARIABLE_MEASURE)).thenReturn(measure);
        when(variables.getInteger(VARIABLE_MEASURE_RESULT_CQL)).thenReturn(cqlResultCount);
        when(variables.getInteger(VARIABLE_MEASURE_RESULT_CCDL)).thenReturn(null);

        service.execute(execution);

        verify(variables).setResource(eq(VARIABLE_MEASURE_REPORT), reportCaptor.capture());
        assertThat(reportCaptor.getValue()).isNotNull();
        assertThat(reportCaptor.getValue().getMeasure()).isEqualTo(measureRef);
        assertThat(reportCaptor.getValue().getGroup()).hasSize(1);
        assertThat(reportCaptor.getValue().getGroupFirstRep().getPopulation()).hasSize(1);
        assertThat(reportCaptor.getValue().getGroupFirstRep().getPopulationFirstRep().getCount())
                .isEqualTo(cqlResultCount);

    }

    @Test
    void NoCQLResultHasOnlyCCDLResultIsInReport() throws Exception {
        var measureRef = "http://foo.bar";
        var measure = new Measure().setUrl(measureRef);
        var ccdlResultCount = 25931;

        when(variables.getResource(VARIABLE_MEASURE)).thenReturn(measure);
        when(variables.getInteger(VARIABLE_MEASURE_RESULT_CQL)).thenReturn(null);
        when(variables.getInteger(VARIABLE_MEASURE_RESULT_CCDL)).thenReturn(ccdlResultCount);

        service.execute(execution);

        verify(variables).setResource(eq(VARIABLE_MEASURE_REPORT), reportCaptor.capture());
        assertThat(reportCaptor.getValue()).isNotNull();
        assertThat(reportCaptor.getValue().getMeasure()).isEqualTo(measureRef);
        assertThat(reportCaptor.getValue().getGroup()).hasSize(1);
        assertThat(reportCaptor.getValue().getGroupFirstRep().getPopulation()).hasSize(1);
        assertThat(reportCaptor.getValue().getGroupFirstRep().getPopulationFirstRep().getCount())
                .isEqualTo(ccdlResultCount);

    }
}
