package de.medizininformatik_initiative.feasibility_dsf_process.service;

import org.camunda.bpm.engine.delegate.DelegateExecution;
import org.highmed.dsf.fhir.authorization.read.ReadAccessHelper;
import org.highmed.dsf.fhir.client.FhirWebserviceClientProvider;
import org.highmed.dsf.fhir.task.TaskHelper;
import org.hl7.fhir.r4.model.CodeableConcept;
import org.hl7.fhir.r4.model.Task;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hl7.fhir.r4.model.Task.TaskStatus.FAILED;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
public class RateLimitExceededTaskRejecterTest {

    @Captor private ArgumentCaptor<CodeableConcept> reasonCaptor;

    @Mock private FhirWebserviceClientProvider clientProvider;
    @Mock private TaskHelper taskHelper;
    @Mock private ReadAccessHelper readAccessHelper;
    @Mock private DelegateExecution execution;
    @Mock private Task task;

    @InjectMocks private RateLimitExceededTaskRejecter service;

    @Test
    @DisplayName("status and status reason is set on task")
    void taskStatusIsSet() throws Exception {
        when(taskHelper.getTask(execution)).thenReturn(task);
        when(task.setStatus(FAILED)).thenReturn(task);

        service.doExecute(execution);

        verify(task).setStatusReason(reasonCaptor.capture());
        assertThat(reasonCaptor.getValue().getText(), is("The request rate limit has been exceeded."));
    }

}
