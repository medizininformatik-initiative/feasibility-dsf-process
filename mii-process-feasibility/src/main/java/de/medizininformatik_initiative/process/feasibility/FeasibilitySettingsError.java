package de.medizininformatik_initiative.process.feasibility;

public class FeasibilitySettingsError {

    private String message;

    public FeasibilitySettingsError(String message) {
        this.message = message;
    }

    @Override
    public String toString() {
        return message;
    }
}
