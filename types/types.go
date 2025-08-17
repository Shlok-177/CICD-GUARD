package types

// Severity represents the severity level of a finding
type Severity string

const (
	SeverityHigh   Severity = "HIGH"
	SeverityMedium Severity = "MEDIUM"
	SeverityLow    Severity = "LOW"
)

// Finding represents a security issue found in a CI/CD file
type Finding struct {
	Severity Severity `json:"severity"`
	Message  string   `json:"message"`
	File     string   `json:"file"`
	Line     int      `json:"line"`
	Rule     string   `json:"rule"`
	Context  string   `json:"context,omitempty"`
	RuleID   string   `json:"rule_id,omitempty"`
}

// CustomRule represents a user-defined security rule
type CustomRule struct {
	ID          string   `yaml:"id"`
	Pattern     string   `yaml:"pattern"`
	Severity    Severity `yaml:"severity"`
	Message     string   `yaml:"message"`
	Description string   `yaml:"description,omitempty"`
}

// CustomRules represents a collection of user-defined rules
type CustomRules struct {
	Rules []CustomRule `yaml:"rules"`
}
