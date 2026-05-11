package safecadence

import "time"

// Asset represents one platform asset (host) tracked by SafeCadence.
type Asset struct {
	ID          string    `json:"id"`
	Hostname    string    `json:"hostname"`
	Vendor      string    `json:"vendor,omitempty"`
	Model       string    `json:"model,omitempty"`
	IPAddress   string    `json:"ip_address,omitempty"`
	Site        string    `json:"site,omitempty"`
	Criticality string    `json:"criticality,omitempty"`
	RiskScore   float64   `json:"risk_score,omitempty"`
	LastSeen    time.Time `json:"last_seen,omitempty"`
	EOL         bool      `json:"eol,omitempty"`
	Tags        []string  `json:"tags,omitempty"`
}

// Finding is a single risk finding (audit rule hit or CVE).
type Finding struct {
	ID          string    `json:"id"`
	AssetID     string    `json:"asset_id"`
	Severity    string    `json:"severity"`
	Title       string    `json:"title"`
	Description string    `json:"description,omitempty"`
	RuleID      string    `json:"rule_id,omitempty"`
	CVEIDs      []string  `json:"cve_ids,omitempty"`
	KEV         bool      `json:"kev,omitempty"`
	EPSS        float64   `json:"epss,omitempty"`
	DetectedAt  time.Time `json:"detected_at,omitempty"`
	Remediation string    `json:"remediation,omitempty"`
}

// Report describes a saved/composed report.
type Report struct {
	ID         string    `json:"id"`
	Name       string    `json:"name"`
	Preset     string    `json:"preset,omitempty"`
	Format     string    `json:"format,omitempty"`
	CreatedAt  time.Time `json:"created_at,omitempty"`
	TemplateID string    `json:"template_id,omitempty"`
}

// Template is a persisted report template.
type Template struct {
	ID        string                 `json:"id"`
	Name      string                 `json:"name"`
	Sections  []string               `json:"sections"`
	Scope     map[string]interface{} `json:"scope,omitempty"`
	CreatedAt time.Time              `json:"created_at,omitempty"`
}

// GenerateJob is returned from the async report-generation endpoint.
type GenerateJob struct {
	ID        string `json:"id"`
	Status    string `json:"status"`
	StatusURL string `json:"status_url,omitempty"`
	ResultURL string `json:"result_url,omitempty"`
}

// ComposeOptions controls the one-shot compose-report call.
type ComposeOptions struct {
	Preset             string                 `json:"preset_id,omitempty"`
	Format             string                 `json:"format"`
	Sections           []string               `json:"sections,omitempty"`
	Scope              map[string]interface{} `json:"scope,omitempty"`
	IndustryTemplateID string                 `json:"industry_template_id,omitempty"`
	PreparedFor        string                 `json:"prepared_for,omitempty"`
	Filename           string                 `json:"filename,omitempty"`
}

// FindingFilters narrow the /findings query.
type FindingFilters struct {
	Severity string
	AssetID  string
}
