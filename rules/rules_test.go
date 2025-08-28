package rules

import (
	"cicd-guard/types"
	"cicd-guard/utils"
	"sort"
	"testing"
)

func TestBuiltinRules(t *testing.T) {
	engine := NewEngine()

	tests := []struct {
		name     string
		filePath string
		content  string
		expected []types.Finding
	}{
		// Secrets
		{
			name:     "AWS Access Key ID - Positive",
			filePath: "test.yml",
			content:  "aws_access_key_id: AKIAIOSFODNN7EXAMPLE",
			expected: []types.Finding{{RuleID: "SEC001", Severity: types.SeverityHigh}},
		},
		{
			name:     "AWS Access Key ID - Negative",
			filePath: "test.yml",
			content:  "aws_access_key_id: notakey",
			expected: []types.Finding{},
		},
		{
			name:     "Azure Connection String - Positive",
			filePath: "azure-pipelines.yml",
			content:  "connectionString: DefaultEndpointsProtocol=https;AccountName=test;AccountKey=supersecretkey;",
			expected: []types.Finding{{RuleID: "SEC002", Severity: types.SeverityHigh}},
		},
		{
			name:     "Azure Connection String - Negative",
			filePath: "azure-pipelines.yml",
			content:  "connectionString: notaconnectionstring",
			expected: []types.Finding{},
		},
		{
			name:     "GitHub Token - Positive",
			filePath: ".github/workflows/build.yml",
			content:  "GITHUB_TOKEN: ghp_abcdefghijklmnopqrstuvwxyz0123456789",
			expected: []types.Finding{{RuleID: "SEC003", Severity: types.SeverityHigh}},
		},
		{
			name:     "GitHub Token - Negative",
			filePath: ".github/workflows/build.yml",
			content:  "GITHUB_TOKEN: notatoken",
			expected: []types.Finding{},
		},
		{
			name:     "Generic High-Entropy Secret - Positive",
			filePath: "test.yml",
			content:  "secret: aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789aBcDeFgHiJkLmNoPqRsTuVwXyZ",
			expected: []types.Finding{{RuleID: "SEC004", Severity: types.SeverityHigh}},
		},
		{
			name:     "Generic High-Entropy Secret - Negative (too short)",
			filePath: "test.yml",
			content:  "secret: short",
			expected: []types.Finding{},
		},
		// Misconfigurations
		// GitHub Actions
		{
			name:     "GitHub Actions Unpinned Action - Positive",
			filePath: ".github/workflows/build.yml",
			content:  "uses: actions/checkout@master",
			expected: []types.Finding{{RuleID: "UNPINNED_ACTION", Severity: types.SeverityMedium}},
		},
		{
			name:     "GitHub Actions Unpinned Action - Negative (pinned)",
			filePath: ".github/workflows/build.yml",
			content:  "uses: actions/checkout@v2",
			expected: []types.Finding{},
		},
		{
			name:     "GitHub Actions Write-All Permissions - Positive",
			filePath: ".github/workflows/deploy.yml",
			content:  "permissions: write-all",
			expected: []types.Finding{{RuleID: "GH002", Severity: types.SeverityHigh}},
		},
		{
			name:     "GitHub Actions Write-All Permissions - Negative",
			filePath: ".github/workflows/deploy.yml",
			content:  "permissions: read-all",
			expected: []types.Finding{},
		},
		// GitLab CI
		{
			name:     "GitLab CI Hardcoded Master Branch - Positive",
			filePath: ".gitlab-ci.yml",
			content:  "default_branch: master",
			expected: []types.Finding{{RuleID: "GL001", Severity: types.SeverityMedium}},
		},
		{
			name:     "GitLab CI Hardcoded Master Branch - Negative (main)",
			filePath: ".gitlab-ci.yml",
			content:  "default_branch: main",
			expected: []types.Finding{},
		},
		{
			name:     "GitLab CI Job Without Only/Except - Positive",
			filePath: ".gitlab-ci.yml",
			content:  "build_job:\n  script: echo 'hello'",
			expected: []types.Finding{{RuleID: "GL002", Severity: types.SeverityMedium}},
		},
		{
			name:     "GitLab CI Job Without Only/Except - Negative (with only)",
			filePath: ".gitlab-ci.yml",
			content:  "build_job:\n  only: [main]\n  script: echo 'hello'",
			expected: []types.Finding{},
		},
		// Azure Pipelines
		{
			name:     "Azure Pipelines Unpinned VM Image - Positive",
			filePath: "azure-pipelines.yml",
			content:  "pool: vmImage: 'windows-latest'",
			expected: []types.Finding{{RuleID: "AZ001", Severity: types.SeverityMedium}},
		},
		{
			name:     "Azure Pipelines Unpinned VM Image - Negative (pinned)",
			filePath: "azure-pipelines.yml",
			content:  "pool: vmImage: 'windows-2019'",
			expected: []types.Finding{},
		},
		{
			name:     "Azure Pipelines Inline Secret - Positive",
			filePath: "azure-pipelines.yml",
			content:  "password: mysecretpassword",
			expected: []types.Finding{{RuleID: "AZ002", Severity: types.SeverityHigh}},
		},
		{
			name:     "Azure Pipelines Inline Secret - Negative",
			filePath: "azure-pipelines.yml",
			content:  "username: myuser",
			expected: []types.Finding{},
		},
		// Jenkins
		{
			name:     "Jenkins Plaintext withCredentials - Positive",
			filePath: "Jenkinsfile",
			content:  `withCredentials([string(credentialsId: 'my-secret', variable: 'MY_SECRET')])`,
			expected: []types.Finding{{RuleID: "JK001", Severity: types.SeverityHigh}},
		},
		{
			name:     "Jenkins Plaintext withCredentials - Negative (not plaintext)",
			filePath: "Jenkinsfile",
			content:  `withCredentials([file(credentialsId: 'my-secret-file', variable: 'MY_SECRET_FILE')])`,
			expected: []types.Finding{},
		},
		{
			name:     "Jenkins Hardcoded Password in Groovy - Positive",
			filePath: "Jenkinsfile",
			content:  `def password = "hardcodedpassword123"`,
			expected: []types.Finding{{RuleID: "JK002", Severity: types.SeverityHigh}},
		},
		{
			name:     "Jenkins Hardcoded Password in Groovy - Negative",
			filePath: "Jenkinsfile",
			content:  `def username = "myuser"`,
			expected: []types.Finding{},
		},
		// Platform Specificity Tests
		{
			name:     "GitHub Action rule on non-GitHub file",
			filePath: "test.yml",
			content:  "uses: actions/checkout@master",
			expected: []types.Finding{}, // Should not trigger
		},
		{
			name:     "Azure rule on non-Azure file",
			filePath: ".github/workflows/build.yml",
			content:  "pool: vmImage: 'windows-latest'",
			expected: []types.Finding{}, // Should not trigger
		},
		{
			name:     "Global rule on GitHub file",
			filePath: ".github/workflows/build.yml",
			content:  "AKIAIOSFODNN7EXAMPLE",
			expected: []types.Finding{{RuleID: "SEC001", Severity: types.SeverityHigh}},
		},
		{
			name:     "Global rule on Azure file",
			filePath: "azure-pipelines.yml",
			content:  "AKIAIOSFODNN7EXAMPLE",
			expected: []types.Finding{{RuleID: "SEC001", Severity: types.SeverityHigh}},
		},
		// Mixed-pipeline repo scenario
		{
			name:     "Mixed-pipeline: GitHub file with GitHub and Global rules",
			filePath: ".github/workflows/mixed.yml",
			content:  "uses: actions/checkout@master\nGITHUB_TOKEN: ghp_abcdefghijklmnopqrstuvwxyz0123456789\nAKIAIOSFODNN7EXAMPLE",
			expected: []types.Finding{
				{RuleID: "UNPINNED_ACTION", Severity: types.SeverityMedium},
				{RuleID: "SEC003", Severity: types.SeverityHigh},
				{RuleID: "SEC001", Severity: types.SeverityHigh},
			},
		},
		{
			name:     "Mixed-pipeline: GitLab file with GitLab and Global rules",
			filePath: ".gitlab-ci.yml",
			content:  "default_branch: master\nbuild_job:\n  script: echo 'hello'\nAKIAIOSFODNN7EXAMPLE",
			expected: []types.Finding{
				{RuleID: "GL001", Severity: types.SeverityMedium},
				{RuleID: "GL002", Severity: types.SeverityMedium},
				{RuleID: "SEC001", Severity: types.SeverityHigh},
			},
		},
		{
			name:     "Mixed-pipeline: Azure file with Azure and Global rules",
			filePath: "azure-pipelines.yml",
			content:  "pool: vmImage: 'windows-latest'\npassword: mysecretpassword\nAKIAIOSFODNN7EXAMPLE",
			expected: []types.Finding{
				{RuleID: "AZ001", Severity: types.SeverityMedium},
				{RuleID: "AZ002", Severity: types.SeverityHigh},
				{RuleID: "SEC001", Severity: types.SeverityHigh},
			},
		},
		{
			name:     "Mixed-pipeline: Jenkinsfile with Jenkins and Global rules",
			filePath: "Jenkinsfile",
			content:  `withCredentials([string(credentialsId: 'my-secret', variable: 'MY_SECRET')])` + "\n" + `def password = "hardcodedpassword123"` + "\n" + `AKIAIOSFODNN7EXAMPLE`,
			expected: []types.Finding{
				{RuleID: "JK001", Severity: types.SeverityHigh},
				{RuleID: "JK002", Severity: types.SeverityHigh},
				{RuleID: "SEC001", Severity: types.SeverityHigh},
			},
		},
		// New Rules Tests
		{
			name:     "GitLab CI Insecure Curl to Bash Pipe - Positive",
			filePath: ".gitlab-ci.yml",
			content:  "  script: curl -s example.com | bash",
			expected: []types.Finding{{RuleID: "GL004", Severity: types.SeverityHigh}},
		},
		{
			name:     "GitLab CI Insecure Curl to Bash Pipe - Negative",
			filePath: ".gitlab-ci.yml",
			content:  "  script: curl -s example.com",
			expected: []types.Finding{},
		},
		{
			name:     "GitHub Actions Sudo Run - Positive",
			filePath: ".github/workflows/build.yml",
			content:  "    - run: sudo apt-get update",
			expected: []types.Finding{{RuleID: "GH004", Severity: types.SeverityMedium}},
		},
		{
			name:     "GitHub Actions Sudo Run - Negative",
			filePath: ".github/workflows/build.yml",
			content:  "    - run: apt-get update",
			expected: []types.Finding{},
		},
		{
			name:     "Azure Pipelines System.AccessToken Usage - Positive",
			filePath: "azure-pipelines.yml",
			content:  "  script: echo $(System.AccessToken)",
			expected: []types.Finding{{RuleID: "AZ004", Severity: types.SeverityHigh}},
		},
		{
			name:     "Azure Pipelines System.AccessToken Usage - Negative",
			filePath: "azure-pipelines.yml",
			content:  "  script: echo $(Build.DefinitionName)",
			expected: []types.Finding{},
		},
		{
			name:     "Jenkins Unsafe Shell Step - Positive (sh)",
			filePath: "Jenkinsfile",
			content:  `sh "echo $UNSAFE_VAR"`,
			expected: []types.Finding{{RuleID: "JK004", Severity: types.SeverityHigh}},
		},
		{
			name:     "Jenkins Unsafe Shell Step - Positive (bat)",
			filePath: "Jenkinsfile",
			content:  `bat "echo %UNSAFE_VAR%"`,
			expected: []types.Finding{{RuleID: "JK004", Severity: types.SeverityHigh}},
		},
		{
			name:     "Jenkins Unsafe Shell Step - Negative",
			filePath: "Jenkinsfile",
			content:  `sh "echo 'safe string'"`,
			expected: []types.Finding{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := engine.RunRules(tt.filePath, tt.content)

			if len(findings) != len(tt.expected) {
				t.Errorf("Expected %d findings, got %d for %s", len(tt.expected), len(findings), tt.name)
				for _, f := range findings {
					t.Logf("  Found: %s (%s)", f.Message, f.RuleID)
				}
				return
			}

			// Sort findings by RuleID for consistent comparison
			sort.Slice(findings, func(i, j int) bool {
				return findings[i].RuleID < findings[j].RuleID
			})
			sort.Slice(tt.expected, func(i, j int) bool {
				return tt.expected[i].RuleID < tt.expected[j].RuleID
			})

			for i, expectedFinding := range tt.expected {
				if findings[i].RuleID != expectedFinding.RuleID || findings[i].Severity != expectedFinding.Severity {
					t.Errorf("Finding mismatch for %s. Expected RuleID: %s, Severity: %s. Got RuleID: %s, Severity: %s",
						tt.name, expectedFinding.RuleID, expectedFinding.Severity, findings[i].RuleID, findings[i].Severity)
				}
			}
		})
	}
}

func TestDetectPipelinePlatform(t *testing.T) {
	tests := []struct {
		name     string
		filePath string
		expected utils.Platform
	}{
		{"GitHub Workflow", ".github/workflows/build.yml", utils.PlatformGitHub},
		{"GitHub Workflow Subdir", "repo/.github/workflows/test/deploy.yaml", utils.PlatformGitHub},
		{"GitLab CI", ".gitlab-ci.yml", utils.PlatformGitLab},
		{"Azure Pipelines YML", "azure-pipelines.yml", utils.PlatformAzure},
		{"Azure Pipelines YAML", "subdir/azure-pipelines-deploy.yaml", utils.PlatformAzure},
		{"Jenkinsfile", "Jenkinsfile", utils.PlatformJenkins},
		{"Jenkinsfile in subdir", "project/Jenkinsfile", utils.PlatformJenkins},
		{"Jenkins Groovy", "my-pipeline.jenkins", utils.PlatformJenkins},
		{"Unknown File", "random.txt", utils.PlatformUnknown},
		{"YAML not pipeline", "config.yml", utils.PlatformUnknown},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			platform := utils.DetectPipelinePlatform(tt.filePath)
			if platform != tt.expected {
				t.Errorf("For file %s, expected platform %s, got %s", tt.filePath, tt.expected, platform)
			}
		})
	}
}
