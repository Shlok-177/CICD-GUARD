package detector

import "regexp"

var (
	awsKeyRe    = regexp.MustCompile(`AKIA[0-9A-Z]{16,20}`)
	ghTokenRe   = regexp.MustCompile(`ghp_[A-Za-z0-9]{36}`)
	azureConnRe = regexp.MustCompile(`DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[^;]+`)
	longTokenRe = regexp.MustCompile(`[A-Za-z0-9]{40,}`)
)
