package scanner

import (
	"fmt"
	"strings"
	"sync"

	"github.com/zanicool/apex-cli/pkg/crawler"
	"github.com/zanicool/apex-cli/pkg/engine"
	"github.com/zanicool/apex-cli/pkg/oob"
)

// scanCloudSecurity checks for cloud misconfigurations across AWS/GCP/Azure/K8s/Docker
func scanCloudSecurity(cfg *engine.Config, h *engine.HTTPClient, crawl *crawler.Result, _ *oob.Client) []Finding {
	var findings []Finding
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, cfg.Threads)

	if len(crawl.Pages) == 0 {
		return findings
	}
	baseURL := extractBaseURL(crawl.Pages[0].URL)
	domain := extractDomain(baseURL)

	// Run all cloud checks in parallel
	checks := []func() []Finding{
		func() []Finding { return checkS3Buckets(h, domain) },
		func() []Finding { return checkAWSMetadata(h, crawl) },
		func() []Finding { return checkGCPMetadata(h, crawl) },
		func() []Finding { return checkAzureMetadata(h, crawl) },
		func() []Finding { return checkKubernetes(h, baseURL) },
		func() []Finding { return checkDocker(h, baseURL) },
		func() []Finding { return checkTerraform(h, baseURL) },
		func() []Finding { return checkCloudStorage(h, domain) },
	}

	for _, check := range checks {
		wg.Add(1)
		go func(fn func() []Finding) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			results := fn()
			if len(results) > 0 {
				mu.Lock()
				findings = append(findings, results...)
				mu.Unlock()
			}
		}(check)
	}
	wg.Wait()
	return findings
}

// --- S3 Bucket Enumeration ---

func checkS3Buckets(h *engine.HTTPClient, domain string) []Finding {
	var findings []Finding
	// Generate bucket name permutations SPECIFIC to the target
	parts := strings.Split(domain, ".")
	base := parts[0]
	// Only use names clearly tied to this domain
	permutations := []string{
		base + "-backup", base + "-backups",
		base + "-assets", base + "-uploads", base + "-media",
		base + "-data", base + "-logs", base + "-private",
		base + "-dev", base + "-staging", base + "-prod",
		base + "-internal", base + "-public",
		domain, strings.ReplaceAll(domain, ".", "-"),
		strings.ReplaceAll(domain, ".", "-") + "-backup",
	}

	for _, bucket := range permutations {
		// Check S3
		url := fmt.Sprintf("https://%s.s3.amazonaws.com", bucket)
		resp := h.Get(url)
		if resp.Err != nil {
			continue
		}
		if resp.StatusCode == 200 && strings.Contains(resp.Body, "<ListBucketResult") {
			// Verify it actually belongs to this target by checking content
			if !bucketBelongsToTarget(resp.Body, domain, base) {
				continue
			}
			findings = append(findings, Finding{
				Type: "Open S3 Bucket (Listable)", Severity: "critical",
				URL: url, Detail: fmt.Sprintf("S3 bucket '%s' allows public listing", bucket),
				Template: "apex-s3-open",
			})
		}
	}
	return findings
}

// --- AWS Metadata SSRF ---

func checkAWSMetadata(h *engine.HTTPClient, crawl *crawler.Result) []Finding {
	var findings []Finding
	metadataURLs := []string{
		"http://169.254.169.254/latest/meta-data/",
		"http://169.254.169.254/latest/meta-data/iam/security-credentials/",
		"http://169.254.169.254/latest/user-data",
		"http://169.254.170.2/v2/credentials",                    // ECS
		"http://169.254.169.254/latest/api/token",                // IMDSv2
	}

	// Try SSRF via URL parameters
	urlParams := []string{"url", "uri", "path", "redirect", "next", "target", "dest", "src", "source", "link", "file", "page"}
	for u, params := range crawl.Params {
		// Skip static assets
		if strings.HasSuffix(u, ".js") || strings.HasSuffix(u, ".css") || strings.Contains(u, "/assets/") {
			continue
		}
		// Only test actual URL endpoints
		if !strings.Contains(u, "?") && !strings.Contains(u, "/api") {
			continue
		}
		for _, p := range params {
			pLower := strings.ToLower(p)
			isURLParam := false
			for _, up := range urlParams {
				if strings.Contains(pLower, up) {
					isURLParam = true
					break
				}
			}
			if !isURLParam {
				continue
			}
			for _, metaURL := range metadataURLs {
				testURL := injectParam(u, p, metaURL)
				resp := h.Get(testURL)
				if resp.Err != nil || engine.IsWAFChallenge(resp) {
					continue
				}
				if strings.Contains(resp.Body, "ami-id") || strings.Contains(resp.Body, "instance-id") ||
					strings.Contains(resp.Body, "AccessKeyId") || strings.Contains(resp.Body, "iam") {
					findings = append(findings, Finding{
						Type: "SSRF → AWS Metadata", Severity: "critical",
						URL: testURL, Param: p, Payload: metaURL,
						Detail:   "SSRF reaches AWS metadata service — IAM credentials extractable",
						Evidence: truncate(resp.Body, 200),
						Template: "apex-ssrf-aws",
					})
					return findings
				}
			}
		}
	}
	return findings
}

// --- GCP Metadata ---

func checkGCPMetadata(h *engine.HTTPClient, crawl *crawler.Result) []Finding {
	var findings []Finding
	gcpURLs := []string{
		"http://metadata.google.internal/computeMetadata/v1/project/project-id",
		"http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
		"http://169.254.169.254/computeMetadata/v1/",
	}

	urlParams := []string{"url", "uri", "path", "redirect", "src", "source", "file"}
	for u, params := range crawl.Params {
		for _, p := range params {
			pLower := strings.ToLower(p)
			isURLParam := false
			for _, up := range urlParams {
				if strings.Contains(pLower, up) {
					isURLParam = true
					break
				}
			}
			if !isURLParam {
				continue
			}
			for _, metaURL := range gcpURLs {
				testURL := injectParam(u, p, metaURL)
				resp := h.Get(testURL)
				if resp.Err == nil && !engine.IsWAFChallenge(resp) && (strings.Contains(resp.Body, "project-id") || strings.Contains(resp.Body, "access_token")) {
					findings = append(findings, Finding{
						Type: "SSRF → GCP Metadata", Severity: "critical",
						URL: testURL, Param: p, Payload: metaURL,
						Detail:   "SSRF reaches GCP metadata — service account token extractable",
						Template: "apex-ssrf-gcp",
					})
					return findings
				}
			}
		}
	}
	return findings
}

// --- Azure Metadata ---

func checkAzureMetadata(h *engine.HTTPClient, crawl *crawler.Result) []Finding {
	var findings []Finding
	azureURLs := []string{
		"http://169.254.169.254/metadata/instance?api-version=2021-02-01",
		"http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/",
	}

	urlParams := []string{"url", "uri", "path", "redirect", "src", "file"}
	for u, params := range crawl.Params {
		for _, p := range params {
			pLower := strings.ToLower(p)
			isURLParam := false
			for _, up := range urlParams {
				if strings.Contains(pLower, up) {
					isURLParam = true
					break
				}
			}
			if !isURLParam {
				continue
			}
			for _, metaURL := range azureURLs {
				testURL := injectParam(u, p, metaURL)
				resp := h.Get(testURL)
				if resp.Err == nil && !engine.IsWAFChallenge(resp) && (strings.Contains(resp.Body, "subscriptionId") || strings.Contains(resp.Body, "access_token")) {
					findings = append(findings, Finding{
						Type: "SSRF → Azure Metadata", Severity: "critical",
						URL: testURL, Param: p, Payload: metaURL,
						Detail:   "SSRF reaches Azure IMDS — managed identity token extractable",
						Template: "apex-ssrf-azure",
					})
					return findings
				}
			}
		}
	}
	return findings
}

// --- Kubernetes ---

func checkKubernetes(h *engine.HTTPClient, baseURL string) []Finding {
	var findings []Finding
	k8sPaths := []struct {
		path   string
		detect string
		desc   string
	}{
		{"/api/v1/namespaces", "items", "Kubernetes API — namespace listing"},
		{"/api/v1/pods", "items", "Kubernetes API — pod listing"},
		{"/api/v1/secrets", "items", "Kubernetes API — secrets exposed"},
		{"/dashboard/", "kubernetes-dashboard", "Kubernetes Dashboard exposed"},
		{"/api/v1/nodes", "items", "Kubernetes API — node listing"},
		{"/apis", "apiVersion", "Kubernetes API discovery endpoint"},
		{"/healthz", "ok", "Kubernetes health endpoint"},
		{"/metrics", "process_", "Kubernetes metrics (Prometheus)"},
	}

	// Check if target itself exposes K8s
	for _, k := range k8sPaths {
		resp := h.Get(baseURL + k.path)
		if resp.Err == nil && resp.StatusCode == 200 && strings.Contains(resp.Body, k.detect) {
			sev := "high"
			if strings.Contains(k.path, "secrets") || strings.Contains(k.path, "pods") {
				sev = "critical"
			}
			findings = append(findings, Finding{
				Type: "Kubernetes Exposure: " + k.desc, Severity: sev,
				URL: baseURL + k.path, Detail: k.desc,
				Template: "apex-k8s",
			})
		}
	}

	// Check common K8s ports on same host
	domain := extractDomain(baseURL)
	k8sPorts := []string{"6443", "8443", "10250", "10255", "2379"}
	for _, port := range k8sPorts {
		url := fmt.Sprintf("https://%s:%s", domain, port)
		resp := h.Get(url)
		if resp.Err == nil && resp.StatusCode != 0 {
			if strings.Contains(resp.Body, "apiVersion") || strings.Contains(resp.Body, "kubelet") {
				findings = append(findings, Finding{
					Type: "Kubernetes Service Exposed", Severity: "critical",
					URL: url, Detail: fmt.Sprintf("K8s service on port %s accessible from internet", port),
					Template: "apex-k8s-port",
				})
			}
		}
	}
	return findings
}

// --- Docker ---

func checkDocker(h *engine.HTTPClient, baseURL string) []Finding {
	var findings []Finding
	domain := extractDomain(baseURL)

	// Docker API
	dockerURLs := []string{
		fmt.Sprintf("http://%s:2375/version", domain),
		fmt.Sprintf("http://%s:2376/version", domain),
		fmt.Sprintf("https://%s:2376/version", domain),
		baseURL + "/v2/_catalog", // Docker Registry
	}

	for _, url := range dockerURLs {
		resp := h.Get(url)
		if resp.Err != nil {
			continue
		}
		if strings.Contains(resp.Body, "ApiVersion") || strings.Contains(resp.Body, "GoVersion") {
			findings = append(findings, Finding{
				Type: "Docker API Exposed", Severity: "critical",
				URL: url, Detail: "Docker daemon API accessible — full container/host compromise possible",
				Template: "apex-docker-api",
			})
		}
		if strings.Contains(resp.Body, "repositories") {
			findings = append(findings, Finding{
				Type: "Docker Registry Exposed", Severity: "high",
				URL: url, Detail: "Docker registry accessible — container images can be pulled/pushed",
				Template: "apex-docker-registry",
			})
		}
	}
	return findings
}

// --- Terraform ---

func checkTerraform(h *engine.HTTPClient, baseURL string) []Finding {
	var findings []Finding
	tfPaths := []string{
		"/.terraform/terraform.tfstate",
		"/terraform.tfstate",
		"/tfstate",
		"/.terraform.lock.hcl",
		"/main.tf",
		"/variables.tf",
	}

	for _, path := range tfPaths {
		resp := h.Get(baseURL + path)
		if resp.Err == nil && resp.StatusCode == 200 {
			if strings.Contains(resp.Body, "terraform") || strings.Contains(resp.Body, "provider") ||
				strings.Contains(resp.Body, "resource") || strings.Contains(resp.Body, "aws_") {
				sev := "critical"
				if strings.Contains(resp.Body, "secret") || strings.Contains(resp.Body, "password") ||
					strings.Contains(resp.Body, "access_key") {
					sev = "critical"
				}
				findings = append(findings, Finding{
					Type: "Terraform State/Config Exposed", Severity: sev,
					URL: baseURL + path, Detail: "Terraform files accessible — infrastructure secrets and topology exposed",
					Template: "apex-terraform",
				})
			}
		}
	}
	return findings
}

// --- Cloud Storage (GCS, Azure Blob) ---

func checkCloudStorage(h *engine.HTTPClient, domain string) []Finding {
	var findings []Finding
	parts := strings.Split(domain, ".")
	base := parts[0]

	// Google Cloud Storage - only target-specific names
	gcsBuckets := []string{base + "-backup", base + "-data", base + "-uploads", base + "-assets", strings.ReplaceAll(domain, ".", "-")}
	for _, bucket := range gcsBuckets {
		url := fmt.Sprintf("https://storage.googleapis.com/%s", bucket)
		resp := h.Get(url)
		if resp.Err == nil && resp.StatusCode == 200 && strings.Contains(resp.Body, "<ListBucketResult") {
			if !bucketBelongsToTarget(resp.Body, domain, base) {
				continue
			}
			findings = append(findings, Finding{
				Type: "Open GCS Bucket", Severity: "critical",
				URL: url, Detail: fmt.Sprintf("Google Cloud Storage bucket '%s' publicly listable", bucket),
				Template: "apex-gcs-open",
			})
		}
	}

	// Azure Blob Storage - only target-specific names
	azureContainers := []string{base + "-data", base + "-backup"}
	for _, container := range azureContainers {
		url := fmt.Sprintf("https://%s.blob.core.windows.net/%s?restype=container&comp=list", base, container)
		resp := h.Get(url)
		if resp.Err == nil && resp.StatusCode == 200 && strings.Contains(resp.Body, "<EnumerationResults") {
			findings = append(findings, Finding{
				Type: "Open Azure Blob Container", Severity: "critical",
				URL: url, Detail: fmt.Sprintf("Azure blob container '%s' publicly listable", container),
				Template: "apex-azure-blob",
			})
		}
	}
	return findings
}

// bucketBelongsToTarget checks if bucket content is related to the target domain
func bucketBelongsToTarget(body, domain, base string) bool {
	bodyLower := strings.ToLower(body)
	domainLower := strings.ToLower(domain)
	baseLower := strings.ToLower(base)
	// Check if any file keys reference the target
	return strings.Contains(bodyLower, domainLower) || strings.Contains(bodyLower, baseLower)
}
