using System;
using System.Collections.Generic;

namespace BugBountyTool.Models
{
    /// <summary>
    /// Represents the complete scan result including reconnaissance and vulnerability data
    /// </summary>
    public class ScanResult
    {
        public string Target { get; set; } = string.Empty;
        public DateTime Timestamp { get; set; }
        public ReconnaissanceResult Reconnaissance { get; set; } = new();
        public List<Vulnerability> Vulnerabilities { get; set; } = new();
        public ScanSummary Summary { get; set; } = new();
    }

    /// <summary>
    /// Represents reconnaissance results
    /// </summary>
    public class ReconnaissanceResult
    {
        public List<string> Subdomains { get; set; } = new();
        public List<ValidSubdomain> ValidSubdomains { get; set; } = new();
        public List<Directory> Directories { get; set; } = new();
        public List<string> Parameters { get; set; } = new();
        public WafInfo WafInfo { get; set; } = new();
    }

    /// <summary>
    /// Represents a valid subdomain with additional information
    /// </summary>
    public class ValidSubdomain
    {
        public string Subdomain { get; set; } = string.Empty;
        public string Protocol { get; set; } = string.Empty;
        public int StatusCode { get; set; }
        public string Title { get; set; } = string.Empty;
        public string Server { get; set; } = string.Empty;
    }

    /// <summary>
    /// Represents a discovered directory or file
    /// </summary>
    public class Directory
    {
        public string Path { get; set; } = string.Empty;
        public string Url { get; set; } = string.Empty;
        public int StatusCode { get; set; }
        public long ContentLength { get; set; }
        public string Server { get; set; } = string.Empty;
    }

    /// <summary>
    /// Represents WAF detection information
    /// </summary>
    public class WafInfo
    {
        public bool Detected { get; set; }
        public string Type { get; set; } = "Unknown";
        public int Confidence { get; set; }
        public List<string> Indicators { get; set; } = new();
    }

    /// <summary>
    /// Represents a discovered vulnerability
    /// </summary>
    public class Vulnerability
    {
        public string Type { get; set; } = string.Empty;
        public string Subtype { get; set; } = string.Empty;
        public string Url { get; set; } = string.Empty;
        public string Parameter { get; set; } = string.Empty;
        public string Payload { get; set; } = string.Empty;
        public string Severity { get; set; } = string.Empty;
        public string Description { get; set; } = string.Empty;
        public string Evidence { get; set; } = string.Empty;
        public string TargetSubdomain { get; set; } = string.Empty;
        public DateTime ScanTimestamp { get; set; }
    }

    /// <summary>
    /// Represents scan summary statistics
    /// </summary>
    public class ScanSummary
    {
        public int TotalVulnerabilities { get; set; }
        public int CriticalVulnerabilities { get; set; }
        public int HighVulnerabilities { get; set; }
        public int MediumVulnerabilities { get; set; }
        public int LowVulnerabilities { get; set; }
        public int SubdomainsFound { get; set; }
        public int DirectoriesFound { get; set; }
        public int ParametersFound { get; set; }
        public bool WafDetected { get; set; }
    }
}