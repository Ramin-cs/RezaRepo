using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using BugBountyTool.Models;
using BugBountyTool.Services;
using Colorful.Console;
using CommandLine;
using Newtonsoft.Json;

namespace BugBountyTool
{
    /// <summary>
    /// Main entry point for the Advanced Bug Bounty Tool
    /// </summary>
    class Program
    {
        static async Task<int> Main(string[] args)
        {
            return await Parser.Default.ParseArguments<CommandLineOptions>(args)
                .MapResult(
                    async options => await RunToolAsync(options),
                    errors => Task.FromResult(1)
                );
        }

        /// <summary>
        /// Run the bug bounty tool with the specified options
        /// </summary>
        static async Task<int> RunToolAsync(CommandLineOptions options)
        {
            try
            {
                // Validate target domain
                if (string.IsNullOrEmpty(options.Target) || !options.Target.Contains('.'))
                {
                    Console.WriteLine("Error: Please provide a valid target domain (e.g., example.com)", Color.Red);
                    return 1;
                }

                // Initialize tool
                var tool = new BugBountyTool(options.Target, options.OutputDir);
                
                bool success;
                
                if (options.ReconOnly)
                {
                    // Run only reconnaissance
                    success = await tool.RunReconnaissancePhaseAsync();
                }
                else if (options.VulnOnly)
                {
                    // Run only vulnerability scanning
                    success = await tool.RunVulnerabilityScanningPhaseAsync();
                }
                else
                {
                    // Run complete assessment
                    success = await tool.RunCompleteAssessmentAsync();
                }

                if (success)
                {
                    Console.WriteLine("\n✅ Assessment completed successfully!", Color.Green);
                    return 0;
                }
                else
                {
                    Console.WriteLine("\n❌ Assessment failed!", Color.Red);
                    return 1;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"\n❌ Unexpected error: {ex.Message}", Color.Red);
                return 1;
            }
        }
    }

    /// <summary>
    /// Command line options for the tool
    /// </summary>
    public class CommandLineOptions
    {
        [Value(0, Required = true, HelpText = "Target domain to test (e.g., example.com)")]
        public string Target { get; set; } = string.Empty;

        [Option('o', "output-dir", Default = "bug_bounty_results", HelpText = "Output directory for results")]
        public string OutputDir { get; set; } = "bug_bounty_results";

        [Option("recon-only", HelpText = "Run only reconnaissance phase")]
        public bool ReconOnly { get; set; }

        [Option("vuln-only", HelpText = "Run only vulnerability scanning phase (requires existing recon results)")]
        public bool VulnOnly { get; set; }
    }

    /// <summary>
    /// Main Bug Bounty Tool class that orchestrates reconnaissance and vulnerability scanning
    /// </summary>
    public class BugBountyTool
    {
        private readonly string _targetDomain;
        private readonly string _outputDir;
        private ReconnaissanceResult _reconResults;
        private List<Vulnerability> _vulnResults;

        public BugBountyTool(string targetDomain, string outputDir)
        {
            _targetDomain = targetDomain;
            _outputDir = outputDir;
            _reconResults = new ReconnaissanceResult();
            _vulnResults = new List<Vulnerability>();
            
            // Create output directory
            Directory.CreateDirectory(_outputDir);
            
            PrintBanner();
        }

        /// <summary>
        /// Print main tool banner
        /// </summary>
        private void PrintBanner()
        {
            var banner = $@"
╔══════════════════════════════════════════════════════════════════════════════╗
║                        ADVANCED BUG BOUNTY TOOL                              ║
║                    Reconnaissance + Vulnerability Scanner                     ║
║                              Version 1.0.0                                   ║
╚══════════════════════════════════════════════════════════════════════════════╝

Target Domain: {_targetDomain}
Output Directory: {_outputDir}
Start Time: {DateTime.Now:yyyy-MM-dd HH:mm:ss}

Starting comprehensive security assessment...
";
            Console.WriteLine(banner, Color.Cyan);
        }

        /// <summary>
        /// Log messages with timestamps and colors
        /// </summary>
        private void Log(string message, string level = "INFO")
        {
            var timestamp = DateTime.Now.ToString("HH:mm:ss");
            var color = level switch
            {
                "INFO" => Color.Blue,
                "SUCCESS" => Color.Green,
                "WARNING" => Color.Yellow,
                "ERROR" => Color.Red,
                "CRITICAL" => Color.Magenta,
                "PHASE" => Color.Cyan,
                _ => Color.White
            };
            
            Console.WriteLine($"[{timestamp}] [{level}] {message}", color);
        }

        /// <summary>
        /// Run reconnaissance phase
        /// </summary>
        public async Task<bool> RunReconnaissancePhaseAsync()
        {
            Log("=" + new string('=', 59), "PHASE");
            Log("PHASE 1: RECONNAISSANCE", "PHASE");
            Log("=" + new string('=', 59), "PHASE");

            try
            {
                using var reconService = new ReconnaissanceService(_targetDomain, _outputDir);
                _reconResults = await reconService.RunCompleteReconnaissanceAsync();
                
                if (_reconResults != null)
                {
                    Log("Reconnaissance phase completed successfully!", "SUCCESS");
                    return true;
                }
                else
                {
                    Log("Reconnaissance phase failed!", "ERROR");
                    return false;
                }
            }
            catch (Exception ex)
            {
                Log($"Error during reconnaissance phase: {ex.Message}", "ERROR");
                return false;
            }
        }

        /// <summary>
        /// Run vulnerability scanning phase
        /// </summary>
        public async Task<bool> RunVulnerabilityScanningPhaseAsync()
        {
            Log("=" + new string('=', 59), "PHASE");
            Log("PHASE 2: VULNERABILITY SCANNING", "PHASE");
            Log("=" + new string('=', 59), "PHASE");

            // Try to load existing reconnaissance results
            if (_reconResults == null || !_reconResults.Parameters.Any())
            {
                var reconFile = Path.Combine(_outputDir, $"{_targetDomain}_recon.json");
                if (File.Exists(reconFile))
                {
                    try
                    {
                        var reconJson = await File.ReadAllTextAsync(reconFile);
                        var scanResult = JsonConvert.DeserializeObject<ScanResult>(reconJson);
                        _reconResults = scanResult?.Reconnaissance ?? new ReconnaissanceResult();
                    }
                    catch (Exception ex)
                    {
                        Log($"Error loading reconnaissance results: {ex.Message}", "WARNING");
                    }
                }
            }

            if (_reconResults == null || !_reconResults.Parameters.Any())
            {
                Log("No reconnaissance results available. Skipping vulnerability scanning.", "WARNING");
                return false;
            }

            try
            {
                // Get parameters from reconnaissance results
                var parameters = _reconResults.Parameters;
                
                // Add common parameters if none found
                if (!parameters.Any())
                {
                    parameters = new List<string> { "id", "page", "search", "q", "url", "redirect", "return", "next", "callback" };
                    Log("No parameters found in reconnaissance. Using common parameters.", "WARNING");
                }

                // Get valid subdomains for scanning
                var validSubdomains = _reconResults.ValidSubdomains;
                
                // Add main domain if no subdomains found
                if (!validSubdomains.Any())
                {
                    validSubdomains = new List<ValidSubdomain> 
                    { 
                        new ValidSubdomain { Subdomain = _targetDomain, Protocol = "https" } 
                    };
                }

                // Scan each valid subdomain
                foreach (var subdomainInfo in validSubdomains)
                {
                    var subdomain = subdomainInfo.Subdomain;
                    var protocol = subdomainInfo.Protocol;
                    var targetUrl = $"{protocol}://{subdomain}";
                    
                    Log($"Scanning {targetUrl} for vulnerabilities...", "INFO");
                    
                    using var scanner = new VulnerabilityScannerService(targetUrl, _outputDir);
                    var vulnResults = await scanner.RunCompleteScanAsync(parameters);
                    
                    if (vulnResults.Any())
                    {
                        // Add subdomain info to each vulnerability
                        foreach (var vuln in vulnResults)
                        {
                            vuln.TargetSubdomain = subdomain;
                            vuln.ScanTimestamp = DateTime.Now;
                        }
                        
                        _vulnResults.AddRange(vulnResults);
                        Log($"Found {vulnResults.Count} vulnerabilities on {subdomain}", "SUCCESS");
                    }
                    else
                    {
                        Log($"No vulnerabilities found on {subdomain}", "INFO");
                    }
                }

                Log($"Vulnerability scanning completed! Total vulnerabilities found: {_vulnResults.Count}", "SUCCESS");
                return true;
            }
            catch (Exception ex)
            {
                Log($"Error during vulnerability scanning phase: {ex.Message}", "ERROR");
                return false;
            }
        }

        /// <summary>
        /// Generate final report
        /// </summary>
        public async Task<string> GenerateFinalReportAsync()
        {
            Log("=" + new string('=', 59), "PHASE");
            Log("PHASE 3: REPORT GENERATION", "PHASE");
            Log("=" + new string('=', 59), "PHASE");

            try
            {
                // Generate HTML report
                var reportService = new ReportGeneratorService(_outputDir);
                var reportPath = reportService.GenerateReport(_reconResults, _vulnResults, _targetDomain);
                
                // Save JSON summary
                var summary = new ScanResult
                {
                    Target = _targetDomain,
                    Timestamp = DateTime.Now,
                    Reconnaissance = _reconResults,
                    Vulnerabilities = _vulnResults,
                    Summary = new ScanSummary
                    {
                        TotalVulnerabilities = _vulnResults.Count,
                        CriticalVulnerabilities = _vulnResults.Count(v => v.Severity.Equals("Critical", StringComparison.OrdinalIgnoreCase)),
                        HighVulnerabilities = _vulnResults.Count(v => v.Severity.Equals("High", StringComparison.OrdinalIgnoreCase)),
                        MediumVulnerabilities = _vulnResults.Count(v => v.Severity.Equals("Medium", StringComparison.OrdinalIgnoreCase)),
                        LowVulnerabilities = _vulnResults.Count(v => v.Severity.Equals("Low", StringComparison.OrdinalIgnoreCase)),
                        SubdomainsFound = _reconResults.Subdomains.Count,
                        DirectoriesFound = _reconResults.Directories.Count,
                        ParametersFound = _reconResults.Parameters.Count,
                        WafDetected = _reconResults.WafInfo?.Detected ?? false
                    }
                };
                
                var summaryPath = Path.Combine(_outputDir, $"{_targetDomain}_summary.json");
                var summaryJson = JsonConvert.SerializeObject(summary, Formatting.Indented);
                await File.WriteAllTextAsync(summaryPath, summaryJson);
                
                Log($"JSON summary saved: {summaryPath}", "SUCCESS");
                
                return reportPath;
            }
            catch (Exception ex)
            {
                Log($"Error generating report: {ex.Message}", "ERROR");
                return string.Empty;
            }
        }

        /// <summary>
        /// Print final summary of the scan
        /// </summary>
        public void PrintFinalSummary()
        {
            Log("=" + new string('=', 59), "PHASE");
            Log("SCAN COMPLETED - FINAL SUMMARY", "PHASE");
            Log("=" + new string('=', 59), "PHASE");

            if (_reconResults != null)
            {
                Log($"Subdomains discovered: {_reconResults.Subdomains.Count}", "INFO");
                Log($"Valid subdomains: {_reconResults.ValidSubdomains.Count}", "INFO");
                Log($"Directories found: {_reconResults.Directories.Count}", "INFO");
                Log($"Parameters discovered: {_reconResults.Parameters.Count}", "INFO");
                
                if (_reconResults.WafInfo?.Detected == true)
                {
                    Log($"WAF detected: {_reconResults.WafInfo.Type} (Confidence: {_reconResults.WafInfo.Confidence}%)", "WARNING");
                }
                else
                {
                    Log("No WAF detected", "INFO");
                }
            }

            Log($"Total vulnerabilities found: {_vulnResults.Count}", "INFO");
            
            if (_vulnResults.Any())
            {
                var critical = _vulnResults.Count(v => v.Severity.Equals("Critical", StringComparison.OrdinalIgnoreCase));
                var high = _vulnResults.Count(v => v.Severity.Equals("High", StringComparison.OrdinalIgnoreCase));
                var medium = _vulnResults.Count(v => v.Severity.Equals("Medium", StringComparison.OrdinalIgnoreCase));
                var low = _vulnResults.Count(v => v.Severity.Equals("Low", StringComparison.OrdinalIgnoreCase));
                
                if (critical > 0)
                    Log($"Critical vulnerabilities: {critical}", "ERROR");
                if (high > 0)
                    Log($"High vulnerabilities: {high}", "ERROR");
                if (medium > 0)
                    Log($"Medium vulnerabilities: {medium}", "WARNING");
                if (low > 0)
                    Log($"Low vulnerabilities: {low}", "INFO");
            }

            Log($"Results saved in: {_outputDir}", "SUCCESS");
            Log("Check the HTML report for detailed findings!", "SUCCESS");
        }

        /// <summary>
        /// Run complete bug bounty assessment
        /// </summary>
        public async Task<bool> RunCompleteAssessmentAsync()
        {
            var startTime = DateTime.Now;
            
            try
            {
                // Phase 1: Reconnaissance
                if (!await RunReconnaissancePhaseAsync())
                {
                    Log("Reconnaissance phase failed. Exiting.", "ERROR");
                    return false;
                }

                // Phase 2: Vulnerability Scanning
                if (!await RunVulnerabilityScanningPhaseAsync())
                {
                    Log("Vulnerability scanning phase failed. Exiting.", "ERROR");
                    return false;
                }

                // Phase 3: Report Generation
                var reportPath = await GenerateFinalReportAsync();
                if (string.IsNullOrEmpty(reportPath))
                {
                    Log("Report generation failed.", "ERROR");
                    return false;
                }

                // Print final summary
                PrintFinalSummary();
                
                var endTime = DateTime.Now;
                var duration = endTime - startTime;
                
                Log($"Total scan duration: {duration}", "SUCCESS");
                Log("Bug bounty assessment completed successfully!", "SUCCESS");
                
                return true;
            }
            catch (Exception ex)
            {
                Log($"Unexpected error during assessment: {ex.Message}", "ERROR");
                return false;
            }
        }
    }
}