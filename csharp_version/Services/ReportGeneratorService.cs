using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using BugBountyTool.Models;
using Colorful.Console;

namespace BugBountyTool.Services
{
    /// <summary>
    /// Service for generating comprehensive HTML reports
    /// </summary>
    public class ReportGeneratorService
    {
        private readonly string _outputDir;

        public ReportGeneratorService(string outputDir)
        {
            _outputDir = outputDir;
            Directory.CreateDirectory(_outputDir);
        }

        /// <summary>
        /// Generate comprehensive HTML report
        /// </summary>
        public string GenerateReport(ReconnaissanceResult reconResults, List<Vulnerability> vulnResults, string targetDomain)
        {
            var timestamp = DateTime.Now.ToString("yyyyMMdd_HHmmss");
            var filename = $"bug_bounty_report_{targetDomain}_{timestamp}.html";
            var filepath = Path.Combine(_outputDir, filename);

            var htmlContent = GenerateHtmlContent(reconResults, vulnResults, targetDomain);
            
            File.WriteAllText(filepath, htmlContent, Encoding.UTF8);
            
            Log($"HTML report generated: {filepath}", "SUCCESS");
            return filepath;
        }

        /// <summary>
        /// Generate HTML content for the report
        /// </summary>
        private string GenerateHtmlContent(ReconnaissanceResult reconResults, List<Vulnerability> vulnResults, string targetDomain)
        {
            // Calculate statistics
            var totalVulnerabilities = vulnResults.Count;
            var criticalCount = vulnResults.Count(v => v.Severity.Equals("Critical", StringComparison.OrdinalIgnoreCase));
            var highCount = vulnResults.Count(v => v.Severity.Equals("High", StringComparison.OrdinalIgnoreCase));
            var mediumCount = vulnResults.Count(v => v.Severity.Equals("Medium", StringComparison.OrdinalIgnoreCase));
            var lowCount = vulnResults.Count(v => v.Severity.Equals("Low", StringComparison.OrdinalIgnoreCase));
            var subdomainsCount = reconResults.Subdomains.Count;
            var directoriesCount = reconResults.Directories.Count;

            var html = $@"
<!DOCTYPE html>
<html lang=""en"">
<head>
    <meta charset=""UTF-8"">
    <meta name=""viewport"" content=""width=device-width, initial-scale=1.0"">
    <title>Bug Bounty Report - {targetDomain}</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            background-color: #f5f5f5;
        }}
        
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }}
        
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            border-radius: 10px;
            margin-bottom: 30px;
            text-align: center;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
        }}
        
        .header h1 {{
            font-size: 2.5em;
            margin-bottom: 10px;
        }}
        
        .header p {{
            font-size: 1.2em;
            opacity: 0.9;
        }}
        
        .summary {{
            background: white;
            padding: 25px;
            border-radius: 10px;
            margin-bottom: 30px;
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
        }}
        
        .summary h2 {{
            color: #667eea;
            margin-bottom: 20px;
            border-bottom: 2px solid #667eea;
            padding-bottom: 10px;
        }}
        
        .stats {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 20px;
        }}
        
        .stat-card {{
            background: #f8f9fa;
            padding: 20px;
            border-radius: 8px;
            text-align: center;
            border-left: 4px solid #667eea;
        }}
        
        .stat-number {{
            font-size: 2em;
            font-weight: bold;
            color: #667eea;
        }}
        
        .stat-label {{
            color: #666;
            margin-top: 5px;
        }}
        
        .section {{
            background: white;
            padding: 25px;
            border-radius: 10px;
            margin-bottom: 30px;
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
        }}
        
        .section h2 {{
            color: #667eea;
            margin-bottom: 20px;
            border-bottom: 2px solid #667eea;
            padding-bottom: 10px;
        }}
        
        .vulnerability {{
            background: #fff5f5;
            border: 1px solid #fed7d7;
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 15px;
        }}
        
        .vulnerability.critical {{
            background: #fff5f5;
            border-color: #f56565;
        }}
        
        .vulnerability.high {{
            background: #fffaf0;
            border-color: #ed8936;
        }}
        
        .vulnerability.medium {{
            background: #f0fff4;
            border-color: #48bb78;
        }}
        
        .vulnerability.low {{
            background: #f7fafc;
            border-color: #4299e1;
        }}
        
        .vuln-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 15px;
        }}
        
        .vuln-type {{
            font-size: 1.2em;
            font-weight: bold;
            color: #2d3748;
        }}
        
        .severity {{
            padding: 5px 15px;
            border-radius: 20px;
            color: white;
            font-weight: bold;
            text-transform: uppercase;
            font-size: 0.8em;
        }}
        
        .severity.critical {{
            background: #e53e3e;
        }}
        
        .severity.high {{
            background: #dd6b20;
        }}
        
        .severity.medium {{
            background: #38a169;
        }}
        
        .severity.low {{
            background: #3182ce;
        }}
        
        .vuln-details {{
            margin-bottom: 15px;
        }}
        
        .vuln-details p {{
            margin-bottom: 10px;
        }}
        
        .vuln-details strong {{
            color: #2d3748;
        }}
        
        .code-block {{
            background: #2d3748;
            color: #e2e8f0;
            padding: 15px;
            border-radius: 5px;
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
            overflow-x: auto;
            margin: 10px 0;
        }}
        
        .subdomain-list, .directory-list, .parameter-list {{
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
            gap: 10px;
        }}
        
        .list-item {{
            background: #f8f9fa;
            padding: 15px;
            border-radius: 5px;
            border-left: 4px solid #667eea;
        }}
        
        .waf-info {{
            background: #f0f4f8;
            padding: 20px;
            border-radius: 8px;
            border-left: 4px solid #4299e1;
        }}
        
        .waf-detected {{
            background: #fff5f5;
            border-left-color: #f56565;
        }}
        
        .footer {{
            text-align: center;
            padding: 30px;
            color: #666;
            border-top: 1px solid #e2e8f0;
            margin-top: 30px;
        }}
        
        .timestamp {{
            color: #a0aec0;
            font-size: 0.9em;
        }}
        
        @media (max-width: 768px) {{
            .container {{
                padding: 10px;
            }}
            
            .header h1 {{
                font-size: 2em;
            }}
            
            .stats {{
                grid-template-columns: 1fr;
            }}
            
            .vuln-header {{
                flex-direction: column;
                align-items: flex-start;
            }}
            
            .severity {{
                margin-top: 10px;
            }}
        }}
    </style>
</head>
<body>
    <div class=""container"">
        <div class=""header"">
            <h1>🛡️ Bug Bounty Security Report</h1>
            <p>Target: {targetDomain}</p>
            <p class=""timestamp"">Generated on {DateTime.Now:yyyy-MM-dd HH:mm:ss}</p>
        </div>
        
        <div class=""summary"">
            <h2>📊 Executive Summary</h2>
            <div class=""stats"">
                <div class=""stat-card"">
                    <div class=""stat-number"">{totalVulnerabilities}</div>
                    <div class=""stat-label"">Total Vulnerabilities</div>
                </div>
                <div class=""stat-card"">
                    <div class=""stat-number"">{criticalCount}</div>
                    <div class=""stat-label"">Critical</div>
                </div>
                <div class=""stat-card"">
                    <div class=""stat-number"">{highCount}</div>
                    <div class=""stat-label"">High</div>
                </div>
                <div class=""stat-card"">
                    <div class=""stat-number"">{mediumCount}</div>
                    <div class=""stat-label"">Medium</div>
                </div>
                <div class=""stat-card"">
                    <div class=""stat-number"">{subdomainsCount}</div>
                    <div class=""stat-label"">Subdomains Found</div>
                </div>
                <div class=""stat-card"">
                    <div class=""stat-number"">{directoriesCount}</div>
                    <div class=""stat-label"">Directories Found</div>
                </div>
            </div>
        </div>";

            // Add vulnerabilities section
            if (vulnResults.Any())
            {
                html += @"
        <div class=""section"">
            <h2>🚨 Vulnerabilities Found</h2>";
                
                foreach (var vuln in vulnResults)
                {
                    html += $@"
            <div class=""vulnerability {vuln.Severity.ToLower()}"">
                <div class=""vuln-header"">
                    <div class=""vuln-type"">{vuln.Type} - {vuln.Subtype}</div>
                    <div class=""severity {vuln.Severity.ToLower()}"">{vuln.Severity}</div>
                </div>
                <div class=""vuln-details"">
                    <p><strong>Description:</strong> {vuln.Description}</p>
                    <p><strong>URL:</strong> {vuln.Url}</p>
                    <p><strong>Parameter:</strong> {vuln.Parameter}</p>
                    <p><strong>Evidence:</strong> {vuln.Evidence}</p>
                    <div class=""code-block"">
                        <strong>Payload:</strong><br>
                        {vuln.Payload}
                    </div>
                </div>
            </div>";
                }
                
                html += @"
        </div>";
            }

            // Add subdomains section
            if (reconResults.Subdomains.Any())
            {
                html += @"
        <div class=""section"">
            <h2>🌐 Subdomains Discovered</h2>
            <div class=""subdomain-list"">";
                
                foreach (var subdomain in reconResults.Subdomains)
                {
                    html += $@"
                <div class=""list-item"">
                    <strong>{subdomain}</strong>
                </div>";
                }
                
                html += @"
            </div>
        </div>";
            }

            // Add valid subdomains section
            if (reconResults.ValidSubdomains.Any())
            {
                html += @"
        <div class=""section"">
            <h2>✅ Valid Subdomains</h2>
            <div class=""subdomain-list"">";
                
                foreach (var subdomain in reconResults.ValidSubdomains)
                {
                    html += $@"
                <div class=""list-item"">
                    <strong>{subdomain.Subdomain}</strong><br>
                    <small>Protocol: {subdomain.Protocol} | Status: {subdomain.StatusCode} | Server: {subdomain.Server}</small>
                </div>";
                }
                
                html += @"
            </div>
        </div>";
            }

            // Add directories section
            if (reconResults.Directories.Any())
            {
                html += @"
        <div class=""section"">
            <h2>📁 Directories & Files Found</h2>
            <div class=""directory-list"">";
                
                foreach (var directory in reconResults.Directories)
                {
                    html += $@"
                <div class=""list-item"">
                    <strong>{directory.Path}</strong><br>
                    <small>Status: {directory.StatusCode} | Size: {directory.ContentLength} bytes</small>
                </div>";
                }
                
                html += @"
            </div>
        </div>";
            }

            // Add parameters section
            if (reconResults.Parameters.Any())
            {
                html += @"
        <div class=""section"">
            <h2>🔍 Parameters Discovered</h2>
            <div class=""parameter-list"">";
                
                foreach (var param in reconResults.Parameters)
                {
                    html += $@"
                <div class=""list-item"">
                    <strong>{param}</strong>
                </div>";
                }
                
                html += @"
            </div>
        </div>";
            }

            // Add WAF info section
            if (reconResults.WafInfo != null)
            {
                html += $@"
        <div class=""section"">
            <h2>🛡️ WAF Detection Results</h2>
            <div class=""waf-info {(reconResults.WafInfo.Detected ? "waf-detected" : "")}"">
                <p><strong>WAF Detected:</strong> {(reconResults.WafInfo.Detected ? "Yes" : "No")}</p>";
                
                if (reconResults.WafInfo.Detected)
                {
                    html += $@"
                <p><strong>WAF Type:</strong> {reconResults.WafInfo.Type}</p>
                <p><strong>Confidence:</strong> {reconResults.WafInfo.Confidence}%</p>";
                    
                    if (reconResults.WafInfo.Indicators.Any())
                    {
                        html += @"
                <p><strong>Indicators:</strong></p>
                <ul>";
                        
                        foreach (var indicator in reconResults.WafInfo.Indicators)
                        {
                            html += $@"
                    <li>{indicator}</li>";
                        }
                        
                        html += @"
                </ul>";
                    }
                }
                
                html += @"
            </div>
        </div>";
            }

            html += $@"
        <div class=""footer"">
            <p>Report generated by Advanced Bug Bounty Tool</p>
            <p class=""timestamp"">Generated on {DateTime.Now:yyyy-MM-dd HH:mm:ss}</p>
        </div>
    </div>
</body>
</html>";

            return html;
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
                _ => Color.White
            };
            
            Console.WriteLine($"[{timestamp}] [{level}] {message}", color);
        }
    }
}