using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Net;
using System.Net.NetworkInformation;
using HtmlAgilityPack;
using BugBountyTool.Models;
using Colorful.Console;
using DnsClient;

namespace BugBountyTool.Services
{
    /// <summary>
    /// Service for performing comprehensive reconnaissance
    /// </summary>
    public class ReconnaissanceService
    {
        private readonly HttpClient _httpClient;
        private readonly LookupClient _dnsClient;
        private readonly string _targetDomain;
        private readonly string _outputDir;

        public ReconnaissanceService(string targetDomain, string outputDir)
        {
            _targetDomain = targetDomain;
            _outputDir = outputDir;
            _httpClient = new HttpClient();
            _dnsClient = new LookupClient();
            
            // Set up HTTP client headers
            _httpClient.DefaultRequestHeaders.Add("User-Agent", 
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36");
        }

        /// <summary>
        /// Print reconnaissance banner
        /// </summary>
        public void PrintBanner()
        {
            var banner = $@"
╔══════════════════════════════════════════════════════════════╗
║                    ADVANCED RECONNAISSANCE TOOL                    ║
║                        Bug Bounty Edition                          ║
╚══════════════════════════════════════════════════════════════╝

Target: {_targetDomain}
Output Directory: {_outputDir}
Timestamp: {DateTime.Now:yyyy-MM-dd HH:mm:ss}
";
            Console.WriteLine(banner, Color.Cyan);
        }

        /// <summary>
        /// Log messages with timestamps and colors
        /// </summary>
        public void Log(string message, string level = "INFO")
        {
            var timestamp = DateTime.Now.ToString("HH:mm:ss");
            var color = level switch
            {
                "INFO" => Color.Blue,
                "SUCCESS" => Color.Green,
                "WARNING" => Color.Yellow,
                "ERROR" => Color.Red,
                "CRITICAL" => Color.Magenta,
                _ => Color.White
            };
            
            Console.WriteLine($"[{timestamp}] [{level}] {message}", color);
        }

        /// <summary>
        /// Run complete reconnaissance process
        /// </summary>
        public async Task<ReconnaissanceResult> RunCompleteReconnaissanceAsync()
        {
            Log("Starting complete reconnaissance process...", "CRITICAL");
            
            var result = new ReconnaissanceResult();
            
            try
            {
                // Phase 1: Passive subdomain discovery
                result.Subdomains = await PassiveSubdomainDiscoveryAsync();
                
                // Phase 2: Active subdomain validation
                result.ValidSubdomains = await ActiveSubdomainDiscoveryAsync(result.Subdomains);
                
                // Phase 3: Directory discovery
                var mainUrl = $"https://{_targetDomain}";
                result.Directories = await DirectoryDiscoveryAsync(mainUrl);
                
                // Phase 4: Parameter discovery
                result.Parameters = await ParameterDiscoveryAsync(mainUrl);
                
                // Phase 5: WAF detection
                result.WafInfo = await WafDetectionAsync(mainUrl);
                
                Log("Reconnaissance completed successfully!", "SUCCESS");
                return result;
            }
            catch (Exception ex)
            {
                Log($"Error during reconnaissance: {ex.Message}", "ERROR");
                return result;
            }
        }

        /// <summary>
        /// Perform passive subdomain discovery
        /// </summary>
        private async Task<List<string>> PassiveSubdomainDiscoveryAsync()
        {
            Log("Starting passive subdomain discovery...", "INFO");
            
            var subdomains = new HashSet<string>();
            
            // Common subdomain wordlist
            var commonSubdomains = new[]
            {
                "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "webdisk", "ns2",
                "cpanel", "whm", "autodiscover", "autoconfig", "m", "imap", "test", "ns", "blog",
                "pop3", "dev", "www2", "admin", "forum", "news", "vpn", "ns3", "mail2", "new",
                "mysql", "old", "www1", "beta", "shop", "api", "secure", "demo", "www3", "dns2",
                "mail3", "search", "staging", "server", "mx", "chat", "wap", "my", "svn", "mail1",
                "sites", "proxy", "ads", "host", "crm", "cms", "backup", "mx1", "static", "docs",
                "beta", "staging", "app", "dev2", "admin2", "mx2", "cdn", "api2", "secure2",
                "test2", "mail4", "static2", "beta2", "staging2", "app2", "dev3", "admin3"
            };
            
            // DNS brute force for common subdomains
            Log("Performing DNS brute force for common subdomains...", "INFO");
            foreach (var subdomain in commonSubdomains)
            {
                try
                {
                    var fullDomain = $"{subdomain}.{_targetDomain}";
                    var result = await _dnsClient.QueryAsync(fullDomain, QueryType.A);
                    
                    if (result.Answers.Any())
                    {
                        subdomains.Add(fullDomain);
                        Log($"Found subdomain: {fullDomain}", "SUCCESS");
                    }
                }
                catch
                {
                    // Subdomain doesn't exist, continue
                }
            }
            
            // Certificate Transparency logs
            Log("Checking Certificate Transparency logs...", "INFO");
            try
            {
                var ctSubdomains = await CheckCertificateTransparencyAsync();
                foreach (var subdomain in ctSubdomains)
                {
                    subdomains.Add(subdomain);
                }
            }
            catch (Exception ex)
            {
                Log($"Error checking CT logs: {ex.Message}", "WARNING");
            }
            
            Log($"Passive discovery found {subdomains.Count} subdomains", "SUCCESS");
            return subdomains.ToList();
        }

        /// <summary>
        /// Check Certificate Transparency logs for subdomains
        /// </summary>
        private async Task<List<string>> CheckCertificateTransparencyAsync()
        {
            var subdomains = new HashSet<string>();
            
            try
            {
                // Using crt.sh API
                var url = $"https://crt.sh/?q=%.{_targetDomain}&output=json&fl=original&collapse=urlkey";
                var response = await _httpClient.GetStringAsync(url);
                
                // Parse JSON response (simplified)
                var lines = response.Split('\n');
                foreach (var line in lines)
                {
                    if (line.Contains(_targetDomain) && !line.Contains('*'))
                    {
                        // Extract domain from JSON line
                        var match = Regex.Match(line, @"""([^""]*\.{_targetDomain})""");
                        if (match.Success)
                        {
                            subdomains.Add(match.Groups[1].Value);
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Log($"Error checking CT logs: {ex.Message}", "WARNING");
            }
            
            return subdomains.ToList();
        }

        /// <summary>
        /// Perform active subdomain discovery and validation
        /// </summary>
        private async Task<List<ValidSubdomain>> ActiveSubdomainDiscoveryAsync(List<string> subdomains)
        {
            Log("Starting active subdomain validation...", "INFO");
            
            var validSubdomains = new List<ValidSubdomain>();
            
            var tasks = subdomains.Select(async subdomain =>
            {
                try
                {
                    // Check if subdomain is accessible via HTTP/HTTPS
                    foreach (var protocol in new[] { "http", "https" })
                    {
                        try
                        {
                            var url = $"{protocol}://{subdomain}";
                            var response = await _httpClient.GetAsync(url);
                            
                            if (response.IsSuccessStatusCode || 
                                response.StatusCode == HttpStatusCode.MovedPermanently ||
                                response.StatusCode == HttpStatusCode.Found ||
                                response.StatusCode == HttpStatusCode.Forbidden ||
                                response.StatusCode == HttpStatusCode.Unauthorized)
                            {
                                var content = await response.Content.ReadAsStringAsync();
                                var title = ExtractTitle(content);
                                var server = response.Headers.Server?.ToString() ?? "Unknown";
                                
                                validSubdomains.Add(new ValidSubdomain
                                {
                                    Subdomain = subdomain,
                                    Protocol = protocol,
                                    StatusCode = (int)response.StatusCode,
                                    Title = title,
                                    Server = server
                                });
                                
                                Log($"Valid subdomain: {subdomain} ({protocol}) - {(int)response.StatusCode}", "SUCCESS");
                                break;
                            }
                        }
                        catch
                        {
                            continue;
                        }
                    }
                }
                catch
                {
                    // Subdomain validation failed
                }
            });
            
            await Task.WhenAll(tasks);
            
            Log($"Active validation found {validSubdomains.Count} valid subdomains", "SUCCESS");
            return validSubdomains;
        }

        /// <summary>
        /// Extract page title from HTML content
        /// </summary>
        private string ExtractTitle(string htmlContent)
        {
            try
            {
                var doc = new HtmlDocument();
                doc.LoadHtml(htmlContent);
                var titleNode = doc.DocumentNode.SelectSingleNode("//title");
                return titleNode?.InnerText?.Trim() ?? "No title";
            }
            catch
            {
                return "Error extracting title";
            }
        }

        /// <summary>
        /// Perform directory and file discovery
        /// </summary>
        private async Task<List<Directory>> DirectoryDiscoveryAsync(string baseUrl)
        {
            Log($"Starting directory discovery on {baseUrl}...", "INFO");
            
            // Common directory and file wordlist
            var wordlist = new[]
            {
                "admin", "administrator", "login", "wp-admin", "phpmyadmin", "admin.php",
                "config", "configuration", "backup", "backups", "old", "test", "testing",
                "dev", "development", "staging", "api", "v1", "v2", "docs", "documentation",
                "files", "uploads", "images", "img", "css", "js", "assets", "static",
                "robots.txt", "sitemap.xml", ".htaccess", ".env", "config.php", "wp-config.php",
                "database", "db", "sql", "mysql", "postgres", "oracle", "mssql",
                "logs", "log", "error", "errors", "debug", "info", "status",
                "cgi-bin", "bin", "tmp", "temp", "cache", "session", "sessions",
                "user", "users", "profile", "profiles", "account", "accounts",
                "search", "find", "query", "results", "index", "home", "main",
                "about", "contact", "help", "support", "faq", "terms", "privacy"
            };
            
            var foundDirectories = new List<Directory>();
            
            var tasks = wordlist.Select(async path =>
            {
                try
                {
                    var url = $"{baseUrl.TrimEnd('/')}/{path}";
                    var response = await _httpClient.GetAsync(url);
                    
                    if (response.IsSuccessStatusCode || 
                        response.StatusCode == HttpStatusCode.MovedPermanently ||
                        response.StatusCode == HttpStatusCode.Found ||
                        response.StatusCode == HttpStatusCode.Forbidden ||
                        response.StatusCode == HttpStatusCode.Unauthorized)
                    {
                        var content = await response.Content.ReadAsStringAsync();
                        var server = response.Headers.Server?.ToString() ?? "Unknown";
                        
                        foundDirectories.Add(new Directory
                        {
                            Path = path,
                            Url = url,
                            StatusCode = (int)response.StatusCode,
                            ContentLength = content.Length,
                            Server = server
                        });
                        
                        Log($"Found: {path} - {(int)response.StatusCode}", "SUCCESS");
                    }
                }
                catch
                {
                    // Directory check failed
                }
            });
            
            await Task.WhenAll(tasks);
            
            Log($"Directory discovery found {foundDirectories.Count} directories/files", "SUCCESS");
            return foundDirectories;
        }

        /// <summary>
        /// Perform parameter discovery
        /// </summary>
        private async Task<List<string>> ParameterDiscoveryAsync(string baseUrl)
        {
            Log($"Starting parameter discovery on {baseUrl}...", "INFO");
            
            var parameters = new HashSet<string>();
            
            // Check Wayback Machine
            Log("Checking Wayback Machine for historical URLs...", "INFO");
            try
            {
                var waybackParams = await CheckWaybackMachineAsync(baseUrl);
                foreach (var param in waybackParams)
                {
                    parameters.Add(param);
                }
            }
            catch (Exception ex)
            {
                Log($"Error checking Wayback Machine: {ex.Message}", "WARNING");
            }
            
            // Common parameter wordlist
            var commonParams = new[]
            {
                "id", "page", "view", "action", "cmd", "command", "exec", "execute",
                "file", "path", "dir", "directory", "url", "link", "href", "src",
                "user", "username", "pass", "password", "email", "mail", "phone",
                "name", "title", "subject", "message", "content", "text", "data",
                "search", "query", "q", "find", "filter", "sort", "order", "limit",
                "offset", "start", "end", "from", "to", "date", "time", "year",
                "month", "day", "category", "type", "format", "mode", "lang",
                "language", "locale", "country", "region", "state", "city",
                "zip", "code", "key", "token", "session", "sid", "uid", "pid",
                "ref", "referer", "return", "redirect", "next", "callback",
                "jsonp", "callback", "format", "output", "response", "result"
            };
            
            // Test common parameters
            Log("Testing common parameters...", "INFO");
            foreach (var param in commonParams)
            {
                try
                {
                    var testUrl = $"{baseUrl}?{param}=test";
                    var response = await _httpClient.GetAsync(testUrl);
                    
                    // Check if parameter affects response
                    var baselineResponse = await _httpClient.GetAsync(baseUrl);
                    var testContent = await response.Content.ReadAsStringAsync();
                    var baselineContent = await baselineResponse.Content.ReadAsStringAsync();
                    
                    if (testContent.Length != baselineContent.Length)
                    {
                        parameters.Add(param);
                        Log($"Found parameter: {param}", "SUCCESS");
                    }
                }
                catch
                {
                    continue;
                }
            }
            
            Log($"Parameter discovery found {parameters.Count} parameters", "SUCCESS");
            return parameters.ToList();
        }

        /// <summary>
        /// Check Wayback Machine for historical URLs and parameters
        /// </summary>
        private async Task<List<string>> CheckWaybackMachineAsync(string baseUrl)
        {
            var parameters = new HashSet<string>();
            
            try
            {
                // Wayback Machine API
                var waybackUrl = $"http://web.archive.org/cdx/search/cdx?url={baseUrl}/*&output=json&fl=original&collapse=urlkey";
                var response = await _httpClient.GetStringAsync(waybackUrl);
                
                // Parse response for parameters
                var lines = response.Split('\n');
                foreach (var line in lines)
                {
                    if (line.Contains("?"))
                    {
                        var queryPart = line.Split('?')[1];
                        if (queryPart.Contains("&"))
                        {
                            var queryParams = queryPart.Split('&');
                            foreach (var param in queryParams)
                            {
                                if (param.Contains("="))
                                {
                                    var paramName = param.Split('=')[0];
                                    parameters.Add(paramName);
                                }
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Log($"Error accessing Wayback Machine: {ex.Message}", "WARNING");
            }
            
            return parameters.ToList();
        }

        /// <summary>
        /// Detect Web Application Firewall (WAF)
        /// </summary>
        private async Task<WafInfo> WafDetectionAsync(string baseUrl)
        {
            Log($"Starting WAF detection on {baseUrl}...", "INFO");
            
            var wafInfo = new WafInfo
            {
                Detected = false,
                Type = "Unknown",
                Confidence = 0,
                Indicators = new List<string>()
            };
            
            // WAF detection payloads
            var wafPayloads = new[]
            {
                // SQL Injection payloads
                "' OR '1'='1",
                "'; DROP TABLE users; --",
                "1' UNION SELECT 1,2,3--",
                
                // XSS payloads
                "<script>alert('XSS')</script>",
                "javascript:alert('XSS')",
                "<img src=x onerror=alert('XSS')>",
                
                // Path traversal
                "../../../etc/passwd",
                "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
                
                // Command injection
                "; ls -la",
                "| whoami",
                "&& id"
            };
            
            foreach (var payload in wafPayloads)
            {
                try
                {
                    // Test with different parameter names
                    var testUrls = new[]
                    {
                        $"{baseUrl}?id={payload}",
                        $"{baseUrl}?search={payload}",
                        $"{baseUrl}?q={payload}",
                        $"{baseUrl}?file={payload}"
                    };
                    
                    foreach (var testUrl in testUrls)
                    {
                        var response = await _httpClient.GetAsync(testUrl);
                        var content = await response.Content.ReadAsStringAsync();
                        
                        // Check for WAF indicators in response
                        var wafIndicators = CheckWafIndicators(content, response.StatusCode);
                        if (wafIndicators.Any())
                        {
                            wafInfo.Detected = true;
                            wafInfo.Indicators.AddRange(wafIndicators);
                            wafInfo.Confidence += 10;
                        }
                    }
                }
                catch
                {
                    continue;
                }
            }
            
            // Check response headers for WAF signatures
            try
            {
                var response = await _httpClient.GetAsync(baseUrl);
                var headerIndicators = CheckWafHeaders(response.Headers);
                if (headerIndicators.Any())
                {
                    wafInfo.Detected = true;
                    wafInfo.Indicators.AddRange(headerIndicators);
                    wafInfo.Confidence += 20;
                }
            }
            catch
            {
                // Header check failed
            }
            
            // Determine WAF type based on indicators
            if (wafInfo.Detected)
            {
                wafInfo.Type = DetermineWafType(wafInfo.Indicators);
            }
            
            Log($"WAF detection completed - Detected: {wafInfo.Detected}, Type: {wafInfo.Type}", "SUCCESS");
            return wafInfo;
        }

        /// <summary>
        /// Check response for WAF indicators
        /// </summary>
        private List<string> CheckWafIndicators(string content, HttpStatusCode statusCode)
        {
            var indicators = new List<string>();
            
            // Common WAF response patterns
            var wafPatterns = new[]
            {
                @"blocked by.*firewall",
                @"access denied",
                @"forbidden",
                @"security.*violation",
                @"request.*blocked",
                @"cloudflare",
                @"incapsula",
                @"akamai",
                @"barracuda",
                @"f5",
                @"fortinet",
                @"checkpoint",
                @"palo alto",
                @"juniper",
                @"cisco",
                @"aws.*waf",
                @"azure.*waf"
            };
            
            foreach (var pattern in wafPatterns)
            {
                if (Regex.IsMatch(content, pattern, RegexOptions.IgnoreCase))
                {
                    indicators.Add($"Content pattern: {pattern}");
                }
            }
            
            // Check status codes
            if (statusCode == HttpStatusCode.Forbidden || 
                statusCode == HttpStatusCode.NotAcceptable ||
                statusCode == (HttpStatusCode)418 ||
                statusCode == (HttpStatusCode)429 ||
                statusCode == HttpStatusCode.ServiceUnavailable)
            {
                indicators.Add($"Suspicious status code: {(int)statusCode}");
            }
            
            return indicators;
        }

        /// <summary>
        /// Check response headers for WAF signatures
        /// </summary>
        private List<string> CheckWafHeaders(HttpResponseHeaders headers)
        {
            var indicators = new List<string>();
            
            var wafHeaders = new Dictionary<string, string>
            {
                { "cf-ray", "Cloudflare" },
                { "x-sucuri-id", "Sucuri" },
                { "x-sucuri-cache", "Sucuri" },
                { "x-akamai-transformed", "Akamai" },
                { "x-cache", "Akamai" },
                { "x-imforwards", "Incapsula" },
                { "x-iinfo", "Incapsula" },
                { "x-protected-by", "Various WAFs" },
                { "x-security", "Various WAFs" }
            };
            
            foreach (var header in wafHeaders)
            {
                if (headers.Contains(header.Key))
                {
                    indicators.Add($"Header {header.Key}: {header.Value}");
                }
            }
            
            return indicators;
        }

        /// <summary>
        /// Determine WAF type based on indicators
        /// </summary>
        private string DetermineWafType(List<string> indicators)
        {
            var wafTypes = new Dictionary<string, int>
            {
                { "cloudflare", 0 },
                { "incapsula", 0 },
                { "akamai", 0 },
                { "sucuri", 0 },
                { "barracuda", 0 },
                { "f5", 0 },
                { "aws", 0 },
                { "azure", 0 }
            };
            
            foreach (var indicator in indicators)
            {
                var indicatorLower = indicator.ToLower();
                foreach (var wafType in wafTypes.Keys.ToList())
                {
                    if (indicatorLower.Contains(wafType))
                    {
                        wafTypes[wafType]++;
                    }
                }
            }
            
            // Return WAF type with highest score
            if (wafTypes.Values.Max() > 0)
            {
                return wafTypes.OrderByDescending(x => x.Value).First().Key;
            }
            else
            {
                return "Unknown";
            }
        }

        /// <summary>
        /// Dispose resources
        /// </summary>
        public void Dispose()
        {
            _httpClient?.Dispose();
        }
    }
}