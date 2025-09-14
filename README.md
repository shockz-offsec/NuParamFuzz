<h1 align="center"> 
  NuParamFuzz = Nuclei + Paramspider + Waybackurls + Gauplus + Hakrawler + Katana + Fuzzing Templates + Enhanced Param Fuzzing
  <br>
</h1>

## Overview
`NuParamFuzz` is the **next-generation evolution of NucleiFuzzer**, built to provide a more **efficient, precise, and exhaustive web vulnerability scanning workflow**. It integrates `ParamSpider`, `Waybackurls`, `Katana`, `Gauplus`, and `Hakrawler` to collect URLs and parameters, while performing **intelligent filtering, deduplication, and validation** using `uro` and `paramx`. Leveraging `Nuclei` with advanced `fuzzing-templates`, it identifies vulnerabilities with **greater depth**, particularly in parameter fuzzing.

Designed for **security researchers, bug bounty hunters, and web developers**, `NuParamFuzz` introduces **per-target output organization, HTTPS prioritization, subdomain filtering, timeout-controlled URL collection**, and the `-all` flag for exhaustive parameter fuzzing. These features ensure faster scans, higher accuracy, and actionable results compared to the original NucleiFuzzer.

---

## Key Improvements Over NucleiFuzzer

1. **Exhaustive Parameter Fuzzing with Flexibility**: By default, NuParamFuzz uses `paramx` to filter and fuzz only **vulnerable-like parameters**, reducing noise and providing a more focused input to Nuclei. When the `-all` flag is enabled, it performs **full parameter fuzzing**, testing **all discovered parameters**, including hidden or less obvious ones, for maximum coverage.
2. **Cohesive URL Collection Pipeline**: Combines `ParamSpider`, `Waybackurls`, `Katana`, `Gauplus`, and `Hakrawler` with timeout-controlled execution to reduce hangs and redundant scans.  
3. **Enhanced Validation & Deduplication**: URLs are filtered and deduplicated using both `uro` and `paramx`, ensuring only actionable endpoints reach Nuclei.  
4. **HTTPS Prioritization & Subdomain Filtering**: Automatically prefers secure URLs and retains only those matching the target domain or subdomains.  
5. **Timeout-Controlled Discovery**: Each collection tool has configurable timeouts to improve efficiency and prevent delays on slow targets.  
6. **Improved Logging & Progress Feedback**: Real-time, color-coded logs display errors, warnings, and scan progress for better observability.  
7. **Per-Target Output Organization**: Results are stored in dedicated folders per domain, keeping raw, validated, filtered, and Nuclei output neatly separated.  

> With **smarter URL processing, deeper parameter fuzzing, and enhanced scan management**, NuParamFuzz represents a **significant upgrade** over NucleiFuzzer.

### Summary

| Feature | NucleiFuzzer | NuParamFuzz |
|---------|-------------|-------------|
| Parameter fuzzing depth | Standard | Default: only vulnerable-like parameters using `paramx`; `-all` flag enables exhaustive fuzzing of all parameters |
| URL deduplication | `uro` only | `uro` + `paramx` filtering |
| HTTPS prioritization | No | Yes, automatically prefers HTTPS when available |
| Subdomain filtering | Minimal | Full host/subdomain filtering |
| Timeout control | Limited | Configurable per discovery tool, avoids hangs on slow targets |
| Logging | Basic | Verbose, color-coded, real-time progress tracking |
| Output structure | Flat | Per-target folders with organized raw, validated, filtered, and results files |
| Minor fixes |  | Various small improvements and bug fixes for smoother execution |
---

## Tools included:
- [Nuclei](https://github.com/projectdiscovery/nuclei)  
- [ParamSpider](https://github.com/0xKayala/ParamSpider)  
- [Waybackurls](https://github.com/tomnomnom/waybackurls)  
- [Gauplus](https://github.com/bp0lr/gauplus)  
- [Hakrawler](https://github.com/hakluke/hakrawler)  
- [Katana](https://github.com/projectdiscovery/katana)  
- [httpx](https://github.com/projectdiscovery/httpx)  
- [uro](https://github.com/s0md3v/uro)
- [paramx](https://github.com/cyinnove/paramx)

### Templates:
[Fuzzing Templates](https://github.com/projectdiscovery/nuclei-templates)

---

## Screenshot
<img width="1067" height="559" alt="NuParamFuzz Screenshot" src="" />

## Output
<img width="1733" height="901" alt="NuParamFuzz Output" src="" />

---

## Usage

```sh
npf -h

        _   _       _____                          ______
       | \ | |     |  __ \                        |  ____|
       |  \| |_   _| |__) |_ _ _ __ __ _ _ __ ___ | |__ _   _ ________
       | . ` | | | |  ___/ _` | '__/ _` | '_ ` _ \|  __| | | |_  /_  /
       | |\  | |_| | |  | (_| | | | (_| | | | | | | |  | |_| |/ / / /
       |_| \_|\__,_|_|   \__,_|_|  \__,_|_| |_| |_|_|   \__,_/___/___|
                                                               v1.0

                                     Made by Shockz-Offsec
                                            Inspired from NucleiFuzzer by Prakash (0xKayala)

NuParamFuzz: Advanced URL & Parameter Fuzzing Tool

Usage: /usr/bin/npf [options]
Options:
  -h, --help              Display this help menu
  -d, --domain <domain>   Scan a single domain
  -f, --file <filename>   Scan multiple domains/URLs from a file
  -o, --output <folder>   Output folder (default: ./output)
  -t, --templates <path>  Custom Nuclei templates directory
  -v, --verbose           Enable verbose output (logs to terminal)
  -k, --keep-temp         Keep temporary files after execution
  -r, --rate <limit>      Set rate limit for Nuclei (default: 50)
```

## Installation:

```bash
git clone https://github.com/shockz-offsec/NuParamFuzz.git && cd NuParamFuzz && sudo chmod +x install.sh && ./install.sh && (command -v npf &> /dev/null && npf -h || echo "Installation failed: Command 'npf' not found.") && cd ..
```

## Examples:
Scan a single domain:
```bash
npf -d example.com
```
Scan multiple domains from a file:
```bash
npf -f subdomains.txt
```
Perform exhaustive parameter fuzzing (By default: Extract just vulnerable-like params):
```bash
npf -d site.example.com -all
```

## Contributing

- We welcome contributions! To contribute to NuParamFuzz:
- Fork the repository.
- Create a new branch.
- Make changes and commit.
- Submit a pull request.