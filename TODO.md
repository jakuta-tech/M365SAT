# Project TO-DO List

## Version 3.0 Release

### Fixes (v3.0)
- **Object Sorting Bug**: Resolved a bug where object sorting was incorrect, leading to inaccurate reports. [Issue #47](https://github.com/asterictnl-lvdw/M365SAT/issues/47) **Status: FIXED**
- **Azure Audit Optimization**: Enhanced multiple Azure audit scripts for improved auditing efficiency. **Status: FIXED**
- **Inspector List Update**: Added v3.0.0 inspectors to the available list. **Status: FIXED**
- **Inspector Rewrite**: Rewritten all v2.x.x inspectors based on v3.x.x models for greater accuracy. **Status: FIXED**
- **Conditional Access Enhancements**: Improved the accuracy of Conditional Access auditing. **Status: FIXED**

### Implemented Features
- **CIS Microsoft 365 Benchmark**: Implemented version 4.0.0 of the CIS Microsoft 365 Benchmark. **Status: DONE**
- **CIS Azure Benchmark**: Implemented version 3.1.0 of the CIS Azure Benchmark. **Status: DONE**
- [Issue #39](https://github.com/asterictnl-lvdw/M365SAT/issues/39) **Status: DONE**
- **PnP PowerShell Integration**: Transitioned to using PnP.Powershell alongside the Microsoft SharePoint module for enhanced compatibility. **Status: DONE**
- **Cross-Platform Compatibility**: Achieved compatibility with MacOS and Linux. **Status: TESTING**
- **Government Environments**: Uncertain compatibility with government-issued environments; further testing required. **Status: TESTING**

### Ongoing Fixes
- **Report Status Enhancement**: Introduce a 3-status reporting mechanism (OK, FAIL, UNKNOWN) to include successfully passed checks in the report. **Status: IN-PROGRESS**
- **Finding-Objects Expansion**: Add new objects to enhance reporting, including Paragraph and Status attributes. **Status: IN-PROGRESS**
- **AzAccount MultiAPI Replacement**: Replacing AzAccount MultiAPI Connector with a no-dependency connector; requires a one-time authentication for token generation. **Status: TESTING**
- [Issue #37](https://github.com/asterictnl-lvdw/M365SAT/issues/37) **Status: IN-PROGRESS**
- **CSV Output Improvement**: Enhance CSV output functionality for better data handling. **Status: M365 Converted, Azure IN-PROGRESS**
- **XML/JSON Output Support**: Add support for XML and JSON as additional output formats. **Status: IN-PROGRESS**
- **Service Principal Integration**: Explore using a service principal instead of a global admin account for operations, ensuring proper permissions. **Status: IN-PROGRESS**
- **CISA Benchmark Implementation**: Integrate CISA Benchmark and create mappings with the CIS Benchmark. **Status: IN-PROGRESS**

### Investigation & Future Tasks
- **Docker-Container Creation**: Develop a Docker container version of M365SAT for containerized environments. **Status: DELAYED**
- **Multi-Threaded Compatibility**: Explore wider compatibility for Multi-Threaded Mode execution. **Status: UNDER INVESTIGATION**
- **Exchange Cmdlets Multi-Threading Issues**: Address multithreading compatibility issues when running Exchange Cmdlets. Workarounds from [Microsoft](https://learn.microsoft.com/en-us/powershell/exchange/invoke-command-workarounds-rest-api?view=exchange-ps) are under review. If unresolved, cmdlets will execute in single-threaded mode to ensure stability.
- **Inspector Multi-Threading Issues**: Ongoing investigation into multithreading challenges with inspector execution. No current fix or timeline available. 