# TO-DO List

### TO-DO (v3.0)
- Object-Sorting Fix, due to a bug where the sorting was not correctly done resulting into a messed up report [#47](https://github.com/asterictnl-lvdw/M365SAT/issues/47) **FIXED**
- I have optimized multiple Azure related audit scripts to ensure you can optimally audit environments. **FIXED**
- I have added the v3.0.0 inspectors to the list of availability. **FIXED**
- Removal of all v2.x.x Inspectors to rewrite them all based on the v3.x.x inspectors which are more accurate. **FIXED**
- Multiple Conditional Access Enhancements where possible to improve accuracy with auditing **FIXED**
- Implemented CIS v4.0.0 Microsoft 365 Benchmark **DONE**
- Implemented CIS v3.1.0 Azure Benchmark **DONE**
- Fully cross-platform compatibility (including MacOSX and Linux) **TESTING**
- [#37](https://github.com/asterictnl-lvdw/M365SAT/issues/37) **IN-PROGRESS**
- [#39](https://github.com/asterictnl-lvdw/M365SAT/issues/39) **DONE**
- Creating a Docker-Container of M365SAT to run a containerized environment. **DELAYED**
- Improve the CSV output support **IN-PROGRESS**
- Add XML and JSON support as output possibility **IN-PROGRESS**
- There is no detection for government issued environments and I do not know if the script does work for it. **TESTING**
- Looking into the implementation with a service principal instead of a global admin account with respective permissions. **IN-PROGRESS**
- Implementing the CISA Benchmark and creating a mapping with the CIS benchmark. **IN-PROGRESS**
- We are going to start using PnP.Powershell alongside the Microsoft Sharepoint module to PnP PowerShell, due to wider compatibility and better support. **DONE**
- Add additional objects within the finding-objects to enhance reporting mechanism. (Paragraph, Status) **IN-PROGRESS**
- Add the OK status so you will get a report including the things that are OK as well. (3-status-mechanism: OK,FAIL,UNKNOWN). **IN-PROGRESS**
- Replaced the AzAccount MultiAPI Connector with a no dependency connector, the only thing is that you need to authenticate once to gather the token to authenticate to the endpoints. **IN-PROGRESS**

### Unknown

- We are going to widen the compatibility of MultiThreaded-Mode.
- There are issues with MultiThreading when running Exchange Cmdlets. Source: https://learn.microsoft.com/en-us/powershell/exchange/invoke-command-workarounds-rest-api?view=exchange-ps we are looking into implementing the workaround to make this work so multithreading will be no issue with these cmdlets. Eventually these cmdlets will be executed in singlethreaded mode afterwards to make sure they succeed all.
- There are multiple issues with multithreading mode when executing the inspectors. This is being investigated, but there is no fix available at this moment. When this will be fixed is unknown.