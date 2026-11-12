using System.Reflection;
using System.Runtime.Versioning;
[assembly: AssemblyTitle("Standalone LAPS Agent")]
[assembly: AssemblyProduct("PriCoSoft SLAPS")]
// Version comes from web\IisVault\App_Code\AppVersion.cs (linked by Build-FrameworkAgent.ps1).
[assembly: AssemblyVersion(StandaloneLapsWeb.AppVersion.Assembly)]
[assembly: AssemblyFileVersion(StandaloneLapsWeb.AppVersion.Assembly)]
[assembly: AssemblyInformationalVersion(StandaloneLapsWeb.AppVersion.Number)]
[assembly: TargetFramework(".NETFramework,Version=v4.7.2", FrameworkDisplayName = ".NET Framework 4.7.2")]
