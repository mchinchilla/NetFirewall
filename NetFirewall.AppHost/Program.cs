var builder = DistributedApplication.CreateBuilder(args);

// Aspire 17 project resources are path-based (AddDotnetProject); paths are
// relative to this AppHost directory.
builder.AddDotnetProject("apiservice", "../NetFirewall.ApiService/NetFirewall.ApiService.csproj");

builder.AddDotnetProject("netfirewall-web", "../NetFirewall.Web/NetFirewall.Web.csproj");

builder.AddDotnetProject("netfirewall-dhcpserver", "../NetFirewall.DhcpServer/NetFirewall.DhcpServer.csproj");

builder.Build().Run();
