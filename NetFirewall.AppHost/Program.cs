var builder = DistributedApplication.CreateBuilder(args);

var apiService = builder.AddProject<Projects.NetFirewall_ApiService>("apiservice");

builder.AddProject<Projects.NetFirewall_Web>("webfrontend")
    .WithExternalHttpEndpoints()
    .WithReference(apiService)
    .WaitFor(apiService);

builder.AddProject<Projects.NetFirewall_DhcpServer>("netfirewall-dhcpserver");

builder.Build().Run();
