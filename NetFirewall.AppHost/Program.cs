var builder = DistributedApplication.CreateBuilder(args);


var apiService = builder.AddProject<Projects.NetFirewall_ApiService>("apiservice");

builder.AddProject<Projects.NetFirewall_Web>("netfirewall-web");

builder.AddProject<Projects.NetFirewall_DhcpServer>("netfirewall-dhcpserver");

builder.Build().Run();
