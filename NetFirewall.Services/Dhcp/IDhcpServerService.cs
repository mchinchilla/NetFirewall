using NetFirewall.Models.Dhcp;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace NetFirewall.Services.Dhcp;

public interface IDhcpServerService
{
    Task<byte[]> CreateDhcpResponse( DhcpRequest request );
}