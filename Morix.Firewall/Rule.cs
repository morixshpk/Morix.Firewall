using System;
using System.Collections.Generic;
using System.Net;
using System.Security.Principal;
using Vanara.PInvoke;

namespace Morix.Firewall
{
    public class Rule
    {
        private readonly HashSet<string> _localPorts = new HashSet<string>();
        private readonly HashSet<string> _remoteAddressses = new HashSet<string>();

        public string Name { get; set; }
        public string LocalPorts { get; private set; }
        public string RemoteAddresses { get; private set; }


        public Rule()
        { 
        
        }


        public Rule(string name)
        {
            this.Name = name.Trim();
        }

        public void AddLocalPorts(string ports)
        {
            try
            {
                var str = ports.Split(',');

                foreach (var s in str)
                {
                    if (int.TryParse(s, out int port))
                    {
                        if (port > 0)
                            _localPorts.Add(port.ToString());
                    }
                }

                LocalPorts = String.Join(",", _localPorts);
            }
            catch
            {

            }
        }

        public void AddRemoteAddresses(string addresses)
        {
            try
            {
                var str = addresses.Split(',');

                foreach (var s in str)
                {
                    if (IPAddress.TryParse(s, out IPAddress ipAddress))
                    {
                        if (ipAddress.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                            _remoteAddressses.Add(ipAddress.ToString());
                    }
                }

                RemoteAddresses = String.Join(",", _remoteAddressses);
            }
            catch
            {

            }
        }

        public void RemoveRemoteAddresses(string address)
        {
            try
            {
                address = address.Trim();
                _remoteAddressses.Remove(address);
                RemoteAddresses = String.Join(",", _remoteAddressses);
            }
            catch
            {

            }
        }

        public bool WriteToFirewall()
        {
            var identity = WindowsIdentity.GetCurrent();
            var principal = new WindowsPrincipal(identity);
            if (!principal.IsInRole(WindowsBuiltInRole.Administrator))
            {
                throw new ApplicationException("Run as Administator this method!");
            }
            try
            {
                var rule = (FirewallApi.INetFwRule)Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FWRule"));
                rule.Action = FirewallApi.NET_FW_ACTION.NET_FW_ACTION_ALLOW;
                rule.Description = "Access betting platform for all products";
                rule.Direction = FirewallApi.NET_FW_RULE_DIRECTION.NET_FW_RULE_DIR_IN;
                rule.Enabled = true;
                rule.InterfaceTypes = "All";
                rule.Protocol = (int)FirewallApi.NET_FW_IP_PROTOCOL.NET_FW_IP_PROTOCOL_TCP;
                rule.LocalPorts = this.LocalPorts;
                rule.RemoteAddresses = this.RemoteAddresses;
                rule.Name = this.Name;

                var firewallPolicy = (FirewallApi.INetFwPolicy2)Activator.CreateInstance(
                    Type.GetTypeFromProgID("HNetCfg.FwPolicy2"));
                firewallPolicy.Rules.Remove(rule.Name);
                firewallPolicy.Rules.Add(rule);

                return true;
            }
            catch (Exception ex)
            { 
            
            }

            return false;
        }
    }
}
