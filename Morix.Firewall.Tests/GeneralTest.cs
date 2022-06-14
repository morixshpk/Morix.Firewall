namespace Morix.Firewall.Tests
{
    [TestClass]
    public class GeneralTest
    {
        [TestMethod]
        public void TestMethod1()
        {
            var rule = new Morix.Firewall.Rule("AAAAA"); // firewall rule name

            // add ports to the rules
            rule.AddLocalPorts("1433, 8585, 8686, ad2564");

            Assert.IsTrue(rule.LocalPorts == "1433,8585,8686", "Problem with local ports");

            // add remote addressses (only IPV4)
            rule.AddRemoteAddresses("192.168.1.140,localhost");
            rule.RemoveRemoteAddresses("192.168.1.140");
            rule.AddRemoteAddresses("192.168.1.141");

            Assert.IsTrue(rule.RemoteAddresses == "192.168.1.141", "Problem remote address");

            // write to firewall
            Assert.IsTrue(rule.WriteToFirewall(), "Problem writing");
        }
    }
}