#include "ns3/applications-module.h"
#include "ns3/core-module.h"
#include "ns3/flow-monitor-module.h"
#include "ns3/internet-module.h"
#include "ns3/network-module.h"
#include "ns3/point-to-point-module.h"

using namespace ns3;

NS_LOG_COMPONENT_DEFINE("NormalIIoT");

int
main(int argc, char* argv[])
{
    // Simulation parameters
    double simulationTime = 20.0;

    CommandLine cmd(__FILE__);
    cmd.AddValue("simulationTime",
                 "Simulation duration in seconds",
                 simulationTime);
    cmd.Parse(argc, argv);

    // ---------------------------------------------------------
    // 1. CREATE NODES
    // ---------------------------------------------------------

    // Three virtual IIoT sensors
    NodeContainer sensors;
    sensors.Create(3);

    // Edge gateway
    Ptr<Node> gateway = CreateObject<Node>();

    // Industrial server
    Ptr<Node> server = CreateObject<Node>();

    // ---------------------------------------------------------
    // 2. CREATE NETWORK LINKS
    // ---------------------------------------------------------

    PointToPointHelper p2p;
    p2p.SetDeviceAttribute("DataRate", StringValue("10Mbps"));
    p2p.SetChannelAttribute("Delay", StringValue("2ms"));

    // Connect each sensor to the gateway
    NetDeviceContainer sensorGateway[3];

    for (uint32_t i = 0; i < 3; ++i)
    {
        sensorGateway[i] =
            p2p.Install(sensors.Get(i), gateway);
    }

    // Connect gateway to server
    NetDeviceContainer gatewayServer =
        p2p.Install(gateway, server);

// ---------------------------------------------------------
// ENABLE PCAP CAPTURE
// ---------------------------------------------------------

for (uint32_t i = 0; i < 3; ++i)
{
    p2p.EnablePcap(
        "dataset/ns3_normal_sensor_" + std::to_string(i + 1),
        sensorGateway[i],
        true);
}

p2p.EnablePcap(
    "dataset/ns3_normal_gateway_server",
    gatewayServer,
    true);

    // ---------------------------------------------------------
    // 3. INSTALL INTERNET STACK
    // ---------------------------------------------------------

    InternetStackHelper internet;

    internet.Install(sensors);
    internet.Install(gateway);
    internet.Install(server);

    // ---------------------------------------------------------
    // 4. ASSIGN IP ADDRESSES
    // ---------------------------------------------------------

    Ipv4AddressHelper address;

    Ipv4InterfaceContainer sensorInterfaces[3];

    for (uint32_t i = 0; i < 3; ++i)
    {
        std::ostringstream subnet;
        subnet << "10.0." << (i + 1) << ".0";

        address.SetBase(
            Ipv4Address(subnet.str().c_str()),
            Ipv4Mask("255.255.255.0"));

        sensorInterfaces[i] =
            address.Assign(sensorGateway[i]);
    }

    // Gateway-server network
    address.SetBase(
        Ipv4Address("10.0.10.0"),
        Ipv4Mask("255.255.255.0"));

    Ipv4InterfaceContainer gatewayServerInterfaces =
        address.Assign(gatewayServer);

    // ---------------------------------------------------------
    // 5. CREATE NORMAL IIoT TRAFFIC
    // ---------------------------------------------------------

    uint16_t port = 9000;

    // Server acts as UDP sink
    PacketSinkHelper sinkHelper(
        "ns3::UdpSocketFactory",
        InetSocketAddress(Ipv4Address::GetAny(), port));

    ApplicationContainer sink =
        sinkHelper.Install(server);

    sink.Start(Seconds(0.0));
    sink.Stop(Seconds(simulationTime));

    // Each sensor sends periodic UDP packets
    for (uint32_t i = 0; i < 3; ++i)
    {
        UdpClientHelper client(
            gatewayServerInterfaces.GetAddress(1),
            port);

        client.SetAttribute(
            "MaxPackets",
            UintegerValue(1000));

        client.SetAttribute(
            "Interval",
            TimeValue(MilliSeconds(100)));

        client.SetAttribute(
            "PacketSize",
            UintegerValue(200));

        ApplicationContainer clientApp =
            client.Install(sensors.Get(i));

        clientApp.Start(
            Seconds(1.0 + i * 0.2));

        clientApp.Stop(
            Seconds(simulationTime - 1));
    }

    // ---------------------------------------------------------
    // 6. ENABLE ROUTING
    // ---------------------------------------------------------

    Ipv4GlobalRoutingHelper::PopulateRoutingTables();

    // ---------------------------------------------------------
    // 7. SIMULATION
    // ---------------------------------------------------------

    NS_LOG_INFO("Starting normal IIoT simulation");

	FlowMonitorHelper flowmonHelper;
	Ptr<FlowMonitor> monitor = flowmonHelper.InstallAll();

    Simulator::Stop(Seconds(simulationTime));

    Simulator::Run();
monitor->CheckForLostPackets();

Ptr<Ipv4FlowClassifier> classifier =
    DynamicCast<Ipv4FlowClassifier>(
        flowmonHelper.GetClassifier());

std::map<FlowId, FlowMonitor::FlowStats> stats =
    monitor->GetFlowStats();

std::cout << "\n========================================\n";
std::cout << "      NORMAL IIoT TRAFFIC RESULTS\n";
std::cout << "========================================\n";

for (const auto& flow : stats)
{
    Ipv4FlowClassifier::FiveTuple t =
        classifier->FindFlow(flow.first);

    std::cout << "\nFlow ID: " << flow.first << "\n";
    std::cout << "Source: " << t.sourceAddress << "\n";
    std::cout << "Destination: " << t.destinationAddress << "\n";
    std::cout << "Protocol: " << static_cast<int>(t.protocol) << "\n";
    std::cout << "Packets Sent: "
              << flow.second.txPackets << "\n";
    std::cout << "Packets Received: "
              << flow.second.rxPackets << "\n";
    std::cout << "Packets Lost: "
              << flow.second.lostPackets << "\n";
}

    // ---------------------------------------------------------
    // 8. FINISH
    // ---------------------------------------------------------

    NS_LOG_INFO("Normal IIoT simulation completed");

    Simulator::Destroy();

    return 0;
}
