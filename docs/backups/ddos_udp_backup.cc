#include "ns3/applications-module.h"
#include "ns3/core-module.h"
#include "ns3/flow-monitor-module.h"
#include "ns3/internet-module.h"
#include "ns3/network-module.h"
#include "ns3/point-to-point-module.h"

using namespace ns3;

NS_LOG_COMPONENT_DEFINE("DDoSUDP");

int
main(int argc, char *argv[])
{
    double simulationTime = 20.0;

    CommandLine cmd(__FILE__);
    cmd.AddValue("simulationTime",
                 "Simulation duration in seconds",
                 simulationTime);
    cmd.Parse(argc, argv);

    // ============================================================
    // 1. CREATE NODES
    // ============================================================

    // Three legitimate IIoT sensors
    NodeContainer sensors;
    sensors.Create(3);

    // One controlled DDoS traffic source
    NodeContainer attacker;
    attacker.Create(1);

    // Edge security gateway
    NodeContainer gateway;
    gateway.Create(1);

    // Industrial server / OT service
    NodeContainer server;
    server.Create(1);

    // ============================================================
    // 2. INTERNET STACK
    // ============================================================

    InternetStackHelper internet;

    internet.Install(sensors);
    internet.Install(attacker);
    internet.Install(gateway);
    internet.Install(server);

    // ============================================================
    // 3. CREATE LINKS
    // ============================================================

    // Sensor -> Gateway links
    PointToPointHelper sensorLink;
    sensorLink.SetDeviceAttribute("DataRate",
                                  StringValue("10Mbps"));
    sensorLink.SetChannelAttribute("Delay",
                                   StringValue("2ms"));

    // Attacker -> Gateway link
    PointToPointHelper attackerLink;
    attackerLink.SetDeviceAttribute("DataRate",
                                     StringValue("10Mbps"));
    attackerLink.SetChannelAttribute("Delay",
                                      StringValue("2ms"));

    // Gateway -> Server bottleneck link
    //
    // This deliberately represents a constrained industrial
    // network link so that high-rate DDoS traffic can create
    // measurable congestion in the simulation.
    PointToPointHelper gatewayServerLink;
    gatewayServerLink.SetDeviceAttribute("DataRate",
                                          StringValue("2Mbps"));
    gatewayServerLink.SetChannelAttribute("Delay",
                                           StringValue("5ms"));

    // ============================================================
    // 4. INSTALL SENSOR LINKS
    // ============================================================

    NetDeviceContainer sensorDevices[3];
    Ipv4InterfaceContainer sensorInterfaces[3];

    for (uint32_t i = 0; i < 3; ++i)
    {
        sensorDevices[i] =
            sensorLink.Install(sensors.Get(i), gateway.Get(0));
    }

    // ============================================================
    // 5. INSTALL ATTACKER LINK
    // ============================================================

    NetDeviceContainer attackerDevices;
    attackerDevices =
        attackerLink.Install(attacker.Get(0), gateway.Get(0));

    // ============================================================
    // 6. INSTALL GATEWAY -> SERVER LINK
    // ============================================================

    NetDeviceContainer gatewayServerDevices;
    gatewayServerDevices =
        gatewayServerLink.Install(gateway.Get(0), server.Get(0));

    // ============================================================
    // 7. ASSIGN IP ADDRESSES
    // ============================================================

    Ipv4AddressHelper address;

    // Sensor 1
    address.SetBase("10.0.1.0", "255.255.255.0");
    sensorInterfaces[0] =
        address.Assign(sensorDevices[0]);

    // Sensor 2
    address.SetBase("10.0.2.0", "255.255.255.0");
    sensorInterfaces[1] =
        address.Assign(sensorDevices[1]);

    // Sensor 3
    address.SetBase("10.0.3.0", "255.255.255.0");
    sensorInterfaces[2] =
        address.Assign(sensorDevices[2]);

    // Attacker
    address.SetBase("10.0.4.0", "255.255.255.0");
    Ipv4InterfaceContainer attackerInterface =
        address.Assign(attackerDevices);

    // Gateway -> Server
    address.SetBase("10.0.10.0", "255.255.255.0");
    Ipv4InterfaceContainer gatewayServerInterface =
        address.Assign(gatewayServerDevices);

    // ============================================================
    // 8. ENABLE ROUTING
    // ============================================================

    Ipv4GlobalRoutingHelper::PopulateRoutingTables();

    // ============================================================
    // 9. INDUSTRIAL SERVER
    // ============================================================

    uint16_t sensorPort = 9000;

    PacketSinkHelper sinkHelper(
        "ns3::UdpSocketFactory",
        InetSocketAddress(Ipv4Address::GetAny(), sensorPort));

    ApplicationContainer sinkApp =
        sinkHelper.Install(server.Get(0));

    sinkApp.Start(Seconds(0.0));
    sinkApp.Stop(Seconds(simulationTime));

    // ============================================================
    // 10. NORMAL IIoT TRAFFIC
    // ============================================================

    // Each sensor sends low-rate periodic telemetry.
    for (uint32_t i = 0; i < 3; ++i)
    {
        UdpClientHelper sensorClient(
            gatewayServerInterface.GetAddress(1),
            sensorPort);

        sensorClient.SetAttribute(
            "MaxPackets",
            UintegerValue(1000));

        sensorClient.SetAttribute(
            "Interval",
            TimeValue(MilliSeconds(100)));

        sensorClient.SetAttribute(
            "PacketSize",
            UintegerValue(200));

        ApplicationContainer sensorApp =
            sensorClient.Install(sensors.Get(i));

        sensorApp.Start(Seconds(1.0 + i * 0.1));
        sensorApp.Stop(Seconds(simulationTime - 1));
    }

    // ============================================================
    // 11. CONTROLLED UDP DDoS TRAFFIC
    // ============================================================

    uint16_t ddosPort = 9001;

    PacketSinkHelper ddosSinkHelper(
        "ns3::UdpSocketFactory",
        InetSocketAddress(Ipv4Address::GetAny(), ddosPort));

    ApplicationContainer ddosSink =
        ddosSinkHelper.Install(server.Get(0));

    ddosSink.Start(Seconds(0.0));
    ddosSink.Stop(Seconds(simulationTime));

    // High-rate UDP traffic from the simulated attacker.
    //
    // This traffic remains entirely inside NS-3.
    UdpClientHelper ddosClient(
        gatewayServerInterface.GetAddress(1),
        ddosPort);

    ddosClient.SetAttribute(
        "MaxPackets",
        UintegerValue(100000));

    ddosClient.SetAttribute(
        "Interval",
        TimeValue(MilliSeconds(1)));

    ddosClient.SetAttribute(
        "PacketSize",
        UintegerValue(512));

    ApplicationContainer ddosApp =
        ddosClient.Install(attacker.Get(0));

    // Start the DDoS after normal traffic has begun.
    ddosApp.Start(Seconds(5.0));
    ddosApp.Stop(Seconds(simulationTime - 1));

    // ============================================================
    // 12. FLOW MONITOR
    // ============================================================

    FlowMonitorHelper flowHelper;
    Ptr<FlowMonitor> monitor =
        flowHelper.InstallAll();

    // ============================================================
    // 13. RUN SIMULATION
    // ============================================================

    Simulator::Stop(Seconds(simulationTime));

    Simulator::Run();

    // ============================================================
    // 14. PRINT RESULTS
    // ============================================================

    Ptr<Ipv4FlowClassifier> classifier =
        DynamicCast<Ipv4FlowClassifier>(
            flowHelper.GetClassifier());

    FlowMonitor::FlowStatsContainer stats =
        monitor->GetFlowStats();

    std::cout << std::endl;
    std::cout << "========================================"
              << std::endl;
    std::cout << "       CONTROLLED UDP DDoS RESULTS"
              << std::endl;
    std::cout << "========================================"
              << std::endl;

    for (const auto &flow : stats)
    {
        Ipv4FlowClassifier::FiveTuple tuple =
            classifier->FindFlow(flow.first);

        std::cout << std::endl;

        std::cout << "Flow ID: "
                  << flow.first
                  << std::endl;

        std::cout << "Source: "
                  << tuple.sourceAddress
                  << std::endl;

        std::cout << "Destination: "
                  << tuple.destinationAddress
                  << std::endl;

        std::cout << "Protocol: "
                  << static_cast<uint32_t>(tuple.protocol)
                  << std::endl;

        std::cout << "Packets Sent: "
                  << flow.second.txPackets
                  << std::endl;

        std::cout << "Packets Received: "
                  << flow.second.rxPackets
                  << std::endl;

        std::cout << "Packets Lost: "
                  << flow.second.lostPackets
                  << std::endl;
    }

    std::cout << std::endl;
    std::cout << "========================================"
              << std::endl;

    Simulator::Destroy();

    return 0;
}
