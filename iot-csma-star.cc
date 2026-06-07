#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/internet-module.h"
#include "ns3/csma-module.h"
#include "ns3/applications-module.h"
#include "ns3/flow-monitor-module.h"
#include "ns3/netanim-module.h"

using namespace ns3;

NS_LOG_COMPONENT_DEFINE("IoTCsmaStar");

uint32_t g_totalTx  = 0;
uint32_t g_totalRx  = 0;

void PacketTxTrace(Ptr<const Packet> pkt)
{
    g_totalTx++;
}

void PacketRxTrace(Ptr<const Packet> pkt, const Address &addr)
{
    g_totalRx++;
}

void PrintStats(double interval)
{
    double lossRate = (g_totalTx > 0)
                    ? 100.0 * (g_totalTx - g_totalRx) / g_totalTx
                    : 0.0;

    std::cout << std::fixed << std::setprecision(2)
              << "[t=" << Simulator::Now().GetSeconds() << "s] "
              << "Tx=" << g_totalTx
              << "  Rx=" << g_totalRx
              << "  Lost=" << (g_totalTx - g_totalRx)
              << "  LossRate=" << lossRate << "%\n";

    Simulator::Schedule(Seconds(interval), &PrintStats, interval);
}

int main(int argc, char *argv[])
{
    uint32_t    numSensors      = 5;
    double      simTime         = 20.0;
    std::string dataRate        = "100Mbps";
    std::string channelDelay    = "1ms";
    uint32_t    packetSize      = 64;
    double      sendInterval    = 0.5;
    bool        enableNetAnim   = true;

    CommandLine cmd;
    cmd.AddValue("numSensors",    "Number of IoT sensors",           numSensors);
    cmd.AddValue("simTime",       "Simulation duration (seconds)",   simTime);
    cmd.AddValue("dataRate",      "CSMA channel data rate",          dataRate);
    cmd.AddValue("channelDelay",  "CSMA propagation delay",          channelDelay);
    cmd.AddValue("packetSize",    "UDP payload size (bytes)",        packetSize);
    cmd.AddValue("sendInterval",  "Interval between sensor packets", sendInterval);
    cmd.AddValue("enableNetAnim", "Generate NetAnim XML output",     enableNetAnim);
    cmd.Parse(argc, argv);

    LogComponentEnable("IoTCsmaStar", LOG_LEVEL_INFO);

    NS_LOG_INFO("IoT Sensor Network - CSMA Star Topology");
    NS_LOG_INFO("Sensors    : " << numSensors);
    NS_LOG_INFO("Sim time   : " << simTime << " s");
    NS_LOG_INFO("Packet size: " << packetSize << " bytes");
    NS_LOG_INFO("Tx interval: " << sendInterval << " s/sensor");

    NodeContainer allNodes;
    allNodes.Create(numSensors + 1);

    Ptr<Node> gateway = allNodes.Get(0);

    NodeContainer sensors;
    for (uint32_t i = 1; i <= numSensors; i++)
        sensors.Add(allNodes.Get(i));

    CsmaHelper csma;
    csma.SetChannelAttribute("DataRate", StringValue(dataRate));
    csma.SetChannelAttribute("Delay",    StringValue(channelDelay));

    csma.SetDeviceAttribute("TxQueue",
        StringValue("ns3::DropTailQueue[MaxSize=10p]"));

    NetDeviceContainer devices = csma.Install(allNodes);

    InternetStackHelper internet;
    internet.Install(allNodes);

    Ipv4AddressHelper ipv4;
    ipv4.SetBase("192.168.1.0", "255.255.255.0");
    Ipv4InterfaceContainer interfaces = ipv4.Assign(devices);

    Ipv4Address gatewayAddr = interfaces.GetAddress(0);
    NS_LOG_INFO("Gateway IP : " << gatewayAddr);

    uint16_t port = 5000;
    PacketSinkHelper sinkHelper(
        "ns3::UdpSocketFactory",
        InetSocketAddress(Ipv4Address::GetAny(), port));

    ApplicationContainer sinkApp = sinkHelper.Install(gateway);
    sinkApp.Start(Seconds(0.0));
    sinkApp.Stop(Seconds(simTime));

    sinkApp.Get(0)->TraceConnectWithoutContext(
        "Rx", MakeCallback(&PacketRxTrace));

    OnOffHelper onoff(
        "ns3::UdpSocketFactory",
        InetSocketAddress(gatewayAddr, port));

    onoff.SetAttribute("PacketSize",  UintegerValue(packetSize));
    onoff.SetAttribute("DataRate",    DataRateValue(DataRate("8bps")));
    onoff.SetAttribute("OnTime",
        StringValue("ns3::ConstantRandomVariable[Constant=0.1]"));
    onoff.SetAttribute("OffTime",
        StringValue("ns3::ConstantRandomVariable[Constant="
                    + std::to_string(sendInterval) + "]"));

    ApplicationContainer sensorApps;
    for (uint32_t i = 0; i < numSensors; i++)
    {
        double startTime = 0.1 + i * (sendInterval / numSensors);

        ApplicationContainer app = onoff.Install(sensors.Get(i));
        app.Start(Seconds(startTime));
        app.Stop(Seconds(simTime - 0.1));
        sensorApps.Add(app);
    }

    for (uint32_t i = 0; i < sensorApps.GetN(); i++)
    {
        sensorApps.Get(i)->TraceConnectWithoutContext(
            "Tx", MakeCallback(&PacketTxTrace));
    }

    FlowMonitorHelper flowmon;
    Ptr<FlowMonitor> monitor = flowmon.InstallAll();

    AsciiTraceHelper ascii;
    csma.EnableAsciiAll(ascii.CreateFileStream("iot-csma-star.tr"));

    csma.EnablePcap("iot-gateway", devices.Get(0), true);

    AnimationInterface *anim = nullptr;
    if (enableNetAnim)
    {
        anim = new AnimationInterface("iot-csma-star.xml");

        anim->SetConstantPosition(gateway, 50.0, 50.0);
        anim->UpdateNodeDescription(gateway, "Gateway");
        anim->UpdateNodeColor(gateway, 255, 0, 0);

        double radius = 30.0;
        for (uint32_t i = 0; i < numSensors; i++)
        {
            double angle = 2.0 * M_PI * i / numSensors;
            double x = 50.0 + radius * std::cos(angle);
            double y = 50.0 + radius * std::sin(angle);
            anim->SetConstantPosition(sensors.Get(i), x, y);
            anim->UpdateNodeDescription(sensors.Get(i),
                                        "Sensor" + std::to_string(i));
            anim->UpdateNodeColor(sensors.Get(i), 0, 128, 255);
        }
    }

    Simulator::Schedule(Seconds(2.0), &PrintStats, 2.0);

    std::cout << "\n========================================\n";
    std::cout << "  IoT CSMA Star - Simulation Starting\n";
    std::cout << "  Sensors: " << numSensors
              << "  |  Duration: " << simTime << "s\n";
    std::cout << "========================================\n\n";

    Simulator::Stop(Seconds(simTime));
    Simulator::Run();

    monitor->CheckForLostPackets();
    Ptr<Ipv4FlowClassifier> classifier =
        DynamicCast<Ipv4FlowClassifier>(flowmon.GetClassifier());
    FlowMonitor::FlowStatsContainer stats = monitor->GetFlowStats();

    std::cout << "\n========================================\n";
    std::cout << "  Per-Flow Results (FlowMonitor)\n";
    std::cout << "========================================\n";

    double totalThroughput = 0.0;
    uint64_t totalLost     = 0;
    uint64_t totalRxPkts   = 0;

    for (auto &f : stats)
    {
        Ipv4FlowClassifier::FiveTuple t = classifier->FindFlow(f.first);
        double dur = f.second.timeLastRxPacket.GetSeconds()
                   - f.second.timeFirstTxPacket.GetSeconds();
        double tput = (dur > 0 && f.second.rxBytes > 0)
                    ? f.second.rxBytes * 8.0 / dur / 1000.0
                    : 0.0;
        double meanDelay = (f.second.rxPackets > 0)
                         ? f.second.delaySum.GetMilliSeconds()
                           / f.second.rxPackets
                         : 0.0;
        double lossRate  = (f.second.txPackets > 0)
                         ? 100.0 * f.second.lostPackets / f.second.txPackets
                         : 0.0;

        totalThroughput += tput;
        totalLost       += f.second.lostPackets;
        totalRxPkts     += f.second.rxPackets;

        std::cout << "\n  Flow " << f.first << ": "
                  << t.sourceAddress << " -> " << t.destinationAddress << "\n"
                  << "    Tx Packets  : " << f.second.txPackets << "\n"
                  << "    Rx Packets  : " << f.second.rxPackets << "\n"
                  << "    Lost Packets: " << f.second.lostPackets
                  << "  (" << std::fixed << std::setprecision(1)
                  << lossRate << "%)\n"
                  << "    Throughput  : " << std::setprecision(3)
                  << tput << " kbps\n"
                  << "    Mean Delay  : " << std::setprecision(3)
                  << meanDelay << " ms\n";
    }

    double globalLoss = (g_totalTx > 0)
                      ? 100.0 * (g_totalTx - g_totalRx) / g_totalTx
                      : 0.0;

    std::cout << "\n========================================\n";
    std::cout << "  SUMMARY\n";
    std::cout << "========================================\n";
    std::cout << "  Total Tx (all sensors) : " << g_totalTx    << " pkts\n";
    std::cout << "  Total Rx (gateway)     : " << g_totalRx    << " pkts\n";
    std::cout << "  Total Lost             : "
              << (g_totalTx - g_totalRx) << " pkts\n";
    std::cout << "  Global Packet Loss     : "
              << std::fixed << std::setprecision(2)
              << globalLoss << "%\n";
    std::cout << "  Aggregate Throughput   : "
              << std::setprecision(3)
              << totalThroughput << " kbps\n";
    std::cout << "========================================\n\n";

    delete anim;
    Simulator::Destroy();
    return 0;
}
