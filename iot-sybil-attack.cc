/* ================================================================
 *  iot-sybil-attack.cc
 *  -------------------
 *  Sybil Attack Simulation on a CSMA-based IoT Sensor Network
 *  NS-3 version: 3.48
 *
 *  Extends the baseline iot-csma-star.cc with:
 *    - K Sybil identity nodes (one physical attacker, K fake IPs)
 *    - Configurable attack start time and send-rate multiplier
 *    - Threshold-based Intrusion Detection System (IDS)
 *    - Per-node packet tracking at the gateway
 *    - CSV output for automated batch analysis
 *    - NetAnim colour coding (blue=legit, orange=sybil, red=gateway)
 *
 *  Usage:
 *    cp iot-sybil-attack.cc ~/ns-3/scratch/
 *    cd ~/ns-3 && ./ns3 build
 *    ./ns3 run "scratch/iot-sybil-attack --numSensors=5 --numSybilIds=10"
 * ================================================================ */

#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/internet-module.h"
#include "ns3/csma-module.h"
#include "ns3/applications-module.h"
#include "ns3/flow-monitor-module.h"
#include "ns3/netanim-module.h"

#include <map>
#include <set>
#include <vector>
#include <fstream>
#include <iomanip>
#include <algorithm>
#include <cmath>
#include <sstream>

using namespace ns3;

NS_LOG_COMPONENT_DEFINE("IoTSybilAttack");

/* ================================================================
 *  SECTION 1 — Threshold-Based Intrusion Detection System (IDS)
 * ================================================================
 *
 *  Runs on the gateway.  Every  `windowSec`  seconds it computes the
 *  packet arrival rate for each source IP observed in the last window.
 *  Sources whose rate exceeds `thresholdPps` packets/s are flagged as
 *  suspicious (potential Sybil identities).
 *
 *  After the simulation ends, ground-truth labels (legitimate vs Sybil)
 *  are used to compute TP / FP / TN / FN / Precision / Recall / F1.
 * ================================================================ */

class SybilIDS
{
public:
    SybilIDS()
        : m_thresholdPps(3.0),
          m_windowSec(2.0),
          m_firstDetectionTime(-1.0),
          m_attackStartTime(0.0)
    {
    }

    SybilIDS(double thresholdPps, double windowSec, double attackStartTime)
        : m_thresholdPps(thresholdPps),
          m_windowSec(windowSec),
          m_firstDetectionTime(-1.0),
          m_attackStartTime(attackStartTime)
    {
    }

    /* ---------- registration (ground truth) ---------- */

    void RegisterLegitNode(Ipv4Address addr)
    {
        m_legitNodes.insert(addr);
    }

    void RegisterSybilNode(Ipv4Address addr)
    {
        m_sybilNodes.insert(addr);
    }

    /* ---------- packet recording ---------- */

    void RecordPacket(Ipv4Address src)
    {
        double now = Simulator::Now().GetSeconds();
        m_packetLog[src].push_back(now);
    }

    /* ---------- periodic detection ---------- */

    void SchedulePeriodicDetection(double startTime)
    {
        Simulator::Schedule(Seconds(startTime),
                            &SybilIDS::DoPeriodicDetection, this);
    }

    /* ---------- result accessors ---------- */

    uint32_t GetTP() const
    {
        uint32_t tp = 0;
        for (auto &addr : m_flaggedNodes)
            if (m_sybilNodes.count(addr))
                ++tp;
        return tp;
    }

    uint32_t GetFP() const
    {
        uint32_t fp = 0;
        for (auto &addr : m_flaggedNodes)
            if (m_legitNodes.count(addr))
                ++fp;
        return fp;
    }

    uint32_t GetTN() const
    {
        uint32_t tn = 0;
        for (auto &addr : m_legitNodes)
            if (!m_flaggedNodes.count(addr))
                ++tn;
        return tn;
    }

    uint32_t GetFN() const
    {
        uint32_t fn = 0;
        for (auto &addr : m_sybilNodes)
            if (!m_flaggedNodes.count(addr))
                ++fn;
        return fn;
    }

    double GetPrecision() const
    {
        uint32_t tp = GetTP(), fp = GetFP();
        return (tp + fp > 0) ? (double)tp / (tp + fp) : 0.0;
    }

    double GetRecall() const
    {
        uint32_t tp = GetTP(), fn = GetFN();
        return (tp + fn > 0) ? (double)tp / (tp + fn) : 0.0;
    }

    double GetF1() const
    {
        double p = GetPrecision(), r = GetRecall();
        return (p + r > 0.0) ? 2.0 * p * r / (p + r) : 0.0;
    }

    double GetAccuracy() const
    {
        uint32_t tp = GetTP(), tn = GetTN(), fp = GetFP(), fn = GetFN();
        uint32_t total = tp + tn + fp + fn;
        return (total > 0) ? (double)(tp + tn) / total : 0.0;
    }

    double GetFPR() const
    {
        uint32_t fp = GetFP(), tn = GetTN();
        return (fp + tn > 0) ? (double)fp / (fp + tn) : 0.0;
    }

    double GetDetectionLatency() const
    {
        return m_firstDetectionTime;
    }

    std::set<Ipv4Address> GetFlaggedNodes() const
    {
        return m_flaggedNodes;
    }

    /* ---------- final report to stdout ---------- */

    void PrintReport() const
    {
        std::cout << "\n========================================\n";
        std::cout << "  IDS DETECTION REPORT\n";
        std::cout << "========================================\n";
        std::cout << "  Threshold   : " << m_thresholdPps << " pkt/s\n";
        std::cout << "  Window      : " << m_windowSec    << " s\n";
        std::cout << "  Legit nodes : " << m_legitNodes.size()  << "\n";
        std::cout << "  Sybil nodes : " << m_sybilNodes.size()  << "\n";
        std::cout << "  Flagged     : " << m_flaggedNodes.size() << "\n";
        std::cout << "  ────────────────────────────────────\n";
        std::cout << "  True Positives  (TP): " << GetTP() << "\n";
        std::cout << "  False Positives (FP): " << GetFP() << "\n";
        std::cout << "  True Negatives  (TN): " << GetTN() << "\n";
        std::cout << "  False Negatives (FN): " << GetFN() << "\n";
        std::cout << "  ────────────────────────────────────\n";
        std::cout << std::fixed << std::setprecision(4);
        std::cout << "  Precision : " << GetPrecision() << "\n";
        std::cout << "  Recall    : " << GetRecall()    << "\n";
        std::cout << "  F1 Score  : " << GetF1()        << "\n";
        std::cout << "  Accuracy  : " << GetAccuracy()  << "\n";
        std::cout << "  FPR       : " << GetFPR()       << "\n";
        if (m_firstDetectionTime >= 0.0)
            std::cout << "  Detection latency: "
                      << (m_firstDetectionTime - m_attackStartTime) << " s\n";
        else
            std::cout << "  Detection latency: NOT DETECTED\n";
        std::cout << "========================================\n\n";
    }

private:
    double m_thresholdPps;
    double m_windowSec;
    double m_firstDetectionTime;
    double m_attackStartTime;

    std::map<Ipv4Address, std::vector<double>> m_packetLog;
    std::set<Ipv4Address> m_legitNodes;
    std::set<Ipv4Address> m_sybilNodes;
    std::set<Ipv4Address> m_flaggedNodes;

    void DoPeriodicDetection()
    {
        double now = Simulator::Now().GetSeconds();
        double windowStart = now - m_windowSec;

        for (auto &entry : m_packetLog)
        {
            Ipv4Address addr = entry.first;
            std::vector<double> &times = entry.second;

            /* Count packets inside [windowStart, now] */
            uint32_t count = 0;
            for (auto it = times.rbegin(); it != times.rend(); ++it)
            {
                if (*it >= windowStart)
                    ++count;
                else
                    break;   /* sorted chronologically, so stop early */
            }

            double rate = (m_windowSec > 0.0) ? count / m_windowSec : 0.0;

            if (rate > m_thresholdPps)
            {
                if (!m_flaggedNodes.count(addr))
                {
                    m_flaggedNodes.insert(addr);
                    std::cout << "[IDS t=" << std::fixed << std::setprecision(2)
                              << now << "s]  ALERT — " << addr
                              << " flagged (" << std::setprecision(1)
                              << rate << " pkt/s > "
                              << m_thresholdPps << " threshold)\n";

                    /* Record first detection of any Sybil node */
                    if (m_firstDetectionTime < 0.0 && m_sybilNodes.count(addr))
                        m_firstDetectionTime = now;
                }
            }
        }

        /* Re-schedule for next window */
        Simulator::Schedule(Seconds(m_windowSec),
                            &SybilIDS::DoPeriodicDetection, this);
    }
};

/* ================================================================
 *  SECTION 2 — Global Counters & Trace Callbacks
 * ================================================================ */

uint32_t g_totalTx = 0;
uint32_t g_totalRx = 0;

/* Per-source-IP counters at the gateway */
std::map<Ipv4Address, uint32_t> g_perNodeRx;

/* Pointer to the IDS (set in main, used in trace callback) */
SybilIDS *g_ids = nullptr;

/* Ground-truth address sets (filled in main) */
std::set<Ipv4Address> g_sybilAddresses;
std::set<Ipv4Address> g_legitAddresses;

/* ----- Tx trace (called per OnOff application) ----- */
void TxTrace(Ptr<const Packet> pkt)
{
    g_totalTx++;
}

/* ----- Rx trace (called at the gateway PacketSink) ----- */
void RxTrace(Ptr<const Packet> pkt, const Address &addr)
{
    g_totalRx++;
    if (InetSocketAddress::IsMatchingType(addr))
    {
        Ipv4Address src = InetSocketAddress::ConvertFrom(addr).GetIpv4();
        g_perNodeRx[src]++;

        if (g_ids)
            g_ids->RecordPacket(src);
    }
}

/* ----- Periodic live-stats printer ----- */
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

/* ================================================================
 *  SECTION 3 — Helper: write one row to the CSV results file
 * ================================================================ */

void WriteCsvRow(const std::string &filename,
                 uint32_t numSensors, uint32_t numSybilIds,
                 double sybilRateMulti, double simTime,
                 double idsThreshold, double idsWindow,
                 uint32_t totalTx, uint32_t totalRx,
                 double globalPDR,
                 double legitPDR, double sybilPDR,
                 double avgThroughputKbps, double avgDelayMs,
                 const SybilIDS &ids)
{
    /* Check if file exists to decide whether to write header */
    bool writeHeader = false;
    {
        std::ifstream check(filename);
        if (!check.good() || check.peek() == std::ifstream::traits_type::eof())
            writeHeader = true;
    }

    std::ofstream csv(filename, std::ios::app);
    if (!csv.is_open())
    {
        std::cerr << "ERROR: cannot open " << filename << "\n";
        return;
    }

    if (writeHeader)
    {
        csv << "numSensors,numSybilIds,sybilRateMulti,simTime,"
            << "idsThreshold,idsWindow,"
            << "totalTx,totalRx,globalPDR,"
            << "legitPDR,sybilPDR,"
            << "avgThroughputKbps,avgDelayMs,"
            << "idsTP,idsFP,idsTN,idsFN,"
            << "idsPrecision,idsRecall,idsF1,idsAccuracy,idsFPR,"
            << "idsDetectionLatency\n";
    }

    csv << numSensors      << ","
        << numSybilIds     << ","
        << sybilRateMulti  << ","
        << simTime         << ","
        << idsThreshold    << ","
        << idsWindow       << ","
        << totalTx         << ","
        << totalRx         << ","
        << std::fixed << std::setprecision(4)
        << globalPDR       << ","
        << legitPDR        << ","
        << sybilPDR        << ","
        << std::setprecision(3)
        << avgThroughputKbps << ","
        << avgDelayMs      << ","
        << ids.GetTP()     << ","
        << ids.GetFP()     << ","
        << ids.GetTN()     << ","
        << ids.GetFN()     << ","
        << std::setprecision(4)
        << ids.GetPrecision()       << ","
        << ids.GetRecall()          << ","
        << ids.GetF1()              << ","
        << ids.GetAccuracy()        << ","
        << ids.GetFPR()             << ","
        << ids.GetDetectionLatency() << "\n";

    csv.close();
}

/* ================================================================
 *  SECTION 4 — MAIN
 * ================================================================ */

int main(int argc, char *argv[])
{
    /* ---- default parameters ---- */
    uint32_t    numSensors      = 5;
    uint32_t    numSybilIds     = 5;
    double      sybilRateMulti  = 2.0;
    double      attackStartTime = 5.0;
    double      simTime         = 60.0;
    std::string dataRate        = "100Mbps";
    std::string channelDelay    = "1ms";
    uint32_t    packetSize      = 64;
    double      sendInterval    = 0.5;
    bool        enableIDS       = true;
    double      idsThreshold    = 3.0;
    double      idsWindow       = 2.0;
    bool        enableNetAnim   = true;
    std::string csvFile         = "sybil-results.csv";
    uint32_t    runNumber       = 1;

    /* ---- command-line parsing ---- */
    CommandLine cmd;
    cmd.AddValue("numSensors",      "Number of legitimate IoT sensors",     numSensors);
    cmd.AddValue("numSybilIds",     "Number of Sybil (fake) identities",    numSybilIds);
    cmd.AddValue("sybilRateMulti",  "Sybil send-rate multiplier (1=stealth)", sybilRateMulti);
    cmd.AddValue("attackStartTime", "When the Sybil attack begins (sec)",   attackStartTime);
    cmd.AddValue("simTime",         "Simulation duration (seconds)",        simTime);
    cmd.AddValue("dataRate",        "CSMA channel data rate",               dataRate);
    cmd.AddValue("channelDelay",    "CSMA propagation delay",               channelDelay);
    cmd.AddValue("packetSize",      "UDP payload size (bytes)",             packetSize);
    cmd.AddValue("sendInterval",    "Interval between sensor packets (s)",  sendInterval);
    cmd.AddValue("enableIDS",       "Enable intrusion detection",           enableIDS);
    cmd.AddValue("idsThreshold",    "IDS alert threshold (pkt/s)",          idsThreshold);
    cmd.AddValue("idsWindow",       "IDS detection window (seconds)",       idsWindow);
    cmd.AddValue("enableNetAnim",   "Generate NetAnim XML",                 enableNetAnim);
    cmd.AddValue("csvFile",         "Output CSV filename",                  csvFile);
    cmd.AddValue("runNumber",       "RNG run number for reproducibility",   runNumber);
    cmd.Parse(argc, argv);

    /* ---- reproducibility ---- */
    RngSeedManager::SetSeed(1);
    RngSeedManager::SetRun(runNumber);

    LogComponentEnable("IoTSybilAttack", LOG_LEVEL_INFO);

    NS_LOG_INFO("=== IoT Sybil Attack Simulation ===");
    NS_LOG_INFO("Legitimate sensors : " << numSensors);
    NS_LOG_INFO("Sybil identities   : " << numSybilIds);
    NS_LOG_INFO("Rate multiplier    : " << sybilRateMulti << "x");
    NS_LOG_INFO("Attack start       : " << attackStartTime << " s");
    NS_LOG_INFO("Sim time           : " << simTime << " s");

    /* ========================================================
     *  4-A   CREATE NODES
     *
     *    Node  0           = Gateway  (packet sink + IDS)
     *    Nodes 1..N        = Legitimate sensors
     *    Nodes N+1 .. N+K  = Sybil identities
     * ======================================================== */

    uint32_t totalNodes = 1 + numSensors + numSybilIds;
    NodeContainer allNodes;
    allNodes.Create(totalNodes);

    Ptr<Node> gateway = allNodes.Get(0);

    NodeContainer legitSensors;
    for (uint32_t i = 1; i <= numSensors; i++)
        legitSensors.Add(allNodes.Get(i));

    NodeContainer sybilNodes;
    for (uint32_t i = numSensors + 1; i < totalNodes; i++)
        sybilNodes.Add(allNodes.Get(i));

    /* ========================================================
     *  4-B   CSMA CHANNEL  (shared bus — all nodes)
     * ======================================================== */

    CsmaHelper csma;
    csma.SetChannelAttribute("DataRate", StringValue(dataRate));
    csma.SetChannelAttribute("Delay",    StringValue(channelDelay));
    csma.SetDeviceAttribute("TxQueue",
        StringValue("ns3::DropTailQueue[MaxSize=10p]"));

    NetDeviceContainer devices = csma.Install(allNodes);

    /* ========================================================
     *  4-C   INTERNET STACK + IP ADDRESSING
     * ======================================================== */

    InternetStackHelper internet;
    internet.Install(allNodes);

    Ipv4AddressHelper ipv4;
    ipv4.SetBase("192.168.1.0", "255.255.255.0");
    Ipv4InterfaceContainer interfaces = ipv4.Assign(devices);

    Ipv4Address gatewayAddr = interfaces.GetAddress(0);
    NS_LOG_INFO("Gateway IP : " << gatewayAddr);

    /* Record ground-truth IP sets */
    for (uint32_t i = 1; i <= numSensors; i++)
    {
        Ipv4Address a = interfaces.GetAddress(i);
        g_legitAddresses.insert(a);
        NS_LOG_INFO("  Legit sensor " << (i - 1) << " : " << a);
    }
    for (uint32_t i = numSensors + 1; i < totalNodes; i++)
    {
        Ipv4Address a = interfaces.GetAddress(i);
        g_sybilAddresses.insert(a);
        NS_LOG_INFO("  Sybil id     " << (i - numSensors - 1) << " : " << a);
    }

    /* ========================================================
     *  4-D   GATEWAY SINK  (receives all sensor data)
     * ======================================================== */

    uint16_t port = 5000;
    PacketSinkHelper sinkHelper(
        "ns3::UdpSocketFactory",
        InetSocketAddress(Ipv4Address::GetAny(), port));

    ApplicationContainer sinkApp = sinkHelper.Install(gateway);
    sinkApp.Start(Seconds(0.0));
    sinkApp.Stop(Seconds(simTime));

    sinkApp.Get(0)->TraceConnectWithoutContext(
        "Rx", MakeCallback(&RxTrace));

    /* ========================================================
     *  4-E   LEGITIMATE SENSOR APPLICATIONS
     * ======================================================== */

    OnOffHelper onoffLegit(
        "ns3::UdpSocketFactory",
        InetSocketAddress(gatewayAddr, port));

    onoffLegit.SetAttribute("PacketSize", UintegerValue(packetSize));
    onoffLegit.SetAttribute("DataRate",   DataRateValue(DataRate("8bps")));
    onoffLegit.SetAttribute("OnTime",
        StringValue("ns3::ConstantRandomVariable[Constant=0.1]"));
    onoffLegit.SetAttribute("OffTime",
        StringValue("ns3::ConstantRandomVariable[Constant="
                    + std::to_string(sendInterval) + "]"));

    ApplicationContainer legitApps;
    for (uint32_t i = 0; i < numSensors; i++)
    {
        double startTime = 0.1 + i * (sendInterval / numSensors);
        ApplicationContainer app = onoffLegit.Install(legitSensors.Get(i));
        app.Start(Seconds(startTime));
        app.Stop(Seconds(simTime - 0.1));
        legitApps.Add(app);
    }

    /* Connect Tx traces for legitimate sensors */
    for (uint32_t i = 0; i < legitApps.GetN(); i++)
    {
        legitApps.Get(i)->TraceConnectWithoutContext(
            "Tx", MakeCallback(&TxTrace));
    }

    /* ========================================================
     *  4-F   SYBIL NODE APPLICATIONS  (delayed start)
     *
     *  Each Sybil identity sends at  sybilRateMulti × normal rate.
     *  We achieve this by scaling the OffTime down by the multiplier.
     * ======================================================== */

    double sybilOffTime = sendInterval / sybilRateMulti;

    OnOffHelper onoffSybil(
        "ns3::UdpSocketFactory",
        InetSocketAddress(gatewayAddr, port));

    onoffSybil.SetAttribute("PacketSize", UintegerValue(packetSize));
    onoffSybil.SetAttribute("DataRate",   DataRateValue(DataRate("8bps")));
    onoffSybil.SetAttribute("OnTime",
        StringValue("ns3::ConstantRandomVariable[Constant=0.1]"));
    onoffSybil.SetAttribute("OffTime",
        StringValue("ns3::ConstantRandomVariable[Constant="
                    + std::to_string(sybilOffTime) + "]"));

    ApplicationContainer sybilApps;
    for (uint32_t i = 0; i < numSybilIds; i++)
    {
        /* Stagger Sybil start times slightly so they don't all
         * burst at the same instant (more realistic). */
        double startTime = attackStartTime + i * 0.05;

        ApplicationContainer app = onoffSybil.Install(sybilNodes.Get(i));
        app.Start(Seconds(startTime));
        app.Stop(Seconds(simTime - 0.1));
        sybilApps.Add(app);
    }

    /* Connect Tx traces for Sybil nodes */
    for (uint32_t i = 0; i < sybilApps.GetN(); i++)
    {
        sybilApps.Get(i)->TraceConnectWithoutContext(
            "Tx", MakeCallback(&TxTrace));
    }

    /* ========================================================
     *  4-G   INTRUSION DETECTION SYSTEM
     * ======================================================== */

    SybilIDS ids(idsThreshold, idsWindow, attackStartTime);

    /* Register ground-truth labels */
    for (auto &addr : g_legitAddresses)
        ids.RegisterLegitNode(addr);
    for (auto &addr : g_sybilAddresses)
        ids.RegisterSybilNode(addr);

    if (enableIDS)
    {
        g_ids = &ids;
        /* Start detection checks after the attack window begins */
        ids.SchedulePeriodicDetection(attackStartTime + idsWindow);
    }

    /* ========================================================
     *  4-H   FLOW MONITOR  +  TRACING
     * ======================================================== */

    FlowMonitorHelper flowmon;
    Ptr<FlowMonitor> monitor = flowmon.InstallAll();

    AsciiTraceHelper ascii;
    csma.EnableAsciiAll(ascii.CreateFileStream("iot-sybil-attack.tr"));
    csma.EnablePcap("iot-sybil-gateway", devices.Get(0), true);

    /* ========================================================
     *  4-I   NETANIM VISUALISATION
     * ======================================================== */

    AnimationInterface *anim = nullptr;
    if (enableNetAnim)
    {
        anim = new AnimationInterface("iot-sybil-attack.xml");

        /* Gateway — centre, red */
        anim->SetConstantPosition(gateway, 50.0, 50.0);
        anim->UpdateNodeDescription(gateway, "Gateway");
        anim->UpdateNodeColor(gateway, 255, 0, 0);

        /* Legitimate sensors — blue ring */
        double radius = 30.0;
        for (uint32_t i = 0; i < numSensors; i++)
        {
            double angle = 2.0 * M_PI * i / numSensors;
            double x = 50.0 + radius * std::cos(angle);
            double y = 50.0 + radius * std::sin(angle);
            anim->SetConstantPosition(legitSensors.Get(i), x, y);
            anim->UpdateNodeDescription(legitSensors.Get(i),
                                         "Sensor" + std::to_string(i));
            anim->UpdateNodeColor(legitSensors.Get(i), 0, 128, 255);
        }

        /* Sybil nodes — orange cluster (co-located: same physical device) */
        double sybilBaseX = 50.0 + radius * 1.4;
        double sybilBaseY = 50.0;
        for (uint32_t i = 0; i < numSybilIds; i++)
        {
            /* Small spread to make them individually visible */
            double dx = 3.0 * std::cos(2.0 * M_PI * i / std::max(numSybilIds, 1u));
            double dy = 3.0 * std::sin(2.0 * M_PI * i / std::max(numSybilIds, 1u));
            anim->SetConstantPosition(sybilNodes.Get(i),
                                       sybilBaseX + dx, sybilBaseY + dy);
            anim->UpdateNodeDescription(sybilNodes.Get(i),
                                         "Sybil" + std::to_string(i));
            anim->UpdateNodeColor(sybilNodes.Get(i), 255, 165, 0);   /* orange */
        }
    }

    /* ========================================================
     *  4-J   SCHEDULE LIVE STATS  &  RUN
     * ======================================================== */

    Simulator::Schedule(Seconds(2.0), &PrintStats, 2.0);

    std::cout << "\n=============================================\n";
    std::cout << "  IoT Sybil Attack Simulation — Starting\n";
    std::cout << "  Legit sensors : " << numSensors    << "\n";
    std::cout << "  Sybil IDs     : " << numSybilIds   << "\n";
    std::cout << "  Rate multi    : " << sybilRateMulti << "x\n";
    std::cout << "  Attack at     : " << attackStartTime << " s\n";
    std::cout << "  Duration      : " << simTime << " s\n";
    std::cout << "  IDS           : " << (enableIDS ? "ON" : "OFF") << "\n";
    if (enableIDS)
        std::cout << "  IDS threshold : " << idsThreshold << " pkt/s\n";
    std::cout << "=============================================\n\n";

    Simulator::Stop(Seconds(simTime));
    Simulator::Run();

    /* ========================================================
     *  4-K   COLLECT RESULTS
     * ======================================================== */

    monitor->CheckForLostPackets();
    Ptr<Ipv4FlowClassifier> classifier =
        DynamicCast<Ipv4FlowClassifier>(flowmon.GetClassifier());
    FlowMonitor::FlowStatsContainer stats = monitor->GetFlowStats();

    /* ---- per-flow printout ---- */
    std::cout << "\n========================================\n";
    std::cout << "  Per-Flow Results (FlowMonitor)\n";
    std::cout << "========================================\n";

    double totalThroughput = 0.0;
    double totalDelay      = 0.0;
    uint64_t totalRxPkts   = 0;
    uint32_t flowCount     = 0;

    /* Separate counters for legitimate vs Sybil flows */
    uint64_t legitTxPkts   = 0, legitRxPkts = 0;
    uint64_t sybilTxPkts   = 0, sybilRxPkts = 0;

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
        double lossRate = (f.second.txPackets > 0)
                        ? 100.0 * f.second.lostPackets / f.second.txPackets
                        : 0.0;

        totalThroughput += tput;
        totalDelay      += (f.second.rxPackets > 0 ? f.second.delaySum.GetMilliSeconds() : 0.0);
        totalRxPkts     += f.second.rxPackets;
        flowCount++;

        /* Classify flow as legitimate or Sybil */
        bool isSybilFlow = g_sybilAddresses.count(t.sourceAddress) > 0;
        if (isSybilFlow)
        {
            sybilTxPkts += f.second.txPackets;
            sybilRxPkts += f.second.rxPackets;
        }
        else
        {
            legitTxPkts += f.second.txPackets;
            legitRxPkts += f.second.rxPackets;
        }

        std::string label = isSybilFlow ? " [SYBIL]" : " [LEGIT]";
        std::cout << "\n  Flow " << f.first << label << ": "
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

    /* ---- compute PDR breakdown ---- */
    double globalPDR = (g_totalTx > 0)
                     ? 100.0 * g_totalRx / g_totalTx
                     : 0.0;
    double legitPDR  = (legitTxPkts > 0)
                     ? 100.0 * legitRxPkts / legitTxPkts
                     : 0.0;
    double sybilPDR  = (sybilTxPkts > 0)
                     ? 100.0 * sybilRxPkts / sybilTxPkts
                     : 0.0;
    double avgDelay  = (totalRxPkts > 0)
                     ? totalDelay / totalRxPkts
                     : 0.0;

    /* ---- summary printout ---- */
    std::cout << "\n========================================\n";
    std::cout << "  NETWORK SUMMARY\n";
    std::cout << "========================================\n";
    std::cout << "  Total Tx (all nodes)   : " << g_totalTx  << " pkts\n";
    std::cout << "  Total Rx (gateway)     : " << g_totalRx  << " pkts\n";
    std::cout << "  Total Lost             : " << (g_totalTx - g_totalRx) << " pkts\n";
    std::cout << std::fixed << std::setprecision(2);
    std::cout << "  Global PDR             : " << globalPDR  << "%\n";
    std::cout << "  ────────────────────────────────────\n";
    std::cout << "  Legitimate Tx/Rx       : " << legitTxPkts << "/" << legitRxPkts << "\n";
    std::cout << "  Legitimate PDR         : " << legitPDR   << "%\n";
    std::cout << "  Sybil Tx/Rx            : " << sybilTxPkts << "/" << sybilRxPkts << "\n";
    std::cout << "  Sybil PDR              : " << sybilPDR   << "%\n";
    std::cout << "  ────────────────────────────────────\n";
    std::cout << "  Aggregate Throughput   : " << std::setprecision(3)
              << totalThroughput << " kbps\n";
    std::cout << "  Mean End-to-End Delay  : " << std::setprecision(3)
              << avgDelay << " ms\n";
    std::cout << "========================================\n";

    /* ---- per-source-IP breakdown (gateway view) ---- */
    std::cout << "\n========================================\n";
    std::cout << "  PER-SOURCE PACKET COUNT (Gateway)\n";
    std::cout << "========================================\n";
    for (auto &entry : g_perNodeRx)
    {
        std::string tag = g_sybilAddresses.count(entry.first) ? "SYBIL" : "LEGIT";
        std::cout << "  " << entry.first << "  [" << tag << "]  : "
                  << entry.second << " pkts\n";
    }
    std::cout << "========================================\n";

    /* ---- IDS report ---- */
    if (enableIDS)
        ids.PrintReport();

    /* ---- CSV output ---- */
    WriteCsvRow(csvFile,
                numSensors, numSybilIds, sybilRateMulti, simTime,
                idsThreshold, idsWindow,
                g_totalTx, g_totalRx, globalPDR,
                legitPDR, sybilPDR,
                totalThroughput, avgDelay,
                ids);

    std::cout << "Results appended to: " << csvFile << "\n\n";

    /* ---- cleanup ---- */
    delete anim;
    Simulator::Destroy();
    return 0;
}
