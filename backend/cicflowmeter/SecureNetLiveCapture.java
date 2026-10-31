/*
 * SecureNet — live CICFlowMeter capture (headless)
 *
 * CICFlowMeter only offers live capture inside its Swing GUI. This small program uses the same
 * CICFlowMeter classes (FlowGenerator, PacketReader, BasicFlow — exactly as the GUI's
 * TrafficFlowWorker does) without a window: it captures packets from one network interface with
 * jNetPcap/Npcap and appends every finished flow to a CSV file, in CICFlowMeter's own CSV format
 * (its header, its 84 features, microsecond times).
 *
 *   java -Djava.library.path=<native> -cp <jars;classes> SecureNetLiveCapture <device> <csv> [idleSeconds]
 *   java ... SecureNetLiveCapture --list        list capture devices (name \t description \t addresses)
 *   java ... SecureNetLiveCapture --header      print CICFlowMeter's CSV header
 *   java ... SecureNetLiveCapture --pcap <file.pcap> <csv>   same flow code on a saved capture (tests)
 *
 * Flows end as in CICFlowMeter (FIN in both directions, RST, 120 s flow timeout, 5 s activity
 * timeout for active/idle periods). In addition — because a live monitor must report even when a
 * connection simply goes quiet — a flow with no packet for <idleSeconds> (default 15) is written
 * out. Flows with a single packet are skipped, like CICFlowMeter does.
 *
 * Talks to SecureNet over stdout:  "READY <device>" once capturing, then every 5 s
 * "STATS <packets> <flowsWritten> <openFlows>". Errors go to stderr with a non-zero exit code.
 * SecureNet stops it by closing stdin: open flows are written out and the program exits.
 */

import cic.cs.unb.ca.jnetpcap.BasicFlow;
import cic.cs.unb.ca.jnetpcap.BasicPacketInfo;
import cic.cs.unb.ca.jnetpcap.FlowFeature;
import cic.cs.unb.ca.jnetpcap.FlowGenerator;
import cic.cs.unb.ca.jnetpcap.PacketReader;
import cic.cs.unb.ca.jnetpcap.worker.FlowGenListener;
import org.jnetpcap.Pcap;
import org.jnetpcap.PcapAddr;
import org.jnetpcap.PcapIf;
import org.jnetpcap.nio.JMemory;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;
import org.jnetpcap.packet.format.FormatUtils;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.lang.reflect.Field;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

public class SecureNetLiveCapture implements FlowGenListener {

    private static final long FLOW_TIMEOUT_US = 120_000_000L;     // CICFlowMeter default
    private static final long ACTIVITY_TIMEOUT_US = 5_000_000L;   // CICFlowMeter default

    private final Writer out;
    private long written = 0;

    private SecureNetLiveCapture(Writer out) {
        this.out = out;
    }

    @Override
    public synchronized void onFlowGenerated(BasicFlow flow) {
        try {
            out.write(flow.dumpFlowBasedFeaturesEx());
            out.write("\n");
            out.flush();
            written++;
        } catch (IOException e) {
            System.err.println("ERROR cannot write the flow CSV: " + e.getMessage());
            System.exit(3);
        }
    }

    private static void listDevices() {
        List<PcapIf> devices = new ArrayList<>();
        StringBuilder err = new StringBuilder();
        if (Pcap.findAllDevs(devices, err) != Pcap.OK) {
            System.err.println("ERROR cannot list devices: " + err);
            System.exit(2);
        }
        for (PcapIf d : devices) {
            StringBuilder addrs = new StringBuilder();
            for (PcapAddr a : d.getAddresses()) {
                byte[] raw = a.getAddr().getData();
                if (raw != null && raw.length == 4) {
                    if (addrs.length() > 0) addrs.append(' ');
                    addrs.append(FormatUtils.ip(raw));
                }
            }
            System.out.println(d.getName() + "\t" + d.getDescription() + "\t" + addrs);
        }
    }

    /** Saved capture -> CSV with the same CICFlowMeter settings as the live capture. */
    private static void convertPcap(String pcapFile, File csv) throws IOException {
        StringBuilder err = new StringBuilder();
        Pcap pcap = Pcap.openOffline(pcapFile, err);
        if (pcap == null) {
            System.err.println("ERROR cannot open " + pcapFile + ": " + err);
            System.exit(2);
        }
        Writer w = new BufferedWriter(new OutputStreamWriter(new FileOutputStream(csv, false), StandardCharsets.UTF_8));
        w.write(FlowFeature.getHeader());
        w.write("\n");
        SecureNetLiveCapture sink = new SecureNetLiveCapture(w);
        FlowGenerator generator = new FlowGenerator(true, FLOW_TIMEOUT_US, ACTIVITY_TIMEOUT_US);
        generator.addFlowListener(sink);
        final long[] packets = {0};
        PcapPacketHandler<Object> handler = (packet, user) -> {
            PcapPacket permanent = new PcapPacket(JMemory.Type.POINTER);
            packet.transferStateAndDataTo(permanent);
            packets[0]++;
            BasicPacketInfo info = PacketReader.getBasicPacketInfo(permanent, true, false);
            if (info != null) {
                generator.addPacket(info);
            }
        };
        pcap.loop(Pcap.LOOP_INFINITE, handler, null);
        pcap.close();
        try {
            Field field = FlowGenerator.class.getDeclaredField("currentFlows");
            field.setAccessible(true);
            @SuppressWarnings("unchecked")
            HashMap<String, BasicFlow> open = (HashMap<String, BasicFlow>) field.get(generator);
            for (BasicFlow flow : open.values()) {
                if (flow.packetCount() > 1) {
                    sink.onFlowGenerated(flow);
                }
            }
        } catch (ReflectiveOperationException e) {
            System.err.println("ERROR " + e);
            System.exit(4);
        }
        w.close();
        System.out.println("CONVERTED " + packets[0] + " " + sink.written);
    }

    @SuppressWarnings("unchecked")
    public static void main(String[] args) throws Exception {
        // System.exit everywhere: jNetPcap leaves non-daemon threads that keep the JVM alive
        if (args.length == 1 && "--list".equals(args[0])) {
            listDevices();
            System.out.flush();
            System.exit(0);
        }
        if (args.length == 1 && "--header".equals(args[0])) {
            System.out.println(FlowFeature.getHeader());
            System.out.flush();
            System.exit(0);
        }
        if (args.length == 3 && "--pcap".equals(args[0])) {
            convertPcap(args[1], new File(args[2]));
            System.exit(0);
        }
        if (args.length < 2) {
            System.err.println("usage: SecureNetLiveCapture <device> <csv> [idleSeconds] | --list | --header");
            System.exit(1);
        }
        final String device = args[0];
        final File csv = new File(args[1]);
        final long idleUs = (args.length > 2 ? Long.parseLong(args[2]) : 15L) * 1_000_000L;

        boolean newFile = !csv.exists() || csv.length() == 0;
        Writer w = new BufferedWriter(new OutputStreamWriter(new FileOutputStream(csv, true), StandardCharsets.UTF_8));
        if (newFile) {
            w.write(FlowFeature.getHeader());
            w.write("\n");
            w.flush();
        }
        final SecureNetLiveCapture sink = new SecureNetLiveCapture(w);
        final FlowGenerator generator = new FlowGenerator(true, FLOW_TIMEOUT_US, ACTIVITY_TIMEOUT_US);
        generator.addFlowListener(sink);

        StringBuilder err = new StringBuilder();
        final Pcap pcap = Pcap.openLive(device, 64 * 1024, Pcap.MODE_PROMISCUOUS, 1000, err);
        if (pcap == null) {
            System.err.println("ERROR cannot open " + device + ": " + err);
            System.exit(2);
        }

        // open flows, to write out the ones that went quiet (CICFlowMeter keeps them private)
        Field field = FlowGenerator.class.getDeclaredField("currentFlows");
        field.setAccessible(true);
        final HashMap<String, BasicFlow> open = (HashMap<String, BasicFlow>) field.get(generator);

        // SecureNet closes our stdin to stop us
        final boolean[] stop = {false};
        Thread watcher = new Thread(() -> {
            try {
                while (System.in.read() != -1) { /* ignore input */ }
            } catch (IOException ignored) { }
            stop[0] = true;
            pcap.breakloop();
        }, "stdin-watcher");
        watcher.setDaemon(true);
        watcher.start();

        final long[] packets = {0};
        PcapPacketHandler<Object> handler = (packet, user) -> {
            // deep copy, as CICFlowMeter's own live worker does
            PcapPacket permanent = new PcapPacket(JMemory.Type.POINTER);
            packet.transferStateAndDataTo(permanent);
            packets[0]++;
            BasicPacketInfo info = PacketReader.getBasicPacketInfo(permanent, true, false);
            if (info != null) {
                generator.addPacket(info);
            }
        };

        System.out.println("READY " + device);
        System.out.flush();

        long lastSweep = System.currentTimeMillis();
        long lastStats = lastSweep;
        while (!stop[0]) {
            int r = pcap.dispatch(-1, handler, null);
            if (r == -1) {
                System.err.println("ERROR capture failed: " + pcap.getErr());
                break;
            }
            long now = System.currentTimeMillis();
            if (now - lastSweep >= 1000) {
                lastSweep = now;
                long cutoff = now * 1000L - idleUs;
                Iterator<Map.Entry<String, BasicFlow>> it = open.entrySet().iterator();
                while (it.hasNext()) {
                    BasicFlow flow = it.next().getValue();
                    if (flow.getLastSeen() < cutoff) {
                        if (flow.packetCount() > 1) {
                            sink.onFlowGenerated(flow);
                        }
                        it.remove();
                    }
                }
            }
            if (now - lastStats >= 5000) {
                lastStats = now;
                System.out.println("STATS " + packets[0] + " " + sink.written + " " + open.size());
                System.out.flush();
            }
        }

        // stopping: write out what is still open, like CICFlowMeter does at the end of a capture
        for (BasicFlow flow : open.values()) {
            if (flow.packetCount() > 1) {
                sink.onFlowGenerated(flow);
            }
        }
        open.clear();
        pcap.close();
        w.close();
        System.out.println("STOPPED " + packets[0] + " " + sink.written);
        System.out.flush();
        System.exit(0);
    }
}
