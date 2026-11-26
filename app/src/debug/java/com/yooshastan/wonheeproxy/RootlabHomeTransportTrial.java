package com.yooshastan.wonheeproxy;

import android.content.Context;
import android.content.SharedPreferences;
import com.wireguard.android.util.RootShell;
import com.wireguard.android.util.ToolsInstaller;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/** Debug-only, explicit reproduction of the device-tested IPv6 transport fix.
 * Not a production mark allocation, a VPN service, or credential authorization.
 * The existing Home UID guard remains in place. Only exact owned changes are undone.
 */
final class RootlabHomeTransportTrial {
    private static final String PREF = "wonhee_rootlab_home_transport_v1";
    private static final String KEY = "pending";
    private static final long CANDIDATE = 0x00800000L;
    private final Context app;

    RootlabHomeTransportTrial(Context context) { app = context.getApplicationContext(); }
    static boolean pendingOrUnknown(Context app) {
        try { return app.getSharedPreferences(PREF, Context.MODE_PRIVATE).contains(KEY); }
        catch (RuntimeException e) { return true; }
    }
    private SharedPreferences prefs() { return app.getSharedPreferences(PREF, Context.MODE_PRIVATE); }
    private RootShell shell() throws Exception {
        RootShell s = new RootShell(app);
        s.start();
        new ToolsInstaller(app,s).ensureToolsAvailable();
        return s;
    }
    private static List<String> read(RootShell s, String cmd) throws Exception {
        List<String> lines = new ArrayList<>();
        if (s.run(lines,cmd) != 0) throw new IllegalStateException("Kernel read unavailable");
        return lines;
    }
    private static String one(RootShell s,String cmd) throws Exception {
        List<String> lines=read(s,cmd);
        if (lines.size()!=1 || lines.get(0).trim().isEmpty())
            throw new IllegalStateException("Ambiguous kernel read");
        return lines.get(0).trim();
    }
    private static void run(RootShell s,String cmd) throws Exception {
        if (s.run(null,cmd)!=0) throw new IllegalStateException("Kernel write failed");
    }
    private static Set<String> devices(RootShell s) throws Exception {
        String v=String.join(" ",read(s,"wg show interfaces")).trim();
        return v.isEmpty()?Collections.emptySet():new HashSet<>(Arrays.asList(v.split("\\s+")));
    }
    private static String boot(RootShell s) throws Exception {
        return one(s,"cat /proc/sys/kernel/random/boot_id");
    }
    private static String index(RootShell s,String d) throws Exception {
        return one(s,"cat /sys/class/net/"+d+"/ifindex");
    }
    private static String key(RootShell s,String d) throws Exception {
        return one(s,"wg show "+d+" public-key");
    }
    private static long mark(RootShell s,String d) throws Exception {
        String v=one(s,"wg show "+d+" fwmark");
        if ("off".equals(v)||"0".equals(v)||"0x0".equals(v)) return 0;
        long m=RootFirewallMark.parse(Collections.singletonList(v));
        if(m==0) throw new IllegalStateException("Unknown mark");
        return m;
    }
    private static String endpoint(RootShell s,String d) throws Exception {
        String[] f=one(s,"wg show "+d+" endpoints").split("\\s+");
        if(f.length!=2) throw new IllegalStateException("Single numeric peer required");
        return RootTcpProbeTarget.parse(f[1]).label();
    }
    private static int port(RootShell s,String d) throws Exception {
        String v=one(s,"wg show "+d+" listen-port");
        if(!v.matches("[0-9]{1,5}")) throw new IllegalStateException("Invalid port");
        int p=Integer.parseInt(v);
        if(p<1||p>65535) throw new IllegalStateException("Invalid port");
        return p;
    }
    private static String route(RootShell s,RootTcpProbeTarget ep,long m) throws Exception {
        return String.join(" ",read(s,"ip -6 route get "+ep.address+" mark 0x"
                +Long.toHexString(m))).replaceAll("\\s+"," ").trim();
    }
    private static String routeDevice(String route) {
        java.util.regex.Matcher m=java.util.regex.Pattern.compile(
                "(?:^| )dev ([A-Za-z0-9_.-]+)(?: |$)").matcher(route);
        if(!m.find()) throw new IllegalStateException("Unknown underlay");
        return m.group(1);
    }

    /** Immutable identity; never included in diagnostic text. */
    private static final class Saved {
        final String boot,index,key;
        final RootTransportGuardPlan.Plan plan;
        Saved(String boot,String index,String key,RootTransportGuardPlan.Plan plan) {
            if(!boot.matches("[0-9a-fA-F-]{36}")||!index.matches("[1-9][0-9]{0,9}")
                    ||!key.matches("[A-Za-z0-9+/]{43}=")
                    ||plan.endpoint.family!=6||plan.mark!=CANDIDATE
                    ||!plan.uplink.matches("rmnet[A-Za-z0-9_.-]*"))
                throw new IllegalArgumentException("Unknown trial identity");
            this.boot=boot;this.index=index;this.key=key;this.plan=plan;
        }
        String encode() {
            return String.join("|","WHT1",boot,index,key,plan.device,plan.uplink,
                    plan.endpoint.label(),Integer.toString(plan.localPort));
        }
        static Saved decode(String raw) {
            String[] p=raw.split("\\|",-1);
            if(p.length!=8||!"WHT1".equals(p[0])||!p[7].matches("[0-9]{1,5}"))
                throw new IllegalArgumentException("Unknown transport journal");
            RootTransportGuardPlan.Plan plan=RootTransportGuardPlan.compile(
                    p[4],p[6],Integer.parseInt(p[7]),CANDIDATE,p[5],p[5],
                    Collections.singleton(p[4]),Collections.emptySet());
            return new Saved(p[1],p[2],p[3],plan);
        }
    }

    private final class Adapter implements RootTransportGuardLifecycle.Kernel,
            RootTransportGuardLifecycle.Journal {
        private final RootShell s;
        private final Saved saved;
        private final RootTransportGuardPlan.Plan plan;
        Adapter(RootShell s,Saved saved){this.s=s;this.saved=saved;plan=saved.plan;}
        public boolean pending(){return prefs().contains(KEY);}
        public void intent(){
            if(pending()||!prefs().edit().putString(KEY,saved.encode()).commit()
                    ||!saved.encode().equals(prefs().getString(KEY,null)))
                throw new IllegalStateException("Cannot persist exact transport intent");
        }
        public void clear(){
            if(!saved.encode().equals(prefs().getString(KEY,null))
                    ||!prefs().edit().remove(KEY).commit()||pending())
                throw new IllegalStateException("Cannot clear exact transport intent");
        }
        public RootTransportGuardLifecycle.State inspect() throws Exception {
            if(pending()&&!saved.encode().equals(prefs().getString(KEY,null)))
                return RootTransportGuardLifecycle.State.CONFLICT;
            List<String> rows=new ArrayList<>();
            boolean chain=false;
            String name=plan.chain, tag=RootTransportGuardPlan.TAG+"_"+plan.device;
            int tagCount=0;
            for(String raw:read(s,"ip6tables -w 5 -t filter -S")){
                String v=raw.trim().replace("\"","").replaceAll("\\s+"," ");
                if(v.equals("-N "+name)) chain=true;
                if(v.startsWith("-A "+name+" ")) rows.add(v);
                if(v.contains(tag)){
                    tagCount++;
                    if(!v.startsWith("-A "+name+" "))
                        return RootTransportGuardLifecycle.State.CONFLICT;
                }
            }
            boolean present=devices(s).contains(plan.device);
            if(!present&&!chain&&tagCount==0) return RootTransportGuardLifecycle.State.GONE;
            if(!present||!chain||!saved.boot.equals(boot(s))
                    ||!saved.index.equals(index(s,plan.device))
                    ||!saved.key.equals(key(s,plan.device)))
                return RootTransportGuardLifecycle.State.CONFLICT;
            if(rows.isEmpty()||rows.size()>2) return RootTransportGuardLifecycle.State.CONFLICT;
            String reject="-A "+name+" -j REJECT", last=rows.get(rows.size()-1);
            if(!last.equals(reject)&&!last.equals(reject+" --reject-with icmp6-port-unreachable"))
                return RootTransportGuardLifecycle.State.CONFLICT;
            boolean rule=rows.size()==2;
            if(rule){
                if(tagCount!=1||!rows.get(0).contains(tag)
                        ||s.run(null,String.join(" ",plan.check()))!=0)
                    return RootTransportGuardLifecycle.State.CONFLICT;
            }else if(tagCount!=0) return RootTransportGuardLifecycle.State.CONFLICT;
            long current=RootlabHomeTransportTrial.mark(s,plan.device);
            if(current!=0&&current!=plan.mark) return RootTransportGuardLifecycle.State.CONFLICT;
            if(rule) return current==plan.mark?RootTransportGuardLifecycle.State.ACTIVE
                    :RootTransportGuardLifecycle.State.RULE_ONLY;
            return current==plan.mark?RootTransportGuardLifecycle.State.MARKED
                    :RootTransportGuardLifecycle.State.BASELINE;
        }
        public void mark() throws Exception {
            if(inspect()!=RootTransportGuardLifecycle.State.BASELINE)
                throw new IllegalStateException("Changed baseline");
            run(s,"wg set "+plan.device+" fwmark "+RootFirewallMark.display(plan.mark));
        }
        public void insert() throws Exception {
            if(inspect()!=RootTransportGuardLifecycle.State.MARKED
                    ||!plan.endpoint.label().equals(endpoint(s,plan.device))
                    ||plan.localPort!=port(s,plan.device)
                    ||!plan.uplink.equals(routeDevice(route(s,plan.endpoint,plan.mark))))
                throw new IllegalStateException("Changed transport");
            run(s,String.join(" ",plan.insert()));
        }
        public void remove() throws Exception {
            RootTransportGuardLifecycle.State state=inspect();
            if(state!=RootTransportGuardLifecycle.State.ACTIVE
                    &&state!=RootTransportGuardLifecycle.State.RULE_ONLY)
                throw new IllegalStateException("Changed exception");
            run(s,String.join(" ",plan.remove()));
        }
        public void unmark() throws Exception {
            if(inspect()!=RootTransportGuardLifecycle.State.MARKED)
                throw new IllegalStateException("Changed mark");
            run(s,"wg set "+plan.device+" fwmark 0");
        }
    }

    String activate(int uid,String device,Set<String> selected) throws Exception {
        if(pendingOrUnknown(app)||RootlabBraveHomePilot.pendingOrUnknown(app))
            return "TRANSPORT REFUSED: existing recovery state. Use Safe Stop.";
        if(!new RootlabMokaHomeUidSelector(app).exactActiveForTransport(uid,device))
            return "TRANSPORT REFUSED: exact existing Moka policy required.";
        RootShell s=shell();
        Set<String> actual=devices(s);
        if(selected.size()!=3||!actual.equals(selected)||!actual.contains(device))
            return "TRANSPORT REFUSED: expected three known kernel links only.";
        for(String dev:actual) if(mark(s,dev)!=0)
            return "TRANSPORT REFUSED: existing transport mark.";
        RootTcpProbeTarget ep=RootTcpProbeTarget.parse(endpoint(s,device));
        if(ep.family!=6) return "TRANSPORT REFUSED: IPv6 outer transport trial only.";
        String original=route(s,ep,0),candidate=route(s,ep,CANDIDATE);
        if(!original.equals(candidate)) return "TRANSPORT REFUSED: candidate changes route.";
        String uplink=routeDevice(original);
        if(!uplink.startsWith("rmnet")) return "TRANSPORT REFUSED: cellular required.";
        RootTransportGuardPlan.Plan plan=RootTransportGuardPlan.compile(device,ep.label(),
                port(s,device),CANDIDATE,uplink,uplink,selected,Collections.emptySet());
        Saved saved=new Saved(boot(s),index(s,device),key(s,device),plan);
        Adapter a=new Adapter(s,saved);
        RootTransportGuardLifecycle.Outcome outcome=RootTransportGuardLifecycle.start(a,a);
        return "HOME TRANSPORT TRIAL: "+outcome
                +". Experimental mark, not a production reservation. "
                +"Only the no-login TCP diagnostic is permitted. No credentials. "
                +"Run Exact-owned Safe Stop afterward.";
    }
    String recover() throws Exception {
        String raw=prefs().getString(KEY,null);
        if(raw==null) return "HOME TRANSPORT: no journal.";
        Adapter a=new Adapter(shell(),Saved.decode(raw));
        return "HOME TRANSPORT RECOVERY: "+RootTransportGuardLifecycle.stop(a,a);
    }
}
