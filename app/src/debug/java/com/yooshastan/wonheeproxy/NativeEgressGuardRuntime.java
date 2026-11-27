package com.yooshastan.wonheeproxy;

import java.util.*;

/** Exact-owned netfilter transaction. No policy changes, broad flushes or ACCEPT. */
final class NativeEgressGuardRuntime {
    interface OwnedPlan {
        int[] families();
        String chain(int family);
        String tag(int family);
        String prefix(int family);
        String anchor(int family);
        List<String> rules(int family);
    }
    interface Runner { int run(List<String> output,String command)throws Exception; }
    private final Runner runner;
    NativeEgressGuardRuntime(Runner runner){this.runner=runner;}
    private void checked(String cmd)throws Exception{if(runner.run(null,cmd)!=0)throw new IllegalStateException("EGRESS_COMMAND_FAILED");}
    private List<String> listing(OwnedPlan p,int f)throws Exception{
        List<String> out=new ArrayList<>();
        if(runner.run(out,p.prefix(f)+" -S")!=0)throw new IllegalStateException("EGRESS_LIST_UNAVAILABLE");
        if(out.stream().noneMatch(x->x.startsWith("-P OUTPUT ")))throw new IllegalStateException("EGRESS_OUTPUT_UNAVAILABLE");
        return out;
    }
    private static final class Snapshot {
        boolean chain,anchor,first;
        final List<String> rules=new ArrayList<>();
    }
    private Snapshot inspect(OwnedPlan p,int f,boolean full)throws Exception{
        Snapshot state=new Snapshot();String chain=p.chain(f),tag=p.tag(f);
        List<String> expected=p.rules(f),lines=listing(p,f);
        Set<Integer> present=new LinkedHashSet<>();boolean sawOutput=false;
        for(String line:lines){
            if(line.startsWith("-A OUTPUT ")){
                if(line.contains(tag+"_anchor")&&line.endsWith(" -j "+chain)){
                    if(state.anchor)throw new IllegalStateException("EGRESS_DUPLICATE_ANCHOR");
                    state.anchor=true;state.first=!sawOutput;
                }else if(line.contains(chain)||line.contains(tag))throw new IllegalStateException("EGRESS_FOREIGN_REFERENCE");
                sawOutput=true;continue;
            }
            if(line.equals("-N "+chain)){if(state.chain)throw new IllegalStateException("EGRESS_DUPLICATE_CHAIN");state.chain=true;continue;}
            if(line.startsWith("-A "+chain+" ")){
                int index=-1;
                for(int i=0;i<expected.size();i++)if(line.contains(tag+"_"+i+" ")||line.contains("\""+tag+"_"+i+"\" ")){
                    if(index!=-1)throw new IllegalStateException("EGRESS_AMBIGUOUS_RULE");index=i;
                }
                if(index<0||!present.add(index))throw new IllegalStateException("EGRESS_UNOWNED_RULE");
                if(full&&index!=state.rules.size())throw new IllegalStateException("EGRESS_RULE_ORDER_CHANGED");
                state.rules.add(expected.get(index));continue;
            }
            if(line.contains(chain)||line.contains(tag))throw new IllegalStateException("EGRESS_FOREIGN_REFERENCE");
        }
        if(!state.chain&&(state.anchor||!state.rules.isEmpty()))throw new IllegalStateException("EGRESS_CHAIN_MISSING");
        if(full&&(!state.chain||!state.anchor||!state.first||state.rules.size()!=expected.size()))
            throw new IllegalStateException("EGRESS_GUARD_INCOMPLETE_OR_MOVED");
        List<String> checks=new ArrayList<>();
        if(state.anchor)checks.add(p.prefix(f)+" -C OUTPUT "+p.anchor(f));
        for(String rule:state.rules)checks.add(p.prefix(f)+" -C "+chain+" "+rule);
        if(!checks.isEmpty())checked(String.join(" && ",checks));
        return state;
    }
    void preflight(OwnedPlan p)throws Exception{
        for(int f:p.families()){
            Snapshot s=inspect(p,f,false);
            if(s.chain||s.anchor)throw new IllegalStateException("EGRESS_EXISTING_CHAIN_REFUSED");
        }
    }
    void install(NativeEgressGuardPlan p)throws Exception{
        // No activation of broad IPv4 denial until the narrower device trial is proven.
        if(p.mode!=NativeEgressGuardPlan.DNS_IPV6)throw new IllegalStateException("EGRESS_STRICT_IPV4_NOT_ENABLED");
        installOwned(p);
    }
    // Explicit separate opt-in. Never promote a narrow session or enable
    // discovery/validation exceptions in this strict preview.
    void installStrict(NativeEgressGuardPlan p)throws Exception{
        if(p.mode!=NativeEgressGuardPlan.STRICT_IP||p.localDiscovery||p.validationPort!=0)
            throw new IllegalStateException("EGRESS_STRICT_CONFIG_REFUSED");
        installOwned(p);
    }
    // Read-only, including after process death/reboot. A journal alone is not
    // evidence that the kernel still has the exact rules and first anchors.
    String offlineState(OwnedPlan p)throws Exception{
        boolean any=false,complete=true;
        for(int f:p.families()){
            Snapshot s=inspect(p,f,false);
            any|=s.chain||s.anchor;
            complete&=s.chain&&s.anchor&&s.first&&s.rules.equals(p.rules(f));
        }
        if(!any)return "Absent";
        if(!complete)return "Partial or moved";
        verify(p);
        return "Exact rules and first anchors present";
    }
    void installValidation(NativeValidationDnsPlan p)throws Exception{installOwned(p);}
    private void installOwned(OwnedPlan p)throws Exception{
        preflight(p);
        for(int f:p.families()){
            checked(p.prefix(f)+" -N "+p.chain(f));
            for(String rule:p.rules(f))checked(p.prefix(f)+" -A "+p.chain(f)+" "+rule);
            Snapshot s=inspect(p,f,false);
            if(!s.chain||s.anchor||!s.rules.equals(p.rules(f)))throw new IllegalStateException("EGRESS_PREANCHOR_AUDIT_FAILED");
        }
        for(int f:p.families())checked(p.prefix(f)+" -I OUTPUT 1 "+p.anchor(f));
        verify(p);
    }
    void verify(OwnedPlan p)throws Exception{
        for(int f:p.families())inspect(p,f,true);
    }
    void remove(OwnedPlan p)throws Exception{
        // Refuse foreign or duplicate objects in all owned families before mutation.
        Map<Integer,Snapshot> snapshots=new LinkedHashMap<>();
        for(int f:p.families())snapshots.put(f,inspect(p,f,false));
        for(int f:p.families()){
            Snapshot s=snapshots.get(f);
            if(s.anchor)checked(p.prefix(f)+" -D OUTPUT "+p.anchor(f));
        }
        for(int f:p.families()){
            Snapshot s=snapshots.get(f);
            if(!s.chain)continue;
            // Delete each known rule, not the whole chain's contents.
            for(String rule:s.rules)checked(p.prefix(f)+" -D "+p.chain(f)+" "+rule);
            checked(p.prefix(f)+" -X "+p.chain(f));
        }
        preflight(p);
    }
    String validationCounters(NativeValidationDnsPlan p)throws Exception{
        StringBuilder result=new StringBuilder();
        for(int f:p.families()){
        List<String> out=new ArrayList<>();
        if(runner.run(out,p.prefix(f)+" -L "+p.chain(f)+" -v -n -x")!=0)
            throw new IllegalStateException("VALIDATION_COUNTERS_UNAVAILABLE");
        long[] counts=new long[2];boolean[] seen=new boolean[2];int rows=0;
        for(String line:out){
            String[] x=line.trim().split("\\s+");
            if(x.length<3||!x[0].matches("[0-9]+"))continue;
            int idx=-1;
            for(int i=0;i<2;i++)if(line.contains("/* "+p.tag(f)+"_"+i+" */")){
                if(idx!=-1)throw new IllegalStateException("VALIDATION_COUNTER_TAG_AMBIGUOUS");
                idx=i;
            }
            if(idx<0||seen[idx]||idx!=rows++||!x[2].equals("REDIRECT"))
                throw new IllegalStateException("VALIDATION_COUNTER_TAG_MISMATCH");
            seen[idx]=true;counts[idx]=Long.parseLong(x[0]);
        }
        if(rows!=2)throw new IllegalStateException("VALIDATION_COUNTER_ROWS_MISMATCH");
        if(result.length()>0)result.append(" · ");
        result.append("NAT IPv").append(f).append(" redirect UDP=").append(counts[0]).append(" TCP=").append(counts[1]);
        }
        if(!p.dual)result.append(" · IPv6 redirect not installed");
        return result.toString();
    }
    String counters(NativeEgressGuardPlan p)throws Exception{
        StringBuilder report=new StringBuilder();
        for(int f:new int[]{4,6}){
            List<String> out=new ArrayList<>();
            if(runner.run(out,p.prefix(f)+" -L "+p.chain(f)+" -v -n -x")!=0)throw new IllegalStateException("EGRESS_COUNTERS_UNAVAILABLE");
            long dropped=0,returned=0,dns53=0,dns853=0,mdns=0,ssdp=0,other=0,terminalDrop=0;int rows=0;
            List<String> expected=p.rules(f);boolean detailed=true;
            long[] wifiDns=new long[5];long nonWifiDns=0;
            int[] ownerUids={1051,1073,0,1000};
            for(String l:out){
                String[] x=l.trim().split("\\s+");
                if(x.length<3||!x[0].matches("[0-9]+"))continue;
                long n=Long.parseLong(x[0]);
                if(rows>=expected.size())throw new IllegalStateException("EGRESS_COUNTER_ROWS_MISMATCH");
                String rule=expected.get(rows),tag=p.tag(f)+"_"+rows;
                if(!l.contains("/* "+tag+" */"))detailed=false;
                rows++;
                if(x[2].equals("DROP")){
                    dropped+=n;
                    if(rows==expected.size()&&rule.endsWith("-j DROP"))terminalDrop=n;
                    if(rule.contains("--dport 53 ")){
                        dns53+=n;
                        if(p.dnsDiagnostics){
                            if(rule.contains("-o wlan0 ")){
                                int owner=4;
                                for(int i=0;i<ownerUids.length;i++)
                                    if(rule.contains("--uid-owner "+ownerUids[i]+" "))owner=i;
                                wifiDns[owner]+=n;
                            }else nonWifiDns+=n;
                        }
                    }
                    else if(rule.contains("--dport 853 "))dns853+=n;
                    else if(rule.contains("--dport 5353 "))mdns+=n;
                    else if(rule.contains("--dport 1900 "))ssdp+=n;
                    else other+=n;
                }else if(x[2].equals("RETURN"))returned+=n;
                else throw new IllegalStateException("EGRESS_COUNTER_TARGET_MISMATCH");
                if(!rule.endsWith("-j "+x[2]))detailed=false;
            }
            if(rows!=p.rules(f).size())throw new IllegalStateException("EGRESS_COUNTER_ROWS_MISMATCH");
            if(report.length()>0)report.append(" · ");
            report.append("IPv").append(f).append(" dropped=").append(dropped).append(" returned=").append(returned);
            if(detailed)report.append(" [DNS53=").append(dns53).append(" DNS853=").append(dns853)
                .append(" mDNS=").append(mdns).append(" SSDP=").append(ssdp).append(" other=").append(other).append("]");
            else report.append(" [per-rule counters unavailable]");
            if(detailed&&p.mode==NativeEgressGuardPlan.STRICT_IP)report.append(" [terminal DROP packets=").append(terminalDrop).append("]");
            if(detailed&&p.dnsDiagnostics)report.append(" [DNS53 Wi-Fi owner 1051=").append(wifiDns[0])
                .append(" 1073=").append(wifiDns[1]).append(" root=").append(wifiDns[2])
                .append(" system=").append(wifiDns[3]).append(" other/unmatched=").append(wifiDns[4])
                .append(" non-Wi-Fi=").append(nonWifiDns).append("]");
        }
        return report.toString();
    }
}
