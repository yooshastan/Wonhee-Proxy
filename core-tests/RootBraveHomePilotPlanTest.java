package com.yooshastan.wonheeproxy;

public final class RootBraveHomePilotPlanTest {
    private static int n;
    private static void yes(boolean value) {
        n++;
        if (!value) throw new AssertionError("Brave Home safety test #" + n);
    }

    public static void main(String[] args) {
        var p=RootBraveHomePilotPlan.compile(10308,"wnm4ea140588150");
        yes(p.selector.equals("ip -4 rule add pref 12699 iif lo uidrange "
                + "10308-10308 to 10.0.0.169/32 lookup 51002"));
        yes(p.hook4.contains("--uid-owner 10308"));
        yes(p.hook6.contains("--uid-owner 10308"));
        yes(p.allow4.contains("-o wnm4ea140588150"));
        yes(p.allow4.contains("--dport 4533"));
        for(String invalid:new String[]{"rmnet16","wlan0","wnmINVALID",""}) {
            try { RootBraveHomePilotPlan.compile(10308,invalid);
                throw new AssertionError("accepted invalid device "+invalid);
            } catch(IllegalArgumentException expected) { yes(true); }
        }
        try { RootBraveHomePilotPlan.compile(0,p.dev);
            throw new AssertionError("zero UID"); }
        catch(IllegalArgumentException expected) {yes(true);}
        String exact="12699: from all to 10.0.0.169 iif lo uidrange "
                +"10308-10308 lookup 51002";
        yes(RootBraveHomePilotPlan.exactSelector(exact,10308)==1);
        yes(RootBraveHomePilotPlan.exactSelector("0: from all lookup local",10308)==0);
        yes(RootBraveHomePilotPlan.exactSelector(exact+"\n"+exact,10308)==-1);
        yes(RootBraveHomePilotPlan.exactSelector(exact.replace("10308-10308","10300-10300"),10308)==-1);
        yes(RootBraveHomePilotPlan.exactSelector(exact.replace("51002","254"),10308)==-1);
        yes(RootBraveHomePilotPlan.exactSelector("12699: from all lookup 51002",10308)==-1);
        yes(RootBraveHomePilotPlan.onlyExactOutputHook(
                "-P OUTPUT ACCEPT\n"+p.hook4,RootBraveHomePilotPlan.CHAIN4,
                RootBraveHomePilotPlan.TAG4,p.hook4,true));
        yes(RootBraveHomePilotPlan.onlyExactOutputHook(
                "-P OUTPUT ACCEPT",RootBraveHomePilotPlan.CHAIN4,
                RootBraveHomePilotPlan.TAG4,p.hook4,false));
        yes(!RootBraveHomePilotPlan.onlyExactOutputHook(
                p.hook4+"\n"+p.hook4,RootBraveHomePilotPlan.CHAIN4,
                RootBraveHomePilotPlan.TAG4,p.hook4,true));
        yes(!RootBraveHomePilotPlan.onlyExactOutputHook(
                p.hook4.replace("10308","10300"),
                RootBraveHomePilotPlan.CHAIN4,RootBraveHomePilotPlan.TAG4,p.hook4,true));
        String v4="-N WN_BRAVE_HOME4\n"+p.allow4+"\n-A WN_BRAVE_HOME4 -j REJECT";
        yes(RootBraveHomePilotPlan.chainIsExactPrefix(v4,RootBraveHomePilotPlan.CHAIN4,
                p.dev,true));
        yes(RootBraveHomePilotPlan.chainIsExactPrefix(
                "-N WN_BRAVE_HOME4\n-A WN_BRAVE_HOME4 -d 10.0.0.169/32"
                +" -o "+p.dev+" -p tcp -m tcp --dport 4533 -j RETURN"
                +"\n-A WN_BRAVE_HOME4 -j REJECT --reject-with icmp-port-unreachable",
                RootBraveHomePilotPlan.CHAIN4,p.dev,true));
        yes(RootBraveHomePilotPlan.chainIsExactPrefix(
                "-N WN_BRAVE_HOME4",RootBraveHomePilotPlan.CHAIN4,p.dev,true));
        yes(!RootBraveHomePilotPlan.chainIsExactPrefix(
                v4+"\n-A WN_BRAVE_HOME4 -j ACCEPT",
                RootBraveHomePilotPlan.CHAIN4,p.dev,true));
        yes(!RootBraveHomePilotPlan.chainIsExactPrefix(
                v4.replace("--dport 4533","--dport 80"),
                RootBraveHomePilotPlan.CHAIN4,p.dev,true));
        yes(RootBraveHomePilotPlan.chainIsExactPrefix(
                "-N WN_BRAVE_HOME6\n-A WN_BRAVE_HOME6 -j REJECT",
                RootBraveHomePilotPlan.CHAIN6,p.dev,false));
        yes(RootBraveHomePilotPlan.chainIsExactPrefix(
                "-N WN_BRAVE_HOME6\n-A WN_BRAVE_HOME6 -j REJECT --reject-with icmp6-port-unreachable",
                RootBraveHomePilotPlan.CHAIN6,p.dev,false));
        yes(!RootBraveHomePilotPlan.chainIsExactPrefix(
                "-N WN_BRAVE_HOME6\n-A WN_BRAVE_HOME6 -j ACCEPT",
                RootBraveHomePilotPlan.CHAIN6,p.dev,false));
        System.out.println("BRAVE_HOME_EXACT_POLICY "+n+" PASS");
    }
}
