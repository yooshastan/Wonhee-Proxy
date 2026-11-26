package com.yooshastan.wonheeproxy;
final class NativeRecoveryPlan {
    private NativeRecoveryPlan(){}
    static long delay(int attempt){
        if(attempt<0||attempt>=5)throw new IllegalArgumentException();
        return 1000L<<attempt;
    }
}
