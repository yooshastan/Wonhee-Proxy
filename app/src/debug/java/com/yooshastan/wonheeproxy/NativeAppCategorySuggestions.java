package com.yooshastan.wonheeproxy;

import java.util.Locale;

// Local suggestions only; user overrides remain authoritative. No network lookup.
final class NativeAppCategorySuggestions {
    static int suggest(String pkg,int androidCategory,boolean system){
        String p=pkg.toLowerCase(Locale.ROOT);
        if(p.startsWith("com.yooshastan.ultmessenger")||p.equals("org.telegram.messenger")||p.equals("org.thoughtcrime.securesms")||p.equals("org.torproject.torbrowser"))return AppUseCategories.PRIVATE;
        if(p.startsWith("com.yooshastan.moka")||p.equals("org.kde.kdeconnect_tp")||p.equals("io.homeassistant.companion.android"))return AppUseCategories.HOME;
        if(p.equals("com.kroger.mobile")||p.equals("com.usablenet.mobile.walgreen")||p.equals("com.walmart.android")||p.equals("com.amazon.mShop.android.shopping".toLowerCase(Locale.ROOT)))return AppUseCategories.REGIONAL;
        if(p.equals("com.paypal.android.p2pmobile")||p.equals("com.chase.sig.android")||p.equals("com.infonow.bofa"))return AppUseCategories.FINANCE;
        if(p.startsWith("com.microsoft.office.")||p.equals("com.microsoft.teams")||p.equals("com.Slack".toLowerCase(Locale.ROOT)))return AppUseCategories.WORK;
        if(system)return AppUseCategories.SYSTEM;
        // Android ApplicationInfo categories: game, audio, video, image, social, news, maps, productivity.
        if(androidCategory==0||androidCategory==1||androidCategory==2||androidCategory==3)return AppUseCategories.MEDIA;
        if(androidCategory==4)return AppUseCategories.PRIVATE;
        if(androidCategory==6)return AppUseCategories.REGIONAL;
        if(androidCategory==7)return AppUseCategories.WORK;
        return AppUseCategories.EVERYDAY;
    }
    private NativeAppCategorySuggestions(){}
}
