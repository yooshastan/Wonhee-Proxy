package com.yooshastan.wonheeproxy;
public final class NativeAppCategorySuggestionsTest {
    static void eq(int a,int b){if(a!=b)throw new AssertionError(a+" != "+b);}
    public static void main(String[] args){
        eq(NativeAppCategorySuggestions.suggest("com.yooshastan.ultmessenger.foss",-1,false),AppUseCategories.PRIVATE);
        eq(NativeAppCategorySuggestions.suggest("com.yooshastan.mokamusicplayer",-1,false),AppUseCategories.HOME);
        eq(NativeAppCategorySuggestions.suggest("com.kroger.mobile",-1,false),AppUseCategories.REGIONAL);
        eq(NativeAppCategorySuggestions.suggest("unknown.app",-1,false),AppUseCategories.EVERYDAY);
        eq(NativeAppCategorySuggestions.suggest("android",-1,true),AppUseCategories.SYSTEM);
        eq(NativeAppCategorySuggestions.suggest("unknown.media",2,false),AppUseCategories.MEDIA);
        System.out.println("Local category suggestions PASS");
    }
}
