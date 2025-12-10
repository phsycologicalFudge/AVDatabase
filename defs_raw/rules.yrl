rule VX_APK_CLUSTER_00001 {
    strings:
        $s0 = "NYgfP0VTzf4eHU2ymW/xc7O0ryT0ECyI"
        $s1 = "res/drawable-xhdpi/t.xml"
        $s2 = "lib/armeabi-v7a/libvg.so"
    condition:
        any of ($s0, $s1, $s2)
}

rule VX_APK_CLUSTER_00002 {
    strings:
        $s0 = "NYgfP0VTzf4eHU2ymW/xc7O0ryT0ECyI"
        $s1 = "res/drawable-xhdpi/t.xml"
        $s2 = "lib/arm64-v8a/libvg.so"
    condition:
        any of ($s0, $s1, $s2)
}

rule VX_APK_CLUSTER_00003 {
    strings:
        $s0 = "NYgfP0VTzf4eHU2ymW/xc7O0ryT0ECyI"
        $s1 = "res/drawable-xhdpi/t.xml"
        $s2 = "lib/arm64-v8a/libvc.so"
    condition:
        any of ($s0, $s1, $s2)
}

rule VX_APK_CLUSTER_00004 {
    strings:
        $s0 = "NYgfP0VTzf4eHU2ymW/xc7O0ryT0ECyI"
        $s1 = "res/drawable-xhdpi/t.xml"
        $s2 = "lib/arm64-v8a/libvg.so"
        $s3 = "pjgybv1j5hpi8lHInX3MIwzjtlT/tm8skX"
    condition:
        any of ($s0, $s1, $s2, $s3)
}

rule VX_APK_CLUSTER_00005 {
    strings:
        $s0 = "res/raw/act_schemes.cfg"
        $s1 = "res/xml/texts.xml"
        $s2 = "res/layout/off.xml"
        $s3 = "c/nL07Gy7K3maRlEL1MxCVwf4FU"
        $s4 = "res/drawable/checkbox_label_background.9.png"
        $s5 = "18/aznZQx9KN6O9oFh9zkx3tu4w"
        $s6 = "res/drawable/0.temp"
        $s7 = "ShowLink.java"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00006 {
    strings:
        $s0 = "NYgfP0VTzf4eHU2ymW/xc7O0ryT0ECyI"
        $s1 = "res/drawable-xhdpi/t.xml"
        $s2 = "lib/arm64-v8a/libvg.so"
        $s3 = "GRcqHsSaEYTlYJ/8rb7WNrb/tvgjNbFCXCILYfjN24I"
    condition:
        any of ($s0, $s1, $s2, $s3)
}

rule VX_APK_CLUSTER_00007 {
    strings:
        $s0 = "NYgfP0VTzf4eHU2ymW/xc7O0ryT0ECyI"
        $s1 = "res/drawable-xhdpi/t.xml"
        $s2 = "lib/armeabi-v7a/libvg.so"
        $s3 = "CgkjDZ366wQjUefKNMo8VPwY2s5/NZjvbBOYcIGswMY"
    condition:
        any of ($s0, $s1, $s2, $s3)
}

rule VX_APK_CLUSTER_00008 {
    strings:
        $s0 = "res/xml-v22/accessibility_service_config.xml"
        $s1 = "MReceiver.java"
        $s2 = "res/xml-v14/accessibility_service_config.xml"
        $s3 = "Localservice.java"
        $s4 = "MJobService.java"
        $s5 = "assets/fields.css"
        $s6 = "res/mipmap-hdpi/application_icon.png"
        $s7 = "assets/guide.gif"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00009 {
    strings:
        $s0 = "lib/armeabi/libcrypt_sign.so"
        $s1 = "assets/wyzf/res.bin"
        $s2 = "13/Ayo17/DPtKNh46JVIv6osRPo"
        $s3 = "Qmxju5/Ap5mgu1cFHvmJFycrWMw"
        $s4 = "com/unicom/wounipaysms/dialog/images/cancel.png"
        $s5 = "com/unicom/wounipaysms/dialog/images/cancel_on.png"
        $s6 = "com/unicom/wounipaysms/dialog/images/confirm_bt.9.png"
        $s7 = "com/unicom/wounipaysms/dialog/images/confirm_bt_on.9.png"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00010 {
    strings:
        $s0 = "lib/armeabi/libcrypt_sign.so"
        $s1 = "assets/wyzf/res.bin"
        $s2 = "13/Ayo17/DPtKNh46JVIv6osRPo"
        $s3 = "Qmxju5/Ap5mgu1cFHvmJFycrWMw"
        $s4 = "com/unicom/wounipaysms/dialog/images/cancel.png"
        $s5 = "com/unicom/wounipaysms/dialog/images/cancel_on.png"
        $s6 = "com/unicom/wounipaysms/dialog/images/confirm_bt.9.png"
        $s7 = "com/unicom/wounipaysms/dialog/images/confirm_bt_on.9.png"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00011 {
    strings:
        $s0 = "lib/armeabi-v7a/libkc.so"
        $s1 = "res/drawable-xhdpi/i.xml"
    condition:
        any of ($s0, $s1)
}

rule VX_APK_CLUSTER_00012 {
    strings:
        $s0 = "lib/armeabi/libcrypt_sign.so"
        $s1 = "assets/wyzf/res.bin"
        $s2 = "13/Ayo17/DPtKNh46JVIv6osRPo"
        $s3 = "Qmxju5/Ap5mgu1cFHvmJFycrWMw"
        $s4 = "com/unicom/wounipaysms/dialog/images/cancel.png"
        $s5 = "com/unicom/wounipaysms/dialog/images/cancel_on.png"
        $s6 = "com/unicom/wounipaysms/dialog/images/confirm_bt.9.png"
        $s7 = "com/unicom/wounipaysms/dialog/images/confirm_bt_on.9.png"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00013 {
    strings:
        $s0 = "res/layout/rools.xml"
        $s1 = "sRNe/i3dVkjN0LlFUIHAc3hBgfM"
        $s2 = "assets/rools.txt"
        $s3 = "/mnt/sdcard/download/"
        $s4 = "/stats/adv.php"
        $s5 = "/stats/open.php"
        $s6 = "/stats/press.php"
        $s7 = "rools.txt"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00014 {
    strings:
        $s0 = "res/raw/data.db"
        $s1 = "Lorg/MobileDb/Field"
        $s2 = "Lorg/MobileDb/MobileDatabase"
        $s3 = "Lorg/MobileDb/Row"
        $s4 = "Lorg/MobileDb/Table"
        $s5 = "Lorg/MobileDb/Utf8StringBuffer"
        $s6 = ".---NKxx"
        $s7 = "MobileDatabase.java"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00015 {
    strings:
        $s0 = "Lcom/baidu/location/h$a"
        $s1 = "Lcom/baidu/location/f$a"
        $s2 = "Lcom/baidu/location/s$1"
        $s3 = "com.baidu.locTest.LocationServer"
        $s4 = "Lcom/baidu/location/aq$a"
        $s5 = "/con.dat"
        $s6 = "Lcom/baidu/location/y$a"
        $s7 = "Lcom/baidu/location/ai$1"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00016 {
    strings:
        $s0 = "KPx/L5zRxoAcWl6aHTaag/qEiLQ"
        $s1 = "assets/BATTLETO.NES"
        $s2 = "Lcom/trdos/cores/Da"
        $s3 = "Lcom/trdos/cores/Db"
        $s4 = "Lcom/trdos/cores/Dc"
        $s5 = "Lcom/trdos/cores/Ma"
        $s6 = "Lcom/trdos/cores/MainActivity"
        $s7 = "Lcom/trdos/cores/Sb"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00017 {
    strings:
        $s0 = "tmx2ePqGYvOES/jfGp8NEsyAr6VQe6a1ddiSGcNeMew"
        $s1 = "5WUT8N6LC6PF97Z1cG6m0zl4jGoS61p2PFskeHZ/7H8"
        $s2 = "li3j269Eu/41nTYBJ6nDrqOn4nE"
        $s3 = "sSXSzEqFKMrA6jBWGd3/ny0rkM5WbWISaQbV9uWVDnU"
        $s4 = "waSlUxaesqmgrWPt/coLJ37Snvg"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4)
}

rule VX_APK_CLUSTER_00018 {
    strings:
        $s0 = "res/layout/finish.xml"
        $s1 = "res/raw/config.txt"
        $s2 = "OpInfo.java"
        $s3 = "assets/texts/finish_activity.txt"
        $s4 = "assets/texts/first_activity.txt"
        $s5 = "assets/texts/ru/finish_activity.txt"
        $s6 = "assets/texts/ru/first_activity.txt"
        $s7 = "assets/texts/ru/rules_activity.txt"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00019 {
    strings:
        $s0 = "lib/armeabi/libcrypt_sign.so"
        $s1 = "assets/wyzf/res.bin"
        $s2 = "13/Ayo17/DPtKNh46JVIv6osRPo"
        $s3 = "Qmxju5/Ap5mgu1cFHvmJFycrWMw"
        $s4 = "com/unicom/wounipaysms/dialog/images/cancel.png"
        $s5 = "com/unicom/wounipaysms/dialog/images/cancel_on.png"
        $s6 = "com/unicom/wounipaysms/dialog/images/confirm_bt.9.png"
        $s7 = "com/unicom/wounipaysms/dialog/images/confirm_bt_on.9.png"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00020 {
    strings:
        $s0 = "tmx2ePqGYvOES/jfGp8NEsyAr6VQe6a1ddiSGcNeMew"
        $s1 = "5WUT8N6LC6PF97Z1cG6m0zl4jGoS61p2PFskeHZ/7H8"
        $s2 = "li3j269Eu/41nTYBJ6nDrqOn4nE"
        $s3 = "5zYlqV0yGhsf8psU6UD/K9pJraTe5BNHpqXw1m/ldaY"
        $s4 = "6Z1OfrQSv3aFRVck/D2THFRFQy7oPs0r0FzJQ9ZDnsA"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4)
}

rule VX_APK_CLUSTER_00021 {
    strings:
        $s0 = "res/xml-v22/accessibility_service_config.xml"
        $s1 = "MReceiver.java"
        $s2 = "res/xml-v14/accessibility_service_config.xml"
        $s3 = "Localservice.java"
        $s4 = "MJobService.java"
        $s5 = "assets/fields.css"
        $s6 = "res/mipmap-hdpi/application_icon.png"
        $s7 = "assets/guide.gif"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00022 {
    strings:
        $s0 = "res/drawable-xhdpi/ic_.xml"
        $s1 = "lib/armeabi-v7a/libjv.so"
        $s2 = "0veuhHLjGZU/HrrvNvQI2y7snoRNRao5Z1uLalVisxA"
    condition:
        any of ($s0, $s1, $s2)
}

rule VX_APK_CLUSTER_00023 {
    strings:
        $s0 = "lib/armeabi-v7a/libkc.so"
        $s1 = "res/drawable-xhdpi/ic_.xml"
    condition:
        any of ($s0, $s1)
}

rule VX_APK_CLUSTER_00024 {
    strings:
        $s0 = "Lcom/android/system/R"
        $s1 = "Lcom/android/system/R$id"
        $s2 = "Lcom/android/system/R$layout"
        $s3 = "Lcom/android/system/R$string"
        $s4 = ".AppDownloaderActivity"
        $s5 = "Lcom/android/system/BuildConfig"
        $s6 = "Lcom/android/system/R$attr"
        $s7 = "Lcom/android/system/R$drawable"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00025 {
    strings:
        $s0 = "lib/armeabi/libcrypt_sign.so"
        $s1 = "assets/wyzf/res.bin"
        $s2 = "13/Ayo17/DPtKNh46JVIv6osRPo"
        $s3 = "Qmxju5/Ap5mgu1cFHvmJFycrWMw"
        $s4 = "com/unicom/wounipaysms/dialog/images/cancel.png"
        $s5 = "com/unicom/wounipaysms/dialog/images/cancel_on.png"
        $s6 = "com/unicom/wounipaysms/dialog/images/confirm_bt.9.png"
        $s7 = "com/unicom/wounipaysms/dialog/images/confirm_bt_on.9.png"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00026 {
    strings:
        $s0 = "res/layout/finish.xml"
        $s1 = "res/raw/config.txt"
        $s2 = "OpInfo.java"
        $s3 = "assets/texts/finish_activity.txt"
        $s4 = "assets/texts/first_activity.txt"
        $s5 = "assets/texts/ru/finish_activity.txt"
        $s6 = "assets/texts/ru/first_activity.txt"
        $s7 = "assets/texts/ru/rules_activity.txt"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00027 {
    strings:
        $s0 = "res/raw/act_schemes.cfg"
        $s1 = "res/xml/texts.xml"
        $s2 = "res/layout/off.xml"
        $s3 = "c/nL07Gy7K3maRlEL1MxCVwf4FU"
        $s4 = "res/drawable/checkbox_label_background.9.png"
        $s5 = "18/aznZQx9KN6O9oFh9zkx3tu4w"
        $s6 = "ShowLink.java"
        $s7 = "res/layout/grant_access_to_content.xml"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00028 {
    strings:
        $s0 = "res/raw/data.db"
        $s1 = "Lorg/MobileDb/Field"
        $s2 = "Lorg/MobileDb/MobileDatabase"
        $s3 = "Lorg/MobileDb/Row"
        $s4 = "Lorg/MobileDb/Table"
        $s5 = "Lorg/MobileDb/Utf8StringBuffer"
        $s6 = ".---NKxx"
        $s7 = "MobileDatabase.java"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00029 {
    strings:
        $s0 = "lib/armeabi/libcrypt_sign.so"
        $s1 = "assets/wyzf/res.bin"
        $s2 = "13/Ayo17/DPtKNh46JVIv6osRPo"
        $s3 = "Qmxju5/Ap5mgu1cFHvmJFycrWMw"
        $s4 = "com/unicom/wounipaysms/dialog/images/cancel.png"
        $s5 = "com/unicom/wounipaysms/dialog/images/cancel_on.png"
        $s6 = "com/unicom/wounipaysms/dialog/images/confirm_bt.9.png"
        $s7 = "com/unicom/wounipaysms/dialog/images/confirm_bt_on.9.png"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00030 {
    strings:
        $s0 = "res/raw/act_schemes.cfg"
        $s1 = "res/xml/texts.xml"
        $s2 = "res/layout/off.xml"
        $s3 = "c/nL07Gy7K3maRlEL1MxCVwf4FU"
        $s4 = "res/drawable/checkbox_label_background.9.png"
        $s5 = "18/aznZQx9KN6O9oFh9zkx3tu4w"
        $s6 = "ShowLink.java"
        $s7 = "res/layout/grant_access_to_content.xml"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00031 {
    strings:
        $s0 = "getNumber:"
        $s1 = "number1:"
        $s2 = "number2:"
        $s3 = "LocationInfo:"
        $s4 = "example.vcard"
        $s5 = ".httpBuffer"
        $s6 = ".tostring."
        $s7 = "/SendApplicationInstanceIdentifierPayloadBuilder"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00032 {
    strings:
        $s0 = "xoYHeP/23ezgc3yGF9063z"
        $s1 = "res/layout/offert.xml"
        $s2 = "1.6.0_03-p4"
        $s3 = "res/raw/countries.cfg"
        $s4 = "res/layout/activation_done.xml"
        $s5 = "res/raw/sms.cfg"
        $s6 = "FilesParser.java"
        $s7 = "Lcom/depositmobi/FilesParser"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00033 {
    strings:
        $s0 = "res/layout/rools.xml"
        $s1 = "sRNe/i3dVkjN0LlFUIHAc3hBgfM"
        $s2 = "assets/rools.txt"
        $s3 = "/mnt/sdcard/download/"
        $s4 = "/stats/adv.php"
        $s5 = "/stats/open.php"
        $s6 = "/stats/press.php"
        $s7 = "rools.txt"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00034 {
    strings:
        $s0 = "http://124ff42.com/sms/gate.php"
        $s1 = "http://124ffdfsaf.com/sms/gate.php"
        $s2 = "http://124ffsaf.com/sms/gate.php"
        $s3 = "http://124sfafsaffa.com/sms/gate.php"
        $s4 = "ka/AIQXy5TOWzSZyvhyCg/Ptb4c"
        $s5 = "LYrDUXPMwgA0wzcQtC/dRliUuSE"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5)
}

rule VX_APK_CLUSTER_00035 {
    strings:
        $s0 = "assets/css/smoothness/images/ui-bg_flat_0_aaaaaa_40x100.png"
        $s1 = "assets/css/smoothness/images/ui-bg_flat_75_ffffff_40x100.png"
        $s2 = "assets/css/smoothness/images/ui-bg_glass_55_fbf9ee_1x400.png"
        $s3 = "assets/css/smoothness/images/ui-bg_glass_65_ffffff_1x400.png"
        $s4 = "assets/css/smoothness/images/ui-bg_glass_75_dadada_1x400.png"
        $s5 = "assets/css/smoothness/images/ui-bg_glass_75_e6e6e6_1x400.png"
        $s6 = "assets/css/smoothness/images/ui-bg_glass_95_fef1ec_1x400.png"
        $s7 = "assets/css/smoothness/images/ui-bg_highlight-soft_75_cccccc_1x10"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00036 {
    strings:
        $s0 = "5A4o54_5o.:_"
        $s1 = "Lcom/sistlias/esnioteh/ebarenv"
        $s2 = "Lcom/sistlias/esnioteh/q"
        $s3 = "Lcom/sistlias/esnioteh/w"
        $s4 = "assets/jfgxzomq.dat"
        $s5 = "x28V2y.-P46/"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5)
}

rule VX_APK_CLUSTER_00037 {
    strings:
        $s0 = "assets/css/smoothness/images/ui-bg_flat_0_aaaaaa_40x100.png"
        $s1 = "assets/css/smoothness/images/ui-bg_flat_75_ffffff_40x100.png"
        $s2 = "assets/css/smoothness/images/ui-bg_glass_55_fbf9ee_1x400.png"
        $s3 = "assets/css/smoothness/images/ui-bg_glass_65_ffffff_1x400.png"
        $s4 = "assets/css/smoothness/images/ui-bg_glass_75_dadada_1x400.png"
        $s5 = "assets/css/smoothness/images/ui-bg_glass_75_e6e6e6_1x400.png"
        $s6 = "assets/css/smoothness/images/ui-bg_glass_95_fef1ec_1x400.png"
        $s7 = "assets/css/smoothness/images/ui-bg_highlight-soft_75_cccccc_1x10"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00038 {
    strings:
        $s0 = "lib/armeabi/libcrypt_sign.so"
        $s1 = "assets/wyzf/res.bin"
        $s2 = "assets/yf.conf"
        $s3 = "assets/dERlZG"
        $s4 = "Adzwfge96PWi9KOpEQioyGF//NA"
        $s5 = "http://vpay.api.eerichina.com/api/payment"
        $s6 = "plugin.db"
        $s7 = "/LocalPool.xml"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00039 {
    strings:
        $s0 = "au.com.bankwest.mobile"
        $s1 = "ZzxKlxKyki.i"
        $s2 = "commandus.com"
        $s3 = "--.ixKiidAZ"
        $s4 = "/CalsRlpNBoM"
        $s5 = "/p9USHEeoIE3gQO135Rl6PxRJyo"
        $s6 = "2Lcom/note/donote/receivers/ServiceDestroyReceiver"
        $s7 = "3Lcom/note/donote/receivers/sms/PushServiceReciever"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00040 {
    strings:
        $s0 = "au.com.bankwest.mobile"
        $s1 = "ZzxKlxKyki.i"
        $s2 = "commandus.com"
        $s3 = "--.ixKiidAZ"
        $s4 = "/CalsRlpNBoM"
        $s5 = "/p9USHEeoIE3gQO135Rl6PxRJyo"
        $s6 = "2Lcom/note/donote/receivers/ServiceDestroyReceiver"
        $s7 = "3Lcom/note/donote/receivers/sms/PushServiceReciever"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00041 {
    strings:
        $s0 = "lib/armeabi/libcrypt_sign.so"
        $s1 = "assets/wyzf/res.bin"
        $s2 = "13/Ayo17/DPtKNh46JVIv6osRPo"
        $s3 = "Qmxju5/Ap5mgu1cFHvmJFycrWMw"
        $s4 = "com/unicom/wounipaysms/dialog/images/cancel.png"
        $s5 = "com/unicom/wounipaysms/dialog/images/cancel_on.png"
        $s6 = "com/unicom/wounipaysms/dialog/images/confirm_bt.9.png"
        $s7 = "com/unicom/wounipaysms/dialog/images/confirm_bt_on.9.png"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00042 {
    strings:
        $s0 = "lib/armeabi/libcrypt_sign.so"
        $s1 = "assets/wyzf/res.bin"
        $s2 = "13/Ayo17/DPtKNh46JVIv6osRPo"
        $s3 = "Qmxju5/Ap5mgu1cFHvmJFycrWMw"
        $s4 = "com/unicom/wounipaysms/dialog/images/cancel.png"
        $s5 = "com/unicom/wounipaysms/dialog/images/cancel_on.png"
        $s6 = "com/unicom/wounipaysms/dialog/images/confirm_bt.9.png"
        $s7 = "com/unicom/wounipaysms/dialog/images/confirm_bt_on.9.png"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00043 {
    strings:
        $s0 = "xoYHeP/23ezgc3yGF9063z"
        $s1 = "res/layout/offert.xml"
        $s2 = "1.6.0_03-p4"
        $s3 = "res/raw/countries.cfg"
        $s4 = "res/layout/activation_done.xml"
        $s5 = "res/raw/sms.cfg"
        $s6 = "FilesParser.java"
        $s7 = "Lcom/depositmobi/FilesParser"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00044 {
    strings:
        $s0 = "PlJSQqWxy9Pig116SM/fEvHLyIQ"
        $s1 = "//0N3FbUo5cvT8"
        $s2 = "/Xd8TjhwyNbYb2Z/"
        $s3 = "http://ehttp-host-"
        $s4 = "LwcvoEmrFpXVcD/7dJS3ijfU6Fo"
        $s5 = "6/W5YFA9Dv7aBsElhk"
        $s6 = "AaNfidSePp/TeMxfv4Ssd"
        $s7 = "KjQ8YcSDNo0FojMfa/QOJ"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00045 {
    strings:
        $s0 = "lib/armeabi/libcrypt_sign.so"
        $s1 = "assets/wyzf/res.bin"
        $s2 = "13/Ayo17/DPtKNh46JVIv6osRPo"
        $s3 = "Qmxju5/Ap5mgu1cFHvmJFycrWMw"
        $s4 = "com/unicom/wounipaysms/dialog/images/cancel.png"
        $s5 = "com/unicom/wounipaysms/dialog/images/cancel_on.png"
        $s6 = "com/unicom/wounipaysms/dialog/images/confirm_bt.9.png"
        $s7 = "com/unicom/wounipaysms/dialog/images/confirm_bt_on.9.png"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00046 {
    strings:
        $s0 = "res/raw/act_schemes.cfg"
        $s1 = "res/xml/texts.xml"
        $s2 = "res/layout/off.xml"
        $s3 = "c/nL07Gy7K3maRlEL1MxCVwf4FU"
        $s4 = "res/drawable/checkbox_label_background.9.png"
        $s5 = "18/aznZQx9KN6O9oFh9zkx3tu4w"
        $s6 = "res/drawable/0.temp"
        $s7 = "ShowLink.java"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00047 {
    strings:
        $s0 = "Lcom/adwo/adsdk/AdwoAdView"
        $s1 = "Lcom/adwo/adsdk/AdListener"
        $s2 = "http://10.0.0.172/a/p1"
        $s3 = "http://10.0.0.172/t/test"
        $s4 = "assets/adwo_left_arrow.png"
        $s5 = "assets/adwo_right_arrow.png"
        $s6 = "Lcom/adwo/adsdk/a"
        $s7 = "Lcom/adwo/adsdk/b"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00048 {
    strings:
        $s0 = "res/layout/finish.xml"
        $s1 = "res/raw/config.txt"
        $s2 = "OpInfo.java"
        $s3 = "assets/texts/finish_activity.txt"
        $s4 = "assets/texts/first_activity.txt"
        $s5 = "assets/texts/ru/finish_activity.txt"
        $s6 = "assets/texts/ru/first_activity.txt"
        $s7 = "assets/texts/ru/rules_activity.txt"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00049 {
    strings:
        $s0 = "res/raw/act_schemes.cfg"
        $s1 = "res/xml/texts.xml"
        $s2 = "res/layout/off.xml"
        $s3 = "c/nL07Gy7K3maRlEL1MxCVwf4FU"
        $s4 = "res/drawable/checkbox_label_background.9.png"
        $s5 = "18/aznZQx9KN6O9oFh9zkx3tu4w"
        $s6 = "ShowLink.java"
        $s7 = "res/layout/grant_access_to_content.xml"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00050 {
    strings:
        $s0 = "mian.iyu"
        $s1 = "/AcvZ4Yycp/fuahUizra4r219Ug"
        $s2 = "UaAcDtpGmSrYRacrNRzul/Gk4Pw"
        $s3 = "a3V5KpEW/d14VzAGShsebenhDEI"
        $s4 = "assets/lib.so"
        $s5 = "lib/armeabi-v7a/libygsiyu.so"
        $s6 = "lib/x86/libygsiyu.so"
        $s7 = "tTYPFQeo26XIrs6xdPYO/zvBEiM"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00051 {
    strings:
        $s0 = "$Lcom/example/mobilpakket/R$drawable"
        $s1 = "Lcom/example/mobilpakket/BuildConfig"
        $s2 = "Lcom/example/mobilpakket/MainActivity"
        $s3 = "Lcom/example/mobilpakket/MyAppWebViewClient"
        $s4 = "Lcom/example/mobilpakket/R"
        $s5 = "Lcom/example/mobilpakket/R$attr"
        $s6 = "Lcom/example/mobilpakket/R$dimen"
        $s7 = "Lcom/example/mobilpakket/R$id"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00052 {
    strings:
        $s0 = "com.webcash.wooribank"
        $s1 = "res/drawable-hdpi/nh.png"
        $s2 = "res/drawable-hdpi/sh.png"
        $s3 = "/conf.ini"
        $s4 = "App.Alert"
        $s5 = "alert.main"
        $s6 = "app.auto.install"
        $s7 = "app.dwonload.complate"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00053 {
    strings:
        $s0 = "res/xml-v22/accessibility_service_config.xml"
        $s1 = "MReceiver.java"
        $s2 = "res/xml-v14/accessibility_service_config.xml"
        $s3 = "Localservice.java"
        $s4 = "MJobService.java"
        $s5 = "assets/fields.css"
        $s6 = "res/mipmap-hdpi/application_icon.png"
        $s7 = "assets/guide.gif"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00054 {
    strings:
        $s0 = "$Lcom/example/eroplayer/MainActivity"
        $s1 = "//vb1GqdYUo3FtlV1v"
        $s2 = "0Lcom/example/eroplayer/MainActivity$MyAsyncTask"
        $s3 = "5mz/E4HS5UUVxwUj5qs9r77keo"
        $s4 = "Lcom/example/eroplayer/BuildConfig"
        $s5 = "Lcom/example/eroplayer/MainActivity$1"
        $s6 = "Lcom/example/eroplayer/MainActivity$WebC"
        $s7 = "Lcom/example/eroplayer/R"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00055 {
    strings:
        $s0 = "lib/armeabi/libcrypt_sign.so"
        $s1 = "assets/wyzf/res.bin"
        $s2 = "assets/yf.conf"
        $s3 = "assets/dERlZG"
        $s4 = "Adzwfge96PWi9KOpEQioyGF//NA"
        $s5 = "http://vpay.api.eerichina.com/api/payment"
        $s6 = "plugin.db"
        $s7 = "/LocalPool.xml"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00056 {
    strings:
        $s0 = "http://124ff42.com/sms/gate.php"
        $s1 = "http://124ffdfsaf.com/sms/gate.php"
        $s2 = "http://124ffsaf.com/sms/gate.php"
        $s3 = "http://124sfafsaffa.com/sms/gate.php"
        $s4 = "ka/AIQXy5TOWzSZyvhyCg/Ptb4c"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4)
}

rule VX_APK_CLUSTER_00057 {
    strings:
        $s0 = ".Lcom/sirseni/simpleandroidwebviewexample/R$id"
        $s1 = "/CoIXRo5o95LwmcBAYLGXQ5bHtk"
        $s2 = "0Lcom/sirseni/simpleandroidwebviewexample/R$anim"
        $s3 = "0Lcom/sirseni/simpleandroidwebviewexample/R$attr"
        $s4 = "0Lcom/sirseni/simpleandroidwebviewexample/R$bool"
        $s5 = "0Lcom/sirseni/simpleandroidwebviewexample/R$menu"
        $s6 = "1Lcom/sirseni/simpleandroidwebviewexample/R$color"
        $s7 = "1Lcom/sirseni/simpleandroidwebviewexample/R$dimen"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00058 {
    strings:
        $s0 = "PlJSQqWxy9Pig116SM/fEvHLyIQ"
        $s1 = "//0N3FbUo5cvT8"
        $s2 = "/Xd8TjhwyNbYb2Z/"
        $s3 = "http://ehttp-host-"
        $s4 = "LwcvoEmrFpXVcD/7dJS3ijfU6Fo"
        $s5 = "6/W5YFA9Dv7aBsElhk"
        $s6 = "AaNfidSePp/TeMxfv4Ssd"
        $s7 = "KjQ8YcSDNo0FojMfa/QOJ"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00059 {
    strings:
        $s0 = "dI812p8Zx/gCXgn6zKkOfdnYdkn"
        $s1 = "/3L8ACIlBECIORgVNrECOKZI157nDhIP/4nLBN3nxMs"
        $s2 = "/KjIss7JjamFX2/XD9XlPGY8mMPAiByl6QbWBIK/7fM"
        $s3 = "0Iouht/1z/0hx2mU6cB0R0ydvHieSlHCHd/jZGIA8pU"
        $s4 = "2L/DYp4Etza/KZc4FZYE4Xla45ajpuoptjrkK5iAEL4"
        $s5 = "3rCPXx006kdeu/xmRcbNrN0NMC"
        $s6 = "3sJgh4/ha8aUAlz7xkXWlwrKNZlU4t4eQo8Q2XXe8bs"
        $s7 = "7AS7bZUYVlCmGPWI1thXTFK/hE4HaXHZzN78CnKp8gc"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00060 {
    strings:
        $s0 = "http://124ff42.com/sms/gate.php"
        $s1 = "http://124ffdfsaf.com/sms/gate.php"
        $s2 = "http://124ffsaf.com/sms/gate.php"
        $s3 = "http://124sfafsaffa.com/sms/gate.php"
        $s4 = "ka/AIQXy5TOWzSZyvhyCg/Ptb4c"
        $s5 = "LYrDUXPMwgA0wzcQtC/dRliUuSE"
        $s6 = "Lorg/android/system/Constants"
        $s7 = "Lorg/android/system/R"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00061 {
    strings:
        $s0 = "/vSmyuJfe3Ww/taI6TsoDJYn4s4"
        $s1 = "params2:"
        $s2 = "com.google.android.apps.authenticator2:"
        $s3 = "params1:"
        $s4 = "params3:"
        $s5 = "Mw4n3TnrA3nm14CEG/M4n9gnHOc"
        $s6 = "s30/zVw0GhWc91uWUpqyRi1hEzY"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6)
}

rule VX_APK_CLUSTER_00062 {
    strings:
        $s0 = "res/raw/act_schemes.cfg"
        $s1 = "res/xml/texts.xml"
        $s2 = "res/layout/off.xml"
        $s3 = "c/nL07Gy7K3maRlEL1MxCVwf4FU"
        $s4 = "ShowLink.java"
        $s5 = "xoYHeP/23ezgc3yGF9063z"
        $s6 = "res/layout/grant_access_to_content.xml"
        $s7 = "OffertActivity.java"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00063 {
    strings:
        $s0 = "getNumber:"
        $s1 = "number1:"
        $s2 = "number2:"
        $s3 = "LocationInfo:"
        $s4 = "example.vcard"
        $s5 = ".httpBuffer"
        $s6 = ".tostring."
        $s7 = "/SendApplicationInstanceIdentifierPayloadBuilder"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00064 {
    strings:
        $s0 = "PlJSQqWxy9Pig116SM/fEvHLyIQ"
        $s1 = "//0N3FbUo5cvT8"
        $s2 = "/Xd8TjhwyNbYb2Z/"
        $s3 = "http://ehttp-host-"
        $s4 = "LwcvoEmrFpXVcD/7dJS3ijfU6Fo"
        $s5 = "6/W5YFA9Dv7aBsElhk"
        $s6 = "AaNfidSePp/TeMxfv4Ssd"
        $s7 = "KjQ8YcSDNo0FojMfa/QOJ"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00065 {
    strings:
        $s0 = "lib/armeabi/libcrypt_sign.so"
        $s1 = "assets/wyzf/res.bin"
        $s2 = "assets/yf.conf"
        $s3 = "assets/dERlZG"
        $s4 = "Adzwfge96PWi9KOpEQioyGF//NA"
        $s5 = "http://vpay.api.eerichina.com/api/payment"
        $s6 = "plugin.db"
        $s7 = "/LocalPool.xml"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00066 {
    strings:
        $s0 = "com.webcash.wooribank"
        $s1 = "res/drawable-hdpi/nh.png"
        $s2 = "res/drawable-hdpi/sh.png"
        $s3 = "/conf.ini"
        $s4 = "App.Alert"
        $s5 = "alert.main"
        $s6 = "app.auto.install"
        $s7 = "app.dwonload.complate"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00067 {
    strings:
        $s0 = "res/layout/finish.xml"
        $s1 = "res/raw/config.txt"
        $s2 = "OpInfo.java"
        $s3 = "assets/texts/finish_activity.txt"
        $s4 = "assets/texts/first_activity.txt"
        $s5 = "assets/texts/ru/finish_activity.txt"
        $s6 = "assets/texts/ru/first_activity.txt"
        $s7 = "assets/texts/ru/rules_activity.txt"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00068 {
    strings:
        $s0 = "res/raw/act_schemes.cfg"
        $s1 = "res/xml/texts.xml"
        $s2 = "res/layout/off.xml"
        $s3 = "c/nL07Gy7K3maRlEL1MxCVwf4FU"
        $s4 = "res/drawable/checkbox_label_background.9.png"
        $s5 = "18/aznZQx9KN6O9oFh9zkx3tu4w"
        $s6 = "res/drawable/0.temp"
        $s7 = "ShowLink.java"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00069 {
    strings:
        $s0 = "refresh.png"
        $s1 = "smsNumber:"
        $s2 = "/ormma.js"
        $s3 = "ActionHistory.java"
        $s4 = "ParseStep.java"
        $s5 = "messageBody:"
        $s6 = "mraid_close.png"
        $s7 = "$Lorg/ormma/view/OrmmaView$ViewState"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00070 {
    strings:
        $s0 = "xoYHeP/23ezgc3yGF9063z"
        $s1 = "res/layout/offert.xml"
        $s2 = "1.6.0_03-p4"
        $s3 = "res/raw/countries.cfg"
        $s4 = "res/layout/activation_done.xml"
        $s5 = "res/raw/sms.cfg"
        $s6 = "FilesParser.java"
        $s7 = "Lcom/depositmobi/FilesParser"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00071 {
    strings:
        $s0 = "lib/armeabi/libcrypt_sign.so"
        $s1 = "assets/wyzf/res.bin"
        $s2 = "13/Ayo17/DPtKNh46JVIv6osRPo"
        $s3 = "Qmxju5/Ap5mgu1cFHvmJFycrWMw"
        $s4 = "com/unicom/wounipaysms/dialog/images/cancel.png"
        $s5 = "com/unicom/wounipaysms/dialog/images/cancel_on.png"
        $s6 = "com/unicom/wounipaysms/dialog/images/confirm_bt.9.png"
        $s7 = "com/unicom/wounipaysms/dialog/images/confirm_bt_on.9.png"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00072 {
    strings:
        $s0 = "assets/css/smoothness/images/ui-bg_flat_0_aaaaaa_40x100.png"
        $s1 = "assets/css/smoothness/images/ui-bg_flat_75_ffffff_40x100.png"
        $s2 = "assets/css/smoothness/images/ui-bg_glass_55_fbf9ee_1x400.png"
        $s3 = "assets/css/smoothness/images/ui-bg_glass_65_ffffff_1x400.png"
        $s4 = "assets/css/smoothness/images/ui-bg_glass_75_dadada_1x400.png"
        $s5 = "assets/css/smoothness/images/ui-bg_glass_75_e6e6e6_1x400.png"
        $s6 = "assets/css/smoothness/images/ui-bg_glass_95_fef1ec_1x400.png"
        $s7 = "assets/css/smoothness/images/ui-bg_highlight-soft_75_cccccc_1x10"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00073 {
    strings:
        $s0 = "lib/armeabi/libcrypt_sign.so"
        $s1 = "13/Ayo17/DPtKNh46JVIv6osRPo"
        $s2 = "Qmxju5/Ap5mgu1cFHvmJFycrWMw"
        $s3 = "com/unicom/wounipaysms/dialog/images/cancel.png"
        $s4 = "com/unicom/wounipaysms/dialog/images/cancel_on.png"
        $s5 = "com/unicom/wounipaysms/dialog/images/confirm_bt.9.png"
        $s6 = "com/unicom/wounipaysms/dialog/images/confirm_bt_on.9.png"
        $s7 = "com/unicom/wounipaysms/dialog/images/main_bg.9.png"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00074 {
    strings:
        $s0 = "res/layout/rools.xml"
        $s1 = "sRNe/i3dVkjN0LlFUIHAc3hBgfM"
        $s2 = "assets/rools.txt"
    condition:
        any of ($s0, $s1, $s2)
}

rule VX_APK_CLUSTER_00075 {
    strings:
        $s0 = "res/xml/device_admin_data.xml"
        $s1 = "/kmnLuLqBMOCa2bEZzlLoFKq"
        $s2 = "33com.iitr.kaishu.nsidedprogressbar.NSidedProgressBar"
        $s3 = "CSZx6RMpZhVd/V2215WR4fM7llXd2eeuuljaNHfU9Co"
        $s4 = "res/raw/dx"
        $s5 = "skuU2rJZc81sswK/bAkZDnCYrhcw"
        $s6 = "zG5hJB/n2/IwKLG7Ok2tBSq3d8ZqpxaGsNb7RL7r1LM"
        $s7 = "5MJB/GLAcB4JuhRBpPf2uoRkWLEBRVSCw/iyoUXiTos"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00076 {
    strings:
        $s0 = "res/layout/finish.xml"
        $s1 = "res/raw/config.txt"
        $s2 = "OpInfo.java"
        $s3 = "assets/texts/finish_activity.txt"
        $s4 = "assets/texts/first_activity.txt"
        $s5 = "assets/texts/ru/finish_activity.txt"
        $s6 = "assets/texts/ru/first_activity.txt"
        $s7 = "assets/texts/ru/rules_activity.txt"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00077 {
    strings:
        $s0 = "tmx2ePqGYvOES/jfGp8NEsyAr6VQe6a1ddiSGcNeMew"
        $s1 = "5WUT8N6LC6PF97Z1cG6m0zl4jGoS61p2PFskeHZ/7H8"
        $s2 = "5zYlqV0yGhsf8psU6UD/K9pJraTe5BNHpqXw1m/ldaY"
        $s3 = "6Z1OfrQSv3aFRVck/D2THFRFQy7oPs0r0FzJQ9ZDnsA"
        $s4 = "kCH4I/3f0g94P1aiaEWnSfjdalEhvA5zgLcGHl"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4)
}

rule VX_APK_CLUSTER_00078 {
    strings:
        $s0 = "secsuite.db"
        $s1 = "LocalTime:"
        $s2 = "SecurityReceiver::OnBundle"
        $s3 = "SecurityReceiver::ReportFromScheduler"
        $s4 = "SecurityReceiver::onReceive"
        $s5 = "SecurityService::onStartCommand"
        $s6 = "res/layout/mainrelative.xml"
        $s7 = "res/drawable/green_checked.png"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00079 {
    strings:
        $s0 = "res/layout/rools.xml"
        $s1 = "sRNe/i3dVkjN0LlFUIHAc3hBgfM"
        $s2 = "/mnt/sdcard/download/"
        $s3 = "/stats/adv.php"
        $s4 = "/stats/open.php"
        $s5 = "/stats/press.php"
        $s6 = "/stats/recheck.php"
        $s7 = "HAra/EQitI"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00080 {
    strings:
        $s0 = "com.webcash.wooribank"
        $s1 = "res/drawable-hdpi/nh.png"
        $s2 = "res/drawable-hdpi/sh.png"
        $s3 = "3IOmkvQWrLqujnhgiQF/suWDebQ"
        $s4 = "res/drawable-hdpi/kb.png"
        $s5 = "Q0j/LlUSDZKDI8"
        $s6 = "res/drawable-hdpi/v3plus_run.png"
        $s7 = "com.areo.bs"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00081 {
    strings:
        $s0 = "HYp34lJUX/TVVo4AefTwRTX"
        $s1 = "JYiLxailF2yPR/G921PrQTMo3Gs"
        $s2 = "Lcom/zu/zu/MainActivity"
        $s3 = "Lcom/zu/zu/a"
        $s4 = "Lcom/zu/zu/b"
        $s5 = "Lcom/zu/zu/c"
        $s6 = "Lcom/zu/zu/d"
        $s7 = "cB0CCJch63JItcxT103Q2Ql/N3w"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00082 {
    strings:
        $s0 = "res/layout-v17/dialog_progress_without_number.xml"
        $s1 = "res/layout/dialog_progress_without_number.xml"
        $s2 = "nVrxRp9QlafI8dbuZHe5e/KbPlQEfmFLGpnZOjHNZgg"
        $s3 = "/0MMXlDbzsImPwsDA1AW2Qg"
        $s4 = "/GGGcFw6ZWNXD"
        $s5 = "/Pb9wUoAolkZqM8"
        $s6 = "/ZqgngLeMb"
        $s7 = "/xCwKBf9Kv8gwyxrbxLR4gW9mdNDWMOOIhRBA3xnA"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00083 {
    strings:
        $s0 = "assets/css/smoothness/images/ui-bg_flat_0_aaaaaa_40x100.png"
        $s1 = "assets/css/smoothness/images/ui-bg_flat_75_ffffff_40x100.png"
        $s2 = "assets/css/smoothness/images/ui-bg_glass_55_fbf9ee_1x400.png"
        $s3 = "assets/css/smoothness/images/ui-bg_glass_65_ffffff_1x400.png"
        $s4 = "assets/css/smoothness/images/ui-bg_glass_75_dadada_1x400.png"
        $s5 = "assets/css/smoothness/images/ui-bg_glass_75_e6e6e6_1x400.png"
        $s6 = "assets/css/smoothness/images/ui-bg_glass_95_fef1ec_1x400.png"
        $s7 = "assets/css/smoothness/images/ui-bg_highlight-soft_75_cccccc_1x10"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00084 {
    strings:
        $s0 = "res/layout/rools.xml"
        $s1 = "sRNe/i3dVkjN0LlFUIHAc3hBgfM"
        $s2 = "assets/rools.txt"
        $s3 = "/mnt/sdcard/download/"
        $s4 = "rools.txt"
        $s5 = "AReceiver.java"
        $s6 = "Lcom/uniplugin/sender/AReceiver"
        $s7 = "Lcom/uniplugin/sender/AReceiver$Maintwo"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00085 {
    strings:
        $s0 = "res/drawable-hdpi-v4/icon.xml"
        $s1 = "res/layout/activity_g.xml"
        $s2 = "iD2em3JLFcEgtAIneR97M/bukxQxG68VKhvLQQKmin8"
        $s3 = "res/drawable-hdpi-v4/posti.png"
        $s4 = "ETpService.java"
        $s5 = "Lcom/tasks/BuildConfig"
        $s6 = "Lcom/tasks/R"
        $s7 = "Lcom/tasks/R$drawable"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00086 {
    strings:
        $s0 = "http://124ff42.com/sms/gate.php"
        $s1 = "http://124ffdfsaf.com/sms/gate.php"
        $s2 = "http://124ffsaf.com/sms/gate.php"
        $s3 = "http://124sfafsaffa.com/sms/gate.php"
        $s4 = "ka/AIQXy5TOWzSZyvhyCg/Ptb4c"
        $s5 = "Lorg/android/system/Constants"
        $s6 = "Lorg/android/system/R"
        $s7 = "Lorg/android/system/R$attr"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00087 {
    strings:
        $s0 = "assets/css/smoothness/images/ui-bg_flat_0_aaaaaa_40x100.png"
        $s1 = "assets/css/smoothness/images/ui-bg_flat_75_ffffff_40x100.png"
        $s2 = "assets/css/smoothness/images/ui-bg_glass_55_fbf9ee_1x400.png"
        $s3 = "assets/css/smoothness/images/ui-bg_glass_65_ffffff_1x400.png"
        $s4 = "assets/css/smoothness/images/ui-bg_glass_75_dadada_1x400.png"
        $s5 = "assets/css/smoothness/images/ui-bg_glass_75_e6e6e6_1x400.png"
        $s6 = "assets/css/smoothness/images/ui-bg_glass_95_fef1ec_1x400.png"
        $s7 = "assets/css/smoothness/images/ui-bg_highlight-soft_75_cccccc_1x10"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00088 {
    strings:
        $s0 = "com.webcash.wooribank"
        $s1 = "res/drawable-hdpi/nh.png"
        $s2 = "res/drawable-hdpi/sh.png"
        $s3 = "/conf.ini"
        $s4 = "App.Alert"
        $s5 = "alert.main"
        $s6 = "app.auto.install"
        $s7 = "app.dwonload.complate"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00089 {
    strings:
        $s0 = "secsuite.db"
        $s1 = "LocalTime:"
        $s2 = "SecurityReceiver::OnBundle"
        $s3 = "SecurityReceiver::ReportFromScheduler"
        $s4 = "SecurityReceiver::onReceive"
        $s5 = "SecurityService::onStartCommand"
        $s6 = "res/layout/mainrelative.xml"
        $s7 = "res/drawable/green_checked.png"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00090 {
    strings:
        $s0 = "lib/armeabi-v7a/libkc.so"
        $s1 = "res/drawable-xhdpi/i.xml"
        $s2 = "SCaUt8tPgjmh5gdp/qyDth1JJs"
    condition:
        any of ($s0, $s1, $s2)
}

rule VX_APK_CLUSTER_00091 {
    strings:
        $s0 = "assets/google/gaid.dat"
        $s1 = "$Loahi/hgjzcn/gfyoqxuo/assinjector/R"
        $s2 = ".Loahi/hgjzcn/gfyoqxuo/assinjector/AssInjector"
        $s3 = ".Loahi/hgjzcn/gfyoqxuo/assinjector/BuildConfig"
        $s4 = "0Loahi/hgjzcn/gfyoqxuo/assinjector/AssInjector$1"
        $s5 = "2Loahi/hgjzcn/gfyoqxuo/assinjector/CryoAssInjector"
        $s6 = "4Loahi/hgjzcn/gfyoqxuo/assinjector/AssInjector$Smith"
        $s7 = "5Loahi/hgjzcn/gfyoqxuo/assinjector/AssInjector$Cacher"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00092 {
    strings:
        $s0 = "res/layout/rools.xml"
        $s1 = "sRNe/i3dVkjN0LlFUIHAc3hBgfM"
        $s2 = "assets/rools.txt"
        $s3 = "/mnt/sdcard/download/"
        $s4 = "/stats/adv.php"
        $s5 = "/stats/open.php"
        $s6 = "/stats/press.php"
        $s7 = "rools.txt"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00093 {
    strings:
        $s0 = "res/drawable-xhdpi/ic_.xml"
        $s1 = "349VlPLaD1Tgw/cCllK0"
        $s2 = "lib/armeabi-v7a/libinc.so"
    condition:
        any of ($s0, $s1, $s2)
}

rule VX_APK_CLUSTER_00094 {
    strings:
        $s0 = "tmx2ePqGYvOES/jfGp8NEsyAr6VQe6a1ddiSGcNeMew"
        $s1 = "5WUT8N6LC6PF97Z1cG6m0zl4jGoS61p2PFskeHZ/7H8"
        $s2 = "5zYlqV0yGhsf8psU6UD/K9pJraTe5BNHpqXw1m/ldaY"
        $s3 = "6Z1OfrQSv3aFRVck/D2THFRFQy7oPs0r0FzJQ9ZDnsA"
    condition:
        any of ($s0, $s1, $s2, $s3)
}

rule VX_APK_CLUSTER_00095 {
    strings:
        $s0 = "lib/armeabi/libcrypt_sign.so"
        $s1 = "assets/wyzf/res.bin"
        $s2 = "13/Ayo17/DPtKNh46JVIv6osRPo"
        $s3 = "Qmxju5/Ap5mgu1cFHvmJFycrWMw"
        $s4 = "com/unicom/wounipaysms/dialog/images/cancel.png"
        $s5 = "com/unicom/wounipaysms/dialog/images/cancel_on.png"
        $s6 = "com/unicom/wounipaysms/dialog/images/confirm_bt.9.png"
        $s7 = "com/unicom/wounipaysms/dialog/images/confirm_bt_on.9.png"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00096 {
    strings:
        $s0 = "res/raw/act_schemes.cfg"
        $s1 = "res/xml/texts.xml"
        $s2 = "res/layout/off.xml"
        $s3 = "xoYHeP/23ezgc3yGF9063z"
        $s4 = "res/layout/grant_access_to_content.xml"
        $s5 = "res/layout/offert.xml"
        $s6 = "1.6.0_03-p4"
        $s7 = "bPiSqfnm11lHasvNBAqb/Gx2ZiQ"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00097 {
    strings:
        $s0 = "Lcom/adwo/adsdk/AdwoAdView"
        $s1 = "Lcom/adwo/adsdk/AdListener"
        $s2 = "Lnet/youmi/android/AdManager"
        $s3 = "Lnet/youmi/android/AdView"
        $s4 = "Lcom/madhouse/android/ads/AdView"
        $s5 = "Lcn/domob/android/ads/DomobAdView"
        $s6 = "Lcom/wooboo/adlib_android/WoobooAdView"
        $s7 = "$Lcom/madhouse/android/ads/AdManager"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00098 {
    strings:
        $s0 = "lib/armeabi/libcrypt_sign.so"
        $s1 = "assets/wyzf/res.bin"
        $s2 = "13/Ayo17/DPtKNh46JVIv6osRPo"
        $s3 = "Qmxju5/Ap5mgu1cFHvmJFycrWMw"
        $s4 = "com/unicom/wounipaysms/dialog/images/cancel.png"
        $s5 = "com/unicom/wounipaysms/dialog/images/cancel_on.png"
        $s6 = "com/unicom/wounipaysms/dialog/images/confirm_bt.9.png"
        $s7 = "com/unicom/wounipaysms/dialog/images/confirm_bt_on.9.png"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00099 {
    strings:
        $s0 = "com.webcash.wooribank"
        $s1 = "res/drawable-hdpi/nh.png"
        $s2 = "res/drawable-hdpi/sh.png"
        $s3 = "/conf.ini"
        $s4 = "App.Alert"
        $s5 = "alert.main"
        $s6 = "app.auto.install"
        $s7 = "app.dwonload.complate"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00100 {
    strings:
        $s0 = "res/layout/finish.xml"
        $s1 = "res/raw/config.txt"
        $s2 = "OpInfo.java"
        $s3 = "assets/texts/finish_activity.txt"
        $s4 = "assets/texts/first_activity.txt"
        $s5 = "assets/texts/ru/finish_activity.txt"
        $s6 = "assets/texts/ru/first_activity.txt"
        $s7 = "assets/texts/ru/rules_activity.txt"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00101 {
    strings:
        $s0 = "res/raw/act_schemes.cfg"
        $s1 = "res/xml/texts.xml"
        $s2 = "res/layout/off.xml"
        $s3 = "c/nL07Gy7K3maRlEL1MxCVwf4FU"
        $s4 = "res/drawable/checkbox_label_background.9.png"
        $s5 = "18/aznZQx9KN6O9oFh9zkx3tu4w"
        $s6 = "res/drawable/0.temp"
        $s7 = "ShowLink.java"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00102 {
    strings:
        $s0 = "assets/cfg.cfg"
        $s1 = "www.game.com"
        $s2 = "www.games.com"
        $s3 = "Uni.java"
        $s4 = "-/-.LK.y"
        $s5 = ".mocikonMI.a"
        $s6 = ".mocikonim.aiu.dluF.naCl"
        $s7 = ".mocmeis.sneiemi"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00103 {
    strings:
        $s0 = "assets/css/smoothness/images/ui-bg_flat_0_aaaaaa_40x100.png"
        $s1 = "assets/css/smoothness/images/ui-bg_flat_75_ffffff_40x100.png"
        $s2 = "assets/css/smoothness/images/ui-bg_glass_55_fbf9ee_1x400.png"
        $s3 = "assets/css/smoothness/images/ui-bg_glass_65_ffffff_1x400.png"
        $s4 = "assets/css/smoothness/images/ui-bg_glass_75_dadada_1x400.png"
        $s5 = "assets/css/smoothness/images/ui-bg_glass_75_e6e6e6_1x400.png"
        $s6 = "assets/css/smoothness/images/ui-bg_glass_95_fef1ec_1x400.png"
        $s7 = "assets/css/smoothness/images/ui-bg_highlight-soft_75_cccccc_1x10"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00104 {
    strings:
        $s0 = "pLDkmSRkoQXoVF/HluPgotdpwUPxVIOYjlQrGQbkD3g"
        $s1 = "7DExtuS6O6jXtu4jAc/bMQSB6b2k"
        $s2 = "ROCTbAUl/d/KaG"
        $s3 = "xqYRGRhw/nUiYWj"
        $s4 = "/3RlC656bCGoW46k3MsH8hxi7BmKcQaGUrWQbB97eJ0"
        $s5 = "1CYPBLsHZG3Yjj83dl6hhRbv/z6mVGErsrXZRp6uLjo"
        $s6 = "1GnQa3YhH/yPrr7g"
        $s7 = "2/hZPHKCylQezghFrC37xG8LzPwid8qALHHT4"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00105 {
    strings:
        $s0 = "com.webcash.wooribank"
        $s1 = "res/drawable-hdpi/nh.png"
        $s2 = "res/drawable-hdpi/sh.png"
        $s3 = "/conf.ini"
        $s4 = "App.Alert"
        $s5 = "alert.main"
        $s6 = "app.auto.install"
        $s7 = "app.dwonload.complate"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00106 {
    strings:
        $s0 = "hp_getsmsblockstate.php"
        $s1 = "hp_state.php"
        $s2 = "PreodicService.java"
        $s3 = "RegDPMActivity.java"
        $s4 = "application/3gp"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4)
}

rule VX_APK_CLUSTER_00107 {
    strings:
        $s0 = "res/raw/act_schemes.cfg"
        $s1 = "res/xml/texts.xml"
        $s2 = "res/layout/off.xml"
        $s3 = "xoYHeP/23ezgc3yGF9063z"
        $s4 = "res/layout/grant_access_to_content.xml"
        $s5 = "res/layout/offert.xml"
        $s6 = "1.6.0_03-p4"
        $s7 = "bPiSqfnm11lHasvNBAqb/Gx2ZiQ"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00108 {
    strings:
        $s0 = "lib/armeabi-v7a/libdq.so"
        $s1 = "res/drawable-xhdpi/ic.xml"
        $s2 = "dL6w4z44y1gu5CzK4KDp1Q7/NNE"
        $s3 = "uWL5duPpB14k6rZ/dY"
    condition:
        any of ($s0, $s1, $s2, $s3)
}

rule VX_APK_CLUSTER_00109 {
    strings:
        $s0 = "tmx2ePqGYvOES/jfGp8NEsyAr6VQe6a1ddiSGcNeMew"
        $s1 = "5WUT8N6LC6PF97Z1cG6m0zl4jGoS61p2PFskeHZ/7H8"
        $s2 = "2o1f08s4ihKK2fy37dmIRlo3B3/iAOLvEwqe5G3VI6M"
        $s3 = "3PL37/LA6F6cQlcwE/Bez9Tyugc"
        $s4 = "9gvSiI/sWlYAWTkv"
        $s5 = "GT6Z4sjRroSUlaiGL/MTW4o37G9qwI18dLG/VMaBn2k"
        $s6 = "VFXcGqG2OaI/80S7opsg"
        $s7 = "VoPy/hbPPy"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00110 {
    strings:
        $s0 = "tmx2ePqGYvOES/jfGp8NEsyAr6VQe6a1ddiSGcNeMew"
        $s1 = "5WUT8N6LC6PF97Z1cG6m0zl4jGoS61p2PFskeHZ/7H8"
        $s2 = "2o1f08s4ihKK2fy37dmIRlo3B3/iAOLvEwqe5G3VI6M"
        $s3 = "3PL37/LA6F6cQlcwE/Bez9Tyugc"
        $s4 = "9gvSiI/sWlYAWTkv"
        $s5 = "GT6Z4sjRroSUlaiGL/MTW4o37G9qwI18dLG/VMaBn2k"
        $s6 = "VFXcGqG2OaI/80S7opsg"
        $s7 = "VoPy/hbPPy"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00111 {
    strings:
        $s0 = "au.com.bankwest.mobile"
        $s1 = "ZzxKlxKyki.i"
        $s2 = "commandus.com"
        $s3 = "--.ixKiidAZ"
        $s4 = "/CalsRlpNBoM"
        $s5 = "/p9USHEeoIE3gQO135Rl6PxRJyo"
        $s6 = "2Lcom/note/donote/receivers/ServiceDestroyReceiver"
        $s7 = "3Lcom/note/donote/receivers/sms/PushServiceReciever"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00112 {
    strings:
        $s0 = "Lcom/metasploit/stage/Payload"
        $s1 = "A/Tj8qJlKQ8GI"
        $s2 = "Lcom/metasploit/stage/MainActivity"
        $s3 = "Lcom/metasploit/stage/MainBroadcastReceiver"
        $s4 = "Lcom/metasploit/stage/MainService"
        $s5 = "Lcom/metasploit/stage/a"
        $s6 = "Lcom/metasploit/stage/c"
        $s7 = "Lcom/metasploit/stage/b"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00113 {
    strings:
        $s0 = "Lcom/metasploit/stage/Payload"
        $s1 = "A/Tj8qJlKQ8GI"
        $s2 = "Lcom/metasploit/stage/MainActivity"
        $s3 = "Lcom/metasploit/stage/MainBroadcastReceiver"
        $s4 = "Lcom/metasploit/stage/MainService"
        $s5 = "Lcom/metasploit/stage/a"
        $s6 = "Lcom/metasploit/stage/c"
        $s7 = "Lcom/metasploit/stage/b"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00114 {
    strings:
        $s0 = "secsuite.db"
        $s1 = "LocalTime:"
        $s2 = "SecurityReceiver::OnBundle"
        $s3 = "SecurityReceiver::ReportFromScheduler"
        $s4 = "SecurityReceiver::onReceive"
        $s5 = "SecurityService::onStartCommand"
        $s6 = "res/layout/mainrelative.xml"
        $s7 = "res/drawable/green_checked.png"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00115 {
    strings:
        $s0 = "Lcom/android/a"
        $s1 = "www.apkprotect.com"
        $s2 = "$Lcom/android/slientinstall/R$string"
        $s3 = ".Lcom/android/slientinstall/InstallService$1$1"
        $s4 = "Lcom/android/slientinstall/BuildConfig"
        $s5 = "Lcom/android/slientinstall/InstallService"
        $s6 = "Lcom/android/slientinstall/InstallService$1"
        $s7 = "Lcom/android/slientinstall/MainActivity"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00116 {
    strings:
        $s0 = "lib/armeabi-v7a/libkc.so"
        $s1 = "res/drawable-xhdpi/i.xml"
        $s2 = "FjTfXY7FGcqP/OEr2Ei4Ryuz"
        $s3 = "lbzspRBD5O/N7wIkY0GfnvJNlYY"
    condition:
        any of ($s0, $s1, $s2, $s3)
}

rule VX_APK_CLUSTER_00117 {
    strings:
        $s0 = "assets/url.txt"
        $s1 = "contactsutils.java"
        $s2 = "$Lb4a/example/contactsutils$_cuemail"
        $s3 = "$Lb4a/example/contactsutils$_cuphone"
        $s4 = "DiviceInfo.java"
        $s5 = "Lb4a/example/contactsutils"
        $s6 = "Lb4a/example/contactsutils$_cucontact"
        $s7 = "Lcom/reza/sh/deviceinfo/DiviceInfo"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00118 {
    strings:
        $s0 = "com.webcash.wooribank"
        $s1 = "res/drawable-hdpi/nh.png"
        $s2 = "res/drawable-hdpi/sh.png"
        $s3 = "res/drawable-hdpi/kb.png"
        $s4 = "Q0j/LlUSDZKDI8"
        $s5 = "res/drawable-hdpi/hana.png"
        $s6 = "res/layout/woori_main_activity.xml"
        $s7 = "res/drawable-hdpi/intro_bg.png"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00119 {
    strings:
        $s0 = "lib/armeabi/libcrypt_sign.so"
        $s1 = "assets/wyzf/res.bin"
        $s2 = "13/Ayo17/DPtKNh46JVIv6osRPo"
        $s3 = "Qmxju5/Ap5mgu1cFHvmJFycrWMw"
        $s4 = "com/unicom/wounipaysms/dialog/images/cancel.png"
        $s5 = "com/unicom/wounipaysms/dialog/images/cancel_on.png"
        $s6 = "com/unicom/wounipaysms/dialog/images/confirm_bt.9.png"
        $s7 = "com/unicom/wounipaysms/dialog/images/confirm_bt_on.9.png"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00120 {
    strings:
        $s0 = "lib/armeabi/libcrypt_sign.so"
        $s1 = "assets/wyzf/res.bin"
        $s2 = "13/Ayo17/DPtKNh46JVIv6osRPo"
        $s3 = "Qmxju5/Ap5mgu1cFHvmJFycrWMw"
        $s4 = "com/unicom/wounipaysms/dialog/images/cancel.png"
        $s5 = "com/unicom/wounipaysms/dialog/images/cancel_on.png"
        $s6 = "com/unicom/wounipaysms/dialog/images/confirm_bt.9.png"
        $s7 = "com/unicom/wounipaysms/dialog/images/confirm_bt_on.9.png"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00121 {
    strings:
        $s0 = "res/layout/rools.xml"
        $s1 = "sRNe/i3dVkjN0LlFUIHAc3hBgfM"
        $s2 = "assets/rools.txt"
        $s3 = "hRSqTgMvQ5p8/VyIFXdtBnaftNg"
    condition:
        any of ($s0, $s1, $s2, $s3)
}

rule VX_APK_CLUSTER_00122 {
    strings:
        $s0 = "res/drawable-xhdpi/ic_.xml"
        $s1 = "lib/armeabi-v7a/libjv.so"
    condition:
        any of ($s0, $s1)
}

rule VX_APK_CLUSTER_00123 {
    strings:
        $s0 = "l/cUiZLb7ya5qOYV/djf/zcvnb0"
        $s1 = "res/raw/conf.txt"
        $s2 = "res/raw/result"
        $s3 = "res/raw/resulturl"
        $s4 = "res/raw/rool.txt"
        $s5 = "res/drawable-hdpi/iconnews.png"
        $s6 = "res/drawable-mdpi/iconnews.png"
        $s7 = "http://91.213.175.176/api/"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00124 {
    strings:
        $s0 = "res/drawable-xhdpi/ic_.xml"
        $s1 = "lib/armeabi-v7a/libjv.so"
        $s2 = "AnoAUO0EQoPK2N5tct2kxpgnorpjO5hp05/mD5uvoQE"
        $s3 = "H/fwkEbPwESnnmMt4P"
    condition:
        any of ($s0, $s1, $s2, $s3)
}

rule VX_APK_CLUSTER_00125 {
    strings:
        $s0 = "res/raw/config.txt"
        $s1 = "$Lcom/digitaran/goplaygames/R$layout"
        $s2 = "$Lcom/digitaran/goplaygames/R$string"
        $s3 = "$Lcom/tomkoole/smsping/SegunActivity"
        $s4 = "$Lcom/tomkoole/smsping/WebViewWifi$1"
        $s5 = "$Lcom/tomkoole/smsping/WebViewWifi$2"
        $s6 = "$Lcom/tomkoole/smsping/WebViewWifi$3"
        $s7 = "1http://vft.escenasxxx.com"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00126 {
    strings:
        $s0 = "HookDelegate:"
        $s1 = "Lmirror/RefBoolean"
        $s2 = "Lmirror/RefClass"
        $s3 = "Lmirror/RefConstructor"
        $s4 = "Lmirror/RefDouble"
        $s5 = "Lmirror/RefFloat"
        $s6 = "Lmirror/RefInt"
        $s7 = "Lmirror/RefLong"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00127 {
    strings:
        $s0 = "res/layout/finish.xml"
        $s1 = "res/raw/config.txt"
        $s2 = "OpInfo.java"
        $s3 = "assets/texts/finish_activity.txt"
        $s4 = "assets/texts/first_activity.txt"
        $s5 = "assets/texts/ru/finish_activity.txt"
        $s6 = "assets/texts/ru/first_activity.txt"
        $s7 = "assets/texts/ru/rules_activity.txt"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00128 {
    strings:
        $s0 = "res/raw/act_schemes.cfg"
        $s1 = "res/xml/texts.xml"
        $s2 = "res/layout/off.xml"
        $s3 = "c/nL07Gy7K3maRlEL1MxCVwf4FU"
        $s4 = "res/drawable/checkbox_label_background.9.png"
        $s5 = "18/aznZQx9KN6O9oFh9zkx3tu4w"
        $s6 = "res/drawable/0.temp"
        $s7 = "ShowLink.java"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00129 {
    strings:
        $s0 = "tmx2ePqGYvOES/jfGp8NEsyAr6VQe6a1ddiSGcNeMew"
        $s1 = "5WUT8N6LC6PF97Z1cG6m0zl4jGoS61p2PFskeHZ/7H8"
        $s2 = "sSXSzEqFKMrA6jBWGd3/ny0rkM5WbWISaQbV9uWVDnU"
        $s3 = "waSlUxaesqmgrWPt/coLJ37Snvg"
        $s4 = "nATYSIAfjzRbggjV1YNC7AZa4X/gvplYZT5MWRd43fg"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4)
}

rule VX_APK_CLUSTER_00130 {
    strings:
        $s0 = "lib/armeabi-v7a/libdq.so"
        $s1 = "res/drawable-xhdpi/ico.xml"
        $s2 = "J80EJ0M/FJK1XWE4SOsOmXo04iU"
    condition:
        any of ($s0, $s1, $s2)
}

rule VX_APK_CLUSTER_00131 {
    strings:
        $s0 = "lib/armeabi/libcrypt_sign.so"
        $s1 = "assets/wyzf/res.bin"
        $s2 = "13/Ayo17/DPtKNh46JVIv6osRPo"
        $s3 = "Qmxju5/Ap5mgu1cFHvmJFycrWMw"
        $s4 = "com/unicom/wounipaysms/dialog/images/cancel.png"
        $s5 = "com/unicom/wounipaysms/dialog/images/cancel_on.png"
        $s6 = "com/unicom/wounipaysms/dialog/images/confirm_bt.9.png"
        $s7 = "com/unicom/wounipaysms/dialog/images/confirm_bt_on.9.png"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00132 {
    strings:
        $s0 = "/vSmyuJfe3Ww/taI6TsoDJYn4s4"
        $s1 = "params2:"
        $s2 = "com.google.android.apps.authenticator2:"
        $s3 = "params1:"
        $s4 = "params3:"
        $s5 = "G7cZmvcRZpYp/xZikthGcEp6Lqs"
        $s6 = "dUQIlvNsTcgtyYGCyxY1rE2/k68"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6)
}

rule VX_APK_CLUSTER_00133 {
    strings:
        $s0 = "res/drawable-xhdpi/icon.xml"
        $s1 = "ZDjAC6y4OiI48lO/YI"
    condition:
        any of ($s0, $s1)
}

rule VX_APK_CLUSTER_00134 {
    strings:
        $s0 = "res/layout/finish.xml"
        $s1 = "res/raw/config.txt"
        $s2 = "OpInfo.java"
        $s3 = "assets/texts/finish_activity.txt"
        $s4 = "assets/texts/first_activity.txt"
        $s5 = "assets/texts/ru/finish_activity.txt"
        $s6 = "assets/texts/ru/first_activity.txt"
        $s7 = "assets/texts/ru/rules_activity.txt"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00135 {
    strings:
        $s0 = "res/raw/act_schemes.cfg"
        $s1 = "res/xml/texts.xml"
        $s2 = "res/layout/off.xml"
        $s3 = "c/nL07Gy7K3maRlEL1MxCVwf4FU"
        $s4 = "ShowLink.java"
        $s5 = "xoYHeP/23ezgc3yGF9063z"
        $s6 = "res/layout/grant_access_to_content.xml"
        $s7 = "OffertActivity.java"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00136 {
    strings:
        $s0 = "assets/hp1"
        $s1 = "assets/ss"
    condition:
        any of ($s0, $s1)
}

rule VX_APK_CLUSTER_00137 {
    strings:
        $s0 = "assets/css/smoothness/images/ui-bg_flat_0_aaaaaa_40x100.png"
        $s1 = "assets/css/smoothness/images/ui-bg_flat_75_ffffff_40x100.png"
        $s2 = "assets/css/smoothness/images/ui-bg_glass_55_fbf9ee_1x400.png"
        $s3 = "assets/css/smoothness/images/ui-bg_glass_65_ffffff_1x400.png"
        $s4 = "assets/css/smoothness/images/ui-bg_glass_75_dadada_1x400.png"
        $s5 = "assets/css/smoothness/images/ui-bg_glass_75_e6e6e6_1x400.png"
        $s6 = "assets/css/smoothness/images/ui-bg_glass_95_fef1ec_1x400.png"
        $s7 = "assets/css/smoothness/images/ui-bg_highlight-soft_75_cccccc_1x10"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00138 {
    strings:
        $s0 = "res/layout/rools.xml"
        $s1 = "sRNe/i3dVkjN0LlFUIHAc3hBgfM"
        $s2 = "assets/rools.txt"
        $s3 = "/mnt/sdcard/download/"
        $s4 = "/stats/adv.php"
        $s5 = "/stats/open.php"
        $s6 = "/stats/press.php"
        $s7 = "rools.txt"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00139 {
    strings:
        $s0 = "tmx2ePqGYvOES/jfGp8NEsyAr6VQe6a1ddiSGcNeMew"
        $s1 = "5WUT8N6LC6PF97Z1cG6m0zl4jGoS61p2PFskeHZ/7H8"
        $s2 = "sSXSzEqFKMrA6jBWGd3/ny0rkM5WbWISaQbV9uWVDnU"
        $s3 = "waSlUxaesqmgrWPt/coLJ37Snvg"
        $s4 = "kCH4I/3f0g94P1aiaEWnSfjdalEhvA5zgLcGHl"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4)
}

rule VX_APK_CLUSTER_00140 {
    strings:
        $s0 = "au.com.bankwest.mobile"
        $s1 = "ZzxKlxKyki.i"
        $s2 = "commandus.com"
        $s3 = "--.ixKiidAZ"
        $s4 = "/CalsRlpNBoM"
        $s5 = "/p9USHEeoIE3gQO135Rl6PxRJyo"
        $s6 = "2Lcom/note/donote/receivers/ServiceDestroyReceiver"
        $s7 = "3Lcom/note/donote/receivers/sms/PushServiceReciever"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00141 {
    strings:
        $s0 = "l/cUiZLb7ya5qOYV/djf/zcvnb0"
        $s1 = "res/raw/conf.txt"
        $s2 = "res/raw/result"
        $s3 = "res/raw/resulturl"
        $s4 = "res/raw/rool.txt"
        $s5 = "res/drawable-hdpi/iconnews.png"
        $s6 = "res/drawable-mdpi/iconnews.png"
        $s7 = "http://91.213.175.176/api/"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00142 {
    strings:
        $s0 = "lib/armeabi/libcrypt_sign.so"
        $s1 = "assets/wyzf/res.bin"
        $s2 = "assets/jmpay.xml"
        $s3 = "assets/provincecode.xml"
        $s4 = "assets/yf.conf"
        $s5 = "assets/qsha_80001_5096"
        $s6 = "assets/qpzf.dat"
        $s7 = "assets/knds.dat"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00143 {
    strings:
        $s0 = "res/layout/logo_layout.xml"
        $s1 = "$Lcom/exoclick/app/tubes/BuildConfig"
        $s2 = "$Lcom/exoclick/app/tubes/R$styleable"
        $s3 = "$Lcom/exoclick/app/tubes/model/Video"
        $s4 = "--com.exoclick.app.tubes.customviews.CardLayout"
        $s5 = "--com.exoclick.app.tubes.downloads.DownloadItem"
        $s6 = "-Lcom/exoclick/app/tubes/DisclaimerActivity$1"
        $s7 = "-Lcom/exoclick/app/tubes/DisclaimerActivity$2"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00144 {
    strings:
        $s0 = "Settings::save"
        $s1 = "ThreadOperationListener.java"
        $s2 = "Settings::load"
        $s3 = "RwY7bp1C/mAHk1MxPLhfhPev/oM"
        $s4 = "javascript:androidVersion"
        $s5 = "webapi.cancelUse"
        $s6 = "/license.html"
        $s7 = "assets/html/default/icon.png"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00145 {
    strings:
        $s0 = "com.webcash.wooribank"
        $s1 = "3IOmkvQWrLqujnhgiQF/suWDebQ"
        $s2 = "Q0j/LlUSDZKDI8"
        $s3 = "com.areo.bs"
        $s4 = "res/drawable-hdpi/bgsp.jpg"
        $s5 = "com.kakaotalk.synservice.TIK"
        $s6 = "com.kakaotalk.synservice.URL"
        $s7 = "Ppc2qe3pbHXr7i/fpIqi0VUnHrs"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00146 {
    strings:
        $s0 = "assets/css/smoothness/images/ui-bg_flat_0_aaaaaa_40x100.png"
        $s1 = "assets/css/smoothness/images/ui-bg_flat_75_ffffff_40x100.png"
        $s2 = "assets/css/smoothness/images/ui-bg_glass_55_fbf9ee_1x400.png"
        $s3 = "assets/css/smoothness/images/ui-bg_glass_65_ffffff_1x400.png"
        $s4 = "assets/css/smoothness/images/ui-bg_glass_75_dadada_1x400.png"
        $s5 = "assets/css/smoothness/images/ui-bg_glass_75_e6e6e6_1x400.png"
        $s6 = "assets/css/smoothness/images/ui-bg_glass_95_fef1ec_1x400.png"
        $s7 = "assets/css/smoothness/images/ui-bg_highlight-soft_75_cccccc_1x10"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00147 {
    strings:
        $s0 = "res/layout/rools.xml"
        $s1 = "sRNe/i3dVkjN0LlFUIHAc3hBgfM"
        $s2 = "assets/rools.txt"
        $s3 = "QGaGmfqVuOnqnJPQRJFAKhw/iFM"
    condition:
        any of ($s0, $s1, $s2, $s3)
}

rule VX_APK_CLUSTER_00148 {
    strings:
        $s0 = "res/drawable-hdpi-v4/icon.xml"
        $s1 = "res/layout/activity_g.xml"
        $s2 = "res/drawable-hdpi-v4/app_launcher.png"
        $s3 = "WFWBO9a7m6MbO/sP/B/yxtr11hnZJLIj8xj46"
        $s4 = "res/layout/nothing_layout.xml"
        $s5 = "assets/hoal/even"
        $s6 = "hoal/even"
        $s7 = "eZ/UkP90YpvGyHDxZbUMzgah60ebUDfudofqYWVBWo8"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00149 {
    strings:
        $s0 = "assets/url.txt"
        $s1 = "contactsutils.java"
        $s2 = "$Lb4a/example/contactsutils$_cuemail"
        $s3 = "$Lb4a/example/contactsutils$_cuphone"
        $s4 = "DiviceInfo.java"
        $s5 = "Lb4a/example/contactsutils"
        $s6 = "Lb4a/example/contactsutils$_cucontact"
        $s7 = "Lcom/reza/sh/deviceinfo/DiviceInfo"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00150 {
    strings:
        $s0 = "assets/css/smoothness/images/ui-bg_flat_0_aaaaaa_40x100.png"
        $s1 = "assets/css/smoothness/images/ui-bg_flat_75_ffffff_40x100.png"
        $s2 = "assets/css/smoothness/images/ui-bg_glass_55_fbf9ee_1x400.png"
        $s3 = "assets/css/smoothness/images/ui-bg_glass_65_ffffff_1x400.png"
        $s4 = "assets/css/smoothness/images/ui-bg_glass_75_dadada_1x400.png"
        $s5 = "assets/css/smoothness/images/ui-bg_glass_75_e6e6e6_1x400.png"
        $s6 = "assets/css/smoothness/images/ui-bg_glass_95_fef1ec_1x400.png"
        $s7 = "assets/css/smoothness/images/ui-bg_highlight-soft_75_cccccc_1x10"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00151 {
    strings:
        $s0 = "tmx2ePqGYvOES/jfGp8NEsyAr6VQe6a1ddiSGcNeMew"
        $s1 = "5WUT8N6LC6PF97Z1cG6m0zl4jGoS61p2PFskeHZ/7H8"
        $s2 = "5zYlqV0yGhsf8psU6UD/K9pJraTe5BNHpqXw1m/ldaY"
        $s3 = "6Z1OfrQSv3aFRVck/D2THFRFQy7oPs0r0FzJQ9ZDnsA"
        $s4 = "nATYSIAfjzRbggjV1YNC7AZa4X/gvplYZT5MWRd43fg"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4)
}

rule VX_APK_CLUSTER_00152 {
    strings:
        $s0 = "com.webcash.wooribank"
        $s1 = "res/drawable-hdpi/nh.png"
        $s2 = "res/drawable-hdpi/sh.png"
        $s3 = "/conf.ini"
        $s4 = "App.Alert"
        $s5 = "alert.main"
        $s6 = "app.auto.install"
        $s7 = "app.dwonload.complate"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00153 {
    strings:
        $s0 = "lib/armeabi-v7a/libkc.so"
        $s1 = "res/drawable-xhdpi/i.xml"
        $s2 = "7W/Dw4PV5zyQ7DQStT9Oucg6OwOH8v8Kp2Aerjo3iMA"
    condition:
        any of ($s0, $s1, $s2)
}

rule VX_APK_CLUSTER_00154 {
    strings:
        $s0 = "mian.iyu"
        $s1 = "/AcvZ4Yycp/fuahUizra4r219Ug"
        $s2 = "UaAcDtpGmSrYRacrNRzul/Gk4Pw"
        $s3 = "a3V5KpEW/d14VzAGShsebenhDEI"
        $s4 = "assets/lib.so"
        $s5 = "lib/armeabi-v7a/libygsiyu.so"
        $s6 = "lib/x86/libygsiyu.so"
        $s7 = "tTYPFQeo26XIrs6xdPYO/zvBEiM"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00155 {
    strings:
        $s0 = "-Lcom/getjar/sdk/response/BlacklistedResponse"
        $s1 = "-Lcom/getjar/sdk/utilities/TransactionUtility"
        $s2 = ".Lcom/getjar/sdk/response/FailureRetryResponse"
        $s3 = ".Lcom/getjar/sdk/rewards/GetJarWebViewActivity"
        $s4 = "/Lcom/getjar/sdk/data/metadata/PackageMonitor$2"
        $s5 = "/Lcom/getjar/sdk/data/metadata/PackageMonitor$3"
        $s6 = "/Lcom/getjar/sdk/data/metadata/PackageMonitor$4"
        $s7 = "/Lcom/getjar/sdk/response/BlacklistedResponse$1"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00156 {
    strings:
        $s0 = "assets/css/smoothness/images/ui-bg_flat_0_aaaaaa_40x100.png"
        $s1 = "assets/css/smoothness/images/ui-bg_flat_75_ffffff_40x100.png"
        $s2 = "assets/css/smoothness/images/ui-bg_glass_55_fbf9ee_1x400.png"
        $s3 = "assets/css/smoothness/images/ui-bg_glass_65_ffffff_1x400.png"
        $s4 = "assets/css/smoothness/images/ui-bg_glass_75_dadada_1x400.png"
        $s5 = "assets/css/smoothness/images/ui-bg_glass_75_e6e6e6_1x400.png"
        $s6 = "assets/css/smoothness/images/ui-bg_glass_95_fef1ec_1x400.png"
        $s7 = "assets/css/smoothness/images/ui-bg_highlight-soft_75_cccccc_1x10"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00157 {
    strings:
        $s0 = "assets/css/smoothness/images/ui-bg_flat_0_aaaaaa_40x100.png"
        $s1 = "assets/css/smoothness/images/ui-bg_flat_75_ffffff_40x100.png"
        $s2 = "assets/css/smoothness/images/ui-bg_glass_55_fbf9ee_1x400.png"
        $s3 = "assets/css/smoothness/images/ui-bg_glass_65_ffffff_1x400.png"
        $s4 = "assets/css/smoothness/images/ui-bg_glass_75_dadada_1x400.png"
        $s5 = "assets/css/smoothness/images/ui-bg_glass_75_e6e6e6_1x400.png"
        $s6 = "assets/css/smoothness/images/ui-bg_glass_95_fef1ec_1x400.png"
        $s7 = "assets/css/smoothness/images/ui-bg_highlight-soft_75_cccccc_1x10"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00158 {
    strings:
        $s0 = "xoYHeP/23ezgc3yGF9063z"
        $s1 = "res/layout/offert.xml"
        $s2 = "1.6.0_03-p4"
        $s3 = "res/raw/countries.cfg"
        $s4 = "res/layout/activation_done.xml"
        $s5 = "res/raw/sms.cfg"
        $s6 = "FilesParser.java"
        $s7 = "Lcom/depositmobi/FilesParser"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00159 {
    strings:
        $s0 = "res/xml/empty.xml"
        $s1 = "content://ABC"
        $s2 = "res/layout/ad_helper.xml"
        $s3 = "res/layout/shield.xml"
        $s4 = ".android.settings"
        $s5 = "res/drawable/pm_ok.xml"
        $s6 = "res/drawable/pmok_state.xml"
        $s7 = "res/layout/activity_pm.xml"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00160 {
    strings:
        $s0 = "com.webcash.wooribank"
        $s1 = "res/drawable-hdpi/nh.png"
        $s2 = "res/drawable-hdpi/sh.png"
        $s3 = "res/drawable-hdpi/kb.png"
        $s4 = "Q0j/LlUSDZKDI8"
        $s5 = "res/drawable-hdpi/hana.png"
        $s6 = "res/layout/woori_main_activity.xml"
        $s7 = "res/drawable-hdpi/intro_bg.png"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00161 {
    strings:
        $s0 = "myAOnVezFsTkzSr/E8uO/KdEA"
        $s1 = "res/anim/large_progressbar_animator.xml"
        $s2 = "jJuOui8LVgvIX/td4WnbqpYysO8"
        $s3 = "res/drawable/progressdialog_bg.xml"
        $s4 = "res/layout/hor_line_gray.xml"
        $s5 = "layout/hor_line_gray"
        $s6 = "res/layout/main_left_layout.xml"
        $s7 = "res/layout/main_right_layout.xml"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00162 {
    strings:
        $s0 = "res/drawable-xxxhdpi-v4/pay_kind_normal.png"
        $s1 = "res/drawable-xxxhdpi-v4/pay_kind_select.png"
        $s2 = "res/drawable-xxxhdpi-v4/pay_weixin.png"
        $s3 = "res/drawable-xxxhdpi-v4/pay_zhifubao.png"
        $s4 = "K3v2G3ljflXAQJj95mStWFBkZ/Q"
        $s5 = "Lcom/unionpay/UPPayAssistEx"
        $s6 = "res/drawable/dia_money_selecor.xml"
        $s7 = "res/drawable/pay_dialog_close_selector.xml"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00163 {
    strings:
        $s0 = "xoYHeP/23ezgc3yGF9063z"
        $s1 = "res/layout/grant_access_to_content.xml"
        $s2 = "res/layout/offert.xml"
        $s3 = "1.6.0_03-p4"
        $s4 = "SmsSender.java"
        $s5 = "res/raw/activation_schemes.cfg"
        $s6 = "NfImZUlrjjdAxlih/kZXenDCSU8"
        $s7 = "res/drawable/progress_finished.xml"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00164 {
    strings:
        $s0 = "lib/armeabi/libcrypt_sign.so"
        $s1 = "assets/wyzf/res.bin"
        $s2 = "13/Ayo17/DPtKNh46JVIv6osRPo"
        $s3 = "Qmxju5/Ap5mgu1cFHvmJFycrWMw"
        $s4 = "com/unicom/wounipaysms/dialog/images/cancel.png"
        $s5 = "com/unicom/wounipaysms/dialog/images/cancel_on.png"
        $s6 = "com/unicom/wounipaysms/dialog/images/confirm_bt.9.png"
        $s7 = "com/unicom/wounipaysms/dialog/images/confirm_bt_on.9.png"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00165 {
    strings:
        $s0 = "res/layout/finish.xml"
        $s1 = "res/raw/config.txt"
        $s2 = "OpInfo.java"
        $s3 = "assets/texts/finish_activity.txt"
        $s4 = "assets/texts/first_activity.txt"
        $s5 = "assets/texts/ru/finish_activity.txt"
        $s6 = "assets/texts/ru/first_activity.txt"
        $s7 = "assets/texts/ru/rules_activity.txt"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00166 {
    strings:
        $s0 = "res/layout/finish.xml"
        $s1 = "res/raw/config.txt"
        $s2 = "OpInfo.java"
        $s3 = "assets/texts/finish_activity.txt"
        $s4 = "assets/texts/first_activity.txt"
        $s5 = "assets/texts/ru/finish_activity.txt"
        $s6 = "assets/texts/ru/first_activity.txt"
        $s7 = "assets/texts/ru/rules_activity.txt"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00167 {
    strings:
        $s0 = "res/raw/act_schemes.cfg"
        $s1 = "res/xml/texts.xml"
        $s2 = "res/layout/off.xml"
        $s3 = "c/nL07Gy7K3maRlEL1MxCVwf4FU"
        $s4 = "res/drawable/checkbox_label_background.9.png"
        $s5 = "18/aznZQx9KN6O9oFh9zkx3tu4w"
        $s6 = "res/drawable/0.temp"
        $s7 = "ShowLink.java"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00168 {
    strings:
        $s0 = "tmx2ePqGYvOES/jfGp8NEsyAr6VQe6a1ddiSGcNeMew"
        $s1 = "5WUT8N6LC6PF97Z1cG6m0zl4jGoS61p2PFskeHZ/7H8"
        $s2 = "2o1f08s4ihKK2fy37dmIRlo3B3/iAOLvEwqe5G3VI6M"
        $s3 = "3PL37/LA6F6cQlcwE/Bez9Tyugc"
        $s4 = "9gvSiI/sWlYAWTkv"
        $s5 = "GT6Z4sjRroSUlaiGL/MTW4o37G9qwI18dLG/VMaBn2k"
        $s6 = "VFXcGqG2OaI/80S7opsg"
        $s7 = "VoPy/hbPPy"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00169 {
    strings:
        $s0 = "tmx2ePqGYvOES/jfGp8NEsyAr6VQe6a1ddiSGcNeMew"
        $s1 = "5WUT8N6LC6PF97Z1cG6m0zl4jGoS61p2PFskeHZ/7H8"
        $s2 = "2o1f08s4ihKK2fy37dmIRlo3B3/iAOLvEwqe5G3VI6M"
        $s3 = "3PL37/LA6F6cQlcwE/Bez9Tyugc"
        $s4 = "9gvSiI/sWlYAWTkv"
        $s5 = "GT6Z4sjRroSUlaiGL/MTW4o37G9qwI18dLG/VMaBn2k"
        $s6 = "VFXcGqG2OaI/80S7opsg"
        $s7 = "VoPy/hbPPy"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00170 {
    strings:
        $s0 = "assets/css/smoothness/images/ui-bg_flat_0_aaaaaa_40x100.png"
        $s1 = "assets/css/smoothness/images/ui-bg_flat_75_ffffff_40x100.png"
        $s2 = "assets/css/smoothness/images/ui-bg_glass_55_fbf9ee_1x400.png"
        $s3 = "assets/css/smoothness/images/ui-bg_glass_65_ffffff_1x400.png"
        $s4 = "assets/css/smoothness/images/ui-bg_glass_75_dadada_1x400.png"
        $s5 = "assets/css/smoothness/images/ui-bg_glass_75_e6e6e6_1x400.png"
        $s6 = "assets/css/smoothness/images/ui-bg_glass_95_fef1ec_1x400.png"
        $s7 = "assets/css/smoothness/images/ui-bg_highlight-soft_75_cccccc_1x10"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00171 {
    strings:
        $s0 = "lib/armeabi/libcrypt_sign.so"
        $s1 = "13/Ayo17/DPtKNh46JVIv6osRPo"
        $s2 = "Qmxju5/Ap5mgu1cFHvmJFycrWMw"
        $s3 = "com/unicom/wounipaysms/dialog/images/cancel.png"
        $s4 = "com/unicom/wounipaysms/dialog/images/cancel_on.png"
        $s5 = "com/unicom/wounipaysms/dialog/images/confirm_bt.9.png"
        $s6 = "com/unicom/wounipaysms/dialog/images/confirm_bt_on.9.png"
        $s7 = "com/unicom/wounipaysms/dialog/images/main_bg.9.png"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00172 {
    strings:
        $s0 = "res/raw/data.db"
        $s1 = "Lorg/MobileDb/Field"
        $s2 = "Lorg/MobileDb/MobileDatabase"
        $s3 = "Lorg/MobileDb/Row"
        $s4 = "Lorg/MobileDb/Table"
        $s5 = "Lorg/MobileDb/Utf8StringBuffer"
        $s6 = ".---NKxx"
        $s7 = "MobileDatabase.java"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00173 {
    strings:
        $s0 = "res/raw/data.db"
        $s1 = "Lorg/MobileDb/Field"
        $s2 = "Lorg/MobileDb/MobileDatabase"
        $s3 = "Lorg/MobileDb/Row"
        $s4 = "Lorg/MobileDb/Table"
        $s5 = "Lorg/MobileDb/Utf8StringBuffer"
        $s6 = ".---NKxx"
        $s7 = "MobileDatabase.java"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00174 {
    strings:
        $s0 = "res/raw/data.db"
        $s1 = "Lorg/MobileDb/Field"
        $s2 = "Lorg/MobileDb/MobileDatabase"
        $s3 = "Lorg/MobileDb/Row"
        $s4 = "Lorg/MobileDb/Table"
        $s5 = "Lorg/MobileDb/Utf8StringBuffer"
        $s6 = ".---NKxx"
        $s7 = "MobileDatabase.java"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00175 {
    strings:
        $s0 = "receiver/install"
        $s1 = "http://app"
        $s2 = "receiver/uninstall"
        $s3 = "receiver/load_ad"
        $s4 = "receiver/load_offer"
        $s5 = "Lcom/waps/OffersWebView"
        $s6 = "UPermission.ACCESS_WIFI_STATE"
        $s7 = "Lcom/waps/a"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00176 {
    strings:
        $s0 = "Settings::save"
        $s1 = "ThreadOperationListener.java"
        $s2 = "Settings::load"
        $s3 = "RwY7bp1C/mAHk1MxPLhfhPev/oM"
        $s4 = "javascript:androidVersion"
        $s5 = "webapi.cancelUse"
        $s6 = "/license.html"
        $s7 = "assets/html/default/icon.png"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00177 {
    strings:
        $s0 = "MReceiver.java"
        $s1 = "Localservice.java"
        $s2 = "MJobService.java"
        $s3 = "res/mipmap-hdpi/application_icon.png"
        $s4 = "layout/include_loading"
        $s5 = "$Lcom/h5game/service/RemoteService$1"
        $s6 = "$Lcom/h5game/service/RemoteService$a"
        $s7 = "/Download/com.h5game.txt"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00178 {
    strings:
        $s0 = "PlJSQqWxy9Pig116SM/fEvHLyIQ"
        $s1 = "//0N3FbUo5cvT8"
        $s2 = "/Xd8TjhwyNbYb2Z/"
        $s3 = "http://ehttp-host-"
        $s4 = "LwcvoEmrFpXVcD/7dJS3ijfU6Fo"
        $s5 = "6/W5YFA9Dv7aBsElhk"
        $s6 = "AaNfidSePp/TeMxfv4Ssd"
        $s7 = "KjQ8YcSDNo0FojMfa/QOJ"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00179 {
    strings:
        $s0 = "xoYHeP/23ezgc3yGF9063z"
        $s1 = "res/layout/grant_access_to_content.xml"
        $s2 = "res/layout/offert.xml"
        $s3 = "1.6.0_03-p4"
        $s4 = "GrantAccess.java"
        $s5 = "res/raw/activation_schemes.cfg"
        $s6 = "NfImZUlrjjdAxlih/kZXenDCSU8"
        $s7 = "res/drawable/progress_finished.xml"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00180 {
    strings:
        $s0 = "res/mipmap-xxhdpi-v4/ic_launcher_empty.png"
        $s1 = "res/mipmap-xxhdpi-v4/ic_launcher_video.png"
        $s2 = "Md3MSA/sg/op1reCKgNZCskn84E"
        $s3 = "res/mipmap-xxhdpi-v4/ic_launcher_antivirus.png"
        $s4 = "res/mipmap-xxhdpi-v4/ic_launcher_flash.png"
        $s5 = "res/mipmap-xxhdpi-v4/ic_launcher_music.png"
        $s6 = "res/mipmap-xxhdpi-v4/ic_launcher_robot.png"
        $s7 = "res/mipmap-xxhdpi-v4/ic_launcher_security.png"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00181 {
    strings:
        $s0 = "res/mipmap-xxhdpi-v4/ic_launcher_empty.png"
        $s1 = "res/mipmap-xxhdpi-v4/ic_launcher_video.png"
        $s2 = "Md3MSA/sg/op1reCKgNZCskn84E"
        $s3 = "res/mipmap-xxhdpi-v4/ic_launcher_antivirus.png"
        $s4 = "res/mipmap-xxhdpi-v4/ic_launcher_flash.png"
        $s5 = "res/mipmap-xxhdpi-v4/ic_launcher_music.png"
        $s6 = "res/mipmap-xxhdpi-v4/ic_launcher_robot.png"
        $s7 = "res/mipmap-xxhdpi-v4/ic_launcher_security.png"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00182 {
    strings:
        $s0 = "DeviceAdminCustomReceiver.java"
        $s1 = "xJhBFhG/dtme7AU76jxJO8aPLi0"
        $s2 = "0c8EZd/vg9"
        $s3 = "2DSVeVn/v/bnTR5/JFK3Ced"
        $s4 = "6w5m/FzZSaKminEO9WYThWdqtaM"
        $s5 = "Fl63jz/7ulRrqVTlz34Faw4"
        $s6 = "SSsay/2cyBvZU6vqA0R1Shmpd8c"
        $s7 = "U3aoRwyh/XYaSMBihQTrfafJN1E"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00183 {
    strings:
        $s0 = "l/cUiZLb7ya5qOYV/djf/zcvnb0"
        $s1 = "res/raw/conf.txt"
        $s2 = "res/raw/result"
        $s3 = "res/raw/resulturl"
        $s4 = "res/raw/rool.txt"
        $s5 = "res/drawable-hdpi/iconnews.png"
        $s6 = "res/drawable-mdpi/iconnews.png"
        $s7 = "http://91.213.175.176/api/"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00184 {
    strings:
        $s0 = "res/layout/finish.xml"
        $s1 = "res/raw/config.txt"
        $s2 = "OpInfo.java"
        $s3 = "assets/texts/finish_activity.txt"
        $s4 = "assets/texts/first_activity.txt"
        $s5 = "assets/texts/ru/finish_activity.txt"
        $s6 = "assets/texts/ru/first_activity.txt"
        $s7 = "assets/texts/ru/rules_activity.txt"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00185 {
    strings:
        $s0 = "res/raw/act_schemes.cfg"
        $s1 = "res/xml/texts.xml"
        $s2 = "res/layout/off.xml"
        $s3 = "ShowLink.java"
        $s4 = "res/layout/grant_access_to_content.xml"
        $s5 = "OffertActivity.java"
        $s6 = "com.software.app.CHECKER"
        $s7 = "res/drawable/install_icon.png"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00186 {
    strings:
        $s0 = "res/raw/act_schemes.cfg"
        $s1 = "res/xml/texts.xml"
        $s2 = "res/layout/off.xml"
        $s3 = "c/nL07Gy7K3maRlEL1MxCVwf4FU"
        $s4 = "res/drawable/checkbox_label_background.9.png"
        $s5 = "18/aznZQx9KN6O9oFh9zkx3tu4w"
        $s6 = "ShowLink.java"
        $s7 = "res/layout/grant_access_to_content.xml"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00187 {
    strings:
        $s0 = "res/drawable-mdpi/abc_textfield_search_activated_mtrl_alpha.9.png"
        $s1 = "res/drawable-xxhdpi/abc_textfield_search_activated_mtrl_alpha.9.pn"
        $s2 = "res/drawable-xxhdpi/abc_textfield_search_default_mtrl_alpha.9.png"
        $s3 = "res/drawable-hdpi/abc_textfield_search_activated_mtrl_alpha.9.png"
        $s4 = "res/drawable-xhdpi/abc_textfield_search_activated_mtrl_alpha.9.png"
        $s5 = "res/drawable-xxxhdpi/abc_scrubber_control_to_pressed_mtrl_000.png"
        $s6 = "res/drawable-xxxhdpi/abc_scrubber_control_to_pressed_mtrl_005.png"
        $s7 = "res/drawable-xxhdpi/common_google_signin_btn_icon_dark_normal_back"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00188 {
    strings:
        $s0 = "res/layout/rools.xml"
        $s1 = "sRNe/i3dVkjN0LlFUIHAc3hBgfM"
        $s2 = "assets/rools.txt"
        $s3 = "/mnt/sdcard/download/"
        $s4 = "/stats/adv.php"
        $s5 = "/stats/open.php"
        $s6 = "/stats/press.php"
        $s7 = "rools.txt"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00189 {
    strings:
        $s0 = "tmx2ePqGYvOES/jfGp8NEsyAr6VQe6a1ddiSGcNeMew"
        $s1 = "5WUT8N6LC6PF97Z1cG6m0zl4jGoS61p2PFskeHZ/7H8"
        $s2 = "2o1f08s4ihKK2fy37dmIRlo3B3/iAOLvEwqe5G3VI6M"
        $s3 = "3PL37/LA6F6cQlcwE/Bez9Tyugc"
        $s4 = "9gvSiI/sWlYAWTkv"
        $s5 = "GT6Z4sjRroSUlaiGL/MTW4o37G9qwI18dLG/VMaBn2k"
        $s6 = "VFXcGqG2OaI/80S7opsg"
        $s7 = "VoPy/hbPPy"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00190 {
    strings:
        $s0 = "RwY7bp1C/mAHk1MxPLhfhPev/oM"
        $s1 = "javascript:androidVersion"
        $s2 = "webapi.cancelUse"
        $s3 = "/license.html"
        $s4 = "assets/html/default/icon.png"
        $s5 = "assets/html/default/index.html"
        $s6 = "assets/html/default/license.html"
        $s7 = "assets/html/default/style.css"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00191 {
    strings:
        $s0 = "assets/css/smoothness/images/ui-bg_flat_0_aaaaaa_40x100.png"
        $s1 = "assets/css/smoothness/images/ui-bg_flat_75_ffffff_40x100.png"
        $s2 = "assets/css/smoothness/images/ui-bg_glass_55_fbf9ee_1x400.png"
        $s3 = "assets/css/smoothness/images/ui-bg_glass_65_ffffff_1x400.png"
        $s4 = "assets/css/smoothness/images/ui-bg_glass_75_dadada_1x400.png"
        $s5 = "assets/css/smoothness/images/ui-bg_glass_75_e6e6e6_1x400.png"
        $s6 = "assets/css/smoothness/images/ui-bg_glass_95_fef1ec_1x400.png"
        $s7 = "assets/css/smoothness/images/ui-bg_highlight-soft_75_cccccc_1x10"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00192 {
    strings:
        $s0 = "apkprotect.com/key.dat"
        $s1 = "apkprotect.com/readme.txt"
        $s2 = "ReplayStruct.java"
        $s3 = "RequestStruct.java"
        $s4 = "LSecScreen.java"
        $s5 = "res/xml/lsecscreen.xml"
        $s6 = "serivce."
        $s7 = "BaseBootReceiver.java"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00193 {
    strings:
        $s0 = "receiver/install"
        $s1 = "UPermission.ACCESS_WIFI_STATE"
        $s2 = "UnPackage.dat"
        $s3 = "complete.Click"
        $s4 = "installed.Click"
        $s5 = "CacheTime.dat"
        $s6 = "/Android/data/cache/iconCache"
        $s7 = "Permission.ACCESS_WIFI_STATE"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00194 {
    strings:
        $s0 = "tmx2ePqGYvOES/jfGp8NEsyAr6VQe6a1ddiSGcNeMew"
        $s1 = "5WUT8N6LC6PF97Z1cG6m0zl4jGoS61p2PFskeHZ/7H8"
        $s2 = "sSXSzEqFKMrA6jBWGd3/ny0rkM5WbWISaQbV9uWVDnU"
        $s3 = "waSlUxaesqmgrWPt/coLJ37Snvg"
    condition:
        any of ($s0, $s1, $s2, $s3)
}

rule VX_APK_CLUSTER_00195 {
    strings:
        $s0 = "res/layout/rools.xml"
        $s1 = "sRNe/i3dVkjN0LlFUIHAc3hBgfM"
        $s2 = "assets/rools.txt"
        $s3 = "/mnt/sdcard/download/"
        $s4 = "rools.txt"
        $s5 = "AReceiver.java"
        $s6 = "Lcom/uniplugin/sender/AReceiver"
        $s7 = "Lcom/uniplugin/sender/AReceiver$Maintwo"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00196 {
    strings:
        $s0 = "com.webcash.wooribank"
        $s1 = "res/drawable-hdpi/nh.png"
        $s2 = "res/drawable-hdpi/sh.png"
        $s3 = "/conf.ini"
        $s4 = "App.Alert"
        $s5 = "alert.main"
        $s6 = "app.auto.install"
        $s7 = "app.dwonload.complate"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00197 {
    strings:
        $s0 = "res/drawable/img_android.png"
        $s1 = "res/layout/instruction_dialog.xml"
        $s2 = "res/drawable/shape_gray_border_bottom.xml"
        $s3 = "res/layout/samsung_show_top_dialog.xml"
        $s4 = "res/layout/xiaomi_background_activity_dialog.xml"
        $s5 = "iOTls283qxBiqp1Kk5XhZl3nAXbWKnOn/DsVjWD9f9Q"
        $s6 = "ATvqoz3o52G2n71RMsMXWVtAsQXcjnkHuaAIjvwqS/g"
        $s7 = "assets/shaders/fragment.glsl"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00198 {
    strings:
        $s0 = "$Lcom/hamedia/gamestore/MainActivity"
        $s1 = "Lcom/hamedia/gamestore/BuildConfig"
        $s2 = "Lcom/hamedia/gamestore/MainActivity$GrabURL"
        $s3 = "Lcom/hamedia/gamestore/R"
        $s4 = "Lcom/hamedia/gamestore/R$attr"
        $s5 = "Lcom/hamedia/gamestore/R$dimen"
        $s6 = "Lcom/hamedia/gamestore/R$drawable"
        $s7 = "Lcom/hamedia/gamestore/R$id"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00199 {
    strings:
        $s0 = "res/raw/google.apk"
        $s1 = "res/drawable-hdpi/notification_bg_low_normal.png"
        $s2 = "res/drawable-hdpi/notification_bg_low_pressed.png"
        $s3 = "res/drawable-hdpi/notification_bg_normal.png"
        $s4 = "res/drawable-hdpi/notification_bg_normal_pressed.png"
        $s5 = "res/drawable-mdpi/notification_bg_low_normal.png"
        $s6 = "res/drawable-mdpi/notification_bg_low_pressed.png"
        $s7 = "res/drawable-mdpi/notification_bg_normal.png"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00200 {
    strings:
        $s0 = "l/cUiZLb7ya5qOYV/djf/zcvnb0"
        $s1 = "res/raw/conf.txt"
        $s2 = "res/raw/result"
        $s3 = "res/raw/resulturl"
        $s4 = "res/raw/rool.txt"
        $s5 = "res/drawable-hdpi/iconnews.png"
        $s6 = "res/drawable-mdpi/iconnews.png"
        $s7 = "http://91.213.175.176/api/"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00201 {
    strings:
        $s0 = "mian.iyu"
        $s1 = "/YouGaile/AppFile"
        $s2 = "/iApp/Userimg"
        $s3 = "/iApp/downFile/"
        $s4 = "Lcom/Hy/UI/PredicateLayout"
        $s5 = "Lcom/Hy/UI/a"
        $s6 = "Lcom/Hy/UI/b"
        $s7 = "Lcom/Hy/UI/c"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00202 {
    strings:
        $s0 = "lib/armeabi-v7a/libdq.so"
        $s1 = "ME0YMPt/vxme7iNk"
        $s2 = "res/drawable-xhdpi/empty.xml"
    condition:
        any of ($s0, $s1, $s2)
}

rule VX_APK_CLUSTER_00203 {
    strings:
        $s0 = "PlJSQqWxy9Pig116SM/fEvHLyIQ"
        $s1 = "game.swf"
        $s2 = "get_flash.jsp"
        $s3 = "res/drawable/zt__back.png"
        $s4 = "res/drawable/zt__down.png"
        $s5 = "res/drawable/zt__down_w.png"
        $s6 = "res/drawable/zt__icon_lack.png"
        $s7 = "res/drawable/zt__title_sep.xml"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00204 {
    strings:
        $s0 = "PlJSQqWxy9Pig116SM/fEvHLyIQ"
        $s1 = "game.swf"
        $s2 = "get_flash.jsp"
        $s3 = "res/drawable/zt__back.png"
        $s4 = "res/drawable/zt__down.png"
        $s5 = "res/drawable/zt__down_w.png"
        $s6 = "res/drawable/zt__icon_lack.png"
        $s7 = "res/drawable/zt__title_sep.xml"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00205 {
    strings:
        $s0 = "$Lcom/registr/registrator/R$drawable"
        $s1 = "-Lcom/registr/registrator/RegistratorActivity"
        $s2 = "/Lcom/registr/registrator/RegistratorActivity$1"
        $s3 = "3feFaEAsjjEDulSrntYohJAu/Vs"
        $s4 = "Lcom/registr/registrator/R"
        $s5 = "Lcom/registr/registrator/R$attr"
        $s6 = "Lcom/registr/registrator/R$id"
        $s7 = "Lcom/registr/registrator/R$layout"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00206 {
    strings:
        $s0 = "res/drawable-hdpi/abc_list_pressed_holo_light.png"
        $s1 = "res/drawable-hdpi/abc_list_selector_disabled_holo_light.png"
        $s2 = "res/drawable-mdpi/abc_list_pressed_holo_light.png"
        $s3 = "res/drawable-mdpi/abc_list_selector_disabled_holo_light.png"
        $s4 = "res/drawable-xhdpi/abc_list_pressed_holo_light.png"
        $s5 = "res/drawable-xhdpi/abc_list_selector_disabled_holo_light.png"
        $s6 = "res/drawable-xxhdpi/abc_list_pressed_holo_light.png"
        $s7 = "res/drawable-xxhdpi/abc_list_selector_disabled_holo_light.png"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00207 {
    strings:
        $s0 = "res/raw/act_schemes.cfg"
        $s1 = "res/xml/texts.xml"
        $s2 = "res/layout/off.xml"
        $s3 = "c/nL07Gy7K3maRlEL1MxCVwf4FU"
        $s4 = "res/drawable/checkbox_label_background.9.png"
        $s5 = "18/aznZQx9KN6O9oFh9zkx3tu4w"
        $s6 = "res/drawable/0.temp"
        $s7 = "ShowLink.java"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00208 {
    strings:
        $s0 = "res/drawable/img_android.png"
        $s1 = "res/layout/instruction_dialog.xml"
        $s2 = "res/drawable/shape_gray_border_bottom.xml"
        $s3 = "res/layout/samsung_show_top_dialog.xml"
        $s4 = "res/layout/xiaomi_background_activity_dialog.xml"
        $s5 = "iOTls283qxBiqp1Kk5XhZl3nAXbWKnOn/DsVjWD9f9Q"
        $s6 = "ATvqoz3o52G2n71RMsMXWVtAsQXcjnkHuaAIjvwqS/g"
        $s7 = "assets/shaders/fragment.glsl"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00209 {
    strings:
        $s0 = "tmx2ePqGYvOES/jfGp8NEsyAr6VQe6a1ddiSGcNeMew"
        $s1 = "5WUT8N6LC6PF97Z1cG6m0zl4jGoS61p2PFskeHZ/7H8"
        $s2 = "2o1f08s4ihKK2fy37dmIRlo3B3/iAOLvEwqe5G3VI6M"
        $s3 = "3PL37/LA6F6cQlcwE/Bez9Tyugc"
        $s4 = "9gvSiI/sWlYAWTkv"
        $s5 = "GT6Z4sjRroSUlaiGL/MTW4o37G9qwI18dLG/VMaBn2k"
        $s6 = "VFXcGqG2OaI/80S7opsg"
        $s7 = "VoPy/hbPPy"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00210 {
    strings:
        $s0 = "tmx2ePqGYvOES/jfGp8NEsyAr6VQe6a1ddiSGcNeMew"
        $s1 = "5WUT8N6LC6PF97Z1cG6m0zl4jGoS61p2PFskeHZ/7H8"
        $s2 = "2o1f08s4ihKK2fy37dmIRlo3B3/iAOLvEwqe5G3VI6M"
        $s3 = "3PL37/LA6F6cQlcwE/Bez9Tyugc"
        $s4 = "9gvSiI/sWlYAWTkv"
        $s5 = "GT6Z4sjRroSUlaiGL/MTW4o37G9qwI18dLG/VMaBn2k"
        $s6 = "VFXcGqG2OaI/80S7opsg"
        $s7 = "VoPy/hbPPy"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00211 {
    strings:
        $s0 = "res/raw/act_schemes.cfg"
        $s1 = "res/xml/texts.xml"
        $s2 = "res/layout/off.xml"
        $s3 = "c/nL07Gy7K3maRlEL1MxCVwf4FU"
        $s4 = "res/drawable/checkbox_label_background.9.png"
        $s5 = "18/aznZQx9KN6O9oFh9zkx3tu4w"
        $s6 = "res/drawable/0.temp"
        $s7 = "3XU8DJNQ9o/iAlhePmHQ2ONZPBE"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00212 {
    strings:
        $s0 = "res/raw/act_schemes.cfg"
        $s1 = "res/xml/texts.xml"
        $s2 = "res/layout/off.xml"
        $s3 = "c/nL07Gy7K3maRlEL1MxCVwf4FU"
        $s4 = "res/drawable/checkbox_label_background.9.png"
        $s5 = "18/aznZQx9KN6O9oFh9zkx3tu4w"
        $s6 = "res/drawable/0.temp"
        $s7 = "3XU8DJNQ9o/iAlhePmHQ2ONZPBE"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00213 {
    strings:
        $s0 = "res/layout/dlg_dialog.xml"
        $s1 = "gVo4bAtRhVe8o83SEBQOEQwy/xk"
        $s2 = "res/drawable-hdpi-v4/btn_skip.9.png"
        $s3 = "res/layout/dialog_full.xml"
        $s4 = "res/layout/dialog_middle.xml"
        $s5 = "res/layout/dialog_notification_mo.xml"
        $s6 = "assets/bzcbq.dat"
        $s7 = "3dFhC3me9jOTVWfput4wDO/MFZY"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00214 {
    strings:
        $s0 = "receiver/install"
        $s1 = "http://app"
        $s2 = "receiver/uninstall"
        $s3 = "receiver/load_ad"
        $s4 = "receiver/load_offer"
        $s5 = "Lcom/waps/OffersWebView"
        $s6 = "UPermission.ACCESS_WIFI_STATE"
        $s7 = "Lcom/waps/a"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00215 {
    strings:
        $s0 = "au.com.bankwest.mobile"
        $s1 = "ZzxKlxKyki.i"
        $s2 = "commandus.com"
        $s3 = "--.ixKiidAZ"
        $s4 = "/CalsRlpNBoM"
        $s5 = "/p9USHEeoIE3gQO135Rl6PxRJyo"
        $s6 = "2Lcom/note/donote/receivers/ServiceDestroyReceiver"
        $s7 = "3Lcom/note/donote/receivers/sms/PushServiceReciever"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00216 {
    strings:
        $s0 = "hGV/eFuLm4sXF7Kgiv2LjTr84vc"
        $s1 = "res/drawable-hdpi/opera.jpg"
        $s2 = "res/drawable-hdpi/textbg.xml"
        $s3 = "res/drawable-hdpi/titlebg.xml"
        $s4 = "Wce1MjOVrsjGKh03cKT/M"
        $s5 = "res/drawable-hdpi/ropera.jpg"
        $s6 = "assets/config.res"
        $s7 = "code.reg"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00217 {
    strings:
        $s0 = "xoYHeP/23ezgc3yGF9063z"
        $s1 = "res/layout/offert.xml"
        $s2 = "1.6.0_03-p4"
        $s3 = "res/raw/countries.cfg"
        $s4 = "res/layout/activation_done.xml"
        $s5 = "res/raw/sms.cfg"
        $s6 = "FilesParser.java"
        $s7 = "Lcom/depositmobi/FilesParser"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00218 {
    strings:
        $s0 = "http://jiepay.jiemengkj.com:8152/ryf_webserver/payment"
        $s1 = ".android/.sys/"
        $s2 = "com.jm.jiepay.pay.JiePay"
        $s3 = "com.jm.jiepay.service.InitService"
        $s4 = "jiepayplugin.apk"
        $s5 = "/checkupdate.html"
        $s6 = "$Lcom/jm/jiesdk/JiePayResultListener"
        $s7 = "Lcom/jm/jiesdk/constant/JiePayResult"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00219 {
    strings:
        $s0 = "assets/url.txt"
        $s1 = "contactsutils.java"
        $s2 = "$Lb4a/example/contactsutils$_cuemail"
        $s3 = "$Lb4a/example/contactsutils$_cuphone"
        $s4 = "DiviceInfo.java"
        $s5 = "Lb4a/example/contactsutils"
        $s6 = "Lb4a/example/contactsutils$_cucontact"
        $s7 = "Lcom/reza/sh/deviceinfo/DiviceInfo"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00220 {
    strings:
        $s0 = "apkprotect.com/key.dat"
        $s1 = "apkprotect.com/readme.txt"
        $s2 = "Lcom/android/a"
        $s3 = "ReplayStruct.java"
        $s4 = "RequestStruct.java"
        $s5 = "LSecScreen.java"
        $s6 = "res/xml/lsecscreen.xml"
        $s7 = "Lcom/android/internal/telephony/a"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00221 {
    strings:
        $s0 = "http://jiepay.jiemengkj.com:8152/ryf_webserver/payment"
        $s1 = "Lcom/mixClass"
        $s2 = "mixClass.java"
        $s3 = "/tx_shell"
        $s4 = "/tx_shell/"
        $s5 = "Lcom/tencent/StubShell/ZipUtil"
        $s6 = "libshellb.so"
        $s7 = "libshellc.so"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00222 {
    strings:
        $s0 = "assets/css/smoothness/images/ui-bg_flat_0_aaaaaa_40x100.png"
        $s1 = "assets/css/smoothness/images/ui-bg_flat_75_ffffff_40x100.png"
        $s2 = "assets/css/smoothness/images/ui-bg_glass_55_fbf9ee_1x400.png"
        $s3 = "assets/css/smoothness/images/ui-bg_glass_65_ffffff_1x400.png"
        $s4 = "assets/css/smoothness/images/ui-bg_glass_75_dadada_1x400.png"
        $s5 = "assets/css/smoothness/images/ui-bg_glass_75_e6e6e6_1x400.png"
        $s6 = "assets/css/smoothness/images/ui-bg_glass_95_fef1ec_1x400.png"
        $s7 = "assets/css/smoothness/images/ui-bg_highlight-soft_75_cccccc_1x10"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00223 {
    strings:
        $s0 = "ThreadOperationListener.java"
        $s1 = ".yxyxxyxyK--."
        $s2 = "notificationTickerText:"
        $s3 = "notificationUrl:"
        $s4 = "showHtml:"
        $s5 = "/res/raw/data.dat"
        $s6 = "Lru/alpha/Alpha"
        $s7 = "Lru/alpha/Constants"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00224 {
    strings:
        $s0 = "com.webcash.wooribank"
        $s1 = "res/drawable-hdpi/nh.png"
        $s2 = "res/drawable-hdpi/sh.png"
        $s3 = "/conf.ini"
        $s4 = "App.Alert"
        $s5 = "alert.main"
        $s6 = "app.auto.install"
        $s7 = "app.dwonload.complate"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00225 {
    strings:
        $s0 = "lib/armeabi/libcrypt_sign.so"
        $s1 = "assets/wyzf/res.bin"
        $s2 = "13/Ayo17/DPtKNh46JVIv6osRPo"
        $s3 = "Qmxju5/Ap5mgu1cFHvmJFycrWMw"
        $s4 = "com/unicom/wounipaysms/dialog/images/cancel.png"
        $s5 = "com/unicom/wounipaysms/dialog/images/cancel_on.png"
        $s6 = "com/unicom/wounipaysms/dialog/images/confirm_bt.9.png"
        $s7 = "com/unicom/wounipaysms/dialog/images/confirm_bt_on.9.png"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00226 {
    strings:
        $s0 = "Lcom/energysource/szj/embeded/AdView"
        $s1 = "Lcom/energysource/szj/embeded/AdListener"
        $s2 = "Lcom/energysource/szj/embeded/AdManager"
        $s3 = "Ljackpal/androidterm/Exec"
        $s4 = "/databases/SZJService"
        $s5 = "/databases/SZJServiceBak"
        $s6 = "adtime_in:"
        $s7 = "-mHandler.removeMessages"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00227 {
    strings:
        $s0 = "CheckConnectivity.java"
        $s1 = "/Lcom/uz4/apkmanager/MainActivity$MySetGetClass"
        $s2 = "6Lcom/uz4/apkmanager/MainActivity$MyAdapter$ViewHolder"
        $s3 = "Lcom/uz4/apkmanager/BuildConfig"
        $s4 = "Lcom/uz4/apkmanager/CheckConnectivity"
        $s5 = "Lcom/uz4/apkmanager/JSONParser"
        $s6 = "Lcom/uz4/apkmanager/MainActivity"
        $s7 = "Lcom/uz4/apkmanager/MainActivity$1"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00228 {
    strings:
        $s0 = "res/mipmap-xxhdpi-v4/ic_launcher_empty.png"
        $s1 = "res/mipmap-xxhdpi-v4/ic_launcher_video.png"
        $s2 = "Md3MSA/sg/op1reCKgNZCskn84E"
        $s3 = "res/mipmap-xxhdpi-v4/ic_launcher_antivirus.png"
        $s4 = "res/mipmap-xxhdpi-v4/ic_launcher_flash.png"
        $s5 = "res/mipmap-xxhdpi-v4/ic_launcher_music.png"
        $s6 = "res/mipmap-xxhdpi-v4/ic_launcher_robot.png"
        $s7 = "res/mipmap-xxhdpi-v4/ic_launcher_security.png"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00229 {
    strings:
        $s0 = "res/xml/device_admin_data.xml"
        $s1 = "/kmnLuLqBMOCa2bEZzlLoFKq"
        $s2 = "33com.iitr.kaishu.nsidedprogressbar.NSidedProgressBar"
        $s3 = "CSZx6RMpZhVd/V2215WR4fM7llXd2eeuuljaNHfU9Co"
        $s4 = "res/raw/dx"
        $s5 = "skuU2rJZc81sswK/bAkZDnCYrhcw"
        $s6 = "zG5hJB/n2/IwKLG7Ok2tBSq3d8ZqpxaGsNb7RL7r1LM"
        $s7 = "5MJB/GLAcB4JuhRBpPf2uoRkWLEBRVSCw/iyoUXiTos"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00230 {
    strings:
        $s0 = ".jpg.dat"
        $s1 = "res/drawable-hdpi/title_bg.png"
        $s2 = "assets/pc/icp.dat"
        $s3 = "clst.dat"
        $s4 = "close.dat"
        $s5 = "post.dpi"
        $s6 = "download.dat"
        $s7 = "more.dat"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00231 {
    strings:
        $s0 = "/soapi/adddev"
        $s1 = "/soapi/addmsg"
        $s2 = "/soapi/getmsgs"
        $s3 = "/soapi/imhere"
        $s4 = "DevAdReceiver.java"
        $s5 = "GJBootReceiver.java"
        $s6 = "GJSMSUtil.java"
        $s7 = "HTTPJob.java"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00232 {
    strings:
        $s0 = "lib/armeabi-v7a/libkc.so"
        $s1 = "res/drawable-xhdpi/i.xml"
        $s2 = "Tt7QEY2Ab51SQ/rGSnI72PlKftqiWJsnko5hwY/XF9w"
    condition:
        any of ($s0, $s1, $s2)
}

rule VX_APK_CLUSTER_00233 {
    strings:
        $s0 = "lib/armeabi/libcrypt_sign.so"
        $s1 = "assets/wyzf/res.bin"
        $s2 = "13/Ayo17/DPtKNh46JVIv6osRPo"
        $s3 = "Qmxju5/Ap5mgu1cFHvmJFycrWMw"
        $s4 = "com/unicom/wounipaysms/dialog/images/cancel.png"
        $s5 = "com/unicom/wounipaysms/dialog/images/cancel_on.png"
        $s6 = "com/unicom/wounipaysms/dialog/images/confirm_bt.9.png"
        $s7 = "com/unicom/wounipaysms/dialog/images/confirm_bt_on.9.png"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00234 {
    strings:
        $s0 = "res/layout/finish.xml"
        $s1 = "res/raw/config.txt"
        $s2 = "OpInfo.java"
        $s3 = "assets/texts/finish_activity.txt"
        $s4 = "assets/texts/first_activity.txt"
        $s5 = "assets/texts/ru/finish_activity.txt"
        $s6 = "assets/texts/ru/first_activity.txt"
        $s7 = "assets/texts/ru/rules_activity.txt"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00235 {
    strings:
        $s0 = "res/layout/finish.xml"
        $s1 = "res/raw/config.txt"
        $s2 = "OpInfo.java"
        $s3 = "assets/texts/finish_activity.txt"
        $s4 = "assets/texts/first_activity.txt"
        $s5 = "assets/texts/ru/finish_activity.txt"
        $s6 = "assets/texts/ru/first_activity.txt"
        $s7 = "assets/texts/ru/rules_activity.txt"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00236 {
    strings:
        $s0 = "res/raw/act_schemes.cfg"
        $s1 = "res/xml/texts.xml"
        $s2 = "res/layout/off.xml"
        $s3 = "c/nL07Gy7K3maRlEL1MxCVwf4FU"
        $s4 = "res/drawable/checkbox_label_background.9.png"
        $s5 = "18/aznZQx9KN6O9oFh9zkx3tu4w"
        $s6 = "res/drawable/0.temp"
        $s7 = "ShowLink.java"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00237 {
    strings:
        $s0 = "res/raw/act_schemes.cfg"
        $s1 = "res/xml/texts.xml"
        $s2 = "res/layout/off.xml"
        $s3 = "ShowLink.java"
        $s4 = "xoYHeP/23ezgc3yGF9063z"
        $s5 = "res/layout/grant_access_to_content.xml"
        $s6 = "OffertActivity.java"
        $s7 = "/com.software.application.permission.C2D_MESSAGE"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00238 {
    strings:
        $s0 = "res/raw/act_schemes.cfg"
        $s1 = "res/xml/texts.xml"
        $s2 = "res/layout/off.xml"
        $s3 = "c/nL07Gy7K3maRlEL1MxCVwf4FU"
        $s4 = "res/drawable/checkbox_label_background.9.png"
        $s5 = "18/aznZQx9KN6O9oFh9zkx3tu4w"
        $s6 = "res/drawable/0.temp"
        $s7 = "ShowLink.java"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00239 {
    strings:
        $s0 = "res/raw/act_schemes.cfg"
        $s1 = "res/xml/texts.xml"
        $s2 = "res/layout/off.xml"
        $s3 = "c/nL07Gy7K3maRlEL1MxCVwf4FU"
        $s4 = "res/drawable/checkbox_label_background.9.png"
        $s5 = "18/aznZQx9KN6O9oFh9zkx3tu4w"
        $s6 = "res/drawable/0.temp"
        $s7 = "ShowLink.java"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00240 {
    strings:
        $s0 = "res/raw/act_schemes.cfg"
        $s1 = "res/xml/texts.xml"
        $s2 = "res/layout/off.xml"
        $s3 = "c/nL07Gy7K3maRlEL1MxCVwf4FU"
        $s4 = "res/drawable/checkbox_label_background.9.png"
        $s5 = "18/aznZQx9KN6O9oFh9zkx3tu4w"
        $s6 = "ShowLink.java"
        $s7 = "xoYHeP/23ezgc3yGF9063z"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00241 {
    strings:
        $s0 = "res/layout/rools.xml"
        $s1 = "sRNe/i3dVkjN0LlFUIHAc3hBgfM"
        $s2 = "assets/rools.txt"
        $s3 = "kfdCIJl2EQ8vCB/lMdcNdG5efLE"
        $s4 = "hRSqTgMvQ5p8/VyIFXdtBnaftNg"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4)
}

rule VX_APK_CLUSTER_00242 {
    strings:
        $s0 = "l/cUiZLb7ya5qOYV/djf/zcvnb0"
        $s1 = "res/raw/conf.txt"
        $s2 = "res/raw/result"
        $s3 = "res/raw/resulturl"
        $s4 = "res/raw/rool.txt"
        $s5 = "fe/F7GKQgCOGQMPC2QkptHQH"
        $s6 = "res/raw/roolurl.txt"
        $s7 = "res/raw/animation.txt"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00243 {
    strings:
        $s0 = "lib/armeabi/libcrypt_sign.so"
        $s1 = "assets/wyzf/res.bin"
        $s2 = "13/Ayo17/DPtKNh46JVIv6osRPo"
        $s3 = "Qmxju5/Ap5mgu1cFHvmJFycrWMw"
        $s4 = "com/unicom/wounipaysms/dialog/images/cancel.png"
        $s5 = "com/unicom/wounipaysms/dialog/images/cancel_on.png"
        $s6 = "com/unicom/wounipaysms/dialog/images/confirm_bt.9.png"
        $s7 = "com/unicom/wounipaysms/dialog/images/confirm_bt_on.9.png"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00244 {
    strings:
        $s0 = "res/mipmap-xxhdpi-v4/ic_launcher_empty.png"
        $s1 = "res/mipmap-xxhdpi-v4/ic_launcher_video.png"
        $s2 = "Md3MSA/sg/op1reCKgNZCskn84E"
        $s3 = "res/mipmap-xxhdpi-v4/ic_launcher_antivirus.png"
        $s4 = "res/mipmap-xxhdpi-v4/ic_launcher_flash.png"
        $s5 = "res/mipmap-xxhdpi-v4/ic_launcher_music.png"
        $s6 = "res/mipmap-xxhdpi-v4/ic_launcher_robot.png"
        $s7 = "res/mipmap-xxhdpi-v4/ic_launcher_security.png"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00245 {
    strings:
        $s0 = "res/drawable-hdpi/background.9.png"
        $s1 = "l1nwXdyEa/dgB6fokaLVLuBiYLo"
        $s2 = "jQ1nY/n1s"
        $s3 = "pnk5qYbWMfys/M2lgeTy4J"
        $s4 = "res/drawable-hdpi/background_button.png"
        $s5 = "res/drawable-hdpi/greenbutton_normal.png"
        $s6 = "res/drawable-hdpi/greenbutton_pressed.png"
        $s7 = "res/drawable-hdpi/linkbutton_normal.png"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00246 {
    strings:
        $s0 = "hGV/eFuLm4sXF7Kgiv2LjTr84vc"
        $s1 = "res/drawable-hdpi/opera.jpg"
        $s2 = "res/drawable-hdpi/textbg.xml"
        $s3 = "res/drawable-hdpi/titlebg.xml"
        $s4 = "Wce1MjOVrsjGKh03cKT/M"
        $s5 = "res/drawable-hdpi/ropera.jpg"
        $s6 = "assets/config.res"
        $s7 = "code.reg"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00247 {
    strings:
        $s0 = "/92T0y8Eg3hwmkt655BvOmGHH/XfOxZOEdiIqIwPT0FPT1D"
        $s1 = "/CmOEnNP6lw5ie"
        $s2 = "/G7vW8JQCmu0vfGnYWwVddg0"
        $s3 = "/H7/T0Kh0JlIJPLHaDT6V5vN9l"
        $s4 = "/SgOYNXi9nXGzpgQ/GLoI/F8cBdd9blJWI3aUlcNik9a54bjfK//AWNnzhbv/YNafPouSxJ1C57QdwRE"
        $s5 = "/eV24SQp5AXoVMCIYgaKW2oM5YW3FsEUa0MM5YYYIiLT7a/qH80dJxpu20OlbUodDqTNtBrFNqQzGtpT"
        $s6 = "/lmAoH0kytnp8PooIXsJDodcGUW5F6s8TJtLPyQAqwOisq7O2U8Is7zJBWXK/EOquTsVWzctRc/"
        $s7 = "/wMWjgermQx"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00248 {
    strings:
        $s0 = "receiver/install"
        $s1 = "UPermission.ACCESS_WIFI_STATE"
        $s2 = "UnPackage.dat"
        $s3 = "complete.Click"
        $s4 = "installed.Click"
        $s5 = "CacheTime.dat"
        $s6 = "/Android/data/cache/iconCache"
        $s7 = "Permission.ACCESS_WIFI_STATE"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00249 {
    strings:
        $s0 = "l/cUiZLb7ya5qOYV/djf/zcvnb0"
        $s1 = "res/raw/conf.txt"
        $s2 = "res/raw/result"
        $s3 = "res/raw/resulturl"
        $s4 = "res/raw/rool.txt"
        $s5 = "fe/F7GKQgCOGQMPC2QkptHQH"
        $s6 = "res/raw/roolurl.txt"
        $s7 = "res/raw/animation.txt"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00250 {
    strings:
        $s0 = "mian.iyu"
        $s1 = "/AcvZ4Yycp/fuahUizra4r219Ug"
        $s2 = "UaAcDtpGmSrYRacrNRzul/Gk4Pw"
        $s3 = "a3V5KpEW/d14VzAGShsebenhDEI"
        $s4 = "assets/lib.so"
        $s5 = "lib/armeabi-v7a/libygsiyu.so"
        $s6 = "lib/x86/libygsiyu.so"
        $s7 = "tTYPFQeo26XIrs6xdPYO/zvBEiM"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00251 {
    strings:
        $s0 = "mian.iyu"
        $s1 = "/AcvZ4Yycp/fuahUizra4r219Ug"
        $s2 = "UaAcDtpGmSrYRacrNRzul/Gk4Pw"
        $s3 = "a3V5KpEW/d14VzAGShsebenhDEI"
        $s4 = "assets/lib.so"
        $s5 = "lib/armeabi-v7a/libygsiyu.so"
        $s6 = "lib/x86/libygsiyu.so"
        $s7 = "tTYPFQeo26XIrs6xdPYO/zvBEiM"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00252 {
    strings:
        $s0 = "mian.iyu"
        $s1 = "/AcvZ4Yycp/fuahUizra4r219Ug"
        $s2 = "UaAcDtpGmSrYRacrNRzul/Gk4Pw"
        $s3 = "a3V5KpEW/d14VzAGShsebenhDEI"
        $s4 = "assets/lib.so"
        $s5 = "lib/armeabi-v7a/libygsiyu.so"
        $s6 = "lib/x86/libygsiyu.so"
        $s7 = "tTYPFQeo26XIrs6xdPYO/zvBEiM"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00253 {
    strings:
        $s0 = "l/cUiZLb7ya5qOYV/djf/zcvnb0"
        $s1 = "res/raw/conf.txt"
        $s2 = "res/raw/result"
        $s3 = "res/raw/resulturl"
        $s4 = "res/raw/rool.txt"
        $s5 = "res/drawable-hdpi/iconnews.png"
        $s6 = "res/drawable-mdpi/iconnews.png"
        $s7 = "http://91.213.175.176/api/"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00254 {
    strings:
        $s0 = "/test.png"
        $s1 = "res/drawable/doodle.jpg"
        $s2 = "Ehttp://chateau-viranel.com/viranelous_nono/include/secu/class_poo.php"
        $s3 = "ErrorU.P"
        $s4 = "BlackMarketAlpha.java"
        $s5 = "Cm3S1JrFqp/UIKrdQ"
        $s6 = "res/raw/v.x"
        $s7 = "$Lcom/android/blackmarket/R$drawable"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00255 {
    strings:
        $s0 = "res/layout/rools.xml"
        $s1 = "sRNe/i3dVkjN0LlFUIHAc3hBgfM"
        $s2 = "assets/rools.txt"
        $s3 = "/mnt/sdcard/download/"
        $s4 = "/stats/adv.php"
        $s5 = "/stats/open.php"
        $s6 = "/stats/press.php"
        $s7 = "rools.txt"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00256 {
    strings:
        $s0 = "CheckConnectivity.java"
        $s1 = "-Lcom/free/appdownload/util/SystemUiHiderBase"
        $s2 = "2Lcom/free/appdownload/util/SystemUiHiderHoneycomb"
        $s3 = "4Lcom/free/appdownload/util/SystemUiHiderHoneycomb$1"
        $s4 = "DLcom/free/appdownload/util/SystemUiHider$OnVisibilityChangeListener"
        $s5 = "Lcom/free/appdownload/BuildConfig"
        $s6 = "Lcom/free/appdownload/CheckConnectivity"
        $s7 = "Lcom/free/appdownload/FullscreenActivity"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00257 {
    strings:
        $s0 = "lib/armeabi/libcrypt_sign.so"
        $s1 = "13/Ayo17/DPtKNh46JVIv6osRPo"
        $s2 = "Qmxju5/Ap5mgu1cFHvmJFycrWMw"
        $s3 = "com/unicom/wounipaysms/dialog/images/cancel.png"
        $s4 = "com/unicom/wounipaysms/dialog/images/cancel_on.png"
        $s5 = "com/unicom/wounipaysms/dialog/images/confirm_bt.9.png"
        $s6 = "com/unicom/wounipaysms/dialog/images/confirm_bt_on.9.png"
        $s7 = "com/unicom/wounipaysms/dialog/images/main_bg.9.png"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00258 {
    strings:
        $s0 = "assets/css/smoothness/images/ui-bg_flat_0_aaaaaa_40x100.png"
        $s1 = "assets/css/smoothness/images/ui-bg_flat_75_ffffff_40x100.png"
        $s2 = "assets/css/smoothness/images/ui-bg_glass_55_fbf9ee_1x400.png"
        $s3 = "assets/css/smoothness/images/ui-bg_glass_65_ffffff_1x400.png"
        $s4 = "assets/css/smoothness/images/ui-bg_glass_75_dadada_1x400.png"
        $s5 = "assets/css/smoothness/images/ui-bg_glass_75_e6e6e6_1x400.png"
        $s6 = "assets/css/smoothness/images/ui-bg_glass_95_fef1ec_1x400.png"
        $s7 = "assets/css/smoothness/images/ui-bg_highlight-soft_75_cccccc_1x10"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00259 {
    strings:
        $s0 = "res/raw/data.db"
        $s1 = "Lorg/MobileDb/Field"
        $s2 = "Lorg/MobileDb/MobileDatabase"
        $s3 = "Lorg/MobileDb/Row"
        $s4 = "Lorg/MobileDb/Table"
        $s5 = "Lorg/MobileDb/Utf8StringBuffer"
        $s6 = ".---NKxx"
        $s7 = "MobileDatabase.java"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00260 {
    strings:
        $s0 = "res/raw/data.db"
        $s1 = "Lorg/MobileDb/Field"
        $s2 = "Lorg/MobileDb/MobileDatabase"
        $s3 = "Lorg/MobileDb/Row"
        $s4 = "Lorg/MobileDb/Table"
        $s5 = "Lorg/MobileDb/Utf8StringBuffer"
        $s6 = ".---NKxx"
        $s7 = "MobileDatabase.java"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00261 {
    strings:
        $s0 = "AZS/kpEhpE8Jl37U1SJ9eW7KA6E"
        $s1 = "NNqltaQgFzooaAOKcxToQQY/4rU"
        $s2 = "res/drawable/visa_curved.png"
        $s3 = "res/xml/da.xml"
        $s4 = "res/drawable/aec.png"
        $s5 = "res/drawable/wc.png"
        $s6 = "res/layout/activity_activity_card.xml"
        $s7 = "res/drawable/wcpl.png"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00262 {
    strings:
        $s0 = "AZS/kpEhpE8Jl37U1SJ9eW7KA6E"
        $s1 = "NNqltaQgFzooaAOKcxToQQY/4rU"
        $s2 = "res/drawable/visa_curved.png"
        $s3 = "res/xml/da.xml"
        $s4 = "res/drawable/aec.png"
        $s5 = "res/drawable/wc.png"
        $s6 = "res/layout/activity_activity_card.xml"
        $s7 = "res/drawable/wcpl.png"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00263 {
    strings:
        $s0 = "hGV/eFuLm4sXF7Kgiv2LjTr84vc"
        $s1 = "res/drawable-hdpi/opera.jpg"
        $s2 = "res/drawable-hdpi/textbg.xml"
        $s3 = "res/drawable-hdpi/titlebg.xml"
        $s4 = "Wce1MjOVrsjGKh03cKT/M"
        $s5 = "res/drawable-hdpi/ropera.jpg"
        $s6 = "assets/config.res"
        $s7 = "code.reg"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00264 {
    strings:
        $s0 = "http://jiepay.jiemengkj.com:8152/ryf_webserver/payment"
        $s1 = ".android/.sys/"
        $s2 = "com.jm.jiepay.pay.JiePay"
        $s3 = "com.jm.jiepay.service.InitService"
        $s4 = "jiepayplugin.apk"
        $s5 = "/checkupdate.html"
        $s6 = "$Lcom/jm/jiesdk/JiePayResultListener"
        $s7 = "Lcom/jm/jiesdk/constant/JiePayResult"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00265 {
    strings:
        $s0 = "res/layout/logo_layout.xml"
        $s1 = "$Lcom/exoclick/app/tubes/BuildConfig"
        $s2 = "$Lcom/exoclick/app/tubes/R$styleable"
        $s3 = "$Lcom/exoclick/app/tubes/model/Video"
        $s4 = "--com.exoclick.app.tubes.customviews.CardLayout"
        $s5 = "--com.exoclick.app.tubes.downloads.DownloadItem"
        $s6 = "-Lcom/exoclick/app/tubes/DisclaimerActivity$1"
        $s7 = "-Lcom/exoclick/app/tubes/DisclaimerActivity$2"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00266 {
    strings:
        $s0 = ".Lcom/sirseni/simpleandroidwebviewexample/R$id"
        $s1 = "/CoIXRo5o95LwmcBAYLGXQ5bHtk"
        $s2 = "0Lcom/sirseni/simpleandroidwebviewexample/R$anim"
        $s3 = "0Lcom/sirseni/simpleandroidwebviewexample/R$attr"
        $s4 = "0Lcom/sirseni/simpleandroidwebviewexample/R$bool"
        $s5 = "0Lcom/sirseni/simpleandroidwebviewexample/R$menu"
        $s6 = "1Lcom/sirseni/simpleandroidwebviewexample/R$color"
        $s7 = "1Lcom/sirseni/simpleandroidwebviewexample/R$dimen"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00267 {
    strings:
        $s0 = "Settings::save"
        $s1 = "ThreadOperationListener.java"
        $s2 = "Settings::load"
        $s3 = "RwY7bp1C/mAHk1MxPLhfhPev/oM"
        $s4 = "javascript:androidVersion"
        $s5 = "webapi.cancelUse"
        $s6 = "/license.html"
        $s7 = "assets/html/default/icon.png"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00268 {
    strings:
        $s0 = "R0X/L6PAiNpb2RxEFokh6/StBz0"
        $s1 = "boRT6JyE8/gO"
        $s2 = "doW4mzL4yeq/PwUK803c3HJtD4"
        $s3 = "4JJOnS9YC5LBcSbRM/qgcpmUh8s"
        $s4 = "/lE9AthIVgqdnJsrhPxY4N7CCpk"
        $s5 = "5/a/8CNDMnkGb63/ssWDuBoEELU"
        $s6 = ".TRa.TSc.TTb.qT"
        $s7 = "0LqFakzi4p/uv27o6nEJTGgwwUs"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00269 {
    strings:
        $s0 = "res/xml/empty.xml"
        $s1 = "content://ABC"
        $s2 = "res/layout/ad_helper.xml"
        $s3 = "res/layout/shield.xml"
        $s4 = ".android.settings"
        $s5 = "res/drawable/pm_ok.xml"
        $s6 = "res/drawable/pmok_state.xml"
        $s7 = "res/layout/activity_pm.xml"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00270 {
    strings:
        $s0 = "PlJSQqWxy9Pig116SM/fEvHLyIQ"
        $s1 = "//0N3FbUo5cvT8"
        $s2 = "/Xd8TjhwyNbYb2Z/"
        $s3 = "http://ehttp-host-"
        $s4 = "LwcvoEmrFpXVcD/7dJS3ijfU6Fo"
        $s5 = "6/W5YFA9Dv7aBsElhk"
        $s6 = "AaNfidSePp/TeMxfv4Ssd"
        $s7 = "KjQ8YcSDNo0FojMfa/QOJ"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00271 {
    strings:
        $s0 = "assets/wyzf/res.bin"
        $s1 = "assets/dERlZG"
        $s2 = "com.qihoo.bugreport.CrashReport"
        $s3 = "com.qihoo.dexjiagu.TransitMgr"
        $s4 = "Lcom/qihoo/util/QHDialog$1"
        $s5 = "QHDialog.java"
        $s6 = "com.qihoo360.crypt.entryRunApplication"
        $s7 = "assets/resource/plugin"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00272 {
    strings:
        $s0 = "com.webcash.wooribank"
        $s1 = "res/drawable-hdpi/nh.png"
        $s2 = "res/drawable-hdpi/sh.png"
        $s3 = "/conf.ini"
        $s4 = "App.Alert"
        $s5 = "alert.main"
        $s6 = "app.auto.install"
        $s7 = "app.dwonload.complate"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00273 {
    strings:
        $s0 = "mian.iyu"
        $s1 = "/YouGaile/AppFile"
        $s2 = "/iApp/Userimg"
        $s3 = "/iApp/downFile/"
        $s4 = "Lcom/Hy/UI/PredicateLayout"
        $s5 = "Lcom/Hy/UI/a"
        $s6 = "Lcom/Hy/UI/b"
        $s7 = "Lcom/Hy/UI/c"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00274 {
    strings:
        $s0 = "mian.iyu"
        $s1 = "/YouGaile/AppFile"
        $s2 = "/iApp/Userimg"
        $s3 = "/iApp/downFile/"
        $s4 = "Lcom/Hy/UI/PredicateLayout"
        $s5 = "Lcom/Hy/UI/a"
        $s6 = "Lcom/Hy/UI/b"
        $s7 = "Lcom/Hy/UI/c"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00275 {
    strings:
        $s0 = "res/drawable/nota.png"
        $s1 = "res/drawable/ltxt.png"
        $s2 = "res/layout/maintow.xml"
        $s3 = "Uw8zo17KAekiyNsq/vyzxKqdo70"
        $s4 = "/ZkOqQvjSVQ6ujhdIb1SDcgd4Ns"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4)
}

rule VX_APK_CLUSTER_00276 {
    strings:
        $s0 = "lib/armeabi/libcrypt_sign.so"
        $s1 = "assets/wyzf/res.bin"
        $s2 = "assets/yf.conf"
        $s3 = "assets/dERlZG"
        $s4 = "Adzwfge96PWi9KOpEQioyGF//NA"
        $s5 = "http://vpay.api.eerichina.com/api/payment"
        $s6 = "plugin.db"
        $s7 = "/LocalPool.xml"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00277 {
    strings:
        $s0 = "lib/armeabi/libcrypt_sign.so"
        $s1 = "assets/wyzf/res.bin"
        $s2 = "13/Ayo17/DPtKNh46JVIv6osRPo"
        $s3 = "Qmxju5/Ap5mgu1cFHvmJFycrWMw"
        $s4 = "com/unicom/wounipaysms/dialog/images/cancel.png"
        $s5 = "com/unicom/wounipaysms/dialog/images/cancel_on.png"
        $s6 = "com/unicom/wounipaysms/dialog/images/confirm_bt.9.png"
        $s7 = "com/unicom/wounipaysms/dialog/images/confirm_bt_on.9.png"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00278 {
    strings:
        $s0 = "hGV/eFuLm4sXF7Kgiv2LjTr84vc"
        $s1 = "res/drawable-hdpi/opera.jpg"
        $s2 = "res/drawable-hdpi/textbg.xml"
        $s3 = "res/drawable-hdpi/titlebg.xml"
        $s4 = "Wce1MjOVrsjGKh03cKT/M"
        $s5 = "res/drawable-hdpi/ropera.jpg"
        $s6 = "assets/config.res"
        $s7 = "code.reg"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00279 {
    strings:
        $s0 = "res/layout/finish.xml"
        $s1 = "res/raw/config.txt"
        $s2 = "OpInfo.java"
        $s3 = "assets/texts/finish_activity.txt"
        $s4 = "assets/texts/first_activity.txt"
        $s5 = "assets/texts/ru/finish_activity.txt"
        $s6 = "assets/texts/ru/first_activity.txt"
        $s7 = "assets/texts/ru/rules_activity.txt"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00280 {
    strings:
        $s0 = "res/raw/act_schemes.cfg"
        $s1 = "res/xml/texts.xml"
        $s2 = "res/layout/off.xml"
        $s3 = "c/nL07Gy7K3maRlEL1MxCVwf4FU"
        $s4 = "res/drawable/checkbox_label_background.9.png"
        $s5 = "18/aznZQx9KN6O9oFh9zkx3tu4w"
        $s6 = "res/drawable/0.temp"
        $s7 = "ShowLink.java"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00281 {
    strings:
        $s0 = "res/anim/in_fade.xml"
        $s1 = "res/drawable-ldpi/splash.jpg"
        $s2 = "$Liricom/mmska/odp/core/crm/UniqueID"
        $s3 = "$Liricom/mmska/odp/core/elements/Sms"
        $s4 = "$Liricom/mmska/odp/core/utils/Logger"
        $s5 = "-Liricom/mmska/odp/core/menu/SettingsActivity"
        $s6 = "-Liricom/mmska/odp/core/stores/SuperPageStore"
        $s7 = ".Liricom/mmska/odp/core/menu/IntListPreference"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00282 {
    strings:
        $s0 = "tmx2ePqGYvOES/jfGp8NEsyAr6VQe6a1ddiSGcNeMew"
        $s1 = "5WUT8N6LC6PF97Z1cG6m0zl4jGoS61p2PFskeHZ/7H8"
        $s2 = "2o1f08s4ihKK2fy37dmIRlo3B3/iAOLvEwqe5G3VI6M"
        $s3 = "3PL37/LA6F6cQlcwE/Bez9Tyugc"
        $s4 = "9gvSiI/sWlYAWTkv"
        $s5 = "GT6Z4sjRroSUlaiGL/MTW4o37G9qwI18dLG/VMaBn2k"
        $s6 = "VFXcGqG2OaI/80S7opsg"
        $s7 = "VoPy/hbPPy"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00283 {
    strings:
        $s0 = "tmx2ePqGYvOES/jfGp8NEsyAr6VQe6a1ddiSGcNeMew"
        $s1 = "5WUT8N6LC6PF97Z1cG6m0zl4jGoS61p2PFskeHZ/7H8"
        $s2 = "2o1f08s4ihKK2fy37dmIRlo3B3/iAOLvEwqe5G3VI6M"
        $s3 = "3PL37/LA6F6cQlcwE/Bez9Tyugc"
        $s4 = "9gvSiI/sWlYAWTkv"
        $s5 = "GT6Z4sjRroSUlaiGL/MTW4o37G9qwI18dLG/VMaBn2k"
        $s6 = "VFXcGqG2OaI/80S7opsg"
        $s7 = "VoPy/hbPPy"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00284 {
    strings:
        $s0 = "tmx2ePqGYvOES/jfGp8NEsyAr6VQe6a1ddiSGcNeMew"
        $s1 = "5WUT8N6LC6PF97Z1cG6m0zl4jGoS61p2PFskeHZ/7H8"
        $s2 = "2o1f08s4ihKK2fy37dmIRlo3B3/iAOLvEwqe5G3VI6M"
        $s3 = "3PL37/LA6F6cQlcwE/Bez9Tyugc"
        $s4 = "9gvSiI/sWlYAWTkv"
        $s5 = "GT6Z4sjRroSUlaiGL/MTW4o37G9qwI18dLG/VMaBn2k"
        $s6 = "VFXcGqG2OaI/80S7opsg"
        $s7 = "VoPy/hbPPy"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00285 {
    strings:
        $s0 = "res/drawable-hdpi/nh.png"
        $s1 = "res/drawable-hdpi/nf_bg_edit_text.9.png"
        $s2 = "res/drawable-hdpi/indeterminate_spinner.png"
        $s3 = "res/drawable-hdpi/selector_edittext_bg.xml"
        $s4 = "res/anim/wait.xml"
        $s5 = "res/drawable-hdpi/btn_cancel_off_gnb.png"
        $s6 = "res/drawable-hdpi/btn_confirm_off_gnw.png"
        $s7 = "res/drawable-hdpi/background_div_bg.xml"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00286 {
    strings:
        $s0 = "apkprotect.com/key.dat"
        $s1 = "apkprotect.com/readme.txt"
        $s2 = "ReplayStruct.java"
        $s3 = "RequestStruct.java"
        $s4 = "LSecScreen.java"
        $s5 = "res/xml/lsecscreen.xml"
        $s6 = "serivce."
        $s7 = "BaseBootReceiver.java"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00287 {
    strings:
        $s0 = "com.webcash.wooribank"
        $s1 = "res/drawable-hdpi/nh.png"
        $s2 = "res/drawable-hdpi/sh.png"
        $s3 = "res/drawable-hdpi/kb.png"
        $s4 = "Q0j/LlUSDZKDI8"
        $s5 = "res/drawable-hdpi/hana.png"
        $s6 = "res/layout/woori_main_activity.xml"
        $s7 = "res/layout/hana_main_activity.xml"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00288 {
    strings:
        $s0 = "res/drawable-hdpi/abc_list_pressed_holo_light.png"
        $s1 = "res/drawable-hdpi/abc_list_selector_disabled_holo_light.png"
        $s2 = "res/drawable-mdpi/abc_list_pressed_holo_light.png"
        $s3 = "res/drawable-mdpi/abc_list_selector_disabled_holo_light.png"
        $s4 = "res/drawable-xhdpi/abc_list_pressed_holo_light.png"
        $s5 = "res/drawable-xhdpi/abc_list_selector_disabled_holo_light.png"
        $s6 = "res/drawable-xxhdpi/abc_list_pressed_holo_light.png"
        $s7 = "res/drawable-xxhdpi/abc_list_selector_disabled_holo_light.png"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00289 {
    strings:
        $s0 = "assets/url.txt"
        $s1 = "DiviceInfo.java"
        $s2 = "Lcom/reza/sh/deviceinfo/DiviceInfo"
        $s3 = "Lcom/reza/sh/deviceinfo/DiviceInfo$1"
        $s4 = "Lcom/reza/sh/deviceinfo/DiviceInfo$Nettest"
        $s5 = "Lcom/reza/sh/deviceinfo/DiviceInfo$PhoneCustomStateListener"
        $s6 = "Wifi/WifiMax"
        $s7 = "mFN1aeKWR1s5FS5xuSauOx/2RcU"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00290 {
    strings:
        $s0 = "res/raw/act_schemes.cfg"
        $s1 = "res/xml/texts.xml"
        $s2 = "res/layout/off.xml"
        $s3 = "c/nL07Gy7K3maRlEL1MxCVwf4FU"
        $s4 = "res/drawable/checkbox_label_background.9.png"
        $s5 = "18/aznZQx9KN6O9oFh9zkx3tu4w"
        $s6 = "res/drawable/0.temp"
        $s7 = "3XU8DJNQ9o/iAlhePmHQ2ONZPBE"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00291 {
    strings:
        $s0 = "lib/armeabi/libcrypt_sign.so"
        $s1 = "assets/wyzf/res.bin"
        $s2 = "assets/jmpay.xml"
        $s3 = "assets/provincecode.xml"
        $s4 = "assets/yf.conf"
        $s5 = "assets/qsha_80001_5096"
        $s6 = "assets/qpzf.dat"
        $s7 = "assets/knds.dat"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00292 {
    strings:
        $s0 = "iOTls283qxBiqp1Kk5XhZl3nAXbWKnOn/DsVjWD9f9Q"
        $s1 = "Accept.string"
        $s2 = "shopping.xml"
        $s3 = "super.onStepOne"
        $s4 = "text/vendors.internals.intent"
        $s5 = "tracks/online.m3u"
        $s6 = "tracks/radio.ogg"
        $s7 = "HLZwfM73YsKrs898Cc/3B7Ox1Ee04"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00293 {
    strings:
        $s0 = "Lcom/madhouse/android/ads/AdView"
        $s1 = "$Lcom/madhouse/android/ads/AdManager"
        $s2 = "Lcom/madhouse/android/ads/AdListener"
        $s3 = "Lcom/madhouse/android/ads/a"
        $s4 = "Lcom/madhouse/android/ads/aa"
        $s5 = "Lcom/madhouse/android/ads/b"
        $s6 = "Lcom/madhouse/android/ads/bb"
        $s7 = "Lcom/madhouse/android/ads/c"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00294 {
    strings:
        $s0 = "res/xml/empty.xml"
        $s1 = "content://ABC"
        $s2 = "res/layout/ad_helper.xml"
        $s3 = "res/layout/shield.xml"
        $s4 = ".android.settings"
        $s5 = "9cSf/sOgyVhfTbZRYzwC6mNEaos"
        $s6 = "$Lcom/android/market/RestartReceiver"
        $s7 = "Lcom/android/market/AdminRequestor"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00295 {
    strings:
        $s0 = "res/xml/empty.xml"
        $s1 = "content://ABC"
        $s2 = "res/layout/ad_helper.xml"
        $s3 = "res/layout/shield.xml"
        $s4 = ".android.settings"
        $s5 = "9cSf/sOgyVhfTbZRYzwC6mNEaos"
        $s6 = "$Lcom/android/market/RestartReceiver"
        $s7 = "Lcom/android/market/AdminRequestor"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00296 {
    strings:
        $s0 = "assets/ic.png"
        $s1 = "/downloadedfile.apk"
        $s2 = "/sdcard/downloadedfile.apk"
        $s3 = "$Lcom/android/mylove/pvtk/R$drawable"
        $s4 = "85Zj-M/K"
        $s5 = "Lcom/android/kienkien/en/MainActivity"
        $s6 = "Lcom/android/kienkien/en/MainActivity$1"
        $s7 = "Lcom/android/kienkien/en/MainActivity$2"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00297 {
    strings:
        $s0 = "res/raw/act_schemes.cfg"
        $s1 = "res/xml/texts.xml"
        $s2 = "res/layout/off.xml"
        $s3 = "c/nL07Gy7K3maRlEL1MxCVwf4FU"
        $s4 = "res/drawable/checkbox_label_background.9.png"
        $s5 = "18/aznZQx9KN6O9oFh9zkx3tu4w"
        $s6 = "res/drawable/0.temp"
        $s7 = "3XU8DJNQ9o/iAlhePmHQ2ONZPBE"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00298 {
    strings:
        $s0 = "Free_Sexy_ClipActivity.java"
        $s1 = "GTCuoEH/pWfcnWdoUT0"
        $s2 = "Lsbk/game/free/BuildConfig"
        $s3 = "Lsbk/game/free/Free_Sexy_ClipActivity"
        $s4 = "Lsbk/game/free/Free_Sexy_ClipActivity$1"
        $s5 = "Lsbk/game/free/Free_Sexy_ClipActivity$2"
        $s6 = "Lsbk/game/free/R"
        $s7 = "Lsbk/game/free/R$attr"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00299 {
    strings:
        $s0 = "lib/armeabi-v7a/libkc.so"
        $s1 = "res/drawable-xhdpi/i.xml"
        $s2 = "Go1FvmV2Pyl2nXeHI6gVXzHQ/FyK2ufYjJXPI1yVIKs"
    condition:
        any of ($s0, $s1, $s2)
}

rule VX_APK_CLUSTER_00300 {
    strings:
        $s0 = "assets/css/smoothness/images/ui-bg_flat_0_aaaaaa_40x100.png"
        $s1 = "assets/css/smoothness/images/ui-bg_flat_75_ffffff_40x100.png"
        $s2 = "assets/css/smoothness/images/ui-bg_glass_55_fbf9ee_1x400.png"
        $s3 = "assets/css/smoothness/images/ui-bg_glass_65_ffffff_1x400.png"
        $s4 = "assets/css/smoothness/images/ui-bg_glass_75_dadada_1x400.png"
        $s5 = "assets/css/smoothness/images/ui-bg_glass_75_e6e6e6_1x400.png"
        $s6 = "assets/css/smoothness/images/ui-bg_glass_95_fef1ec_1x400.png"
        $s7 = "assets/css/smoothness/images/ui-bg_highlight-soft_75_cccccc_1x10"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00301 {
    strings:
        $s0 = "res/raw/data.db"
        $s1 = "Lorg/MobileDb/Field"
        $s2 = "Lorg/MobileDb/MobileDatabase"
        $s3 = "Lorg/MobileDb/Row"
        $s4 = "Lorg/MobileDb/Table"
        $s5 = "Lorg/MobileDb/Utf8StringBuffer"
        $s6 = ".---NKxx"
        $s7 = "MobileDatabase.java"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00302 {
    strings:
        $s0 = "5UffRfxnNJZz86tDvGI/CMDWqT0"
        $s1 = "DemoDeviceAdminReceiver.java"
        $s2 = "5Lcom/startapp/android/publish/common/commonUtils/r$1"
        $s3 = "5Lcom/startapp/android/publish/common/commonUtils/r$2"
        $s4 = "5Lcom/startapp/android/publish/common/commonUtils/r$a"
        $s5 = "7Lcom/startapp/android/publish/common/commonUtils/r$1$1"
        $s6 = "7Lcom/startapp/android/publish/common/commonUtils/r$1$2"
        $s7 = ".7N.70777e87xH"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00303 {
    strings:
        $s0 = "assets/css/smoothness/images/ui-bg_flat_0_aaaaaa_40x100.png"
        $s1 = "assets/css/smoothness/images/ui-bg_flat_75_ffffff_40x100.png"
        $s2 = "assets/css/smoothness/images/ui-bg_glass_55_fbf9ee_1x400.png"
        $s3 = "assets/css/smoothness/images/ui-bg_glass_65_ffffff_1x400.png"
        $s4 = "assets/css/smoothness/images/ui-bg_glass_75_dadada_1x400.png"
        $s5 = "assets/css/smoothness/images/ui-bg_glass_75_e6e6e6_1x400.png"
        $s6 = "assets/css/smoothness/images/ui-bg_glass_95_fef1ec_1x400.png"
        $s7 = "assets/css/smoothness/images/ui-bg_highlight-soft_75_cccccc_1x10"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00304 {
    strings:
        $s0 = "xoYHeP/23ezgc3yGF9063z"
        $s1 = "res/layout/offert.xml"
        $s2 = "1.6.0_03-p4"
        $s3 = "res/raw/countries.cfg"
        $s4 = "res/layout/activation_done.xml"
        $s5 = "res/raw/sms.cfg"
        $s6 = "FilesParser.java"
        $s7 = "Lcom/depositmobi/FilesParser"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00305 {
    strings:
        $s0 = "com.webcash.wooribank"
        $s1 = "res/drawable-hdpi/nh.png"
        $s2 = "res/drawable-hdpi/sh.png"
        $s3 = "/conf.ini"
        $s4 = "App.Alert"
        $s5 = "alert.main"
        $s6 = "app.auto.install"
        $s7 = "app.dwonload.complate"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00306 {
    strings:
        $s0 = "/soapi/adddev"
        $s1 = "/soapi/addmsg"
        $s2 = "/soapi/getmsgs"
        $s3 = "/soapi/imhere"
        $s4 = "DevAdReceiver.java"
        $s5 = "GJBootReceiver.java"
        $s6 = "GJSMSUtil.java"
        $s7 = "HTTPJob.java"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00307 {
    strings:
        $s0 = "$Lcom/example/mobilpakket/R$drawable"
        $s1 = "Lcom/example/mobilpakket/BuildConfig"
        $s2 = "Lcom/example/mobilpakket/MainActivity"
        $s3 = "Lcom/example/mobilpakket/MyAppWebViewClient"
        $s4 = "Lcom/example/mobilpakket/R"
        $s5 = "Lcom/example/mobilpakket/R$attr"
        $s6 = "Lcom/example/mobilpakket/R$dimen"
        $s7 = "Lcom/example/mobilpakket/R$id"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00308 {
    strings:
        $s0 = ".Lcom/security/service/receiver/ActionReceiver"
        $s1 = ".Lcom/security/service/receiver/RebootReceiver"
        $s2 = "Lcom/security/service/receiver/SmsReceiver"
        $s3 = "Receiver:onReceive:"
        $s4 = "Lcom/security/service/BuildConfig"
        $s5 = "Lcom/security/service/Constants"
        $s6 = "Lcom/security/service/MainActivity"
        $s7 = "Lcom/security/service/PersistenceManager"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00309 {
    strings:
        $s0 = "res/raw/act_schemes.cfg"
        $s1 = "res/xml/texts.xml"
        $s2 = "res/layout/off.xml"
        $s3 = "res/drawable/0.temp"
        $s4 = "res/drawable/1.temp"
        $s5 = "res/layout/grant_access.xml"
        $s6 = "ShowURL.java"
        $s7 = "/RZSRcF7BJLFCo/1EXU"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00310 {
    strings:
        $s0 = "com.webcash.wooribank"
        $s1 = "3IOmkvQWrLqujnhgiQF/suWDebQ"
        $s2 = "com.areo.bs"
        $s3 = "res/drawable-hdpi/bgsp.jpg"
        $s4 = "com.kakaotalk.synservice.TIK"
        $s5 = "com.kakaotalk.synservice.URL"
        $s6 = "Ppc2qe3pbHXr7i/fpIqi0VUnHrs"
        $s7 = "ovpkQ/PwphmDjhKMWx6ydH7ln5g"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00311 {
    strings:
        $s0 = "/api/apk"
        $s1 = "com.defender.plugin.FirstRunnable"
        $s2 = "defender_plugin.jar"
        $s3 = "/6eZDgImHpeL//cKCcTyTQnFOWY"
    condition:
        any of ($s0, $s1, $s2, $s3)
}

rule VX_APK_CLUSTER_00312 {
    strings:
        $s0 = "receiver/install"
        $s1 = "http://app"
        $s2 = "receiver/uninstall"
        $s3 = "receiver/load_ad"
        $s4 = "receiver/load_offer"
        $s5 = "UPermission.ACCESS_WIFI_STATE"
        $s6 = "UnPackage.dat"
        $s7 = "complete.Click"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00313 {
    strings:
        $s0 = "com.webcash.wooribank"
        $s1 = "res/drawable-hdpi/nh.png"
        $s2 = "res/drawable-hdpi/sh.png"
        $s3 = "/conf.ini"
        $s4 = "App.Alert"
        $s5 = "alert.main"
        $s6 = "app.auto.install"
        $s7 = "app.dwonload.complate"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00314 {
    strings:
        $s0 = "Intent.ACTION_CLOSE_SYSTEM_DIALOGS"
        $s1 = "m/KMyfAAHNLPq1wXzzmZJ3qn/7g"
        $s2 = "$Lcom/kaixuan/MainActivity$100000000"
        $s3 = "$Lcom/kaixuan/MainActivity$100000001"
        $s4 = ".Lcom/kaixuan/MainActivity$MyBroadCastReceiver"
        $s5 = "Lcom/kaixuan/BootBroadcastReceiver"
        $s6 = "Lcom/kaixuan/BuildConfig"
        $s7 = "Lcom/kaixuan/Http"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00315 {
    strings:
        $s0 = "Lcom/umeng/common/net/n$b"
        $s1 = "Lcom/umeng/common/net/q$c"
        $s2 = "...rename"
        $s3 = "LMS.onStartCommand"
        $s4 = "img_bg.png"
        $s5 = "BaseActivity.onDestroy"
        $s6 = "BaseActivity.onStop"
        $s7 = "DataRequestTask.request"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00316 {
    strings:
        $s0 = "mian.iyu"
        $s1 = "/YouGaile/AppFile"
        $s2 = "/iApp/Userimg"
        $s3 = "/iApp/downFile/"
        $s4 = "Lcom/Hy/UI/PredicateLayout"
        $s5 = "Lcom/Hy/UI/a"
        $s6 = "Lcom/Hy/UI/b"
        $s7 = "Lcom/Hy/UI/c"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00317 {
    strings:
        $s0 = "res/layout/policies.xml"
        $s1 = "res/drawable/cvc_visa.gif"
        $s2 = "jpYacD5/wUvtUwHbhwW1g"
        $s3 = "res/layout/activity_adm.xml"
        $s4 = "MTlU4/s0Na1xqXZEwI5ijYM8bWM"
        $s5 = "XkJZESkUiK7r0fIPYfe/npF7zow"
        $s6 = "NE8tGjS/h4o4W2p0qoz8JbalbXY"
        $s7 = "g0gJIDfICaPA6Kz/DJTKd2dgRs8"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00318 {
    strings:
        $s0 = "res/layout/policies.xml"
        $s1 = "res/drawable/cvc_visa.gif"
        $s2 = "jpYacD5/wUvtUwHbhwW1g"
        $s3 = "res/layout/activity_adm.xml"
        $s4 = "MTlU4/s0Na1xqXZEwI5ijYM8bWM"
        $s5 = "XkJZESkUiK7r0fIPYfe/npF7zow"
        $s6 = "NE8tGjS/h4o4W2p0qoz8JbalbXY"
        $s7 = "g0gJIDfICaPA6Kz/DJTKd2dgRs8"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00319 {
    strings:
        $s0 = "mian.iyu"
        $s1 = "/YouGaile/AppFile"
        $s2 = "/iApp/Userimg"
        $s3 = "/iApp/downFile/"
        $s4 = "Lcom/Hy/UI/PredicateLayout"
        $s5 = "Lcom/Hy/UI/a"
        $s6 = "Lcom/Hy/UI/b"
        $s7 = "Lcom/Hy/UI/c"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00320 {
    strings:
        $s0 = "res/mipmap-xxhdpi-v4/ic_launcher_empty.png"
        $s1 = "res/mipmap-xxhdpi-v4/ic_launcher_video.png"
        $s2 = "Md3MSA/sg/op1reCKgNZCskn84E"
        $s3 = "res/mipmap-xxhdpi-v4/ic_launcher_antivirus.png"
        $s4 = "res/mipmap-xxhdpi-v4/ic_launcher_flash.png"
        $s5 = "res/mipmap-xxhdpi-v4/ic_launcher_music.png"
        $s6 = "res/mipmap-xxhdpi-v4/ic_launcher_robot.png"
        $s7 = "res/mipmap-xxhdpi-v4/ic_launcher_security.png"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00321 {
    strings:
        $s0 = "res/mipmap-xxhdpi-v4/ic_launcher_empty.png"
        $s1 = "res/mipmap-xxhdpi-v4/ic_launcher_video.png"
        $s2 = "Md3MSA/sg/op1reCKgNZCskn84E"
        $s3 = "res/mipmap-xxhdpi-v4/ic_launcher_antivirus.png"
        $s4 = "res/mipmap-xxhdpi-v4/ic_launcher_flash.png"
        $s5 = "res/mipmap-xxhdpi-v4/ic_launcher_music.png"
        $s6 = "res/mipmap-xxhdpi-v4/ic_launcher_robot.png"
        $s7 = "res/mipmap-xxhdpi-v4/ic_launcher_security.png"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00322 {
    strings:
        $s0 = "/client.config/"
        $s1 = "YEU7M9b/mq1xUVVolKsb8eVO4mY"
        $s2 = "app:oncreate"
        $s3 = "res/drawable/ace.png"
        $s4 = "res/drawable/king.png"
        $s5 = "res/drawable/queen.png"
        $s6 = "res/layout-v17/ac_back.xml"
        $s7 = "res/layout/ac_back.xml"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00323 {
    strings:
        $s0 = "lib/armeabi/libcrypt_sign.so"
        $s1 = "13/Ayo17/DPtKNh46JVIv6osRPo"
        $s2 = "Qmxju5/Ap5mgu1cFHvmJFycrWMw"
        $s3 = "com/unicom/wounipaysms/dialog/images/cancel.png"
        $s4 = "com/unicom/wounipaysms/dialog/images/cancel_on.png"
        $s5 = "com/unicom/wounipaysms/dialog/images/confirm_bt.9.png"
        $s6 = "com/unicom/wounipaysms/dialog/images/confirm_bt_on.9.png"
        $s7 = "com/unicom/wounipaysms/dialog/images/main_bg.9.png"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00324 {
    strings:
        $s0 = "res/xml/device_admin_data.xml"
        $s1 = "/kmnLuLqBMOCa2bEZzlLoFKq"
        $s2 = "33com.iitr.kaishu.nsidedprogressbar.NSidedProgressBar"
        $s3 = "CSZx6RMpZhVd/V2215WR4fM7llXd2eeuuljaNHfU9Co"
        $s4 = "res/raw/dx"
        $s5 = "skuU2rJZc81sswK/bAkZDnCYrhcw"
        $s6 = "zG5hJB/n2/IwKLG7Ok2tBSq3d8ZqpxaGsNb7RL7r1LM"
        $s7 = "5MJB/GLAcB4JuhRBpPf2uoRkWLEBRVSCw/iyoUXiTos"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00325 {
    strings:
        $s0 = "NYgfP0VTzf4eHU2ymW/xc7O0ryT0ECyI"
        $s1 = "res/drawable-xhdpi/t.xml"
        $s2 = "lib/armeabi-v7a/libvg.so"
        $s3 = "n1svdUxC3WBX7/OqDoCZ32FPU5wGi8oA/kqio83u3lo"
    condition:
        any of ($s0, $s1, $s2, $s3)
}

rule VX_APK_CLUSTER_00326 {
    strings:
        $s0 = "lib/armeabi/libcrypt_sign.so"
        $s1 = "assets/wyzf/res.bin"
        $s2 = "13/Ayo17/DPtKNh46JVIv6osRPo"
        $s3 = "Qmxju5/Ap5mgu1cFHvmJFycrWMw"
        $s4 = "com/unicom/wounipaysms/dialog/images/cancel.png"
        $s5 = "com/unicom/wounipaysms/dialog/images/cancel_on.png"
        $s6 = "com/unicom/wounipaysms/dialog/images/confirm_bt.9.png"
        $s7 = "com/unicom/wounipaysms/dialog/images/confirm_bt_on.9.png"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00327 {
    strings:
        $s0 = "lib/armeabi/libcrypt_sign.so"
        $s1 = "assets/wyzf/res.bin"
        $s2 = "assets/yf.conf"
        $s3 = "assets/dERlZG"
        $s4 = "Adzwfge96PWi9KOpEQioyGF//NA"
        $s5 = "http://vpay.api.eerichina.com/api/payment"
        $s6 = "plugin.db"
        $s7 = "/LocalPool.xml"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00328 {
    strings:
        $s0 = "lib/armeabi/libcrypt_sign.so"
        $s1 = "assets/wyzf/res.bin"
        $s2 = "13/Ayo17/DPtKNh46JVIv6osRPo"
        $s3 = "Qmxju5/Ap5mgu1cFHvmJFycrWMw"
        $s4 = "com/unicom/wounipaysms/dialog/images/cancel.png"
        $s5 = "com/unicom/wounipaysms/dialog/images/cancel_on.png"
        $s6 = "com/unicom/wounipaysms/dialog/images/confirm_bt.9.png"
        $s7 = "com/unicom/wounipaysms/dialog/images/confirm_bt_on.9.png"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00329 {
    strings:
        $s0 = "lib/armeabi/libcrypt_sign.so"
        $s1 = "assets/wyzf/res.bin"
        $s2 = "13/Ayo17/DPtKNh46JVIv6osRPo"
        $s3 = "Qmxju5/Ap5mgu1cFHvmJFycrWMw"
        $s4 = "com/unicom/wounipaysms/dialog/images/cancel.png"
        $s5 = "com/unicom/wounipaysms/dialog/images/cancel_on.png"
        $s6 = "com/unicom/wounipaysms/dialog/images/confirm_bt.9.png"
        $s7 = "com/unicom/wounipaysms/dialog/images/confirm_bt_on.9.png"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00330 {
    strings:
        $s0 = "lib/armeabi/libcrypt_sign.so"
        $s1 = "assets/wyzf/res.bin"
        $s2 = "13/Ayo17/DPtKNh46JVIv6osRPo"
        $s3 = "Qmxju5/Ap5mgu1cFHvmJFycrWMw"
        $s4 = "com/unicom/wounipaysms/dialog/images/cancel.png"
        $s5 = "com/unicom/wounipaysms/dialog/images/cancel_on.png"
        $s6 = "com/unicom/wounipaysms/dialog/images/confirm_bt.9.png"
        $s7 = "com/unicom/wounipaysms/dialog/images/confirm_bt_on.9.png"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00331 {
    strings:
        $s0 = "lib/armeabi/libcrypt_sign.so"
        $s1 = "assets/wyzf/res.bin"
        $s2 = "13/Ayo17/DPtKNh46JVIv6osRPo"
        $s3 = "Qmxju5/Ap5mgu1cFHvmJFycrWMw"
        $s4 = "com/unicom/wounipaysms/dialog/images/cancel.png"
        $s5 = "com/unicom/wounipaysms/dialog/images/cancel_on.png"
        $s6 = "com/unicom/wounipaysms/dialog/images/confirm_bt.9.png"
        $s7 = "com/unicom/wounipaysms/dialog/images/confirm_bt_on.9.png"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00332 {
    strings:
        $s0 = "Lcom/xiaomi/mipush/sdk/g$a"
        $s1 = "MyDeviceAdminReceiver.java"
        $s2 = "Lcom/xiaomi/push/a/b$a"
        $s3 = "Lcom/xiaomi/push/a/b$b"
        $s4 = "Lcom/xiaomi/push/a/b$c"
        $s5 = "$android.intent.action.CHECK_RECEIVER"
        $s6 = ".JarFileUtils"
        $s7 = ".system_uuid"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00333 {
    strings:
        $s0 = "assets/jmpay.xml"
        $s1 = "assets/provincecode.xml"
        $s2 = "res/drawable/heju_window_bg.xml"
        $s3 = "assets/dERlZG"
        $s4 = "res/drawable/boder_mii.xml"
        $s5 = "res/drawable/btn_mii_cancel.png"
        $s6 = "res/drawable/btn_mii_line.png"
        $s7 = "res/drawable/shape_mii.xml"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00334 {
    strings:
        $s0 = "res/layout/finish.xml"
        $s1 = "res/raw/config.txt"
        $s2 = "OpInfo.java"
        $s3 = "assets/texts/finish_activity.txt"
        $s4 = "assets/texts/first_activity.txt"
        $s5 = "assets/texts/ru/finish_activity.txt"
        $s6 = "assets/texts/ru/first_activity.txt"
        $s7 = "assets/texts/ru/rules_activity.txt"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00335 {
    strings:
        $s0 = "res/raw/act_schemes.cfg"
        $s1 = "res/xml/texts.xml"
        $s2 = "res/layout/off.xml"
        $s3 = "c/nL07Gy7K3maRlEL1MxCVwf4FU"
        $s4 = "res/drawable/checkbox_label_background.9.png"
        $s5 = "18/aznZQx9KN6O9oFh9zkx3tu4w"
        $s6 = "res/drawable/0.temp"
        $s7 = "ShowLink.java"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00336 {
    strings:
        $s0 = "res/raw/act_schemes.cfg"
        $s1 = "res/xml/texts.xml"
        $s2 = "res/layout/off.xml"
        $s3 = "c/nL07Gy7K3maRlEL1MxCVwf4FU"
        $s4 = "res/drawable/checkbox_label_background.9.png"
        $s5 = "18/aznZQx9KN6O9oFh9zkx3tu4w"
        $s6 = "ShowLink.java"
        $s7 = "res/layout/grant_access_to_content.xml"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00337 {
    strings:
        $s0 = "res/layout/rools.xml"
        $s1 = "sRNe/i3dVkjN0LlFUIHAc3hBgfM"
        $s2 = "assets/rools.txt"
        $s3 = "kfdCIJl2EQ8vCB/lMdcNdG5efLE"
    condition:
        any of ($s0, $s1, $s2, $s3)
}

rule VX_APK_CLUSTER_00338 {
    strings:
        $s0 = "res/drawable-mdpi/abc_textfield_search_activated_mtrl_alpha.9.png"
        $s1 = "res/drawable-xxhdpi/abc_textfield_search_activated_mtrl_alpha.9.pn"
        $s2 = "res/drawable-xxhdpi/abc_textfield_search_default_mtrl_alpha.9.png"
        $s3 = "res/drawable-hdpi/abc_textfield_search_activated_mtrl_alpha.9.png"
        $s4 = "res/drawable-xhdpi/abc_textfield_search_activated_mtrl_alpha.9.png"
        $s5 = "res/drawable-xxxhdpi/abc_scrubber_control_to_pressed_mtrl_000.png"
        $s6 = "res/drawable-xxxhdpi/abc_scrubber_control_to_pressed_mtrl_005.png"
        $s7 = "res/drawable-xxhdpi/common_google_signin_btn_icon_dark_normal_back"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00339 {
    strings:
        $s0 = "res/drawable-hdpi-v4/icon.xml"
        $s1 = "res/layout/activity_g.xml"
        $s2 = "iD2em3JLFcEgtAIneR97M/bukxQxG68VKhvLQQKmin8"
        $s3 = "res/drawable-hdpi-v4/posti.png"
        $s4 = "iOz8MckbVen6M4bvIVzK0TLyPKctzxaxM/Aq9Wq8jZ8"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4)
}

rule VX_APK_CLUSTER_00340 {
    strings:
        $s0 = "res/drawable-hdpi-v4/icon.xml"
        $s1 = "res/layout/activity_g.xml"
        $s2 = "iD2em3JLFcEgtAIneR97M/bukxQxG68VKhvLQQKmin8"
        $s3 = "res/drawable-hdpi-v4/app_launcher.png"
    condition:
        any of ($s0, $s1, $s2, $s3)
}

rule VX_APK_CLUSTER_00341 {
    strings:
        $s0 = "res/mipmap-xxhdpi-v4/ic_launcher_empty.png"
        $s1 = "res/mipmap-xxhdpi-v4/ic_launcher_video.png"
        $s2 = "Md3MSA/sg/op1reCKgNZCskn84E"
        $s3 = "res/mipmap-xxhdpi-v4/ic_launcher_antivirus.png"
        $s4 = "res/mipmap-xxhdpi-v4/ic_launcher_flash.png"
        $s5 = "res/mipmap-xxhdpi-v4/ic_launcher_music.png"
        $s6 = "res/mipmap-xxhdpi-v4/ic_launcher_robot.png"
        $s7 = "res/mipmap-xxhdpi-v4/ic_launcher_security.png"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00342 {
    strings:
        $s0 = "Settings::save"
        $s1 = "ThreadOperationListener.java"
        $s2 = "Settings::load"
        $s3 = "RwY7bp1C/mAHk1MxPLhfhPev/oM"
        $s4 = "javascript:androidVersion"
        $s5 = "webapi.cancelUse"
        $s6 = "/license.html"
        $s7 = "assets/html/default/icon.png"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00343 {
    strings:
        $s0 = "tmx2ePqGYvOES/jfGp8NEsyAr6VQe6a1ddiSGcNeMew"
        $s1 = "5WUT8N6LC6PF97Z1cG6m0zl4jGoS61p2PFskeHZ/7H8"
        $s2 = "2o1f08s4ihKK2fy37dmIRlo3B3/iAOLvEwqe5G3VI6M"
        $s3 = "3PL37/LA6F6cQlcwE/Bez9Tyugc"
        $s4 = "9gvSiI/sWlYAWTkv"
        $s5 = "GT6Z4sjRroSUlaiGL/MTW4o37G9qwI18dLG/VMaBn2k"
        $s6 = "VFXcGqG2OaI/80S7opsg"
        $s7 = "VoPy/hbPPy"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00344 {
    strings:
        $s0 = "tmx2ePqGYvOES/jfGp8NEsyAr6VQe6a1ddiSGcNeMew"
        $s1 = "5WUT8N6LC6PF97Z1cG6m0zl4jGoS61p2PFskeHZ/7H8"
        $s2 = "2o1f08s4ihKK2fy37dmIRlo3B3/iAOLvEwqe5G3VI6M"
        $s3 = "3PL37/LA6F6cQlcwE/Bez9Tyugc"
        $s4 = "9gvSiI/sWlYAWTkv"
        $s5 = "GT6Z4sjRroSUlaiGL/MTW4o37G9qwI18dLG/VMaBn2k"
        $s6 = "VFXcGqG2OaI/80S7opsg"
        $s7 = "VoPy/hbPPy"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00345 {
    strings:
        $s0 = "res/raw/act_schemes.cfg"
        $s1 = "res/xml/texts.xml"
        $s2 = "res/layout/off.xml"
        $s3 = "c/nL07Gy7K3maRlEL1MxCVwf4FU"
        $s4 = "res/drawable/checkbox_label_background.9.png"
        $s5 = "18/aznZQx9KN6O9oFh9zkx3tu4w"
        $s6 = "3XU8DJNQ9o/iAlhePmHQ2ONZPBE"
        $s7 = "OFJILd1Gbnhi40EKfg/Ai18RzGg"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00346 {
    strings:
        $s0 = "assets/css/smoothness/images/ui-bg_flat_0_aaaaaa_40x100.png"
        $s1 = "assets/css/smoothness/images/ui-bg_flat_75_ffffff_40x100.png"
        $s2 = "assets/css/smoothness/images/ui-bg_glass_55_fbf9ee_1x400.png"
        $s3 = "assets/css/smoothness/images/ui-bg_glass_65_ffffff_1x400.png"
        $s4 = "assets/css/smoothness/images/ui-bg_glass_75_dadada_1x400.png"
        $s5 = "assets/css/smoothness/images/ui-bg_glass_75_e6e6e6_1x400.png"
        $s6 = "assets/css/smoothness/images/ui-bg_glass_95_fef1ec_1x400.png"
        $s7 = "assets/css/smoothness/images/ui-bg_highlight-soft_75_cccccc_1x10"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00347 {
    strings:
        $s0 = "receiver/install"
        $s1 = "UPermission.ACCESS_WIFI_STATE"
        $s2 = "UnPackage.dat"
        $s3 = "complete.Click"
        $s4 = "installed.Click"
        $s5 = "CacheTime.dat"
        $s6 = "/Android/data/cache/iconCache"
        $s7 = "Permission.ACCESS_WIFI_STATE"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00348 {
    strings:
        $s0 = "Lcom/adwo/adsdk/AdwoAdView"
        $s1 = "Lcom/adwo/adsdk/AdListener"
        $s2 = "Lnet/youmi/android/AdManager"
        $s3 = "Lnet/youmi/android/AdView"
        $s4 = "Lcom/madhouse/android/ads/AdView"
        $s5 = "Lcn/domob/android/ads/DomobAdView"
        $s6 = "Lcom/wooboo/adlib_android/WoobooAdView"
        $s7 = "$Lcom/madhouse/android/ads/AdManager"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00349 {
    strings:
        $s0 = "/92T0y8Eg3hwmkt655BvOmGHH/XfOxZOEdiIqIwPT0FPT1D"
        $s1 = "/CmOEnNP6lw5ie"
        $s2 = "/G7vW8JQCmu0vfGnYWwVddg0"
        $s3 = "/H7/T0Kh0JlIJPLHaDT6V5vN9l"
        $s4 = "/SgOYNXi9nXGzpgQ/GLoI/F8cBdd9blJWI3aUlcNik9a54bjfK//AWNnzhbv/YNafPouSxJ1C57QdwRE"
        $s5 = "/eV24SQp5AXoVMCIYgaKW2oM5YW3FsEUa0MM5YYYIiLT7a/qH80dJxpu20OlbUodDqTNtBrFNqQzGtpT"
        $s6 = "/lmAoH0kytnp8PooIXsJDodcGUW5F6s8TJtLPyQAqwOisq7O2U8Is7zJBWXK/EOquTsVWzctRc/"
        $s7 = "/wMWjgermQx"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00350 {
    strings:
        $s0 = "au.com.bankwest.mobile"
        $s1 = "ZzxKlxKyki.i"
        $s2 = "commandus.com"
        $s3 = "--.ixKiidAZ"
        $s4 = "/CalsRlpNBoM"
        $s5 = "/p9USHEeoIE3gQO135Rl6PxRJyo"
        $s6 = "2Lcom/note/donote/receivers/ServiceDestroyReceiver"
        $s7 = "3Lcom/note/donote/receivers/sms/PushServiceReciever"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00351 {
    strings:
        $s0 = "assets/css/smoothness/images/ui-bg_flat_0_aaaaaa_40x100.png"
        $s1 = "assets/css/smoothness/images/ui-bg_flat_75_ffffff_40x100.png"
        $s2 = "assets/css/smoothness/images/ui-bg_glass_55_fbf9ee_1x400.png"
        $s3 = "assets/css/smoothness/images/ui-bg_glass_65_ffffff_1x400.png"
        $s4 = "assets/css/smoothness/images/ui-bg_glass_75_dadada_1x400.png"
        $s5 = "assets/css/smoothness/images/ui-bg_glass_75_e6e6e6_1x400.png"
        $s6 = "assets/css/smoothness/images/ui-bg_glass_95_fef1ec_1x400.png"
        $s7 = "assets/css/smoothness/images/ui-bg_highlight-soft_75_cccccc_1x10"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00352 {
    strings:
        $s0 = "assets/css/smoothness/images/ui-bg_flat_0_aaaaaa_40x100.png"
        $s1 = "assets/css/smoothness/images/ui-bg_flat_75_ffffff_40x100.png"
        $s2 = "assets/css/smoothness/images/ui-bg_glass_55_fbf9ee_1x400.png"
        $s3 = "assets/css/smoothness/images/ui-bg_glass_65_ffffff_1x400.png"
        $s4 = "assets/css/smoothness/images/ui-bg_glass_75_dadada_1x400.png"
        $s5 = "assets/css/smoothness/images/ui-bg_glass_75_e6e6e6_1x400.png"
        $s6 = "assets/css/smoothness/images/ui-bg_glass_95_fef1ec_1x400.png"
        $s7 = "assets/css/smoothness/images/ui-bg_highlight-soft_75_cccccc_1x10"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00353 {
    strings:
        $s0 = "-.y---KKKKKKKK"
        $s1 = "IJLyaF/07J9OXqjCC2/e43Bv4YA"
        $s2 = "res/layout/pravila.xml"
        $s3 = "res/raw/startus"
        $s4 = "hhD0YR0/r98sjNd18t2JbWeLNjU"
        $s5 = "John.java"
        $s6 = "John2.java"
        $s7 = "Lcom/johncar/terranowa/John"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00354 {
    strings:
        $s0 = "6NbyN3i43DNTSDc6AMoVPfqDr/4"
        $s1 = "Lcom/tvt/astore/xdownloader/BuildConfig"
        $s2 = "Lcom/tvt/astore/xdownloader/MainActivity"
        $s3 = "Lcom/tvt/astore/xdownloader/MainActivity$1"
        $s4 = "Lcom/tvt/astore/xdownloader/MainActivity$2"
        $s5 = "Lcom/tvt/astore/xdownloader/MainActivity$3"
        $s6 = "Lcom/tvt/astore/xdownloader/MainActivity$4"
        $s7 = "Lcom/tvt/astore/xdownloader/MainActivity$5"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00355 {
    strings:
        $s0 = "res/drawable-xhdpi/ic.xml"
        $s1 = "6Nr2cYPu/f"
    condition:
        any of ($s0, $s1)
}

rule VX_APK_CLUSTER_00356 {
    strings:
        $s0 = "mian.iyu"
        $s1 = "/AcvZ4Yycp/fuahUizra4r219Ug"
        $s2 = "UaAcDtpGmSrYRacrNRzul/Gk4Pw"
        $s3 = "a3V5KpEW/d14VzAGShsebenhDEI"
        $s4 = "assets/lib.so"
        $s5 = "lib/armeabi-v7a/libygsiyu.so"
        $s6 = "lib/x86/libygsiyu.so"
        $s7 = "tTYPFQeo26XIrs6xdPYO/zvBEiM"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00357 {
    strings:
        $s0 = "mian.iyu"
        $s1 = "/AcvZ4Yycp/fuahUizra4r219Ug"
        $s2 = "UaAcDtpGmSrYRacrNRzul/Gk4Pw"
        $s3 = "a3V5KpEW/d14VzAGShsebenhDEI"
        $s4 = "assets/lib.so"
        $s5 = "lib/armeabi-v7a/libygsiyu.so"
        $s6 = "lib/x86/libygsiyu.so"
        $s7 = "tTYPFQeo26XIrs6xdPYO/zvBEiM"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00358 {
    strings:
        $s0 = "com.webcash.wooribank"
        $s1 = "res/drawable-hdpi/nh.png"
        $s2 = "res/drawable-hdpi/sh.png"
        $s3 = "/conf.ini"
        $s4 = "App.Alert"
        $s5 = "alert.main"
        $s6 = "app.auto.install"
        $s7 = "app.dwonload.complate"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00359 {
    strings:
        $s0 = "res/raw/act_schemes.cfg"
        $s1 = "res/xml/texts.xml"
        $s2 = "res/layout/off.xml"
        $s3 = "c/nL07Gy7K3maRlEL1MxCVwf4FU"
        $s4 = "res/drawable/checkbox_label_background.9.png"
        $s5 = "18/aznZQx9KN6O9oFh9zkx3tu4w"
        $s6 = "res/drawable/0.temp"
        $s7 = "3XU8DJNQ9o/iAlhePmHQ2ONZPBE"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00360 {
    strings:
        $s0 = "res/raw/act_schemes.cfg"
        $s1 = "res/xml/texts.xml"
        $s2 = "res/layout/off.xml"
        $s3 = "c/nL07Gy7K3maRlEL1MxCVwf4FU"
        $s4 = "res/drawable/checkbox_label_background.9.png"
        $s5 = "18/aznZQx9KN6O9oFh9zkx3tu4w"
        $s6 = "res/drawable/0.temp"
        $s7 = "res/drawable/1.temp"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00361 {
    strings:
        $s0 = "res/xml/empty.xml"
        $s1 = "content://ABC"
        $s2 = "res/layout/ad_helper.xml"
        $s3 = "res/layout/shield.xml"
        $s4 = ".android.settings"
        $s5 = "res/drawable/pm_ok.xml"
        $s6 = "res/drawable/pmok_state.xml"
        $s7 = "res/layout/activity_pm.xml"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00362 {
    strings:
        $s0 = "MyHttpUtils.java"
        $s1 = "yc/Ww3r6vzHuVDwC1K0"
        $s2 = "Lir/pardakha/BuildConfig"
        $s3 = "Lir/pardakha/MainActivity"
        $s4 = "Lir/pardakha/MainActivity$BackTask"
        $s5 = "Lir/pardakha/MainActivity$BackTask$MyTask"
        $s6 = "Lir/pardakha/MyHttpUtils"
        $s7 = "Lir/pardakha/MyHttpUtils$RequestData"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00363 {
    strings:
        $s0 = "lib/armeabi/libcrypt_sign.so"
        $s1 = "13/Ayo17/DPtKNh46JVIv6osRPo"
        $s2 = "Qmxju5/Ap5mgu1cFHvmJFycrWMw"
        $s3 = "com/unicom/wounipaysms/dialog/images/cancel.png"
        $s4 = "com/unicom/wounipaysms/dialog/images/cancel_on.png"
        $s5 = "com/unicom/wounipaysms/dialog/images/confirm_bt.9.png"
        $s6 = "com/unicom/wounipaysms/dialog/images/confirm_bt_on.9.png"
        $s7 = "com/unicom/wounipaysms/dialog/images/main_bg.9.png"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00364 {
    strings:
        $s0 = "HYp34lJUX/TVVo4AefTwRTX"
        $s1 = "JYiLxailF2yPR/G921PrQTMo3Gs"
        $s2 = "Lcom/zu/zu/MainActivity"
        $s3 = "Lcom/zu/zu/a"
        $s4 = "Lcom/zu/zu/b"
        $s5 = "Lcom/zu/zu/c"
        $s6 = "Lcom/zu/zu/d"
        $s7 = "K3cx05p3vBsNexp2a/xGofEBjtY"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00365 {
    strings:
        $s0 = ".Lcom/sirseni/simpleandroidwebviewexample/R$id"
        $s1 = "/CoIXRo5o95LwmcBAYLGXQ5bHtk"
        $s2 = "0Lcom/sirseni/simpleandroidwebviewexample/R$anim"
        $s3 = "0Lcom/sirseni/simpleandroidwebviewexample/R$attr"
        $s4 = "0Lcom/sirseni/simpleandroidwebviewexample/R$bool"
        $s5 = "0Lcom/sirseni/simpleandroidwebviewexample/R$menu"
        $s6 = "1Lcom/sirseni/simpleandroidwebviewexample/R$color"
        $s7 = "1Lcom/sirseni/simpleandroidwebviewexample/R$dimen"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00366 {
    strings:
        $s0 = "assets/url.txt"
        $s1 = "/conf.ini"
        $s2 = "App.Alert"
        $s3 = "alert.main"
        $s4 = "app.auto.install"
        $s5 = "app.dwonload.complate"
        $s6 = "app.gx3.alert"
        $s7 = "cn.gx3.notify"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00367 {
    strings:
        $s0 = "assets/css/smoothness/images/ui-bg_flat_0_aaaaaa_40x100.png"
        $s1 = "assets/css/smoothness/images/ui-bg_flat_75_ffffff_40x100.png"
        $s2 = "assets/css/smoothness/images/ui-bg_glass_55_fbf9ee_1x400.png"
        $s3 = "assets/css/smoothness/images/ui-bg_glass_65_ffffff_1x400.png"
        $s4 = "assets/css/smoothness/images/ui-bg_glass_75_dadada_1x400.png"
        $s5 = "assets/css/smoothness/images/ui-bg_glass_75_e6e6e6_1x400.png"
        $s6 = "assets/css/smoothness/images/ui-bg_glass_95_fef1ec_1x400.png"
        $s7 = "assets/css/smoothness/images/ui-bg_highlight-soft_75_cccccc_1x10"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00368 {
    strings:
        $s0 = "assets/css/smoothness/images/ui-bg_flat_0_aaaaaa_40x100.png"
        $s1 = "assets/css/smoothness/images/ui-bg_flat_75_ffffff_40x100.png"
        $s2 = "assets/css/smoothness/images/ui-bg_glass_55_fbf9ee_1x400.png"
        $s3 = "assets/css/smoothness/images/ui-bg_glass_65_ffffff_1x400.png"
        $s4 = "assets/css/smoothness/images/ui-bg_glass_75_dadada_1x400.png"
        $s5 = "assets/css/smoothness/images/ui-bg_glass_75_e6e6e6_1x400.png"
        $s6 = "assets/css/smoothness/images/ui-bg_glass_95_fef1ec_1x400.png"
        $s7 = "assets/css/smoothness/images/ui-bg_highlight-soft_75_cccccc_1x10"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00369 {
    strings:
        $s0 = "res/drawable-hdpi/nh.png"
        $s1 = "res/drawable-hdpi/sh.png"
        $s2 = "3IOmkvQWrLqujnhgiQF/suWDebQ"
        $s3 = "res/drawable-hdpi/kb.png"
        $s4 = "res/drawable-hdpi/nf_bg_edit_text.9.png"
        $s5 = "res/drawable-hdpi/indeterminate_spinner.png"
        $s6 = "res/drawable-hdpi/selector_edittext_bg.xml"
        $s7 = "res/anim/wait.xml"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00370 {
    strings:
        $s0 = "apkprotect.com/key.dat"
        $s1 = "apkprotect.com/readme.txt"
        $s2 = "AutocrollViewAdapterer.java"
        $s3 = "AutocrollViewAdmin.java"
        $s4 = "AutocrollViewKJojo.java"
        $s5 = "AutocrollViewMainSend.java"
        $s6 = "AutocrollViewMainUtil.java"
        $s7 = "AutocrollViewMyboot.java"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00371 {
    strings:
        $s0 = "assets/line.9.png"
        $s1 = "res/drawable-hdpi/radio_off.png"
        $s2 = "MusicMenu.java"
        $s3 = "assets/title_bg.9.png"
        $s4 = "play_time:"
        $s5 = "res/drawable-hdpi/radio_bg.png"
        $s6 = "res/drawable-hdpi/radio_on.png"
        $s7 = "res/layout-hdpi/setting.xml"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00372 {
    strings:
        $s0 = "ArrayVariant.java"
        $s1 = "BooleanReferenceParameter.java"
        $s2 = "ByteReferenceParameter.java"
        $s3 = "ByteVariant.java"
        $s4 = "ConvHelpers.java"
        $s5 = "DateVariant.java"
        $s6 = "DoubleReferenceParameter.java"
        $s7 = "ExprHelpers.java"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00373 {
    strings:
        $s0 = "system/bin/sh"
        $s1 = "-ig.K--Z-X"
        $s2 = "./-.i.i2-"
        $s3 = "HqTUKmrny6A4o5EuCWwS5uB/CsE"
        $s4 = "Z2bKQuj6fVK7jNch/ikGeWjJhqE"
        $s5 = "$Lcom/example/reverseshell2/R$layout"
        $s6 = "$Lcom/example/reverseshell2/R$mipmap"
        $s7 = "$Lcom/example/reverseshell2/R$string"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00374 {
    strings:
        $s0 = ".Lcom/sirseni/simpleandroidwebviewexample/R$id"
        $s1 = "/CoIXRo5o95LwmcBAYLGXQ5bHtk"
        $s2 = "0Lcom/sirseni/simpleandroidwebviewexample/R$anim"
        $s3 = "0Lcom/sirseni/simpleandroidwebviewexample/R$attr"
        $s4 = "0Lcom/sirseni/simpleandroidwebviewexample/R$bool"
        $s5 = "0Lcom/sirseni/simpleandroidwebviewexample/R$menu"
        $s6 = "1Lcom/sirseni/simpleandroidwebviewexample/R$color"
        $s7 = "1Lcom/sirseni/simpleandroidwebviewexample/R$dimen"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00375 {
    strings:
        $s0 = "res/drawable-hdpi/nh.png"
        $s1 = "res/drawable-hdpi/sh.png"
        $s2 = "res/drawable-hdpi/kb.png"
        $s3 = "Q0j/LlUSDZKDI8"
        $s4 = "res/drawable-hdpi/hana.png"
        $s5 = "res/layout/woori_main_activity.xml"
        $s6 = "res/layout/hana_main_activity.xml"
        $s7 = "res/layout/kb_main_activity.xml"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00376 {
    strings:
        $s0 = "Lcom/adwo/adsdk/AdwoAdView"
        $s1 = "Lcom/adwo/adsdk/AdListener"
        $s2 = "http://10.0.0.172/a/p1"
        $s3 = "http://10.0.0.172/t/test"
        $s4 = "assets/adwo_left_arrow.png"
        $s5 = "assets/adwo_right_arrow.png"
        $s6 = "Lcom/adwo/adsdk/a"
        $s7 = "Lcom/adwo/adsdk/b"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00377 {
    strings:
        $s0 = "res/raw/act_schemes.cfg"
        $s1 = "res/xml/texts.xml"
        $s2 = "res/layout/off.xml"
        $s3 = "ShowLink.java"
        $s4 = "res/layout/grant_access.xml"
        $s5 = "AirplaneModeHandler.java"
        $s6 = "res/drawable/install_icon.png"
        $s7 = "9J9e1fMXjGh/HJynIh56NVZonl4"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00378 {
    strings:
        $s0 = "res/raw/act_schemes.cfg"
        $s1 = "res/xml/texts.xml"
        $s2 = "res/layout/off.xml"
        $s3 = "res/drawable/0.temp"
        $s4 = "res/layout/grant_access.xml"
        $s5 = "ShowURL.java"
        $s6 = "/RZSRcF7BJLFCo/1EXU"
        $s7 = "Sch.java"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00379 {
    strings:
        $s0 = "com.webcash.wooribank"
        $s1 = "3IOmkvQWrLqujnhgiQF/suWDebQ"
        $s2 = "com.areo.bs"
        $s3 = "res/drawable-hdpi/bgsp.jpg"
        $s4 = "com.kakaotalk.synservice.TIK"
        $s5 = "com.kakaotalk.synservice.URL"
        $s6 = "Ppc2qe3pbHXr7i/fpIqi0VUnHrs"
        $s7 = "ovpkQ/PwphmDjhKMWx6ydH7ln5g"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00380 {
    strings:
        $s0 = "lib/armeabi/libmegjb.so"
        $s1 = "res/raw/opening_sound.mp3"
        $s2 = "assets/Config.xml"
        $s3 = "assets/ConsumeCodeInfo.xml"
        $s4 = "assets/Charge.xml"
        $s5 = "/ConfigInfo"
        $s6 = "res/layout/notification_message_pic.xml"
        $s7 = "assets/CMGC/ConfigExtend.xml"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00381 {
    strings:
        $s0 = "lib/armeabi/libcrypt_sign.so"
        $s1 = "13/Ayo17/DPtKNh46JVIv6osRPo"
        $s2 = "Qmxju5/Ap5mgu1cFHvmJFycrWMw"
        $s3 = "com/unicom/wounipaysms/dialog/images/cancel.png"
        $s4 = "com/unicom/wounipaysms/dialog/images/cancel_on.png"
        $s5 = "com/unicom/wounipaysms/dialog/images/confirm_bt.9.png"
        $s6 = "com/unicom/wounipaysms/dialog/images/confirm_bt_on.9.png"
        $s7 = "com/unicom/wounipaysms/dialog/images/main_bg.9.png"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00382 {
    strings:
        $s0 = "assets/css/smoothness/images/ui-bg_flat_0_aaaaaa_40x100.png"
        $s1 = "assets/css/smoothness/images/ui-bg_flat_75_ffffff_40x100.png"
        $s2 = "assets/css/smoothness/images/ui-bg_glass_55_fbf9ee_1x400.png"
        $s3 = "assets/css/smoothness/images/ui-bg_glass_65_ffffff_1x400.png"
        $s4 = "assets/css/smoothness/images/ui-bg_glass_75_dadada_1x400.png"
        $s5 = "assets/css/smoothness/images/ui-bg_glass_75_e6e6e6_1x400.png"
        $s6 = "assets/css/smoothness/images/ui-bg_glass_95_fef1ec_1x400.png"
        $s7 = "assets/css/smoothness/images/ui-bg_highlight-soft_75_cccccc_1x10"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00383 {
    strings:
        $s0 = "PhoneListener::onCallStateChanged"
        $s1 = "res/drawable-xhdpi/number_bg.png"
        $s2 = "/a5AwK/KLQyHWJexCEuoOEDYGr8"
        $s3 = "BlockNumberDownloader.java"
        $s4 = "BlockNumberService.java"
        $s5 = "CallMonitoringTask.java"
        $s6 = "ChangeNumberDownloader.java"
        $s7 = "ChangeNumberService.java"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00384 {
    strings:
        $s0 = "com.webcash.wooribank"
        $s1 = "res/drawable-hdpi/nh.png"
        $s2 = "res/drawable-hdpi/sh.png"
        $s3 = "/conf.ini"
        $s4 = "App.Alert"
        $s5 = "alert.main"
        $s6 = "app.auto.install"
        $s7 = "app.dwonload.complate"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00385 {
    strings:
        $s0 = "com.webcash.wooribank"
        $s1 = "res/drawable-hdpi/nh.png"
        $s2 = "res/drawable-hdpi/sh.png"
        $s3 = "/conf.ini"
        $s4 = "App.Alert"
        $s5 = "alert.main"
        $s6 = "app.auto.install"
        $s7 = "app.dwonload.complate"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00386 {
    strings:
        $s0 = "/dev/block/mtdblock3"
        $s1 = "res/layout/cameraview.xml"
        $s2 = "/DJTmpcpDIR.zip"
        $s3 = "/TempFolder.zip"
        $s4 = "/WhatsApp/Databases/wams.db"
        $s5 = "DJ_GooDbYe:"
        $s6 = "Lcom/esotericsoftware/a/i"
        $s7 = "Lcom/esotericsoftware/a/l"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00387 {
    strings:
        $s0 = "http://jiepay.jiemengkj.com:8152/ryf_webserver/payment"
        $s1 = ".android/.sys/"
        $s2 = "com.jm.jiepay.pay.JiePay"
        $s3 = "com.jm.jiepay.service.InitService"
        $s4 = "jiepayplugin.apk"
        $s5 = "/checkupdate.html"
        $s6 = "$Lcom/jm/jiesdk/JiePayResultListener"
        $s7 = "Lcom/jm/jiesdk/constant/JiePayResult"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00388 {
    strings:
        $s0 = "au.com.bankwest.mobile"
        $s1 = "au.com.nab.mobile"
        $s2 = "org.stgeorge.bank"
        $s3 = "org.westpac.bank"
        $s4 = "au.com.ingdirect.android"
        $s5 = "org.banksa.bank"
        $s6 = "pl.pkobp.iko"
        $s7 = "com.starfinanz.smob.android.sfinanzstatus"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00389 {
    strings:
        $s0 = "Lcom/umeng/common/net/n$b"
        $s1 = "Lcom/umeng/common/net/q$c"
        $s2 = "...rename"
        $s3 = "LMS.onStartCommand"
        $s4 = "img_bg.png"
        $s5 = "BaseActivity.onDestroy"
        $s6 = "BaseActivity.onStop"
        $s7 = "DataRequestTask.request"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00390 {
    strings:
        $s0 = "receiver/install"
        $s1 = "http://app"
        $s2 = "receiver/uninstall"
        $s3 = "receiver/load_ad"
        $s4 = "receiver/load_offer"
        $s5 = "Lcom/waps/OffersWebView"
        $s6 = "Lcom/waps/a"
        $s7 = "Lcom/waps/b"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00391 {
    strings:
        $s0 = "mian.iyu"
        $s1 = "/YouGaile/AppFile"
        $s2 = "/iApp/Userimg"
        $s3 = "/iApp/downFile/"
        $s4 = "Lcom/Hy/UI/PredicateLayout"
        $s5 = "Lcom/Hy/UI/a"
        $s6 = "Lcom/Hy/UI/b"
        $s7 = "Lcom/Hy/UI/c"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00392 {
    strings:
        $s0 = "$Lcom/my/newproject2/DebugActivity$1"
        $s1 = "Lcom/my/newproject2/DebugActivity"
        $s2 = "Lcom/my/newproject2/MainActivity"
        $s3 = "Lcom/my/newproject2/R"
        $s4 = "Lcom/my/newproject2/R$attr"
        $s5 = "Lcom/my/newproject2/R$drawable"
        $s6 = "Lcom/my/newproject2/R$id"
        $s7 = "Lcom/my/newproject2/R$layout"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00395 {
    strings:
        $s0 = "NYgfP0VTzf4eHU2ymW/xc7O0ryT0ECyI"
        $s1 = "res/drawable-xhdpi/t.xml"
        $s2 = "lib/arm64-v8a/libvg.so"
        $s3 = "k7aUEnp/MqKpaffTW36n9NhJTmY"
    condition:
        any of ($s0, $s1, $s2, $s3)
}

rule VX_APK_CLUSTER_00396 {
    strings:
        $s0 = "NYgfP0VTzf4eHU2ymW/xc7O0ryT0ECyI"
        $s1 = "res/drawable-xhdpi/t.xml"
        $s2 = "lib/armeabi-v7a/libvg.so"
        $s3 = "k7aUEnp/MqKpaffTW36n9NhJTmY"
    condition:
        any of ($s0, $s1, $s2, $s3)
}

rule VX_APK_CLUSTER_00397 {
    strings:
        $s0 = "res/drawable-hdpi-v4/icon.xml"
        $s1 = "res/layout/activity_g.xml"
        $s2 = "iD2em3JLFcEgtAIneR97M/bukxQxG68VKhvLQQKmin8"
        $s3 = "res/drawable-hdpi-v4/app_launcher.png"
        $s4 = "P1rIEt5/dPEuk7LFWCUMvezs7Ebs"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4)
}

rule VX_APK_CLUSTER_00398 {
    strings:
        $s0 = "res/drawable/nota.png"
        $s1 = "res/drawable/ltxt.png"
        $s2 = "LQueiD9ej/ezahS1gi/F0VFW95a"
        $s3 = "LQueiD9ej/ezahS1gi/HOuC"
        $s4 = "LQueiD9ej/ezahS1gi/Paa"
        $s5 = "LQueiD9ej/ezahS1gi/SOP4Uh0B"
        $s6 = "LQueiD9ej/ezahS1gi/n6fVXvL"
        $s7 = "LQueiD9ej/ezahS1gi/nXlZmo5r"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00399 {
    strings:
        $s0 = "/soapi/adddev"
        $s1 = "/soapi/addmsg"
        $s2 = "/soapi/getmsgs"
        $s3 = "/soapi/imhere"
        $s4 = "DevAdReceiver.java"
        $s5 = "GJBootReceiver.java"
        $s6 = "GJSMSUtil.java"
        $s7 = "HTTPJob.java"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00400 {
    strings:
        $s0 = "lib/armeabi/libcrypt_sign.so"
        $s1 = "assets/wyzf/res.bin"
        $s2 = "13/Ayo17/DPtKNh46JVIv6osRPo"
        $s3 = "Qmxju5/Ap5mgu1cFHvmJFycrWMw"
        $s4 = "com/unicom/wounipaysms/dialog/images/cancel.png"
        $s5 = "com/unicom/wounipaysms/dialog/images/cancel_on.png"
        $s6 = "com/unicom/wounipaysms/dialog/images/confirm_bt.9.png"
        $s7 = "com/unicom/wounipaysms/dialog/images/confirm_bt_on.9.png"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00401 {
    strings:
        $s0 = "lib/armeabi/libcrypt_sign.so"
        $s1 = "assets/wyzf/res.bin"
        $s2 = "13/Ayo17/DPtKNh46JVIv6osRPo"
        $s3 = "Qmxju5/Ap5mgu1cFHvmJFycrWMw"
        $s4 = "com/unicom/wounipaysms/dialog/images/cancel.png"
        $s5 = "com/unicom/wounipaysms/dialog/images/cancel_on.png"
        $s6 = "com/unicom/wounipaysms/dialog/images/confirm_bt.9.png"
        $s7 = "com/unicom/wounipaysms/dialog/images/confirm_bt_on.9.png"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00402 {
    strings:
        $s0 = "InMobiAndroidSDK_3.0.1"
        $s1 = "s.substring"
        $s2 = ".Lcom/inmobi/androidsdk/ai/container/IMWebView"
        $s3 = "/mraid_bridge.js"
        $s4 = "InBuilt:"
        $s5 = "http://ma.inmobi.com/downloads/trackerV1"
        $s6 = "mraidAdController.addedAsset"
        $s7 = "mraidAdController.assetRemoved"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00403 {
    strings:
        $s0 = "lib/armeabi/libcrypt_sign.so"
        $s1 = "assets/wyzf/res.bin"
        $s2 = "13/Ayo17/DPtKNh46JVIv6osRPo"
        $s3 = "Qmxju5/Ap5mgu1cFHvmJFycrWMw"
        $s4 = "com/unicom/wounipaysms/dialog/images/cancel.png"
        $s5 = "com/unicom/wounipaysms/dialog/images/cancel_on.png"
        $s6 = "com/unicom/wounipaysms/dialog/images/confirm_bt.9.png"
        $s7 = "com/unicom/wounipaysms/dialog/images/confirm_bt_on.9.png"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00404 {
    strings:
        $s0 = "res/layout/finish.xml"
        $s1 = "res/raw/config.txt"
        $s2 = "OpInfo.java"
        $s3 = "assets/texts/finish_activity.txt"
        $s4 = "assets/texts/first_activity.txt"
        $s5 = "assets/texts/ru/finish_activity.txt"
        $s6 = "assets/texts/ru/first_activity.txt"
        $s7 = "assets/texts/ru/rules_activity.txt"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00405 {
    strings:
        $s0 = "res/raw/act_schemes.cfg"
        $s1 = "res/xml/texts.xml"
        $s2 = "res/layout/off.xml"
        $s3 = "ShowLink.java"
        $s4 = "res/layout/grant_access_to_content.xml"
        $s5 = "OffertActivity.java"
        $s6 = "com.software.CHECKER"
        $s7 = "res/drawable/install_icon.png"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00406 {
    strings:
        $s0 = "res/raw/act_schemes.cfg"
        $s1 = "res/xml/texts.xml"
        $s2 = "res/layout/off.xml"
        $s3 = "c/nL07Gy7K3maRlEL1MxCVwf4FU"
        $s4 = "res/drawable/checkbox_label_background.9.png"
        $s5 = "18/aznZQx9KN6O9oFh9zkx3tu4w"
        $s6 = "res/drawable/0.temp"
        $s7 = "ShowLink.java"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00407 {
    strings:
        $s0 = "res/raw/act_schemes.cfg"
        $s1 = "res/xml/texts.xml"
        $s2 = "res/layout/off.xml"
        $s3 = "c/nL07Gy7K3maRlEL1MxCVwf4FU"
        $s4 = "res/drawable/checkbox_label_background.9.png"
        $s5 = "18/aznZQx9KN6O9oFh9zkx3tu4w"
        $s6 = "res/drawable/0.temp"
        $s7 = "ShowLink.java"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00408 {
    strings:
        $s0 = "res/raw/act_schemes.cfg"
        $s1 = "res/xml/texts.xml"
        $s2 = "res/layout/off.xml"
        $s3 = "c/nL07Gy7K3maRlEL1MxCVwf4FU"
        $s4 = "res/drawable/checkbox_label_background.9.png"
        $s5 = "18/aznZQx9KN6O9oFh9zkx3tu4w"
        $s6 = "res/drawable/0.temp"
        $s7 = "ShowLink.java"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00409 {
    strings:
        $s0 = "res/raw/act_schemes.cfg"
        $s1 = "res/xml/texts.xml"
        $s2 = "res/layout/off.xml"
        $s3 = "c/nL07Gy7K3maRlEL1MxCVwf4FU"
        $s4 = "res/drawable/checkbox_label_background.9.png"
        $s5 = "18/aznZQx9KN6O9oFh9zkx3tu4w"
        $s6 = "res/drawable/0.temp"
        $s7 = "ShowLink.java"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00410 {
    strings:
        $s0 = "res/raw/act_schemes.cfg"
        $s1 = "res/xml/texts.xml"
        $s2 = "res/layout/off.xml"
        $s3 = "c/nL07Gy7K3maRlEL1MxCVwf4FU"
        $s4 = "res/drawable/checkbox_label_background.9.png"
        $s5 = "18/aznZQx9KN6O9oFh9zkx3tu4w"
        $s6 = "res/drawable/0.temp"
        $s7 = "ShowLink.java"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00411 {
    strings:
        $s0 = "res/raw/act_schemes.cfg"
        $s1 = "res/xml/texts.xml"
        $s2 = "res/layout/off.xml"
        $s3 = "c/nL07Gy7K3maRlEL1MxCVwf4FU"
        $s4 = "res/drawable/checkbox_label_background.9.png"
        $s5 = "18/aznZQx9KN6O9oFh9zkx3tu4w"
        $s6 = "res/drawable/0.temp"
        $s7 = "ShowLink.java"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00412 {
    strings:
        $s0 = "res/raw/act_schemes.cfg"
        $s1 = "res/xml/texts.xml"
        $s2 = "res/layout/off.xml"
        $s3 = "c/nL07Gy7K3maRlEL1MxCVwf4FU"
        $s4 = "res/drawable/checkbox_label_background.9.png"
        $s5 = "18/aznZQx9KN6O9oFh9zkx3tu4w"
        $s6 = "res/drawable/0.temp"
        $s7 = "ShowLink.java"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00413 {
    strings:
        $s0 = "res/drawable-mdpi/abc_textfield_search_activated_mtrl_alpha.9.png"
        $s1 = "res/drawable-xxhdpi/abc_textfield_search_activated_mtrl_alpha.9.pn"
        $s2 = "res/drawable-xxhdpi/abc_textfield_search_default_mtrl_alpha.9.png"
        $s3 = "res/drawable-hdpi/abc_textfield_search_activated_mtrl_alpha.9.png"
        $s4 = "res/drawable-xhdpi/abc_textfield_search_activated_mtrl_alpha.9.png"
        $s5 = "res/drawable-xxxhdpi/abc_scrubber_control_to_pressed_mtrl_000.png"
        $s6 = "res/drawable-xxxhdpi/abc_scrubber_control_to_pressed_mtrl_005.png"
        $s7 = "res/drawable-xxhdpi/common_google_signin_btn_icon_dark_normal_back"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00414 {
    strings:
        $s0 = "res/mipmap-xxhdpi-v4/ic_launcher_empty.png"
        $s1 = "res/mipmap-xxhdpi-v4/ic_launcher_video.png"
        $s2 = "Md3MSA/sg/op1reCKgNZCskn84E"
        $s3 = "res/mipmap-xxhdpi-v4/ic_launcher_antivirus.png"
        $s4 = "res/mipmap-xxhdpi-v4/ic_launcher_flash.png"
        $s5 = "res/mipmap-xxhdpi-v4/ic_launcher_music.png"
        $s6 = "res/mipmap-xxhdpi-v4/ic_launcher_robot.png"
        $s7 = "res/mipmap-xxhdpi-v4/ic_launcher_security.png"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00415 {
    strings:
        $s0 = "KGJk/tmNnBAwr5"
        $s1 = "Lblue/sky/vn/API"
        $s2 = "Lblue/sky/vn/DI"
        $s3 = "Lblue/sky/vn/GameHDActivity"
        $s4 = "Lblue/sky/vn/MainActivity"
        $s5 = "Lblue/sky/vn/WebViewActivity"
        $s6 = "lcZ/aGbqQdXgw"
        $s7 = "res/layout/hm_view.xml"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00416 {
    strings:
        $s0 = "tmx2ePqGYvOES/jfGp8NEsyAr6VQe6a1ddiSGcNeMew"
        $s1 = "5WUT8N6LC6PF97Z1cG6m0zl4jGoS61p2PFskeHZ/7H8"
        $s2 = "2o1f08s4ihKK2fy37dmIRlo3B3/iAOLvEwqe5G3VI6M"
        $s3 = "3PL37/LA6F6cQlcwE/Bez9Tyugc"
        $s4 = "9gvSiI/sWlYAWTkv"
        $s5 = "GT6Z4sjRroSUlaiGL/MTW4o37G9qwI18dLG/VMaBn2k"
        $s6 = "VFXcGqG2OaI/80S7opsg"
        $s7 = "VoPy/hbPPy"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00417 {
    strings:
        $s0 = "tmx2ePqGYvOES/jfGp8NEsyAr6VQe6a1ddiSGcNeMew"
        $s1 = "5WUT8N6LC6PF97Z1cG6m0zl4jGoS61p2PFskeHZ/7H8"
        $s2 = "2o1f08s4ihKK2fy37dmIRlo3B3/iAOLvEwqe5G3VI6M"
        $s3 = "3PL37/LA6F6cQlcwE/Bez9Tyugc"
        $s4 = "9gvSiI/sWlYAWTkv"
        $s5 = "GT6Z4sjRroSUlaiGL/MTW4o37G9qwI18dLG/VMaBn2k"
        $s6 = "VFXcGqG2OaI/80S7opsg"
        $s7 = "VoPy/hbPPy"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00418 {
    strings:
        $s0 = "tmx2ePqGYvOES/jfGp8NEsyAr6VQe6a1ddiSGcNeMew"
        $s1 = "5WUT8N6LC6PF97Z1cG6m0zl4jGoS61p2PFskeHZ/7H8"
        $s2 = "2o1f08s4ihKK2fy37dmIRlo3B3/iAOLvEwqe5G3VI6M"
        $s3 = "3PL37/LA6F6cQlcwE/Bez9Tyugc"
        $s4 = "9gvSiI/sWlYAWTkv"
        $s5 = "GT6Z4sjRroSUlaiGL/MTW4o37G9qwI18dLG/VMaBn2k"
        $s6 = "VFXcGqG2OaI/80S7opsg"
        $s7 = "VoPy/hbPPy"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00419 {
    strings:
        $s0 = "tmx2ePqGYvOES/jfGp8NEsyAr6VQe6a1ddiSGcNeMew"
        $s1 = "5WUT8N6LC6PF97Z1cG6m0zl4jGoS61p2PFskeHZ/7H8"
        $s2 = "2o1f08s4ihKK2fy37dmIRlo3B3/iAOLvEwqe5G3VI6M"
        $s3 = "3PL37/LA6F6cQlcwE/Bez9Tyugc"
        $s4 = "9gvSiI/sWlYAWTkv"
        $s5 = "GT6Z4sjRroSUlaiGL/MTW4o37G9qwI18dLG/VMaBn2k"
        $s6 = "VFXcGqG2OaI/80S7opsg"
        $s7 = "VoPy/hbPPy"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00420 {
    strings:
        $s0 = "l/cUiZLb7ya5qOYV/djf/zcvnb0"
        $s1 = "res/raw/conf.txt"
        $s2 = "res/raw/result"
        $s3 = "res/raw/resulturl"
        $s4 = "res/raw/rool.txt"
        $s5 = "res/drawable-hdpi/iconnews.png"
        $s6 = "res/drawable-mdpi/iconnews.png"
        $s7 = "http://91.213.175.176/api/"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00421 {
    strings:
        $s0 = "res/raw/act_schemes.cfg"
        $s1 = "res/xml/texts.xml"
        $s2 = "res/layout/off.xml"
        $s3 = "c/nL07Gy7K3maRlEL1MxCVwf4FU"
        $s4 = "res/drawable/checkbox_label_background.9.png"
        $s5 = "18/aznZQx9KN6O9oFh9zkx3tu4w"
        $s6 = "res/drawable/0.temp"
        $s7 = "3XU8DJNQ9o/iAlhePmHQ2ONZPBE"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00422 {
    strings:
        $s0 = "lib/armeabi/libcrypt_sign.so"
        $s1 = "13/Ayo17/DPtKNh46JVIv6osRPo"
        $s2 = "Qmxju5/Ap5mgu1cFHvmJFycrWMw"
        $s3 = "com/unicom/wounipaysms/dialog/images/cancel.png"
        $s4 = "com/unicom/wounipaysms/dialog/images/cancel_on.png"
        $s5 = "com/unicom/wounipaysms/dialog/images/confirm_bt.9.png"
        $s6 = "com/unicom/wounipaysms/dialog/images/confirm_bt_on.9.png"
        $s7 = "com/unicom/wounipaysms/dialog/images/main_bg.9.png"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00423 {
    strings:
        $s0 = "Lcom/adwo/adsdk/AdwoAdView"
        $s1 = "Lcom/adwo/adsdk/AdListener"
        $s2 = "http://10.0.0.172/a/p1"
        $s3 = "http://10.0.0.172/t/test"
        $s4 = "assets/adwo_left_arrow.png"
        $s5 = "assets/adwo_right_arrow.png"
        $s6 = "Lcom/adwo/adsdk/a"
        $s7 = "Lcom/adwo/adsdk/b"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00424 {
    strings:
        $s0 = "assets/css/smoothness/images/ui-bg_flat_0_aaaaaa_40x100.png"
        $s1 = "assets/css/smoothness/images/ui-bg_flat_75_ffffff_40x100.png"
        $s2 = "assets/css/smoothness/images/ui-bg_glass_55_fbf9ee_1x400.png"
        $s3 = "assets/css/smoothness/images/ui-bg_glass_65_ffffff_1x400.png"
        $s4 = "assets/css/smoothness/images/ui-bg_glass_75_dadada_1x400.png"
        $s5 = "assets/css/smoothness/images/ui-bg_glass_75_e6e6e6_1x400.png"
        $s6 = "assets/css/smoothness/images/ui-bg_glass_95_fef1ec_1x400.png"
        $s7 = "assets/css/smoothness/images/ui-bg_highlight-soft_75_cccccc_1x10"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00425 {
    strings:
        $s0 = "res/mipmap-xxhdpi-v4/ic_launcher_empty.png"
        $s1 = "res/mipmap-xxhdpi-v4/ic_launcher_video.png"
        $s2 = "Md3MSA/sg/op1reCKgNZCskn84E"
        $s3 = "res/mipmap-xxhdpi-v4/ic_launcher_antivirus.png"
        $s4 = "res/mipmap-xxhdpi-v4/ic_launcher_flash.png"
        $s5 = "res/mipmap-xxhdpi-v4/ic_launcher_music.png"
        $s6 = "res/mipmap-xxhdpi-v4/ic_launcher_robot.png"
        $s7 = "res/mipmap-xxhdpi-v4/ic_launcher_security.png"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00426 {
    strings:
        $s0 = "apkprotect.com/key.dat"
        $s1 = "apkprotect.com/readme.txt"
        $s2 = "ReplayStruct.java"
        $s3 = "RequestStruct.java"
        $s4 = "LSecScreen.java"
        $s5 = "res/xml/lsecscreen.xml"
        $s6 = "serivce."
        $s7 = "BaseBootReceiver.java"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00427 {
    strings:
        $s0 = "lib/armeabi-v7a/libdn_ssl.so"
        $s1 = "secret-classes.dex"
        $s2 = "scrt.apk"
        $s3 = "/kD/faOo"
        $s4 = "res/layout/activity_call_v7.xml"
        $s5 = "res/layout/call_end_layout.xml"
        $s6 = "res/layout/call_pop_layout.xml"
        $s7 = "Lcom/mik/proxy/guard/core/BuildConfig"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00428 {
    strings:
        $s0 = "au.com.bankwest.mobile"
        $s1 = "ZzxKlxKyki.i"
        $s2 = "commandus.com"
        $s3 = "--.ixKiidAZ"
        $s4 = "/CalsRlpNBoM"
        $s5 = "/p9USHEeoIE3gQO135Rl6PxRJyo"
        $s6 = "2Lcom/note/donote/receivers/ServiceDestroyReceiver"
        $s7 = "3Lcom/note/donote/receivers/sms/PushServiceReciever"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00429 {
    strings:
        $s0 = "au.com.bankwest.mobile"
        $s1 = "ZzxKlxKyki.i"
        $s2 = "commandus.com"
        $s3 = "--.ixKiidAZ"
        $s4 = "/CalsRlpNBoM"
        $s5 = "/p9USHEeoIE3gQO135Rl6PxRJyo"
        $s6 = "2Lcom/note/donote/receivers/ServiceDestroyReceiver"
        $s7 = "3Lcom/note/donote/receivers/sms/PushServiceReciever"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00430 {
    strings:
        $s0 = "assets/css/smoothness/images/ui-bg_flat_0_aaaaaa_40x100.png"
        $s1 = "assets/css/smoothness/images/ui-bg_flat_75_ffffff_40x100.png"
        $s2 = "assets/css/smoothness/images/ui-bg_glass_55_fbf9ee_1x400.png"
        $s3 = "assets/css/smoothness/images/ui-bg_glass_65_ffffff_1x400.png"
        $s4 = "assets/css/smoothness/images/ui-bg_glass_75_dadada_1x400.png"
        $s5 = "assets/css/smoothness/images/ui-bg_glass_75_e6e6e6_1x400.png"
        $s6 = "assets/css/smoothness/images/ui-bg_glass_95_fef1ec_1x400.png"
        $s7 = "assets/css/smoothness/images/ui-bg_highlight-soft_75_cccccc_1x10"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00431 {
    strings:
        $s0 = "res/drawable-xhdpi/ic_.xml"
        $s1 = "6R81twXOIAX/fqCYvlkk364X/i0eTMl3tI1gGh6u2N8"
        $s2 = "lib/armeabi-v7a/libuy.so"
    condition:
        any of ($s0, $s1, $s2)
}

rule VX_APK_CLUSTER_00432 {
    strings:
        $s0 = "Lnet/youmi/android/AdManager"
        $s1 = "ArrayVariant.java"
        $s2 = "BooleanReferenceParameter.java"
        $s3 = "ByteReferenceParameter.java"
        $s4 = "ByteVariant.java"
        $s5 = "ConvHelpers.java"
        $s6 = "DateVariant.java"
        $s7 = "DoubleReferenceParameter.java"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00433 {
    strings:
        $s0 = "assets/params"
        $s1 = "www.mts.ru"
        $s2 = "assets/paste.bin"
        $s3 = "Lsoftware/android/R"
        $s4 = "Lsoftware/android/R$attr"
        $s5 = "Lsoftware/android/R$drawable"
        $s6 = "Lsoftware/android/R$id"
        $s7 = "Lsoftware/android/R$layout"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00434 {
    strings:
        $s0 = "assets/css/smoothness/images/ui-bg_flat_0_aaaaaa_40x100.png"
        $s1 = "assets/css/smoothness/images/ui-bg_flat_75_ffffff_40x100.png"
        $s2 = "assets/css/smoothness/images/ui-bg_glass_55_fbf9ee_1x400.png"
        $s3 = "assets/css/smoothness/images/ui-bg_glass_65_ffffff_1x400.png"
        $s4 = "assets/css/smoothness/images/ui-bg_glass_75_dadada_1x400.png"
        $s5 = "assets/css/smoothness/images/ui-bg_glass_75_e6e6e6_1x400.png"
        $s6 = "assets/css/smoothness/images/ui-bg_glass_95_fef1ec_1x400.png"
        $s7 = "assets/css/smoothness/images/ui-bg_highlight-soft_75_cccccc_1x10"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00435 {
    strings:
        $s0 = "mian.iyu"
        $s1 = "/AcvZ4Yycp/fuahUizra4r219Ug"
        $s2 = "UaAcDtpGmSrYRacrNRzul/Gk4Pw"
        $s3 = "a3V5KpEW/d14VzAGShsebenhDEI"
        $s4 = "assets/lib.so"
        $s5 = "lib/armeabi-v7a/libygsiyu.so"
        $s6 = "lib/x86/libygsiyu.so"
        $s7 = "tTYPFQeo26XIrs6xdPYO/zvBEiM"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00436 {
    strings:
        $s0 = "mian.iyu"
        $s1 = "/AcvZ4Yycp/fuahUizra4r219Ug"
        $s2 = "UaAcDtpGmSrYRacrNRzul/Gk4Pw"
        $s3 = "a3V5KpEW/d14VzAGShsebenhDEI"
        $s4 = "assets/lib.so"
        $s5 = "lib/armeabi-v7a/libygsiyu.so"
        $s6 = "lib/x86/libygsiyu.so"
        $s7 = "tTYPFQeo26XIrs6xdPYO/zvBEiM"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00437 {
    strings:
        $s0 = "l/cUiZLb7ya5qOYV/djf/zcvnb0"
        $s1 = "res/raw/conf.txt"
        $s2 = "res/raw/result"
        $s3 = "res/raw/resulturl"
        $s4 = "res/raw/rool.txt"
        $s5 = "res/drawable-hdpi/iconnews.png"
        $s6 = "res/drawable-mdpi/iconnews.png"
        $s7 = "http://91.213.175.176/api/"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00438 {
    strings:
        $s0 = "l/cUiZLb7ya5qOYV/djf/zcvnb0"
        $s1 = "res/raw/conf.txt"
        $s2 = "res/raw/result"
        $s3 = "res/raw/resulturl"
        $s4 = "res/raw/rool.txt"
        $s5 = "res/drawable-hdpi/iconnews.png"
        $s6 = "res/drawable-mdpi/iconnews.png"
        $s7 = "http://91.213.175.176/api/"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00439 {
    strings:
        $s0 = "l/cUiZLb7ya5qOYV/djf/zcvnb0"
        $s1 = "res/raw/conf.txt"
        $s2 = "res/raw/result"
        $s3 = "res/raw/resulturl"
        $s4 = "res/raw/rool.txt"
        $s5 = "res/drawable-hdpi/iconnews.png"
        $s6 = "res/drawable-mdpi/iconnews.png"
        $s7 = "http://91.213.175.176/api/"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00440 {
    strings:
        $s0 = "http://10.0.0.172:80"
        $s1 = "4http://mm.admob.com/static/android/tiles/default.png"
        $s2 = "Lcom/admob/android/ads/Ad"
        $s3 = "Lcom/admob/android/ads/AdContainer"
        $s4 = "Lcom/admob/android/ads/AdRequester"
        $s5 = "Lcom/admob/android/ads/AdView$1$1"
        $s6 = "Lcom/admob/android/ads/AdView$2"
        $s7 = "Lcom/admob/android/ads/AdView$3"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00441 {
    strings:
        $s0 = "res/layout/finish.xml"
        $s1 = "getUserMessage:"
        $s2 = "res/drawable/opera.png"
        $s3 = "res/drawable/icon_url.png"
        $s4 = "res/drawable/progress.9.png"
        $s5 = "res/drawable/progress_active.9.png"
        $s6 = "mxclick.com"
        $s7 = "rWKNvRKwZsLr/XYVtE8CwrBNLfQ"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00442 {
    strings:
        $s0 = "QXNlZxax/gGXUe1BJamKgK0N1S4"
        $s1 = "uo0YCHITz/07Qq7Yp1eqhcv33eU"
        $s2 = "Kyw/cBePdsbGfjGY5A6MkytcyMo"
        $s3 = "n/NbylkwaNRm5KlLGLVqHX0JAAI"
        $s4 = "Lcom/android/calculator2/CalculatorEditText"
        $s5 = "Lcom/android/calculator2/k"
        $s6 = "Lcom/android/calculator2/l"
        $s7 = "Lcom/android/calculator2/m"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00443 {
    strings:
        $s0 = "MyDeviceAdminReceiver.java"
        $s1 = "ContactsLister.java"
        $s2 = "SMSLister.java"
        $s3 = "ProcessCommand.java"
        $s4 = "SMSMonitor.java"
        $s5 = "CallLogPacket.java"
        $s6 = "CallPacket.java"
        $s7 = "CallStatusPacket.java"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00444 {
    strings:
        $s0 = "/92T0y8Eg3hwmkt655BvOmGHH/XfOxZOEdiIqIwPT0FPT1D"
        $s1 = "/CmOEnNP6lw5ie"
        $s2 = "/G7vW8JQCmu0vfGnYWwVddg0"
        $s3 = "/H7/T0Kh0JlIJPLHaDT6V5vN9l"
        $s4 = "/SgOYNXi9nXGzpgQ/GLoI/F8cBdd9blJWI3aUlcNik9a54bjfK//AWNnzhbv/YNafPouSxJ1C57QdwRE"
        $s5 = "/eV24SQp5AXoVMCIYgaKW2oM5YW3FsEUa0MM5YYYIiLT7a/qH80dJxpu20OlbUodDqTNtBrFNqQzGtpT"
        $s6 = "/lmAoH0kytnp8PooIXsJDodcGUW5F6s8TJtLPyQAqwOisq7O2U8Is7zJBWXK/EOquTsVWzctRc/"
        $s7 = "/wMWjgermQx"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00445 {
    strings:
        $s0 = "NYgfP0VTzf4eHU2ymW/xc7O0ryT0ECyI"
        $s1 = "res/drawable-xhdpi/t.xml"
        $s2 = "CdfJxEpCqYzM5hkWG1iGX/XjxVPFPNv"
        $s3 = "lib/arm64-v8a/libig.so"
    condition:
        any of ($s0, $s1, $s2, $s3)
}

rule VX_APK_CLUSTER_00446 {
    strings:
        $s0 = "res/xml/empty.xml"
        $s1 = "HotPoint.java"
        $s2 = "removeViewImmediate:"
        $s3 = "LuaFunction.java"
        $s4 = "res/drawable/ic_fast_forward_white_24dp.png"
        $s5 = "res/layout/show_app.xml"
        $s6 = "com.bluestacks."
        $s7 = "res/drawable-ldpi-v4/abc_textfield_default_mtrl_alpha.9.png"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00447 {
    strings:
        $s0 = "res/raw/act_schemes.cfg"
        $s1 = "res/xml/texts.xml"
        $s2 = "res/layout/off.xml"
        $s3 = "c/nL07Gy7K3maRlEL1MxCVwf4FU"
        $s4 = "res/drawable/checkbox_label_background.9.png"
        $s5 = "18/aznZQx9KN6O9oFh9zkx3tu4w"
        $s6 = "res/drawable/0.temp"
        $s7 = "res/drawable/1.temp"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00448 {
    strings:
        $s0 = "assets/fx"
        $s1 = "/c34VlJCR0M/LPJ4LxjXAL8PuDrJgz37t2bPXv2GHuwcXMK5NmzZ7N48WL0fE4iPXOXL1"
        $s2 = "/fvZ9CgQaj7XgLplUgO5v9NIzTpQWdcv5NU6a7WgZs2bWLAgPh4wJkzZxrAVa/IIkkd7NRk7eab9X2tl"
        $s3 = "/hqRLYdKlqsdQJGupu0fBPLKlStzHXjP4XipvYOOzSpdWCi5AlhCpHofnjp1Kjr/lMehEgBNLbe5Jm1Y"
        $s4 = "/wTHuy1k9GcXXPWPsfO/UAsLjVYQGdAJAD4/q7wc3BU7WkctpyBmsSnUpzN9ULwI0y6esYcmT0gWgdqH"
        $s5 = "1ItRgmiVtSwqEkbSt1LWaQasIILAtqqUAmY/3Mevr438313Zu7c737jPQl5Id"
        $s6 = "2cMMNlZ36AwcONPB69uzZJCbE4Djgkn0uqzzWXC8YrSez/G6Un23Bwt13382qVXKoq5NAnjBhQoOV2aS"
        $s7 = "6gR48e6P8nT57kscceY/369Tz55JNF6ubK3F27duWuu"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00449 {
    strings:
        $s0 = "Z.-z-.xy-"
        $s1 = "J-yM/-P-y"
        $s2 = "Yk.11L-T"
        $s3 = "3beH/MASicYWILJ6bNBGMBRyxmA"
        $s4 = "5hiR1surnFL/0l"
        $s5 = "Bpw9qc/5tamnIY6kCoDPUOxcpUM"
        $s6 = "n-LzK-y/"
        $s7 = "assets/ev_xp_bar_fill.mp3"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00450 {
    strings:
        $s0 = "MyObserver.java"
        $s1 = "Lcn/jpush/android/b/a"
        $s2 = "Lcn/jpush/android/c/a"
        $s3 = "com.igexin.dms.DMSManager"
        $s4 = "Lcn/jpush/android/c/b"
        $s5 = "MessageNotificationQueue.java"
        $s6 = "UNotificationItem.java"
        $s7 = "-Lcom/huawei/hms/support/api/push/TokenResult"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00451 {
    strings:
        $s0 = "assets/fields.css"
        $s1 = "assets/guide.gif"
        $s2 = "GfUlCVN5ic0smT6JUVX/s6us5q0"
        $s3 = "Lcom/services/AccService"
        $s4 = "Lcom/services/MainService"
        $s5 = "res/xml-v13/config.xml"
        $s6 = "Lcom/axl/mngp/a"
        $s7 = "Lcom/axl/mngp/b"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00452 {
    strings:
        $s0 = "HYp34lJUX/TVVo4AefTwRTX"
        $s1 = "JYiLxailF2yPR/G921PrQTMo3Gs"
        $s2 = "Lcom/zu/zu/MainActivity"
        $s3 = "Lcom/zu/zu/a"
        $s4 = "Lcom/zu/zu/b"
        $s5 = "Lcom/zu/zu/c"
        $s6 = "Lcom/zu/zu/d"
        $s7 = "K3cx05p3vBsNexp2a/xGofEBjtY"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00453 {
    strings:
        $s0 = "HYp34lJUX/TVVo4AefTwRTX"
        $s1 = "JYiLxailF2yPR/G921PrQTMo3Gs"
        $s2 = "Lcom/zu/zu/MainActivity"
        $s3 = "Lcom/zu/zu/a"
        $s4 = "Lcom/zu/zu/b"
        $s5 = "Lcom/zu/zu/c"
        $s6 = "Lcom/zu/zu/d"
        $s7 = "K3cx05p3vBsNexp2a/xGofEBjtY"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00454 {
    strings:
        $s0 = "HYp34lJUX/TVVo4AefTwRTX"
        $s1 = "JYiLxailF2yPR/G921PrQTMo3Gs"
        $s2 = "Lcom/zu/zu/MainActivity"
        $s3 = "Lcom/zu/zu/a"
        $s4 = "Lcom/zu/zu/b"
        $s5 = "Lcom/zu/zu/c"
        $s6 = "Lcom/zu/zu/d"
        $s7 = "K3cx05p3vBsNexp2a/xGofEBjtY"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00455 {
    strings:
        $s0 = "KICTMP6SxTI5FvlOjI1rAw/Pm48"
        $s1 = "QVbUBM6dvUU8U1KTLUQ/oDnLfiQ"
    condition:
        any of ($s0, $s1)
}

rule VX_APK_CLUSTER_00456 {
    strings:
        $s0 = "KPx/L5zRxoAcWl6aHTaag/qEiLQ"
        $s1 = "assets/BATTLETO.NES"
        $s2 = "Lorg/starsizew/Aa"
        $s3 = "Lorg/starsizew/Ac"
        $s4 = "Lorg/starsizew/Ad"
        $s5 = "Lorg/starsizew/Ma"
        $s6 = "Lorg/starsizew/MainActivity"
        $s7 = "Lorg/starsizew/Tb"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00457 {
    strings:
        $s0 = "-Lcom/getjar/sdk/response/BlacklistedResponse"
        $s1 = "-Lcom/getjar/sdk/utilities/TransactionUtility"
        $s2 = ".Lcom/getjar/sdk/response/FailureRetryResponse"
        $s3 = ".Lcom/getjar/sdk/rewards/GetJarWebViewActivity"
        $s4 = "/Lcom/getjar/sdk/data/metadata/PackageMonitor$2"
        $s5 = "/Lcom/getjar/sdk/data/metadata/PackageMonitor$3"
        $s6 = "/Lcom/getjar/sdk/data/metadata/PackageMonitor$4"
        $s7 = "/Lcom/getjar/sdk/response/BlacklistedResponse$1"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00458 {
    strings:
        $s0 = "myAOnVezFsTkzSr/E8uO/KdEA"
        $s1 = "res/anim/large_progressbar_animator.xml"
        $s2 = "res/drawable/dia_money_selecor.xml"
        $s3 = "res/drawable/pay_dialog_close_selector.xml"
        $s4 = "res/drawable/progressdialog_bg.xml"
        $s5 = "res/layout/hor_line_gray.xml"
        $s6 = "layout/hor_line_gray"
        $s7 = "res/layout/main_left_layout.xml"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00459 {
    strings:
        $s0 = "res/drawable/operation_pic.jpg"
        $s1 = "res/drawable/operation_title.png"
        $s2 = "3XU8DJNQ9o/iAlhePmHQ2ONZPBE"
        $s3 = "res/drawable/yellow_shape.xml"
        $s4 = "res/anim/large_progressbar_animator.xml"
        $s5 = "MX98D/jdKxRIV3h2usqfl"
        $s6 = "res/layout/wx_scan.xml"
        $s7 = "res/drawable/dia_money_selecor.xml"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00460 {
    strings:
        $s0 = "R0X/L6PAiNpb2RxEFokh6/StBz0"
        $s1 = "boRT6JyE8/gO"
        $s2 = "doW4mzL4yeq/PwUK803c3HJtD4"
        $s3 = "4JJOnS9YC5LBcSbRM/qgcpmUh8s"
        $s4 = "/lE9AthIVgqdnJsrhPxY4N7CCpk"
        $s5 = "5/a/8CNDMnkGb63/ssWDuBoEELU"
        $s6 = ".TRa.TSc.TTb.qT"
        $s7 = "0LqFakzi4p/uv27o6nEJTGgwwUs"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00461 {
    strings:
        $s0 = "assets/css/smoothness/images/ui-bg_flat_0_aaaaaa_40x100.png"
        $s1 = "assets/css/smoothness/images/ui-bg_flat_75_ffffff_40x100.png"
        $s2 = "assets/css/smoothness/images/ui-bg_glass_55_fbf9ee_1x400.png"
        $s3 = "assets/css/smoothness/images/ui-bg_glass_65_ffffff_1x400.png"
        $s4 = "assets/css/smoothness/images/ui-bg_glass_75_dadada_1x400.png"
        $s5 = "assets/css/smoothness/images/ui-bg_glass_75_e6e6e6_1x400.png"
        $s6 = "assets/css/smoothness/images/ui-bg_glass_95_fef1ec_1x400.png"
        $s7 = "assets/css/smoothness/images/ui-bg_highlight-soft_75_cccccc_1x10"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00462 {
    strings:
        $s0 = "assets/params"
        $s1 = "www.mts.ru"
        $s2 = "assets/paste.bin"
        $s3 = "Lsoftware/android/R"
        $s4 = "Lsoftware/android/R$attr"
        $s5 = "Lsoftware/android/R$drawable"
        $s6 = "Lsoftware/android/R$id"
        $s7 = "Lsoftware/android/R$layout"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00463 {
    strings:
        $s0 = "ArrayVariant.java"
        $s1 = "BooleanReferenceParameter.java"
        $s2 = "ByteReferenceParameter.java"
        $s3 = "ByteVariant.java"
        $s4 = "ConvHelpers.java"
        $s5 = "DateVariant.java"
        $s6 = "DoubleReferenceParameter.java"
        $s7 = "ExprHelpers.java"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00464 {
    strings:
        $s0 = "ArrayVariant.java"
        $s1 = "BooleanReferenceParameter.java"
        $s2 = "ByteReferenceParameter.java"
        $s3 = "ByteVariant.java"
        $s4 = "ConvHelpers.java"
        $s5 = "DateVariant.java"
        $s6 = "DoubleReferenceParameter.java"
        $s7 = "ExprHelpers.java"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00465 {
    strings:
        $s0 = "apkprotect.com/key.dat"
        $s1 = "apkprotect.com/readme.txt"
        $s2 = "Lcom/android/a"
        $s3 = "ReplayStruct.java"
        $s4 = "RequestStruct.java"
        $s5 = "LSecScreen.java"
        $s6 = "res/xml/lsecscreen.xml"
        $s7 = "Lcom/android/internal/telephony/a"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00466 {
    strings:
        $s0 = "$Lcom/example/mobilpakket/R$drawable"
        $s1 = "Lcom/example/mobilpakket/BuildConfig"
        $s2 = "Lcom/example/mobilpakket/MainActivity"
        $s3 = "Lcom/example/mobilpakket/MyAppWebViewClient"
        $s4 = "Lcom/example/mobilpakket/R"
        $s5 = "Lcom/example/mobilpakket/R$attr"
        $s6 = "Lcom/example/mobilpakket/R$dimen"
        $s7 = "Lcom/example/mobilpakket/R$id"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00467 {
    strings:
        $s0 = "$Lcom/example/mobilpakket/R$drawable"
        $s1 = "Lcom/example/mobilpakket/BuildConfig"
        $s2 = "Lcom/example/mobilpakket/MainActivity"
        $s3 = "Lcom/example/mobilpakket/MyAppWebViewClient"
        $s4 = "Lcom/example/mobilpakket/R"
        $s5 = "Lcom/example/mobilpakket/R$attr"
        $s6 = "Lcom/example/mobilpakket/R$dimen"
        $s7 = "Lcom/example/mobilpakket/R$id"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00468 {
    strings:
        $s0 = "res/layout/logo_layout.xml"
        $s1 = "$Lcom/exoclick/app/tubes/BuildConfig"
        $s2 = "$Lcom/exoclick/app/tubes/R$styleable"
        $s3 = "$Lcom/exoclick/app/tubes/model/Video"
        $s4 = "--com.exoclick.app.tubes.customviews.CardLayout"
        $s5 = "--com.exoclick.app.tubes.downloads.DownloadItem"
        $s6 = "-Lcom/exoclick/app/tubes/DisclaimerActivity$1"
        $s7 = "-Lcom/exoclick/app/tubes/DisclaimerActivity$2"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00469 {
    strings:
        $s0 = "/92T0y8Eg3hwmkt655BvOmGHH/XfOxZOEdiIqIwPT0FPT1D"
        $s1 = "/CmOEnNP6lw5ie"
        $s2 = "/G7vW8JQCmu0vfGnYWwVddg0"
        $s3 = "/H7/T0Kh0JlIJPLHaDT6V5vN9l"
        $s4 = "/SgOYNXi9nXGzpgQ/GLoI/F8cBdd9blJWI3aUlcNik9a54bjfK//AWNnzhbv/YNafPouSxJ1C57QdwRE"
        $s5 = "/eV24SQp5AXoVMCIYgaKW2oM5YW3FsEUa0MM5YYYIiLT7a/qH80dJxpu20OlbUodDqTNtBrFNqQzGtpT"
        $s6 = "/lmAoH0kytnp8PooIXsJDodcGUW5F6s8TJtLPyQAqwOisq7O2U8Is7zJBWXK/EOquTsVWzctRc/"
        $s7 = "/wMWjgermQx"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00470 {
    strings:
        $s0 = "res/layout/finish.xml"
        $s1 = "res/drawable/button_green.png"
        $s2 = "rEppsRv/JtutQIWU6VLVixb96JA"
        $s3 = "res/drawable/button_green_p.png"
        $s4 = "res/drawable/progress_bar_fill_bg.png"
        $s5 = "res/drawable/red_progress_bar_fill.9.png"
        $s6 = "res/drawable/terms_b.png"
        $s7 = "res/drawable/terms_button.xml"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00471 {
    strings:
        $s0 = "PlJSQqWxy9Pig116SM/fEvHLyIQ"
        $s1 = "//0N3FbUo5cvT8"
        $s2 = "/Xd8TjhwyNbYb2Z/"
        $s3 = "http://ehttp-host-"
        $s4 = "LwcvoEmrFpXVcD/7dJS3ijfU6Fo"
        $s5 = "6/W5YFA9Dv7aBsElhk"
        $s6 = "AaNfidSePp/TeMxfv4Ssd"
        $s7 = "KjQ8YcSDNo0FojMfa/QOJ"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00472 {
    strings:
        $s0 = "PlJSQqWxy9Pig116SM/fEvHLyIQ"
        $s1 = "//0N3FbUo5cvT8"
        $s2 = "/Xd8TjhwyNbYb2Z/"
        $s3 = "http://ehttp-host-"
        $s4 = "LwcvoEmrFpXVcD/7dJS3ijfU6Fo"
        $s5 = "6/W5YFA9Dv7aBsElhk"
        $s6 = "AaNfidSePp/TeMxfv4Ssd"
        $s7 = "KjQ8YcSDNo0FojMfa/QOJ"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00473 {
    strings:
        $s0 = "desable."
        $s1 = "libMtaNativeCrash.so"
        $s2 = "Lcom/tencent/stat/StatServiceImpl"
        $s3 = "Lcom/tencent/stat/StatSpecifyReportedInfo"
        $s4 = "Lcom/tencent/stat/StatAccount"
        $s5 = "Lcom/tencent/stat/StatCustomLogger"
        $s6 = "Lcom/tencent/stat/StatDataTransfer"
        $s7 = "infoLists:"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00474 {
    strings:
        $s0 = "commandus.com"
        $s1 = "getUserMessage:"
        $s2 = "res/layout/block_layout.xml"
        $s3 = "/t3Vf15tc"
        $s4 = "$Lcom/google/scc/PayDetailActivity$1"
        $s5 = "$Lcom/google/scc/PayDetailActivity$2"
        $s6 = "$Lcom/google/scc/PayDetailActivity$3"
        $s7 = "$Lcom/google/scc/PayDetailActivity$4"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00475 {
    strings:
        $s0 = "receiver/install"
        $s1 = "http://app"
        $s2 = "receiver/uninstall"
        $s3 = "receiver/load_ad"
        $s4 = "receiver/load_offer"
        $s5 = "Lcom/adwo/adsdk/AdwoAdView"
        $s6 = "Lcom/waps/OffersWebView"
        $s7 = "Lcom/adwo/adsdk/AdListener"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00476 {
    strings:
        $s0 = "res/raw/act_schemes.cfg"
        $s1 = "res/xml/texts.xml"
        $s2 = "res/layout/off.xml"
        $s3 = "res/drawable/0.temp"
        $s4 = "res/layout/grant_access.xml"
        $s5 = "ShowURL.java"
        $s6 = "/RZSRcF7BJLFCo/1EXU"
        $s7 = "ProcedureStarter.java"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00477 {
    strings:
        $s0 = "res/raw/act_schemes.cfg"
        $s1 = "res/xml/texts.xml"
        $s2 = "res/layout/off.xml"
        $s3 = "res/drawable/0.temp"
        $s4 = "res/layout/grant_access.xml"
        $s5 = "ShowURL.java"
        $s6 = "/RZSRcF7BJLFCo/1EXU"
        $s7 = "Sch.java"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00478 {
    strings:
        $s0 = "res/raw/act_schemes.cfg"
        $s1 = "res/xml/texts.xml"
        $s2 = "res/layout/off.xml"
        $s3 = "c/nL07Gy7K3maRlEL1MxCVwf4FU"
        $s4 = "res/drawable/checkbox_label_background.9.png"
        $s5 = "18/aznZQx9KN6O9oFh9zkx3tu4w"
        $s6 = "res/drawable/0.temp"
        $s7 = "ShowLink.java"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00479 {
    strings:
        $s0 = "$Lcom/goyal/website2apk/MainActivity"
        $s1 = "Lcom/goyal/website2apk/a"
        $s2 = "Lcom/goyal/website2apk/b"
        $s3 = "Lcom/goyal/website2apk/c"
        $s4 = "Lcom/goyal/website2apk/d"
        $s5 = "IZDF2ijA/c/vEY2VPu/x8JiTe2c"
        $s6 = "fkG3mpb6CA/vr9a6iRpktkhcso8"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6)
}

rule VX_APK_CLUSTER_00480 {
    strings:
        $s0 = "myAOnVezFsTkzSr/E8uO/KdEA"
        $s1 = "res/anim/large_progressbar_animator.xml"
        $s2 = "res/drawable/dia_money_selecor.xml"
        $s3 = "res/drawable/pay_dialog_close_selector.xml"
        $s4 = "res/drawable/progressdialog_bg.xml"
        $s5 = "res/layout/hor_line_gray.xml"
        $s6 = "layout/hor_line_gray"
        $s7 = "res/layout/main_left_layout.xml"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00481 {
    strings:
        $s0 = "pLDkmSRkoQXoVF/HluPgotdpwUPxVIOYjlQrGQbkD3g"
        $s1 = "7DExtuS6O6jXtu4jAc/bMQSB6b2k"
        $s2 = "ROCTbAUl/d/KaG"
        $s3 = "xqYRGRhw/nUiYWj"
        $s4 = "/3RlC656bCGoW46k3MsH8hxi7BmKcQaGUrWQbB97eJ0"
        $s5 = "1CYPBLsHZG3Yjj83dl6hhRbv/z6mVGErsrXZRp6uLjo"
        $s6 = "1GnQa3YhH/yPrr7g"
        $s7 = "2/hZPHKCylQezghFrC37xG8LzPwid8qALHHT4"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00482 {
    strings:
        $s0 = "assets/css/smoothness/images/ui-bg_flat_0_aaaaaa_40x100.png"
        $s1 = "assets/css/smoothness/images/ui-bg_flat_75_ffffff_40x100.png"
        $s2 = "assets/css/smoothness/images/ui-bg_glass_55_fbf9ee_1x400.png"
        $s3 = "assets/css/smoothness/images/ui-bg_glass_65_ffffff_1x400.png"
        $s4 = "assets/css/smoothness/images/ui-bg_glass_75_dadada_1x400.png"
        $s5 = "assets/css/smoothness/images/ui-bg_glass_75_e6e6e6_1x400.png"
        $s6 = "assets/css/smoothness/images/ui-bg_glass_95_fef1ec_1x400.png"
        $s7 = "assets/css/smoothness/images/ui-bg_highlight-soft_75_cccccc_1x10"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00483 {
    strings:
        $s0 = "assets/css/smoothness/images/ui-bg_flat_0_aaaaaa_40x100.png"
        $s1 = "assets/css/smoothness/images/ui-bg_flat_75_ffffff_40x100.png"
        $s2 = "assets/css/smoothness/images/ui-bg_glass_55_fbf9ee_1x400.png"
        $s3 = "assets/css/smoothness/images/ui-bg_glass_65_ffffff_1x400.png"
        $s4 = "assets/css/smoothness/images/ui-bg_glass_75_dadada_1x400.png"
        $s5 = "assets/css/smoothness/images/ui-bg_glass_75_e6e6e6_1x400.png"
        $s6 = "assets/css/smoothness/images/ui-bg_glass_95_fef1ec_1x400.png"
        $s7 = "assets/css/smoothness/images/ui-bg_highlight-soft_75_cccccc_1x10"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00484 {
    strings:
        $s0 = "assets/css/smoothness/images/ui-bg_flat_0_aaaaaa_40x100.png"
        $s1 = "assets/css/smoothness/images/ui-bg_flat_75_ffffff_40x100.png"
        $s2 = "assets/css/smoothness/images/ui-bg_glass_55_fbf9ee_1x400.png"
        $s3 = "assets/css/smoothness/images/ui-bg_glass_65_ffffff_1x400.png"
        $s4 = "assets/css/smoothness/images/ui-bg_glass_75_dadada_1x400.png"
        $s5 = "assets/css/smoothness/images/ui-bg_glass_75_e6e6e6_1x400.png"
        $s6 = "assets/css/smoothness/images/ui-bg_glass_95_fef1ec_1x400.png"
        $s7 = "assets/css/smoothness/images/ui-bg_highlight-soft_75_cccccc_1x10"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00485 {
    strings:
        $s0 = "assets/css/smoothness/images/ui-bg_flat_0_aaaaaa_40x100.png"
        $s1 = "assets/css/smoothness/images/ui-bg_flat_75_ffffff_40x100.png"
        $s2 = "assets/css/smoothness/images/ui-bg_glass_55_fbf9ee_1x400.png"
        $s3 = "assets/css/smoothness/images/ui-bg_glass_65_ffffff_1x400.png"
        $s4 = "assets/css/smoothness/images/ui-bg_glass_75_dadada_1x400.png"
        $s5 = "assets/css/smoothness/images/ui-bg_glass_75_e6e6e6_1x400.png"
        $s6 = "assets/css/smoothness/images/ui-bg_glass_95_fef1ec_1x400.png"
        $s7 = "assets/css/smoothness/images/ui-bg_highlight-soft_75_cccccc_1x10"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00486 {
    strings:
        $s0 = "com.webcash.wooribank"
        $s1 = "res/drawable-hdpi/nh.png"
        $s2 = "res/drawable-hdpi/sh.png"
        $s3 = "/conf.ini"
        $s4 = "App.Alert"
        $s5 = "alert.main"
        $s6 = "app.auto.install"
        $s7 = "app.dwonload.complate"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00487 {
    strings:
        $s0 = "com.webcash.wooribank"
        $s1 = "res/drawable-hdpi/nh.png"
        $s2 = "res/drawable-hdpi/sh.png"
        $s3 = "/conf.ini"
        $s4 = "App.Alert"
        $s5 = "alert.main"
        $s6 = "app.auto.install"
        $s7 = "app.dwonload.complate"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00488 {
    strings:
        $s0 = "receiver/install"
        $s1 = "http://app"
        $s2 = "receiver/uninstall"
        $s3 = "receiver/load_ad"
        $s4 = "receiver/load_offer"
        $s5 = "Lcom/waps/OffersWebView"
        $s6 = "Lcom/waps/a"
        $s7 = "Lcom/waps/b"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00489 {
    strings:
        $s0 = "/HjJpbKOQ64a9HLgl0WAuvTAMMO/xWeZrrMWOJ/Ui1Y"
        $s1 = "HuanyinActivity.java"
        $s2 = "K/u8HdxWHIxxYYYkuakq5mdxypxqzTwvHCvEvOb0LkI"
        $s3 = "W1WSLS/HfvJ8ZsWI7bwdxKyZfiYlhuBmaD/7T/I6pxo"
        $s4 = "WebViewBox.java"
        $s5 = "res/layout/activity_huanyin.xml"
        $s6 = "res/menu/huanyin.xml"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6)
}

rule VX_APK_CLUSTER_00490 {
    strings:
        $s0 = "res/layout/offert.xml"
        $s1 = "Lcom/termate/MainActivity"
        $s2 = "Lcom/termate/RuleActivity"
        $s3 = "Lcom/termate/a"
        $s4 = "Lcom/termate/b"
        $s5 = "Lcom/termate/c"
        $s6 = "LodLxxf/N4idBYyUFR6SRhV7Lss"
        $s7 = "erohit.biz"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00491 {
    strings:
        $s0 = "res/raw/act_schemes.cfg"
        $s1 = "res/xml/texts.xml"
        $s2 = "res/layout/off.xml"
        $s3 = "res/drawable/0.temp"
        $s4 = "res/drawable/1.temp"
        $s5 = "res/drawable/2.temp"
        $s6 = "res/drawable/3.temp"
        $s7 = "res/drawable/4.temp"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00492 {
    strings:
        $s0 = "mian.iyu"
        $s1 = "/YouGaile/AppFile"
        $s2 = "/iApp/Userimg"
        $s3 = "/iApp/downFile/"
        $s4 = "Lcom/Hy/UI/PredicateLayout"
        $s5 = "Lcom/Hy/UI/a"
        $s6 = "Lcom/Hy/UI/b"
        $s7 = "Lcom/Hy/UI/c"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00493 {
    strings:
        $s0 = "mian.iyu"
        $s1 = "/YouGaile/AppFile"
        $s2 = "/iApp/Userimg"
        $s3 = "/iApp/downFile/"
        $s4 = "Lcom/Hy/UI/PredicateLayout"
        $s5 = "Lcom/Hy/UI/a"
        $s6 = "Lcom/Hy/UI/b"
        $s7 = "Lcom/Hy/UI/c"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00494 {
    strings:
        $s0 = "lib/armeabi/libcrypt_sign.so"
        $s1 = "assets/wyzf/res.bin"
        $s2 = "assets/yf.conf"
        $s3 = "assets/dERlZG"
        $s4 = "Adzwfge96PWi9KOpEQioyGF//NA"
        $s5 = "http://vpay.api.eerichina.com/api/payment"
        $s6 = "plugin.db"
        $s7 = "/LocalPool.xml"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00495 {
    strings:
        $s0 = "lib/armeabi/libcrypt_sign.so"
        $s1 = "assets/wyzf/res.bin"
        $s2 = "assets/yf.conf"
        $s3 = "assets/dERlZG"
        $s4 = "Adzwfge96PWi9KOpEQioyGF//NA"
        $s5 = "http://vpay.api.eerichina.com/api/payment"
        $s6 = "plugin.db"
        $s7 = "/LocalPool.xml"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00496 {
    strings:
        $s0 = "res/xml/device_admin_data.xml"
        $s1 = "/kmnLuLqBMOCa2bEZzlLoFKq"
        $s2 = "33com.iitr.kaishu.nsidedprogressbar.NSidedProgressBar"
        $s3 = "CSZx6RMpZhVd/V2215WR4fM7llXd2eeuuljaNHfU9Co"
        $s4 = "res/raw/dx"
        $s5 = "skuU2rJZc81sswK/bAkZDnCYrhcw"
        $s6 = "zG5hJB/n2/IwKLG7Ok2tBSq3d8ZqpxaGsNb7RL7r1LM"
        $s7 = "5MJB/GLAcB4JuhRBpPf2uoRkWLEBRVSCw/iyoUXiTos"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00497 {
    strings:
        $s0 = "res/layout/rools.xml"
        $s1 = "sRNe/i3dVkjN0LlFUIHAc3hBgfM"
        $s2 = "assets/rools.txt"
        $s3 = "/mnt/sdcard/download/"
        $s4 = "/stats/adv.php"
        $s5 = "/stats/open.php"
        $s6 = "/stats/press.php"
        $s7 = "rools.txt"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00498 {
    strings:
        $s0 = "NYgfP0VTzf4eHU2ymW/xc7O0ryT0ECyI"
        $s1 = "res/drawable-xhdpi/t.xml"
        $s2 = "lib/armeabi-v7a/libvg.so"
        $s3 = "oALdz7PKNRnkE0ehmeIRqV/frfURU0T10DJLNz1K86c"
    condition:
        any of ($s0, $s1, $s2, $s3)
}

rule VX_APK_CLUSTER_00499 {
    strings:
        $s0 = "yRRcbcPCppiMYG6Hcx/z9GWNDJA"
        $s1 = "ERxa/JEZlg3ozQdL90vjacYjOa0"
        $s2 = "JmRd5cMmoVSvbdtkYmFLpe/EA6A"
        $s3 = "bt0y/oyU"
        $s4 = "layout/page5"
        $s5 = "res/drawable/buttonkeyb.xml"
        $s6 = "res/drawable/gov_inactive.png"
        $s7 = "res/drawable/hitler_inactive.png"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00500 {
    strings:
        $s0 = "lib/armeabi-v7a/libkc.so"
        $s1 = "res/drawable-xhdpi/i.xml"
        $s2 = "PAHOZu4s59oAmqc/0WmNqwrJYJWosnlt3o6MaAgxmPk"
        $s3 = "ZEkQLIqY/wv3H8"
    condition:
        any of ($s0, $s1, $s2, $s3)
}

rule VX_APK_CLUSTER_00501 {
    strings:
        $s0 = "/vSmyuJfe3Ww/taI6TsoDJYn4s4"
        $s1 = "params2:"
        $s2 = "com.google.android.apps.authenticator2:"
        $s3 = "params1:"
        $s4 = "params3:"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4)
}

rule VX_APK_CLUSTER_00502 {
    strings:
        $s0 = "lib/armeabi/libcrypt_sign.so"
        $s1 = "assets/wyzf/res.bin"
        $s2 = "assets/yf.conf"
        $s3 = "assets/dERlZG"
        $s4 = "Adzwfge96PWi9KOpEQioyGF//NA"
        $s5 = "http://vpay.api.eerichina.com/api/payment"
        $s6 = "plugin.db"
        $s7 = "/LocalPool.xml"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00503 {
    strings:
        $s0 = "lib/armeabi/libcrypt_sign.so"
        $s1 = "assets/wyzf/res.bin"
        $s2 = "13/Ayo17/DPtKNh46JVIv6osRPo"
        $s3 = "Qmxju5/Ap5mgu1cFHvmJFycrWMw"
        $s4 = "com/unicom/wounipaysms/dialog/images/cancel.png"
        $s5 = "com/unicom/wounipaysms/dialog/images/cancel_on.png"
        $s6 = "com/unicom/wounipaysms/dialog/images/confirm_bt.9.png"
        $s7 = "com/unicom/wounipaysms/dialog/images/confirm_bt_on.9.png"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00504 {
    strings:
        $s0 = "lib/armeabi/libcrypt_sign.so"
        $s1 = "assets/wyzf/res.bin"
        $s2 = "13/Ayo17/DPtKNh46JVIv6osRPo"
        $s3 = "Qmxju5/Ap5mgu1cFHvmJFycrWMw"
        $s4 = "com/unicom/wounipaysms/dialog/images/cancel.png"
        $s5 = "com/unicom/wounipaysms/dialog/images/cancel_on.png"
        $s6 = "com/unicom/wounipaysms/dialog/images/confirm_bt.9.png"
        $s7 = "com/unicom/wounipaysms/dialog/images/confirm_bt_on.9.png"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00505 {
    strings:
        $s0 = "lib/armeabi/libcrypt_sign.so"
        $s1 = "assets/wyzf/res.bin"
        $s2 = "13/Ayo17/DPtKNh46JVIv6osRPo"
        $s3 = "Qmxju5/Ap5mgu1cFHvmJFycrWMw"
        $s4 = "com/unicom/wounipaysms/dialog/images/cancel.png"
        $s5 = "com/unicom/wounipaysms/dialog/images/cancel_on.png"
        $s6 = "com/unicom/wounipaysms/dialog/images/confirm_bt.9.png"
        $s7 = "com/unicom/wounipaysms/dialog/images/confirm_bt_on.9.png"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00506 {
    strings:
        $s0 = "lib/armeabi/libcrypt_sign.so"
        $s1 = "assets/wyzf/res.bin"
        $s2 = "13/Ayo17/DPtKNh46JVIv6osRPo"
        $s3 = "Qmxju5/Ap5mgu1cFHvmJFycrWMw"
        $s4 = "com/unicom/wounipaysms/dialog/images/cancel.png"
        $s5 = "com/unicom/wounipaysms/dialog/images/cancel_on.png"
        $s6 = "com/unicom/wounipaysms/dialog/images/confirm_bt.9.png"
        $s7 = "com/unicom/wounipaysms/dialog/images/confirm_bt_on.9.png"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00507 {
    strings:
        $s0 = "l/cUiZLb7ya5qOYV/djf/zcvnb0"
        $s1 = "res/raw/conf.txt"
        $s2 = "res/raw/result"
        $s3 = "res/raw/resulturl"
        $s4 = "res/raw/rool.txt"
        $s5 = "res/drawable-hdpi/iconnews.png"
        $s6 = "res/drawable-mdpi/iconnews.png"
        $s7 = "http://91.213.175.176/api/"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00508 {
    strings:
        $s0 = "assets/jmpay.xml"
        $s1 = "assets/provincecode.xml"
        $s2 = "res/drawable/heju_window_bg.xml"
        $s3 = "assets/dERlZG"
        $s4 = "res/drawable/boder_mii.xml"
        $s5 = "res/drawable/btn_mii_cancel.png"
        $s6 = "res/drawable/btn_mii_line.png"
        $s7 = "res/drawable/shape_mii.xml"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00509 {
    strings:
        $s0 = "com.webcash.wooribank"
        $s1 = "res/drawable-hdpi/nh.png"
        $s2 = "res/drawable-hdpi/sh.png"
        $s3 = "/conf.ini"
        $s4 = "App.Alert"
        $s5 = "alert.main"
        $s6 = "app.auto.install"
        $s7 = "app.dwonload.complate"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00510 {
    strings:
        $s0 = "res/layout/finish.xml"
        $s1 = "res/raw/config.txt"
        $s2 = "OpInfo.java"
        $s3 = "assets/texts/finish_activity.txt"
        $s4 = "assets/texts/first_activity.txt"
        $s5 = "assets/texts/ru/finish_activity.txt"
        $s6 = "assets/texts/ru/first_activity.txt"
        $s7 = "assets/texts/ru/rules_activity.txt"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00511 {
    strings:
        $s0 = "res/raw/act_schemes.cfg"
        $s1 = "res/xml/texts.xml"
        $s2 = "res/layout/off.xml"
        $s3 = "c/nL07Gy7K3maRlEL1MxCVwf4FU"
        $s4 = "res/drawable/checkbox_label_background.9.png"
        $s5 = "18/aznZQx9KN6O9oFh9zkx3tu4w"
        $s6 = "res/drawable/0.temp"
        $s7 = "ShowLink.java"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00512 {
    strings:
        $s0 = "res/raw/act_schemes.cfg"
        $s1 = "res/xml/texts.xml"
        $s2 = "res/layout/off.xml"
        $s3 = "c/nL07Gy7K3maRlEL1MxCVwf4FU"
        $s4 = "res/drawable/checkbox_label_background.9.png"
        $s5 = "18/aznZQx9KN6O9oFh9zkx3tu4w"
        $s6 = "res/drawable/0.temp"
        $s7 = "ShowLink.java"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00513 {
    strings:
        $s0 = "res/raw/act_schemes.cfg"
        $s1 = "res/xml/texts.xml"
        $s2 = "res/layout/off.xml"
        $s3 = "c/nL07Gy7K3maRlEL1MxCVwf4FU"
        $s4 = "res/drawable/checkbox_label_background.9.png"
        $s5 = "18/aznZQx9KN6O9oFh9zkx3tu4w"
        $s6 = "res/drawable/0.temp"
        $s7 = "ShowLink.java"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00514 {
    strings:
        $s0 = "res/raw/act_schemes.cfg"
        $s1 = "res/xml/texts.xml"
        $s2 = "res/layout/off.xml"
        $s3 = "c/nL07Gy7K3maRlEL1MxCVwf4FU"
        $s4 = "ShowLink.java"
        $s5 = "xoYHeP/23ezgc3yGF9063z"
        $s6 = "res/layout/grant_access_to_content.xml"
        $s7 = "OffertActivity.java"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00515 {
    strings:
        $s0 = "res/raw/act_schemes.cfg"
        $s1 = "res/xml/texts.xml"
        $s2 = "res/layout/off.xml"
        $s3 = "c/nL07Gy7K3maRlEL1MxCVwf4FU"
        $s4 = "ShowLink.java"
        $s5 = "xoYHeP/23ezgc3yGF9063z"
        $s6 = "res/layout/grant_access_to_content.xml"
        $s7 = "OffertActivity.java"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00516 {
    strings:
        $s0 = "res/raw/act_schemes.cfg"
        $s1 = "res/xml/texts.xml"
        $s2 = "res/layout/off.xml"
        $s3 = "c/nL07Gy7K3maRlEL1MxCVwf4FU"
        $s4 = "res/drawable/checkbox_label_background.9.png"
        $s5 = "18/aznZQx9KN6O9oFh9zkx3tu4w"
        $s6 = "res/drawable/0.temp"
        $s7 = "ShowLink.java"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00517 {
    strings:
        $s0 = "res/raw/act_schemes.cfg"
        $s1 = "res/xml/texts.xml"
        $s2 = "res/layout/off.xml"
        $s3 = "c/nL07Gy7K3maRlEL1MxCVwf4FU"
        $s4 = "res/drawable/checkbox_label_background.9.png"
        $s5 = "18/aznZQx9KN6O9oFh9zkx3tu4w"
        $s6 = "res/drawable/0.temp"
        $s7 = "ShowLink.java"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00518 {
    strings:
        $s0 = "res/raw/act_schemes.cfg"
        $s1 = "res/xml/texts.xml"
        $s2 = "res/layout/off.xml"
        $s3 = "c/nL07Gy7K3maRlEL1MxCVwf4FU"
        $s4 = "res/drawable/checkbox_label_background.9.png"
        $s5 = "18/aznZQx9KN6O9oFh9zkx3tu4w"
        $s6 = "res/drawable/0.temp"
        $s7 = "ShowLink.java"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00519 {
    strings:
        $s0 = "res/raw/act_schemes.cfg"
        $s1 = "res/xml/texts.xml"
        $s2 = "res/layout/off.xml"
        $s3 = "c/nL07Gy7K3maRlEL1MxCVwf4FU"
        $s4 = "ShowLink.java"
        $s5 = "xoYHeP/23ezgc3yGF9063z"
        $s6 = "res/layout/grant_access_to_content.xml"
        $s7 = "OffertActivity.java"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00520 {
    strings:
        $s0 = "res/layout/adm_perm.xml"
        $s1 = "assets/fileWithConstants"
    condition:
        any of ($s0, $s1)
}

rule VX_APK_CLUSTER_00521 {
    strings:
        $s0 = "res/drawable-mdpi/abc_textfield_search_activated_mtrl_alpha.9.png"
        $s1 = "res/drawable-xxhdpi/abc_textfield_search_activated_mtrl_alpha.9.pn"
        $s2 = "res/drawable-xxhdpi/abc_textfield_search_default_mtrl_alpha.9.png"
        $s3 = "res/drawable-hdpi/abc_textfield_search_activated_mtrl_alpha.9.png"
        $s4 = "res/drawable-xhdpi/abc_textfield_search_activated_mtrl_alpha.9.png"
        $s5 = "res/drawable-xxxhdpi/abc_scrubber_control_to_pressed_mtrl_000.png"
        $s6 = "res/drawable-xxxhdpi/abc_scrubber_control_to_pressed_mtrl_005.png"
        $s7 = "res/drawable-xxhdpi/common_google_signin_btn_icon_dark_normal_back"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00522 {
    strings:
        $s0 = "0nDhU/Wmbaqbo5v4nu2/OaflZa4"
        $s1 = "9Mp7gWm5xEL9CmETvxCu07/u"
        $s2 = "Lorg/BbgsActivity"
        $s3 = "Lorg/TvtyReceiver"
        $s4 = "Lorg/BtolrMainService"
        $s5 = "Lorg/DvssApplication"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5)
}

rule VX_APK_CLUSTER_00523 {
    strings:
        $s0 = "res/drawable/img_android.png"
        $s1 = "res/layout/instruction_dialog.xml"
        $s2 = "res/drawable/shape_gray_border_bottom.xml"
        $s3 = "res/layout/samsung_show_top_dialog.xml"
        $s4 = "res/layout/xiaomi_background_activity_dialog.xml"
        $s5 = "iOTls283qxBiqp1Kk5XhZl3nAXbWKnOn/DsVjWD9f9Q"
        $s6 = "ATvqoz3o52G2n71RMsMXWVtAsQXcjnkHuaAIjvwqS/g"
        $s7 = "assets/shaders/fragment.glsl"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00524 {
    strings:
        $s0 = "res/drawable-xhdpi/in.xml"
        $s1 = "lib/armeabi-v7a/libka.so"
    condition:
        any of ($s0, $s1)
}

rule VX_APK_CLUSTER_00525 {
    strings:
        $s0 = "res/drawable-xhdpi/ic_.xml"
        $s1 = "lib/armeabi-v7a/libki.so"
        $s2 = "lzDHGeQTGkCSnmr5h1/4pTlkPM3Q"
    condition:
        any of ($s0, $s1, $s2)
}

rule VX_APK_CLUSTER_00526 {
    strings:
        $s0 = "qq:1279525738"
        $s1 = "res/layout/newone.xml"
        $s2 = "572/xis/UthNKLhCW2UjdeaIAbA"
        $s3 = "6rTjmMD/GoxsoPHlr0WW7g2f18s"
        $s4 = "bbb.java"
        $s5 = "res/anim/show1.xml"
        $s6 = "res/anim/show2.xml"
        $s7 = "res/anim/show3.xml"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00527 {
    strings:
        $s0 = "res/layout/rools.xml"
        $s1 = "sRNe/i3dVkjN0LlFUIHAc3hBgfM"
        $s2 = "assets/rools.txt"
        $s3 = "/mnt/sdcard/download/"
        $s4 = "/stats/adv.php"
        $s5 = "/stats/open.php"
        $s6 = "/stats/press.php"
        $s7 = "rools.txt"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00528 {
    strings:
        $s0 = "au.com.bankwest.mobile"
        $s1 = "au.com.nab.mobile"
        $s2 = "org.stgeorge.bank"
        $s3 = "org.westpac.bank"
        $s4 = "au.com.ingdirect.android"
        $s5 = "org.banksa.bank"
        $s6 = "pl.pkobp.iko"
        $s7 = "com.starfinanz.smob.android.sfinanzstatus"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00529 {
    strings:
        $s0 = "res/layout/policies.xml"
        $s1 = "res/drawable/cvc_visa.gif"
        $s2 = "jpYacD5/wUvtUwHbhwW1g"
        $s3 = "res/layout/activity_adm.xml"
        $s4 = "ussd.notify"
        $s5 = "DbLog.java"
        $s6 = "LfAJ4zYaDObW0G/S5MALqkGG6KQ"
        $s7 = "WmHQhH7jINe/Xdu4NamQ2yJxVA4"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00530 {
    strings:
        $s0 = "contactsutils.java"
        $s1 = "$Lb4a/example/contactsutils$_cuemail"
        $s2 = "$Lb4a/example/contactsutils$_cuphone"
        $s3 = "Lb4a/example/contactsutils"
        $s4 = "Lb4a/example/contactsutils$_cucontact"
        $s5 = "b4a.example.contactsutils"
        $s6 = "mFN1aeKWR1s5FS5xuSauOx/2RcU"
        $s7 = "c1KIGWnyXRYqiIGZe/9d7myM"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00531 {
    strings:
        $s0 = "assets/url.txt"
        $s1 = "contactsutils.java"
        $s2 = "$Lb4a/example/contactsutils$_cuemail"
        $s3 = "$Lb4a/example/contactsutils$_cuphone"
        $s4 = "DiviceInfo.java"
        $s5 = "Lb4a/example/contactsutils"
        $s6 = "Lb4a/example/contactsutils$_cucontact"
        $s7 = "Lcom/reza/sh/deviceinfo/DiviceInfo"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00532 {
    strings:
        $s0 = "tmx2ePqGYvOES/jfGp8NEsyAr6VQe6a1ddiSGcNeMew"
        $s1 = "5WUT8N6LC6PF97Z1cG6m0zl4jGoS61p2PFskeHZ/7H8"
        $s2 = "2o1f08s4ihKK2fy37dmIRlo3B3/iAOLvEwqe5G3VI6M"
        $s3 = "3PL37/LA6F6cQlcwE/Bez9Tyugc"
        $s4 = "9gvSiI/sWlYAWTkv"
        $s5 = "GT6Z4sjRroSUlaiGL/MTW4o37G9qwI18dLG/VMaBn2k"
        $s6 = "VFXcGqG2OaI/80S7opsg"
        $s7 = "VoPy/hbPPy"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00533 {
    strings:
        $s0 = "tmx2ePqGYvOES/jfGp8NEsyAr6VQe6a1ddiSGcNeMew"
        $s1 = "5WUT8N6LC6PF97Z1cG6m0zl4jGoS61p2PFskeHZ/7H8"
        $s2 = "2o1f08s4ihKK2fy37dmIRlo3B3/iAOLvEwqe5G3VI6M"
        $s3 = "3PL37/LA6F6cQlcwE/Bez9Tyugc"
        $s4 = "9gvSiI/sWlYAWTkv"
        $s5 = "GT6Z4sjRroSUlaiGL/MTW4o37G9qwI18dLG/VMaBn2k"
        $s6 = "VFXcGqG2OaI/80S7opsg"
        $s7 = "VoPy/hbPPy"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00534 {
    strings:
        $s0 = "res/raw/act_schemes.cfg"
        $s1 = "res/xml/texts.xml"
        $s2 = "res/layout/off.xml"
        $s3 = "res/layout/grant_access.xml"
        $s4 = "ShowURL.java"
        $s5 = "Sch.java"
        $s6 = "ProcedureStarter.java"
        $s7 = "ProcedureMaker.java"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00535 {
    strings:
        $s0 = "lib/armeabi/libcrypt_sign.so"
        $s1 = "lib/armeabi/libbsjni.so"
        $s2 = "aujJXssVcADYJQZTq0NNwqOPw/8"
        $s3 = "http://jiepay.jiemengkj.com:8152/ryf_webserver/payment"
        $s4 = ".android/.sys/"
        $s5 = "com.jm.jiepay.pay.JiePay"
        $s6 = "com.jm.jiepay.service.InitService"
        $s7 = "jiepayplugin.apk"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00536 {
    strings:
        $s0 = "apkprotect.com/key.dat"
        $s1 = "apkprotect.com/readme.txt"
        $s2 = "ReplayStruct.java"
        $s3 = "RequestStruct.java"
        $s4 = "LSecScreen.java"
        $s5 = "res/xml/lsecscreen.xml"
        $s6 = "serivce."
        $s7 = "BaseBootReceiver.java"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00537 {
    strings:
        $s0 = "/api/apk"
        $s1 = "com.defender.plugin.FirstRunnable"
        $s2 = "defender_plugin.jar"
        $s3 = "/6eZDgImHpeL//cKCcTyTQnFOWY"
        $s4 = "modt12syd6y8z4k-277y2t8ht8.stream"
        $s5 = "modt14y2i92r2ek-d65392h7h9.stream"
        $s6 = "modt1h87dtt2r4f-kt5a642in6.stream"
        $s7 = "modt1zt2rf2dsyn-s5ik857zh2.stream"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00538 {
    strings:
        $s0 = "receiver/install"
        $s1 = "http://app"
        $s2 = "receiver/uninstall"
        $s3 = "receiver/load_ad"
        $s4 = "receiver/load_offer"
        $s5 = "Lcom/waps/OffersWebView"
        $s6 = "UPermission.ACCESS_WIFI_STATE"
        $s7 = "Lcom/waps/a"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00539 {
    strings:
        $s0 = "lib/armeabi-v7a/libdn_ssl.so"
        $s1 = "secret-classes.dex"
        $s2 = "scrt.apk"
        $s3 = "res/layout/activity_no_bg.xml"
        $s4 = "/kD/faOo"
        $s5 = "Lcom/mik/proxy/guard/core/BuildConfig"
        $s6 = "com.mik.proxy.guard.core"
        $s7 = "Pc2/qke."
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00540 {
    strings:
        $s0 = "lib/armeabi/libcrypt_sign.so"
        $s1 = "assets/wyzf/res.bin"
        $s2 = "assets/yf.conf"
        $s3 = "assets/dERlZG"
        $s4 = "Adzwfge96PWi9KOpEQioyGF//NA"
        $s5 = "http://vpay.api.eerichina.com/api/payment"
        $s6 = "plugin.db"
        $s7 = "/LocalPool.xml"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00541 {
    strings:
        $s0 = "/92T0y8Eg3hwmkt655BvOmGHH/XfOxZOEdiIqIwPT0FPT1D"
        $s1 = "/CmOEnNP6lw5ie"
        $s2 = "/G7vW8JQCmu0vfGnYWwVddg0"
        $s3 = "/H7/T0Kh0JlIJPLHaDT6V5vN9l"
        $s4 = "/SgOYNXi9nXGzpgQ/GLoI/F8cBdd9blJWI3aUlcNik9a54bjfK//AWNnzhbv/YNafPouSxJ1C57QdwRE"
        $s5 = "/eV24SQp5AXoVMCIYgaKW2oM5YW3FsEUa0MM5YYYIiLT7a/qH80dJxpu20OlbUodDqTNtBrFNqQzGtpT"
        $s6 = "/lmAoH0kytnp8PooIXsJDodcGUW5F6s8TJtLPyQAqwOisq7O2U8Is7zJBWXK/EOquTsVWzctRc/"
        $s7 = "/wMWjgermQx"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00542 {
    strings:
        $s0 = "au.com.bankwest.mobile"
        $s1 = "ZzxKlxKyki.i"
        $s2 = "commandus.com"
        $s3 = "--.ixKiidAZ"
        $s4 = "/CalsRlpNBoM"
        $s5 = "/p9USHEeoIE3gQO135Rl6PxRJyo"
        $s6 = "2Lcom/note/donote/receivers/ServiceDestroyReceiver"
        $s7 = "3Lcom/note/donote/receivers/sms/PushServiceReciever"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00543 {
    strings:
        $s0 = "MTaIkHUA/Pve4wl9Z8BxBfceZDI"
        $s1 = "l93LV4jLCK5M/GJ2VVD471iAyLY"
        $s2 = "App.getAppParams"
        $s3 = "Lapp/apk/App"
        $s4 = "Str.file"
        $s5 = "Str.getAppParams"
        $s6 = "Str.parse"
        $s7 = "app.startApp"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00544 {
    strings:
        $s0 = "com.webcash.wooribank"
        $s1 = "com.kakaotalk.synservice.TIK"
        $s2 = "com.kakaotalk.synservice.URL"
        $s3 = "res/xml/an.xml"
        $s4 = "com.xxx.GS"
        $s5 = "MyTools.java"
        $s6 = "rspcode:"
        $s7 = "DeAdminReciver.java"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00545 {
    strings:
        $s0 = "LCute/AESUtils"
        $s1 = "LCute/Base64Utils"
        $s2 = "LCute/StreamGobbler"
        $s3 = "8NOdEEDmepiLlzN72Ygq/e7m"
        $s4 = "Lcom/cute/pin/BuildConfig"
        $s5 = "Lcom/cute/pin/MainActivity"
        $s6 = "Lcom/cute/pin/Pin"
        $s7 = "Lcom/cute/pin/R"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00546 {
    strings:
        $s0 = "lib/armeabi-v7a/libdn_ssl.so"
        $s1 = "secret-classes.dex"
        $s2 = "scrt.apk"
        $s3 = "res/layout/activity_no_bg.xml"
        $s4 = "/kD/faOo"
        $s5 = "Lcom/mik/proxy/guard/core/BuildConfig"
        $s6 = "com.mik.proxy.guard.core"
        $s7 = "Pc2/qke."
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00547 {
    strings:
        $s0 = "Z.-z-.xy-"
        $s1 = "n-LzK-y/"
        $s2 = "res/drawable/img_android.png"
        $s3 = "res/layout/instruction_dialog.xml"
        $s4 = "res/drawable/shape_gray_border_bottom.xml"
        $s5 = "res/layout/samsung_show_top_dialog.xml"
        $s6 = "res/layout/xiaomi_background_activity_dialog.xml"
        $s7 = "E/Wc6nn40l55dvBUNhqxhEW8W2s"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00548 {
    strings:
        $s0 = "assets/css/smoothness/images/ui-bg_flat_0_aaaaaa_40x100.png"
        $s1 = "assets/css/smoothness/images/ui-bg_flat_75_ffffff_40x100.png"
        $s2 = "assets/css/smoothness/images/ui-bg_glass_55_fbf9ee_1x400.png"
        $s3 = "assets/css/smoothness/images/ui-bg_glass_65_ffffff_1x400.png"
        $s4 = "assets/css/smoothness/images/ui-bg_glass_75_dadada_1x400.png"
        $s5 = "assets/css/smoothness/images/ui-bg_glass_75_e6e6e6_1x400.png"
        $s6 = "assets/css/smoothness/images/ui-bg_glass_95_fef1ec_1x400.png"
        $s7 = "assets/css/smoothness/images/ui-bg_highlight-soft_75_cccccc_1x10"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00549 {
    strings:
        $s0 = "mian.iyu"
        $s1 = "/AcvZ4Yycp/fuahUizra4r219Ug"
        $s2 = "UaAcDtpGmSrYRacrNRzul/Gk4Pw"
        $s3 = "a3V5KpEW/d14VzAGShsebenhDEI"
        $s4 = "assets/lib.so"
        $s5 = "lib/armeabi-v7a/libygsiyu.so"
        $s6 = "lib/x86/libygsiyu.so"
        $s7 = "tTYPFQeo26XIrs6xdPYO/zvBEiM"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00550 {
    strings:
        $s0 = "w-----/35"
        $s1 = "assets/layout.bal"
        $s2 = "LS_layout.java"
        $s3 = "7com.android.packageinstaller:id/permission_allow_button"
        $s4 = "res/xml-v22/windowchangedetectingservice.xml"
        $s5 = ".Lio/crossbar/autobahn/websocket/Utf8Validator"
        $s6 = "0Lio/crossbar/autobahn/websocket/WebSocketReader"
        $s7 = "0Lio/crossbar/autobahn/websocket/WebSocketWriter"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00551 {
    strings:
        $s0 = "l/cUiZLb7ya5qOYV/djf/zcvnb0"
        $s1 = "res/raw/conf.txt"
        $s2 = "res/raw/result"
        $s3 = "res/raw/resulturl"
        $s4 = "res/raw/rool.txt"
        $s5 = "res/drawable-hdpi/iconnews.png"
        $s6 = "res/drawable-mdpi/iconnews.png"
        $s7 = "http://91.213.175.176/api/"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00552 {
    strings:
        $s0 = "l/cUiZLb7ya5qOYV/djf/zcvnb0"
        $s1 = "res/raw/conf.txt"
        $s2 = "res/raw/result"
        $s3 = "res/raw/resulturl"
        $s4 = "res/raw/rool.txt"
        $s5 = "res/drawable-hdpi/iconnews.png"
        $s6 = "res/drawable-mdpi/iconnews.png"
        $s7 = "http://91.213.175.176/api/"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00553 {
    strings:
        $s0 = "res/raw/act_schemes.cfg"
        $s1 = "res/xml/texts.xml"
        $s2 = "res/layout/off.xml"
        $s3 = "c/nL07Gy7K3maRlEL1MxCVwf4FU"
        $s4 = "res/drawable/checkbox_label_background.9.png"
        $s5 = "18/aznZQx9KN6O9oFh9zkx3tu4w"
        $s6 = "res/drawable/0.temp"
        $s7 = "res/drawable/1.temp"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00554 {
    strings:
        $s0 = "res/raw/act_schemes.cfg"
        $s1 = "res/xml/texts.xml"
        $s2 = "res/layout/off.xml"
        $s3 = "c/nL07Gy7K3maRlEL1MxCVwf4FU"
        $s4 = "res/drawable/checkbox_label_background.9.png"
        $s5 = "18/aznZQx9KN6O9oFh9zkx3tu4w"
        $s6 = "res/drawable/0.temp"
        $s7 = "3XU8DJNQ9o/iAlhePmHQ2ONZPBE"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00555 {
    strings:
        $s0 = "receiver/install"
        $s1 = "http://app"
        $s2 = "receiver/uninstall"
        $s3 = "receiver/load_ad"
        $s4 = "receiver/load_offer"
        $s5 = "UPermission.ACCESS_WIFI_STATE"
        $s6 = "UnPackage.dat"
        $s7 = "complete.Click"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00556 {
    strings:
        $s0 = "res/xml/empty.xml"
        $s1 = "content://ABC"
        $s2 = "res/layout/ad_helper.xml"
        $s3 = "res/layout/shield.xml"
        $s4 = ".android.settings"
        $s5 = "res/drawable/pm_ok.xml"
        $s6 = "res/drawable/pmok_state.xml"
        $s7 = "res/layout/activity_pm.xml"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00557 {
    strings:
        $s0 = "res/xml/empty.xml"
        $s1 = "content://ABC"
        $s2 = "res/layout/ad_helper.xml"
        $s3 = "res/layout/shield.xml"
        $s4 = ".android.settings"
        $s5 = "9cSf/sOgyVhfTbZRYzwC6mNEaos"
        $s6 = "$Lcom/android/market/RestartReceiver"
        $s7 = "Lcom/android/market/AdminRequestor"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00558 {
    strings:
        $s0 = "res/xml/empty.xml"
        $s1 = "content://ABC"
        $s2 = "res/layout/ad_helper.xml"
        $s3 = "res/layout/shield.xml"
        $s4 = ".android.settings"
        $s5 = "9cSf/sOgyVhfTbZRYzwC6mNEaos"
        $s6 = "$Lcom/android/market/RestartReceiver"
        $s7 = "Lcom/android/market/AdminRequestor"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00559 {
    strings:
        $s0 = "res/drawable-hdpi-v4/icon.xml"
        $s1 = "res/layout/activity_g.xml"
        $s2 = "iD2em3JLFcEgtAIneR97M/bukxQxG68VKhvLQQKmin8"
        $s3 = "res/drawable-hdpi-v4/posti.png"
        $s4 = "ETpService.java"
        $s5 = "Lcom/tasks/BuildConfig"
        $s6 = "Lcom/tasks/R"
        $s7 = "Lcom/tasks/R$drawable"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00560 {
    strings:
        $s0 = "res/layout/policies.xml"
        $s1 = "res/drawable/cvc_visa.gif"
        $s2 = "jpYacD5/wUvtUwHbhwW1g"
        $s3 = "ussd.notify"
        $s4 = "LfAJ4zYaDObW0G/S5MALqkGG6KQ"
        $s5 = "WmHQhH7jINe/Xdu4NamQ2yJxVA4"
        $s6 = "TnVBJ3NE/lZRnBR/lkE/MiJ70B4"
        $s7 = "/controller.php"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00561 {
    strings:
        $s0 = "Lcom/android/a"
        $s1 = "$Lcom/android/slientinstall/R$string"
        $s2 = ".Lcom/android/slientinstall/InstallService$1$1"
        $s3 = "Lcom/android/slientinstall/BuildConfig"
        $s4 = "Lcom/android/slientinstall/InstallService"
        $s5 = "Lcom/android/slientinstall/InstallService$1"
        $s6 = "Lcom/android/slientinstall/MainActivity"
        $s7 = "Lcom/android/slientinstall/R"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00562 {
    strings:
        $s0 = "hp_getsmsblockstate.php"
        $s1 = "hp_state.php"
        $s2 = "PreodicService.java"
        $s3 = "RegDPMActivity.java"
        $s4 = "application/3gp"
        $s5 = "CallStateListner.java"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5)
}

rule VX_APK_CLUSTER_00563 {
    strings:
        $s0 = "Lcom/android/a"
        $s1 = "www.apkprotect.com"
        $s2 = "$Lcom/android/systemsetting/R$layout"
        $s3 = "$Lcom/android/systemsetting/R$string"
        $s4 = "/api/recivReport"
        $s5 = "/api/uploadSMS"
        $s6 = "1Lcom/android/systemsetting/MyDeviceAdminReceiver"
        $s7 = "Lcom/android/systemsetting/App"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00564 {
    strings:
        $s0 = "Mobclick.onError"
        $s1 = "http://www.umeng.com/app_logs"
        $s2 = "http://www.umeng.com/api/check_app_update"
        $s3 = "http://www.umeng.co/app_logs"
        $s4 = "http://www.umeng.co/api/check_app_update"
        $s5 = "http://www.umeng.co/check_config_update"
        $s6 = "http://www.umeng.com/check_config_update"
        $s7 = "tryToSendMessage."
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00565 {
    strings:
        $s0 = "com.qihoo.bugreport.CrashReport"
        $s1 = "com.qihoo.dexjiagu.TransitMgr"
        $s2 = "Lcom/qihoo/util/QHDialog$1"
        $s3 = "QHDialog.java"
        $s4 = "com.qihoo360.crypt.entryRunApplication"
        $s5 = "CrashReport."
        $s6 = "lib/armeabi/libjiagu_art.so"
        $s7 = "lib/x86/libjiagu_art.so"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00566 {
    strings:
        $s0 = "lib/armeabi/libcrypt_sign.so"
        $s1 = "assets/wyzf/res.bin"
        $s2 = "assets/yf.conf"
        $s3 = "assets/dERlZG"
        $s4 = "Adzwfge96PWi9KOpEQioyGF//NA"
        $s5 = "http://vpay.api.eerichina.com/api/payment"
        $s6 = "plugin.db"
        $s7 = "/LocalPool.xml"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00567 {
    strings:
        $s0 = "res/raw/act_schemes.cfg"
        $s1 = "res/xml/texts.xml"
        $s2 = "res/layout/off.xml"
        $s3 = "c/nL07Gy7K3maRlEL1MxCVwf4FU"
        $s4 = "res/drawable/checkbox_label_background.9.png"
        $s5 = "18/aznZQx9KN6O9oFh9zkx3tu4w"
        $s6 = "res/drawable/0.temp"
        $s7 = "res/drawable/1.temp"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00568 {
    strings:
        $s0 = "res/raw/act_schemes.cfg"
        $s1 = "res/xml/texts.xml"
        $s2 = "res/layout/off.xml"
        $s3 = "c/nL07Gy7K3maRlEL1MxCVwf4FU"
        $s4 = "res/drawable/checkbox_label_background.9.png"
        $s5 = "18/aznZQx9KN6O9oFh9zkx3tu4w"
        $s6 = "res/drawable/0.temp"
        $s7 = "res/drawable/1.temp"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00569 {
    strings:
        $s0 = "res/raw/act_schemes.cfg"
        $s1 = "res/xml/texts.xml"
        $s2 = "res/layout/off.xml"
        $s3 = "c/nL07Gy7K3maRlEL1MxCVwf4FU"
        $s4 = "res/drawable/checkbox_label_background.9.png"
        $s5 = "18/aznZQx9KN6O9oFh9zkx3tu4w"
        $s6 = "res/drawable/0.temp"
        $s7 = "3XU8DJNQ9o/iAlhePmHQ2ONZPBE"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00570 {
    strings:
        $s0 = "AdminReceiver:"
        $s1 = "Pdec7Z8DKejV4akRk31BM6yjN/g"
        $s2 = "assets/css/normalize.css"
        $s3 = "assets/img/justice.png"
        $s4 = "$Lcom/app/jingle/common/HttpSender$1"
        $s5 = "-Lcom/app/jingle/services/LockscreenService$1"
        $s6 = "-Lcom/app/jingle/services/LockscreenService$2"
        $s7 = ".Lcom/app/jingle/activities/LockscreenActivity"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00571 {
    strings:
        $s0 = "res/raw/act_schemes.cfg"
        $s1 = "res/xml/texts.xml"
        $s2 = "res/layout/off.xml"
        $s3 = "c/nL07Gy7K3maRlEL1MxCVwf4FU"
        $s4 = "res/drawable/checkbox_label_background.9.png"
        $s5 = "18/aznZQx9KN6O9oFh9zkx3tu4w"
        $s6 = "res/drawable/0.temp"
        $s7 = "3XU8DJNQ9o/iAlhePmHQ2ONZPBE"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00572 {
    strings:
        $s0 = "res/drawable/img_android.png"
        $s1 = "res/layout/instruction_dialog.xml"
        $s2 = "res/drawable/shape_gray_border_bottom.xml"
        $s3 = "res/layout/samsung_show_top_dialog.xml"
        $s4 = "res/layout/xiaomi_background_activity_dialog.xml"
        $s5 = "iOTls283qxBiqp1Kk5XhZl3nAXbWKnOn/DsVjWD9f9Q"
        $s6 = "ATvqoz3o52G2n71RMsMXWVtAsQXcjnkHuaAIjvwqS/g"
        $s7 = "assets/shaders/fragment.glsl"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00573 {
    strings:
        $s0 = "/rgBiUeGVuM9QauYk4hnNYsk7Tg"
        $s1 = "L--K0--/Np-"
        $s2 = "E/Wc6nn40l55dvBUNhqxhEW8W2s"
        $s3 = "PJvmGynTHefcXDN/JmV9lyG/AQQ"
        $s4 = "qEjhQOshQQK/S/fMQ"
        $s5 = "POLITICAS.html"
        $s6 = "calendar1.html"
        $s7 = "circle1.html"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00574 {
    strings:
        $s0 = "Lcom/adwo/adsdk/AdwoAdView"
        $s1 = "Lcom/adwo/adsdk/AdListener"
        $s2 = "http://10.0.0.172/a/p1"
        $s3 = "http://10.0.0.172/t/test"
        $s4 = "assets/adwo_left_arrow.png"
        $s5 = "assets/adwo_right_arrow.png"
        $s6 = "Lcom/adwo/adsdk/a"
        $s7 = "Lcom/adwo/adsdk/b"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00575 {
    strings:
        $s0 = "res/layout/finish.xml"
        $s1 = "getUserMessage:"
        $s2 = "hGV/eFuLm4sXF7Kgiv2LjTr84vc"
        $s3 = "res/drawable/opera.png"
        $s4 = "res/drawable/icon_url.png"
        $s5 = "res/drawable/progress.9.png"
        $s6 = "res/drawable/progress_active.9.png"
        $s7 = "mxclick.com"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00576 {
    strings:
        $s0 = "res/layout/finish.xml"
        $s1 = "getUserMessage:"
        $s2 = "hGV/eFuLm4sXF7Kgiv2LjTr84vc"
        $s3 = "res/drawable/opera.png"
        $s4 = "res/drawable/icon_url.png"
        $s5 = "res/drawable/progress.9.png"
        $s6 = "res/drawable/progress_active.9.png"
        $s7 = "mxclick.com"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00577 {
    strings:
        $s0 = "HYp34lJUX/TVVo4AefTwRTX"
        $s1 = "JYiLxailF2yPR/G921PrQTMo3Gs"
        $s2 = "Lcom/zu/zu/MainActivity"
        $s3 = "Lcom/zu/zu/a"
        $s4 = "Lcom/zu/zu/b"
        $s5 = "Lcom/zu/zu/c"
        $s6 = "Lcom/zu/zu/d"
        $s7 = "K3cx05p3vBsNexp2a/xGofEBjtY"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00578 {
    strings:
        $s0 = "content://ABC"
        $s1 = "7com.android.packageinstaller:id/permission_allow_button"
        $s2 = "/.s_klasse/"
        $s3 = "PhoneNo:"
        $s4 = "4com.android.mms.settings.CheckDefaultSmsAppsActivity"
        $s5 = "-com.android.mms.settings.EntrancePrefActivity"
        $s6 = "/6QowWu5Q5Ps01OzWoQRkiJ5"
        $s7 = "/lt2yUuBpbAVfPaWxbADHEX2NGg"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00579 {
    strings:
        $s0 = "lib/armeabi/libNativeCrash.so"
        $s1 = "Mvm29cxJmsLiCVJi0/8xAXw2UaQ"
        $s2 = "gnUW/wp0U05ZYh/Lc"
        $s3 = "KLZ--K.z-kZ"
        $s4 = "KLZ--K.z-kZC-"
        $s5 = "KMZ--K-z.lZ"
        $s6 = "KMZ--K-z.lZC-"
        $s7 = "YjKLK.y-kZi"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00580 {
    strings:
        $s0 = "res/drawable/operation_pic.jpg"
        $s1 = "res/drawable/operation_title.png"
        $s2 = "3XU8DJNQ9o/iAlhePmHQ2ONZPBE"
        $s3 = "res/drawable/yellow_shape.xml"
        $s4 = "res/anim/large_progressbar_animator.xml"
        $s5 = "MX98D/jdKxRIV3h2usqfl"
        $s6 = "res/layout/wx_scan.xml"
        $s7 = "res/drawable/dia_money_selecor.xml"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00581 {
    strings:
        $s0 = "h9PDMBXx/7AUCTgqBicvs9LMF0/zhcrOR2nK9TY"
        $s1 = "v6BJJrqk2/BlVN7Fb43159u/FLhYJtopJ9zK0rBuxDc"
        $s2 = "8uChfRgL8wSZVSNHrw2/HWd1JoPBtJ8531kWXnLXXUI"
        $s3 = "ZaxJ8tTG5VeCMps62uSOld/A7Ch9zElYYTq4zTjwdeM"
        $s4 = "P1/7e4hQOXnPaxRsNXt4cRh3NkeoaggezLU"
        $s5 = "aUdNblAh16J/88iRYtQKnSMsl"
        $s6 = "g8ieWfiBcOP3/g"
        $s7 = "N2RrTwUehxNWm4m0xVlnaHH/9TSpvLBKuL/MID/UY9U"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00582 {
    strings:
        $s0 = "R0X/L6PAiNpb2RxEFokh6/StBz0"
        $s1 = "boRT6JyE8/gO"
        $s2 = "doW4mzL4yeq/PwUK803c3HJtD4"
        $s3 = "4JJOnS9YC5LBcSbRM/qgcpmUh8s"
        $s4 = "/lE9AthIVgqdnJsrhPxY4N7CCpk"
        $s5 = "5/a/8CNDMnkGb63/ssWDuBoEELU"
        $s6 = ".TRa.TSc.TTb.qT"
        $s7 = "0LqFakzi4p/uv27o6nEJTGgwwUs"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00583 {
    strings:
        $s0 = "AZS/kpEhpE8Jl37U1SJ9eW7KA6E"
        $s1 = "NNqltaQgFzooaAOKcxToQQY/4rU"
        $s2 = "res/drawable/visa_curved.png"
        $s3 = "res/drawable/aec.png"
        $s4 = "res/drawable/wc.png"
        $s5 = "res/layout/activity_activity_card.xml"
        $s6 = "res/drawable/wcpl.png"
        $s7 = "res/layout/activity_activity_first.xml"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00584 {
    strings:
        $s0 = "AZS/kpEhpE8Jl37U1SJ9eW7KA6E"
        $s1 = "NNqltaQgFzooaAOKcxToQQY/4rU"
        $s2 = "res/drawable/visa_curved.png"
        $s3 = "res/drawable/aec.png"
        $s4 = "res/drawable/wc.png"
        $s5 = "res/layout/activity_activity_card.xml"
        $s6 = "res/layout/activity_activity_first.xml"
        $s7 = "res/layout/activity_activity_mms.xml"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00585 {
    strings:
        $s0 = "res/drawable-hdpi/nh.png"
        $s1 = "res/drawable-hdpi/sh.png"
        $s2 = "3IOmkvQWrLqujnhgiQF/suWDebQ"
        $s3 = "res/drawable-hdpi/kb.png"
        $s4 = "res/drawable-hdpi/nf_bg_edit_text.9.png"
        $s5 = "res/drawable-hdpi/indeterminate_spinner.png"
        $s6 = "res/drawable-hdpi/selector_edittext_bg.xml"
        $s7 = "res/anim/wait.xml"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00586 {
    strings:
        $s0 = "assets/css/smoothness/images/ui-bg_flat_0_aaaaaa_40x100.png"
        $s1 = "assets/css/smoothness/images/ui-bg_flat_75_ffffff_40x100.png"
        $s2 = "assets/css/smoothness/images/ui-bg_glass_55_fbf9ee_1x400.png"
        $s3 = "assets/css/smoothness/images/ui-bg_glass_65_ffffff_1x400.png"
        $s4 = "assets/css/smoothness/images/ui-bg_glass_75_dadada_1x400.png"
        $s5 = "assets/css/smoothness/images/ui-bg_glass_75_e6e6e6_1x400.png"
        $s6 = "assets/css/smoothness/images/ui-bg_glass_95_fef1ec_1x400.png"
        $s7 = "assets/css/smoothness/images/ui-bg_highlight-soft_75_cccccc_1x10"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00587 {
    strings:
        $s0 = "hGV/eFuLm4sXF7Kgiv2LjTr84vc"
        $s1 = "res/drawable-hdpi/opera.jpg"
        $s2 = "res/drawable-hdpi/textbg.xml"
        $s3 = "res/drawable-hdpi/titlebg.xml"
        $s4 = "Wce1MjOVrsjGKh03cKT/M"
        $s5 = "res/drawable-hdpi/ropera.jpg"
        $s6 = "assets/config.res"
        $s7 = "code.reg"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00588 {
    strings:
        $s0 = "xoYHeP/23ezgc3yGF9063z"
        $s1 = "res/layout/offert.xml"
        $s2 = "1.6.0_03-p4"
        $s3 = "res/raw/countries.cfg"
        $s4 = "res/layout/activation_done.xml"
        $s5 = "res/raw/sms.cfg"
        $s6 = "FilesParser.java"
        $s7 = "Lcom/depositmobi/FilesParser"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00589 {
    strings:
        $s0 = "res/mipmap-xxhdpi-v4/ic_launcher_empty.png"
        $s1 = "res/mipmap-xxhdpi-v4/ic_launcher_video.png"
        $s2 = "Md3MSA/sg/op1reCKgNZCskn84E"
        $s3 = "res/mipmap-xxhdpi-v4/ic_launcher_antivirus.png"
        $s4 = "res/mipmap-xxhdpi-v4/ic_launcher_flash.png"
        $s5 = "res/mipmap-xxhdpi-v4/ic_launcher_music.png"
        $s6 = "res/mipmap-xxhdpi-v4/ic_launcher_robot.png"
        $s7 = "res/mipmap-xxhdpi-v4/ic_launcher_security.png"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00590 {
    strings:
        $s0 = "res/mipmap-xxhdpi-v4/ic_launcher_empty.png"
        $s1 = "res/mipmap-xxhdpi-v4/ic_launcher_video.png"
        $s2 = "Md3MSA/sg/op1reCKgNZCskn84E"
        $s3 = "res/mipmap-xxhdpi-v4/ic_launcher_antivirus.png"
        $s4 = "res/mipmap-xxhdpi-v4/ic_launcher_flash.png"
        $s5 = "res/mipmap-xxhdpi-v4/ic_launcher_music.png"
        $s6 = "res/mipmap-xxhdpi-v4/ic_launcher_robot.png"
        $s7 = "res/mipmap-xxhdpi-v4/ic_launcher_security.png"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00591 {
    strings:
        $s0 = "res/mipmap-xxhdpi-v4/ic_launcher_empty.png"
        $s1 = "res/mipmap-xxhdpi-v4/ic_launcher_video.png"
        $s2 = "Md3MSA/sg/op1reCKgNZCskn84E"
        $s3 = "res/mipmap-xxhdpi-v4/ic_launcher_antivirus.png"
        $s4 = "res/mipmap-xxhdpi-v4/ic_launcher_flash.png"
        $s5 = "res/mipmap-xxhdpi-v4/ic_launcher_music.png"
        $s6 = "res/mipmap-xxhdpi-v4/ic_launcher_robot.png"
        $s7 = "res/mipmap-xxhdpi-v4/ic_launcher_security.png"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00592 {
    strings:
        $s0 = "ArrayVariant.java"
        $s1 = "BooleanReferenceParameter.java"
        $s2 = "ByteReferenceParameter.java"
        $s3 = "ByteVariant.java"
        $s4 = "ConvHelpers.java"
        $s5 = "DateVariant.java"
        $s6 = "DoubleReferenceParameter.java"
        $s7 = "ExprHelpers.java"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00593 {
    strings:
        $s0 = "$Lcom/example/mobilpakket/R$drawable"
        $s1 = "Lcom/example/mobilpakket/BuildConfig"
        $s2 = "Lcom/example/mobilpakket/MainActivity"
        $s3 = "Lcom/example/mobilpakket/MyAppWebViewClient"
        $s4 = "Lcom/example/mobilpakket/R"
        $s5 = "Lcom/example/mobilpakket/R$attr"
        $s6 = "Lcom/example/mobilpakket/R$dimen"
        $s7 = "Lcom/example/mobilpakket/R$id"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00594 {
    strings:
        $s0 = "$Lcom/example/mobilpakket/R$drawable"
        $s1 = "Lcom/example/mobilpakket/BuildConfig"
        $s2 = "Lcom/example/mobilpakket/MainActivity"
        $s3 = "Lcom/example/mobilpakket/MyAppWebViewClient"
        $s4 = "Lcom/example/mobilpakket/R"
        $s5 = "Lcom/example/mobilpakket/R$attr"
        $s6 = "Lcom/example/mobilpakket/R$dimen"
        $s7 = "Lcom/example/mobilpakket/R$id"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00595 {
    strings:
        $s0 = "res/layout/logo_layout.xml"
        $s1 = "$Lcom/exoclick/app/tubes/BuildConfig"
        $s2 = "$Lcom/exoclick/app/tubes/R$styleable"
        $s3 = "$Lcom/exoclick/app/tubes/model/Video"
        $s4 = "--com.exoclick.app.tubes.customviews.CardLayout"
        $s5 = "--com.exoclick.app.tubes.downloads.DownloadItem"
        $s6 = "-Lcom/exoclick/app/tubes/DisclaimerActivity$1"
        $s7 = "-Lcom/exoclick/app/tubes/DisclaimerActivity$2"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00596 {
    strings:
        $s0 = ".Lcom/sirseni/simpleandroidwebviewexample/R$id"
        $s1 = "/CoIXRo5o95LwmcBAYLGXQ5bHtk"
        $s2 = "0Lcom/sirseni/simpleandroidwebviewexample/R$anim"
        $s3 = "0Lcom/sirseni/simpleandroidwebviewexample/R$attr"
        $s4 = "0Lcom/sirseni/simpleandroidwebviewexample/R$bool"
        $s5 = "0Lcom/sirseni/simpleandroidwebviewexample/R$menu"
        $s6 = "1Lcom/sirseni/simpleandroidwebviewexample/R$color"
        $s7 = "1Lcom/sirseni/simpleandroidwebviewexample/R$dimen"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00597 {
    strings:
        $s0 = ".Lcom/sirseni/simpleandroidwebviewexample/R$id"
        $s1 = "/CoIXRo5o95LwmcBAYLGXQ5bHtk"
        $s2 = "0Lcom/sirseni/simpleandroidwebviewexample/R$anim"
        $s3 = "0Lcom/sirseni/simpleandroidwebviewexample/R$attr"
        $s4 = "0Lcom/sirseni/simpleandroidwebviewexample/R$bool"
        $s5 = "0Lcom/sirseni/simpleandroidwebviewexample/R$menu"
        $s6 = "1Lcom/sirseni/simpleandroidwebviewexample/R$color"
        $s7 = "1Lcom/sirseni/simpleandroidwebviewexample/R$dimen"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00598 {
    strings:
        $s0 = ".Lcom/sirseni/simpleandroidwebviewexample/R$id"
        $s1 = "/CoIXRo5o95LwmcBAYLGXQ5bHtk"
        $s2 = "0Lcom/sirseni/simpleandroidwebviewexample/R$anim"
        $s3 = "0Lcom/sirseni/simpleandroidwebviewexample/R$attr"
        $s4 = "0Lcom/sirseni/simpleandroidwebviewexample/R$bool"
        $s5 = "0Lcom/sirseni/simpleandroidwebviewexample/R$menu"
        $s6 = "1Lcom/sirseni/simpleandroidwebviewexample/R$color"
        $s7 = "1Lcom/sirseni/simpleandroidwebviewexample/R$dimen"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00599 {
    strings:
        $s0 = ".Lcom/sirseni/simpleandroidwebviewexample/R$id"
        $s1 = "/CoIXRo5o95LwmcBAYLGXQ5bHtk"
        $s2 = "0Lcom/sirseni/simpleandroidwebviewexample/R$anim"
        $s3 = "0Lcom/sirseni/simpleandroidwebviewexample/R$attr"
        $s4 = "0Lcom/sirseni/simpleandroidwebviewexample/R$bool"
        $s5 = "0Lcom/sirseni/simpleandroidwebviewexample/R$menu"
        $s6 = "1Lcom/sirseni/simpleandroidwebviewexample/R$color"
        $s7 = "1Lcom/sirseni/simpleandroidwebviewexample/R$dimen"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00600 {
    strings:
        $s0 = ".Lcom/sirseni/simpleandroidwebviewexample/R$id"
        $s1 = "/CoIXRo5o95LwmcBAYLGXQ5bHtk"
        $s2 = "0Lcom/sirseni/simpleandroidwebviewexample/R$anim"
        $s3 = "0Lcom/sirseni/simpleandroidwebviewexample/R$attr"
        $s4 = "0Lcom/sirseni/simpleandroidwebviewexample/R$bool"
        $s5 = "0Lcom/sirseni/simpleandroidwebviewexample/R$menu"
        $s6 = "1Lcom/sirseni/simpleandroidwebviewexample/R$color"
        $s7 = "1Lcom/sirseni/simpleandroidwebviewexample/R$dimen"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00601 {
    strings:
        $s0 = "Landrold/content/Context"
        $s1 = "Landrold/content/pm/PackageManager"
        $s2 = "/c34VlJCR0M/LPJ4LxjXAL8PuDrJgz37t2bPXv2GHuwcXMK5NmzZ7N48WL0fE4iPXOXL1"
        $s3 = "/fvZ9CgQaj7XgLplUgO5v9NIzTpQWdcv5NU6a7WgZs2bWLAgPh4wJkzZxrAVa/IIkkd7NRk7eab9X2tl"
        $s4 = "/hqRLYdKlqsdQJGupu0fBPLKlStzHXjP4XipvYOOzSpdWCi5AlhCpHofnjp1Kjr/lMehEgBNLbe5Jm1Y"
        $s5 = "/wTHuy1k9GcXXPWPsfO/UAsLjVYQGdAJAD4/q7wc3BU7WkctpyBmsSnUpzN9ULwI0y6esYcmT0gWgdqH"
        $s6 = "1ItRgmiVtSwqEkbSt1LWaQasIILAtqqUAmY/3Mevr438313Zu7c737jPQl5Id"
        $s7 = "2cMMNlZ36AwcONPB69uzZJCbE4Djgkn0uqzzWXC8YrSez/G6Un23Bwt13382qVXKoq5NAnjBhQoOV2aS"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00602 {
    strings:
        $s0 = "com.webcash.wooribank"
        $s1 = "res/drawable-hdpi/nh.png"
        $s2 = "res/drawable-hdpi/sh.png"
        $s3 = "/conf.ini"
        $s4 = "App.Alert"
        $s5 = "alert.main"
        $s6 = "app.auto.install"
        $s7 = "app.dwonload.complate"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00603 {
    strings:
        $s0 = "res/layout/finish.xml"
        $s1 = "res/drawable/button_green.png"
        $s2 = "rEppsRv/JtutQIWU6VLVixb96JA"
        $s3 = "res/drawable/button_green_p.png"
        $s4 = "res/drawable/progress_bar_fill_bg.png"
        $s5 = "res/drawable/red_progress_bar_fill.9.png"
        $s6 = "res/drawable/terms_b.png"
        $s7 = "res/drawable/terms_button.xml"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00604 {
    strings:
        $s0 = "res/xml/empty.xml"
        $s1 = "content://ABC"
        $s2 = "res/layout/ad_helper.xml"
        $s3 = "res/layout/shield.xml"
        $s4 = ".android.settings"
        $s5 = "res/drawable/pm_ok.xml"
        $s6 = "res/drawable/pmok_state.xml"
        $s7 = "res/layout/activity_pm.xml"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00605 {
    strings:
        $s0 = "res/xml/empty.xml"
        $s1 = "content://ABC"
        $s2 = "res/layout/ad_helper.xml"
        $s3 = "res/layout/shield.xml"
        $s4 = ".android.settings"
        $s5 = "res/drawable/pm_ok.xml"
        $s6 = "res/drawable/pmok_state.xml"
        $s7 = "res/layout/activity_pm.xml"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00606 {
    strings:
        $s0 = "PlJSQqWxy9Pig116SM/fEvHLyIQ"
        $s1 = "//0N3FbUo5cvT8"
        $s2 = ".bg.color"
        $s3 = ".border.color"
        $s4 = "res/drawable/zt__back.png"
        $s5 = "res/drawable/zt__down.png"
        $s6 = "res/drawable/zt__down_w.png"
        $s7 = "res/drawable/zt__icon_lack.png"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00607 {
    strings:
        $s0 = "PlJSQqWxy9Pig116SM/fEvHLyIQ"
        $s1 = "//0N3FbUo5cvT8"
        $s2 = "/Xd8TjhwyNbYb2Z/"
        $s3 = "http://ehttp-host-"
        $s4 = "LwcvoEmrFpXVcD/7dJS3ijfU6Fo"
        $s5 = "6/W5YFA9Dv7aBsElhk"
        $s6 = "AaNfidSePp/TeMxfv4Ssd"
        $s7 = "KjQ8YcSDNo0FojMfa/QOJ"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00608 {
    strings:
        $s0 = "PlJSQqWxy9Pig116SM/fEvHLyIQ"
        $s1 = "//0N3FbUo5cvT8"
        $s2 = "/Xd8TjhwyNbYb2Z/"
        $s3 = "http://ehttp-host-"
        $s4 = "LwcvoEmrFpXVcD/7dJS3ijfU6Fo"
        $s5 = "6/W5YFA9Dv7aBsElhk"
        $s6 = "AaNfidSePp/TeMxfv4Ssd"
        $s7 = "KjQ8YcSDNo0FojMfa/QOJ"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00609 {
    strings:
        $s0 = "/.cache/classes.jar"
        $s1 = "/.cache/classes.dex"
        $s2 = "/.sec_version"
        $s3 = "ACall.java"
        $s4 = "assets/libsecexe.x86.so"
        $s5 = "libsecexe.x86.so"
        $s6 = "assets/bangcle_classes.jar"
        $s7 = "assets/libsecmain.x86.so"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00610 {
    strings:
        $s0 = "desable."
        $s1 = "libMtaNativeCrash.so"
        $s2 = "Lcom/tencent/stat/StatServiceImpl"
        $s3 = "Lcom/tencent/stat/StatSpecifyReportedInfo"
        $s4 = "Lcom/tencent/stat/StatAccount"
        $s5 = "Lcom/tencent/stat/StatCustomLogger"
        $s6 = "Lcom/tencent/stat/StatDataTransfer"
        $s7 = "infoLists:"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00611 {
    strings:
        $s0 = "res/raw/act_schemes.cfg"
        $s1 = "res/xml/texts.xml"
        $s2 = "res/layout/off.xml"
        $s3 = "ShowLink.java"
        $s4 = "res/layout/grant_access.xml"
        $s5 = "ProcedureStarter.java"
        $s6 = "ProcedureMaker.java"
        $s7 = "AirModeHandler.java"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00612 {
    strings:
        $s0 = "com.webcash.wooribank"
        $s1 = "res/drawable-hdpi/nh.png"
        $s2 = "res/drawable-hdpi/sh.png"
        $s3 = "res/drawable-hdpi/kb.png"
        $s4 = "Q0j/LlUSDZKDI8"
        $s5 = "res/drawable-hdpi/hana.png"
        $s6 = "res/layout/woori_main_activity.xml"
        $s7 = "res/drawable-hdpi/intro_bg.png"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00613 {
    strings:
        $s0 = "res/raw/act_schemes.cfg"
        $s1 = "res/xml/texts.xml"
        $s2 = "res/layout/off.xml"
        $s3 = "res/drawable/0.temp"
        $s4 = "res/drawable/1.temp"
        $s5 = "res/layout/grant_access.xml"
        $s6 = "ShowURL.java"
        $s7 = "/RZSRcF7BJLFCo/1EXU"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00614 {
    strings:
        $s0 = "res/raw/act_schemes.cfg"
        $s1 = "res/xml/texts.xml"
        $s2 = "res/layout/off.xml"
        $s3 = "c/nL07Gy7K3maRlEL1MxCVwf4FU"
        $s4 = "res/drawable/checkbox_label_background.9.png"
        $s5 = "18/aznZQx9KN6O9oFh9zkx3tu4w"
        $s6 = "res/drawable/0.temp"
        $s7 = "ShowLink.java"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00615 {
    strings:
        $s0 = "res/raw/act_schemes.cfg"
        $s1 = "res/xml/texts.xml"
        $s2 = "res/layout/off.xml"
        $s3 = "c/nL07Gy7K3maRlEL1MxCVwf4FU"
        $s4 = "res/drawable/checkbox_label_background.9.png"
        $s5 = "18/aznZQx9KN6O9oFh9zkx3tu4w"
        $s6 = "res/drawable/0.temp"
        $s7 = "ShowLink.java"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00616 {
    strings:
        $s0 = "com.qihoo.bugreport.CrashReport"
        $s1 = "com.qihoo.dexjiagu.TransitMgr"
        $s2 = "Lcom/qihoo/util/QHDialog$1"
        $s3 = "QHDialog.java"
        $s4 = "com.qihoo360.crypt.entryRunApplication"
        $s5 = "Lcom/qihoo/util/QHDialog$1$1"
        $s6 = "lib/armeabi/libabcdefgh.so"
        $s7 = "lib/armeabi-v7a/libabcdefgh.so"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00617 {
    strings:
        $s0 = "com.webcash.wooribank"
        $s1 = "3IOmkvQWrLqujnhgiQF/suWDebQ"
        $s2 = "com.areo.bs"
        $s3 = "res/drawable-hdpi/bgsp.jpg"
        $s4 = "com.kakaotalk.synservice.TIK"
        $s5 = "com.kakaotalk.synservice.URL"
        $s6 = "ovpkQ/PwphmDjhKMWx6ydH7ln5g"
        $s7 = "res/xml/an.xml"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00618 {
    strings:
        $s0 = "assets/wyzf/res.bin"
        $s1 = "assets/dERlZG"
        $s2 = "Adzwfge96PWi9KOpEQioyGF//NA"
        $s3 = "com.qihoo.bugreport.CrashReport"
        $s4 = "com.qihoo.dexjiagu.TransitMgr"
        $s5 = "Lcom/qihoo/util/QHDialog$1"
        $s6 = "QHDialog.java"
        $s7 = "com.qihoo360.crypt.entryRunApplication"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00619 {
    strings:
        $s0 = "assets/wyzf/res.bin"
        $s1 = "assets/dERlZG"
        $s2 = "Adzwfge96PWi9KOpEQioyGF//NA"
        $s3 = "com.qihoo.bugreport.CrashReport"
        $s4 = "com.qihoo.dexjiagu.TransitMgr"
        $s5 = "Lcom/qihoo/util/QHDialog$1"
        $s6 = "QHDialog.java"
        $s7 = "com.qihoo360.crypt.entryRunApplication"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00620 {
    strings:
        $s0 = "myAOnVezFsTkzSr/E8uO/KdEA"
        $s1 = "res/anim/large_progressbar_animator.xml"
        $s2 = "jJuOui8LVgvIX/td4WnbqpYysO8"
        $s3 = "res/drawable/progressdialog_bg.xml"
        $s4 = "res/layout/hor_line_gray.xml"
        $s5 = "layout/hor_line_gray"
        $s6 = "res/layout/main_left_layout.xml"
        $s7 = "res/layout/main_right_layout.xml"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00621 {
    strings:
        $s0 = "res/raw/act_schemes.cfg"
        $s1 = "res/xml/texts.xml"
        $s2 = "res/layout/off.xml"
        $s3 = "c/nL07Gy7K3maRlEL1MxCVwf4FU"
        $s4 = "res/drawable/checkbox_label_background.9.png"
        $s5 = "18/aznZQx9KN6O9oFh9zkx3tu4w"
        $s6 = "res/drawable/0.temp"
        $s7 = "res/drawable/1.temp"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00622 {
    strings:
        $s0 = "res/raw/act_schemes.cfg"
        $s1 = "res/xml/texts.xml"
        $s2 = "res/layout/off.xml"
        $s3 = "c/nL07Gy7K3maRlEL1MxCVwf4FU"
        $s4 = "res/drawable/checkbox_label_background.9.png"
        $s5 = "18/aznZQx9KN6O9oFh9zkx3tu4w"
        $s6 = "res/drawable/0.temp"
        $s7 = "res/drawable/1.temp"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00623 {
    strings:
        $s0 = "myAOnVezFsTkzSr/E8uO/KdEA"
        $s1 = "res/anim/large_progressbar_animator.xml"
        $s2 = "res/drawable/dia_money_selecor.xml"
        $s3 = "res/drawable/pay_dialog_close_selector.xml"
        $s4 = "res/drawable/progressdialog_bg.xml"
        $s5 = "res/layout/hor_line_gray.xml"
        $s6 = "layout/hor_line_gray"
        $s7 = "res/layout/main_left_layout.xml"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00624 {
    strings:
        $s0 = "res/raw/google.apk"
        $s1 = "res/drawable-hdpi/notification_bg_low_normal.png"
        $s2 = "res/drawable-hdpi/notification_bg_low_pressed.png"
        $s3 = "res/drawable-hdpi/notification_bg_normal.png"
        $s4 = "res/drawable-hdpi/notification_bg_normal_pressed.png"
        $s5 = "res/drawable-mdpi/notification_bg_low_normal.png"
        $s6 = "res/drawable-mdpi/notification_bg_low_pressed.png"
        $s7 = "res/drawable-mdpi/notification_bg_normal.png"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00625 {
    strings:
        $s0 = "7DExtuS6O6jXtu4jAc/bMQSB6b2k"
        $s1 = "ROCTbAUl/d/KaG"
        $s2 = "xqYRGRhw/nUiYWj"
        $s3 = "/3RlC656bCGoW46k3MsH8hxi7BmKcQaGUrWQbB97eJ0"
        $s4 = "1CYPBLsHZG3Yjj83dl6hhRbv/z6mVGErsrXZRp6uLjo"
        $s5 = "1GnQa3YhH/yPrr7g"
        $s6 = "2/hZPHKCylQezghFrC37xG8LzPwid8qALHHT4"
        $s7 = "2TjCc74bpjb7/l/qifrIX44/gm3gFVltSkLU9ikLHVY"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00626 {
    strings:
        $s0 = "assets/css/smoothness/images/ui-bg_flat_0_aaaaaa_40x100.png"
        $s1 = "assets/css/smoothness/images/ui-bg_flat_75_ffffff_40x100.png"
        $s2 = "assets/css/smoothness/images/ui-bg_glass_55_fbf9ee_1x400.png"
        $s3 = "assets/css/smoothness/images/ui-bg_glass_65_ffffff_1x400.png"
        $s4 = "assets/css/smoothness/images/ui-bg_glass_75_dadada_1x400.png"
        $s5 = "assets/css/smoothness/images/ui-bg_glass_75_e6e6e6_1x400.png"
        $s6 = "assets/css/smoothness/images/ui-bg_glass_95_fef1ec_1x400.png"
        $s7 = "assets/css/smoothness/images/ui-bg_highlight-soft_75_cccccc_1x10"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00627 {
    strings:
        $s0 = "assets/css/smoothness/images/ui-bg_flat_0_aaaaaa_40x100.png"
        $s1 = "assets/css/smoothness/images/ui-bg_flat_75_ffffff_40x100.png"
        $s2 = "assets/css/smoothness/images/ui-bg_glass_55_fbf9ee_1x400.png"
        $s3 = "assets/css/smoothness/images/ui-bg_glass_65_ffffff_1x400.png"
        $s4 = "assets/css/smoothness/images/ui-bg_glass_75_dadada_1x400.png"
        $s5 = "assets/css/smoothness/images/ui-bg_glass_75_e6e6e6_1x400.png"
        $s6 = "assets/css/smoothness/images/ui-bg_glass_95_fef1ec_1x400.png"
        $s7 = "assets/css/smoothness/images/ui-bg_highlight-soft_75_cccccc_1x10"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00628 {
    strings:
        $s0 = "assets/css/smoothness/images/ui-bg_flat_0_aaaaaa_40x100.png"
        $s1 = "assets/css/smoothness/images/ui-bg_flat_75_ffffff_40x100.png"
        $s2 = "assets/css/smoothness/images/ui-bg_glass_55_fbf9ee_1x400.png"
        $s3 = "assets/css/smoothness/images/ui-bg_glass_65_ffffff_1x400.png"
        $s4 = "assets/css/smoothness/images/ui-bg_glass_75_dadada_1x400.png"
        $s5 = "assets/css/smoothness/images/ui-bg_glass_75_e6e6e6_1x400.png"
        $s6 = "assets/css/smoothness/images/ui-bg_glass_95_fef1ec_1x400.png"
        $s7 = "assets/css/smoothness/images/ui-bg_highlight-soft_75_cccccc_1x10"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00629 {
    strings:
        $s0 = "assets/css/smoothness/images/ui-bg_flat_0_aaaaaa_40x100.png"
        $s1 = "assets/css/smoothness/images/ui-bg_flat_75_ffffff_40x100.png"
        $s2 = "assets/css/smoothness/images/ui-bg_glass_55_fbf9ee_1x400.png"
        $s3 = "assets/css/smoothness/images/ui-bg_glass_65_ffffff_1x400.png"
        $s4 = "assets/css/smoothness/images/ui-bg_glass_75_dadada_1x400.png"
        $s5 = "assets/css/smoothness/images/ui-bg_glass_75_e6e6e6_1x400.png"
        $s6 = "assets/css/smoothness/images/ui-bg_glass_95_fef1ec_1x400.png"
        $s7 = "assets/css/smoothness/images/ui-bg_highlight-soft_75_cccccc_1x10"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00630 {
    strings:
        $s0 = "assets/css/smoothness/images/ui-bg_flat_0_aaaaaa_40x100.png"
        $s1 = "assets/css/smoothness/images/ui-bg_flat_75_ffffff_40x100.png"
        $s2 = "assets/css/smoothness/images/ui-bg_glass_55_fbf9ee_1x400.png"
        $s3 = "assets/css/smoothness/images/ui-bg_glass_65_ffffff_1x400.png"
        $s4 = "assets/css/smoothness/images/ui-bg_glass_75_dadada_1x400.png"
        $s5 = "assets/css/smoothness/images/ui-bg_glass_75_e6e6e6_1x400.png"
        $s6 = "assets/css/smoothness/images/ui-bg_glass_95_fef1ec_1x400.png"
        $s7 = "assets/css/smoothness/images/ui-bg_highlight-soft_75_cccccc_1x10"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00631 {
    strings:
        $s0 = "lib/armeabi/libcrypt_sign.so"
        $s1 = "assets/wyzf/res.bin"
        $s2 = "13/Ayo17/DPtKNh46JVIv6osRPo"
        $s3 = "Qmxju5/Ap5mgu1cFHvmJFycrWMw"
        $s4 = "com/unicom/wounipaysms/dialog/images/cancel.png"
        $s5 = "com/unicom/wounipaysms/dialog/images/cancel_on.png"
        $s6 = "com/unicom/wounipaysms/dialog/images/confirm_bt.9.png"
        $s7 = "com/unicom/wounipaysms/dialog/images/confirm_bt_on.9.png"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00632 {
    strings:
        $s0 = "res/raw/google.apk"
        $s1 = "/exit/chat/"
        $s2 = "0KL/sCsQruNjHoKVtx1XAfmKQCE"
        $s3 = "RBUjYaUJHzZ8fybMFumB5C4No/U"
        $s4 = "bCIgjSvjlEikEH/vA"
        $s5 = "g/5XwPznaB"
        $s6 = "gryuPHtHUsr/K7oP2xpXknw/Gqg"
        $s7 = "rAt/eNCwraG8fq2Ypt13tb7wueg"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00633 {
    strings:
        $s0 = "hGV/eFuLm4sXF7Kgiv2LjTr84vc"
        $s1 = "res/drawable-hdpi/opera.jpg"
        $s2 = "res/drawable-hdpi/textbg.xml"
        $s3 = "res/drawable-hdpi/titlebg.xml"
        $s4 = "Wce1MjOVrsjGKh03cKT/M"
        $s5 = "res/drawable-hdpi/ropera.jpg"
        $s6 = "assets/config.res"
        $s7 = "gXb2U1ShPWEk9O0NoB/thdHOEzk"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00634 {
    strings:
        $s0 = "com.webcash.wooribank"
        $s1 = "res/drawable-hdpi/nh.png"
        $s2 = "res/drawable-hdpi/sh.png"
        $s3 = "/conf.ini"
        $s4 = "App.Alert"
        $s5 = "alert.main"
        $s6 = "app.auto.install"
        $s7 = "app.dwonload.complate"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00635 {
    strings:
        $s0 = "com.webcash.wooribank"
        $s1 = "res/drawable-hdpi/nh.png"
        $s2 = "res/drawable-hdpi/sh.png"
        $s3 = "/conf.ini"
        $s4 = "App.Alert"
        $s5 = "alert.main"
        $s6 = "app.auto.install"
        $s7 = "app.dwonload.complate"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00636 {
    strings:
        $s0 = "com.webcash.wooribank"
        $s1 = "Q0j/LlUSDZKDI8"
        $s2 = "httpclient.execute"
        $s3 = "httppost.setEntity"
        $s4 = "/sdcard/update.apk"
        $s5 = "res/drawable-hdpi/number_bg.png"
        $s6 = "/F1q6CL1qwzRB0x6bvy8"
        $s7 = "/WorkActivity"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00637 {
    strings:
        $s0 = "io.mobby.sdk.APP_ID"
        $s1 = "google.id"
        $s2 = "Cryoloader..."
        $s3 = "Cryopiggy..."
        $s4 = "io.mobby.sdk.Cryopiggy"
        $s5 = "io.mobby.sdk.SyncService"
        $s6 = "revolumbus.space"
        $s7 = "0.1.13-sa-ap1"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00638 {
    strings:
        $s0 = "res/drawable-hdpi-v4/start.jpg"
        $s1 = "res/layout/formcustomspinner.xml"
        $s2 = "mQ8rPJnuGfo/pkLHxQI4pivTOjY"
        $s3 = "res/drawable-hdpi-v4/latest_video_play.png"
        $s4 = "res/layout/video_seekbar.xml"
        $s5 = "res/drawable-hdpi-v4/ic_progress_normal_white.png"
        $s6 = "res/drawable-hdpi-v4/slip_line_background.png"
        $s7 = "res/drawable-hdpi-v4/slip_line_progress.png"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00639 {
    strings:
        $s0 = "assets/data.res"
        $s1 = "/LO1fKWgQ9SjYpljzyo"
        $s2 = "http://topfiless.com/rates.php"
        $s3 = "assets/auto.res"
        $s4 = "res/drawable/button_tariff.xml"
        $s5 = "0fX9oXBM/kc"
        $s6 = "agree.txt"
        $s7 = "assets/agree.txt"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00640 {
    strings:
        $s0 = "assets/data.res"
        $s1 = "/LO1fKWgQ9SjYpljzyo"
        $s2 = "http://topfiless.com/rates.php"
        $s3 = "assets/auto.res"
        $s4 = "res/drawable/button_tariff.xml"
        $s5 = "0fX9oXBM/kc"
        $s6 = "agree.txt"
        $s7 = "assets/agree.txt"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00641 {
    strings:
        $s0 = "assets/data.res"
        $s1 = "/LO1fKWgQ9SjYpljzyo"
        $s2 = "http://topfiless.com/rates.php"
        $s3 = "assets/auto.res"
        $s4 = "res/drawable/button_tariff.xml"
        $s5 = "0fX9oXBM/kc"
        $s6 = "agree.txt"
        $s7 = "assets/agree.txt"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00642 {
    strings:
        $s0 = "Lcom/unionpay/UPPayAssistEx"
        $s1 = "HookDelegate:"
        $s2 = "Lmirror/RefBoolean"
        $s3 = "Lmirror/RefClass"
        $s4 = "Lmirror/RefConstructor"
        $s5 = "Lmirror/RefDouble"
        $s6 = "Lmirror/RefFloat"
        $s7 = "Lmirror/RefInt"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00643 {
    strings:
        $s0 = "res/layout/surface.xml"
        $s1 = "/dev/block/mtdblock3"
        $s2 = "url.substring"
        $s3 = "phonemodel.txt"
        $s4 = "testserver.txt"
        $s5 = "res/drawable-hdpi/btn_download_pressed.png"
        $s6 = "system/priv-app"
        $s7 = "AService.java"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00644 {
    strings:
        $s0 = "h9PDMBXx/7AUCTgqBicvs9LMF0/zhcrOR2nK9TY"
        $s1 = "v6BJJrqk2/BlVN7Fb43159u/FLhYJtopJ9zK0rBuxDc"
        $s2 = "8uChfRgL8wSZVSNHrw2/HWd1JoPBtJ8531kWXnLXXUI"
        $s3 = "ZaxJ8tTG5VeCMps62uSOld/A7Ch9zElYYTq4zTjwdeM"
        $s4 = "MYCo6CT4BCb3LVUJ1BeR2sACt/pn37mqb2PAYvutNOI"
        $s5 = "assets/CMRequire.dat"
        $s6 = "res/layout/activity_compose_sms.xml"
        $s7 = "res/drawable/tbi.xml"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00645 {
    strings:
        $s0 = "Lcom/unionpay/UPPayAssistEx"
        $s1 = "Lcom/alipay/sdk/cons/GlobalConstants"
        $s2 = "1HnrPpggZ8rNgeo0TsoK3uaWC9eSRW6zEhSR8hE/EE7CrI"
        $s3 = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1MLevZ7IPgEcx9hQANi1s/jqAYSk//uRoXBX"
        $s4 = "eUlji8dFm3kw6MwUfbZpfH/"
        $s5 = "https://pay.ipaynow.cn"
        $s6 = "https://pay.ipaynow.cn/sdk/syncException"
        $s7 = "ixhMBAj/F07g/PgvFOZ79mR0E8pT1Jhyj1WN/HlahIYenieciJ1P/L8KHZoZR0hKeZ4K8g951AaZbL5B"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00646 {
    strings:
        $s0 = "res/drawable-mdpi-v4/ic_launcher_bacground.png"
        $s1 = "Lcom/termuxhackers/id/BootReceiver"
        $s2 = "Lcom/termuxhackers/id/BuildConfig"
        $s3 = "Lcom/termuxhackers/id/MainActivity"
        $s4 = "Lcom/termuxhackers/id/MyService"
        $s5 = "Lcom/termuxhackers/id/MyService$100000000"
        $s6 = "Lcom/termuxhackers/id/R"
        $s7 = "Lcom/termuxhackers/id/R$attr"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00647 {
    strings:
        $s0 = "dalvik.system.LexClassLoader"
        $s1 = "HookDelegate:"
        $s2 = "Lmirror/RefBoolean"
        $s3 = "Lmirror/RefClass"
        $s4 = "Lmirror/RefConstructor"
        $s5 = "Lmirror/RefDouble"
        $s6 = "Lmirror/RefFloat"
        $s7 = "Lmirror/RefInt"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00648 {
    strings:
        $s0 = "apkprotect.com/key.dat"
        $s1 = "apkprotect.com/readme.txt"
        $s2 = "Lcom/android/a"
        $s3 = "ReplayStruct.java"
        $s4 = "RequestStruct.java"
        $s5 = "LSecScreen.java"
        $s6 = "res/xml/lsecscreen.xml"
        $s7 = "Lcom/android/internal/telephony/a"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00649 {
    strings:
        $s0 = "com.webcash.wooribank"
        $s1 = "res/drawable-hdpi/nh.png"
        $s2 = "res/drawable-hdpi/sh.png"
        $s3 = "/conf.ini"
        $s4 = "App.Alert"
        $s5 = "alert.main"
        $s6 = "app.auto.install"
        $s7 = "app.dwonload.complate"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00650 {
    strings:
        $s0 = "Z.-z-.xy-"
        $s1 = "n-LzK-y/"
        $s2 = "res/drawable/img_android.png"
        $s3 = "res/layout/instruction_dialog.xml"
        $s4 = "res/drawable/shape_gray_border_bottom.xml"
        $s5 = "res/layout/samsung_show_top_dialog.xml"
        $s6 = "res/layout/xiaomi_background_activity_dialog.xml"
        $s7 = "kCAV6oJ/SmWuiuhnPywY9iAx2Yw"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00651 {
    strings:
        $s0 = "mc/3kSeNxAEsxmxTfb2OdAvKSmcT"
        $s1 = "/OyhFnx6nI8qJ4RJIyGlRjv"
        $s2 = "/Ro3dhXHv3NV"
        $s3 = "/digi.my"
        $s4 = "00np5cF2qhi4aNJitIokUCgFifavi9laQwVmYjAEL/w"
        $s5 = "1dO4t7KqGGPYO7/Sdmgc"
        $s6 = "2XHUEKgyHRlz7jsAM3HmNW/VjWfOGhb8DGJFPfl0s9Y"
        $s7 = "6/gnaRgCgbQNdjZ/Tqdhhu2wK3mP4jky2/KpvAIjQVg"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00652 {
    strings:
        $s0 = "lib/armeabi/libcrypt_sign.so"
        $s1 = "assets/wyzf/res.bin"
        $s2 = "13/Ayo17/DPtKNh46JVIv6osRPo"
        $s3 = "Qmxju5/Ap5mgu1cFHvmJFycrWMw"
        $s4 = "com/unicom/wounipaysms/dialog/images/cancel.png"
        $s5 = "com/unicom/wounipaysms/dialog/images/cancel_on.png"
        $s6 = "com/unicom/wounipaysms/dialog/images/confirm_bt.9.png"
        $s7 = "com/unicom/wounipaysms/dialog/images/confirm_bt_on.9.png"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00653 {
    strings:
        $s0 = "res/raw/act_schemes.cfg"
        $s1 = "res/xml/texts.xml"
        $s2 = "res/layout/off.xml"
        $s3 = "c/nL07Gy7K3maRlEL1MxCVwf4FU"
        $s4 = "res/drawable/checkbox_label_background.9.png"
        $s5 = "18/aznZQx9KN6O9oFh9zkx3tu4w"
        $s6 = "res/drawable/0.temp"
        $s7 = "res/drawable/1.temp"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00654 {
    strings:
        $s0 = "res/raw/act_schemes.cfg"
        $s1 = "res/xml/texts.xml"
        $s2 = "res/layout/off.xml"
        $s3 = "c/nL07Gy7K3maRlEL1MxCVwf4FU"
        $s4 = "res/drawable/checkbox_label_background.9.png"
        $s5 = "18/aznZQx9KN6O9oFh9zkx3tu4w"
        $s6 = "res/drawable/0.temp"
        $s7 = "res/drawable/1.temp"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00655 {
    strings:
        $s0 = "res/raw/act_schemes.cfg"
        $s1 = "res/xml/texts.xml"
        $s2 = "res/layout/off.xml"
        $s3 = "c/nL07Gy7K3maRlEL1MxCVwf4FU"
        $s4 = "res/drawable/checkbox_label_background.9.png"
        $s5 = "18/aznZQx9KN6O9oFh9zkx3tu4w"
        $s6 = "res/drawable/0.temp"
        $s7 = "res/drawable/1.temp"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00656 {
    strings:
        $s0 = "KGJk/tmNnBAwr5"
        $s1 = "Lblue/sky/vn/API"
        $s2 = "Lblue/sky/vn/DI"
        $s3 = "Lblue/sky/vn/GameHDActivity"
        $s4 = "Lblue/sky/vn/MainActivity"
        $s5 = "Lblue/sky/vn/WebViewActivity"
        $s6 = "lcZ/aGbqQdXgw"
        $s7 = "res/layout/hm_view.xml"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00657 {
    strings:
        $s0 = "KGJk/tmNnBAwr5"
        $s1 = "Lblue/sky/vn/API"
        $s2 = "Lblue/sky/vn/DI"
        $s3 = "Lblue/sky/vn/GameHDActivity"
        $s4 = "Lblue/sky/vn/MainActivity"
        $s5 = "Lblue/sky/vn/WebViewActivity"
        $s6 = "lcZ/aGbqQdXgw"
        $s7 = "res/layout/hm_view.xml"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00658 {
    strings:
        $s0 = "res/layout/policies.xml"
        $s1 = "res/drawable/cvc_visa.gif"
        $s2 = "jpYacD5/wUvtUwHbhwW1g"
        $s3 = "res/layout/activity_adm.xml"
        $s4 = "MTlU4/s0Na1xqXZEwI5ijYM8bWM"
        $s5 = "XkJZESkUiK7r0fIPYfe/npF7zow"
        $s6 = "NE8tGjS/h4o4W2p0qoz8JbalbXY"
        $s7 = "g0gJIDfICaPA6Kz/DJTKd2dgRs8"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00659 {
    strings:
        $s0 = "res/layout/policies.xml"
        $s1 = "res/drawable/cvc_visa.gif"
        $s2 = "jpYacD5/wUvtUwHbhwW1g"
        $s3 = "res/layout/activity_adm.xml"
        $s4 = "MTlU4/s0Na1xqXZEwI5ijYM8bWM"
        $s5 = "XkJZESkUiK7r0fIPYfe/npF7zow"
        $s6 = "NE8tGjS/h4o4W2p0qoz8JbalbXY"
        $s7 = "g0gJIDfICaPA6Kz/DJTKd2dgRs8"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00660 {
    strings:
        $s0 = "mian.iyu"
        $s1 = "/YouGaile/AppFile"
        $s2 = "/iApp/Userimg"
        $s3 = "/iApp/downFile/"
        $s4 = "Lcom/Hy/UI/PredicateLayout"
        $s5 = "Lcom/Hy/UI/a"
        $s6 = "Lcom/Hy/UI/b"
        $s7 = "Lcom/Hy/UI/c"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00661 {
    strings:
        $s0 = "mian.iyu"
        $s1 = "/YouGaile/AppFile"
        $s2 = "/iApp/Userimg"
        $s3 = "/iApp/downFile/"
        $s4 = "Lcom/Hy/UI/PredicateLayout"
        $s5 = "Lcom/Hy/UI/a"
        $s6 = "Lcom/Hy/UI/b"
        $s7 = "Lcom/Hy/UI/c"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00662 {
    strings:
        $s0 = "MyHttpUtils.java"
        $s1 = "yc/Ww3r6vzHuVDwC1K0"
        $s2 = "Lir/pardakht/BuildConfig"
        $s3 = "Lir/pardakht/MainActivity"
        $s4 = "Lir/pardakht/MainActivity$BackTask"
        $s5 = "Lir/pardakht/MainActivity$BackTask$MyTask"
        $s6 = "Lir/pardakht/MyHttpUtils"
        $s7 = "Lir/pardakht/MyHttpUtils$RequestData"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00663 {
    strings:
        $s0 = "res/mipmap-xxhdpi-v4/ic_launcher_empty.png"
        $s1 = "res/mipmap-xxhdpi-v4/ic_launcher_video.png"
        $s2 = "Md3MSA/sg/op1reCKgNZCskn84E"
        $s3 = "res/mipmap-xxhdpi-v4/ic_launcher_antivirus.png"
        $s4 = "res/mipmap-xxhdpi-v4/ic_launcher_flash.png"
        $s5 = "res/mipmap-xxhdpi-v4/ic_launcher_music.png"
        $s6 = "res/mipmap-xxhdpi-v4/ic_launcher_robot.png"
        $s7 = "res/mipmap-xxhdpi-v4/ic_launcher_security.png"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00664 {
    strings:
        $s0 = "$Lcom/my/newproject2/DebugActivity$1"
        $s1 = "Lcom/my/newproject2/DebugActivity"
        $s2 = "Lcom/my/newproject2/MainActivity"
        $s3 = "Lcom/my/newproject2/R"
        $s4 = "Lcom/my/newproject2/R$attr"
        $s5 = "Lcom/my/newproject2/R$drawable"
        $s6 = "Lcom/my/newproject2/R$id"
        $s7 = "Lcom/my/newproject2/R$layout"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00665 {
    strings:
        $s0 = "LogCatBroadcaster.java"
        $s1 = "com.aide.runtime.VIEW_LOGCAT_ENTRY"
    condition:
        any of ($s0, $s1)
}

rule VX_APK_CLUSTER_00666 {
    strings:
        $s0 = "lib/armeabi/libcrypt_sign.so"
        $s1 = "assets/wyzf/res.bin"
        $s2 = "13/Ayo17/DPtKNh46JVIv6osRPo"
        $s3 = "Qmxju5/Ap5mgu1cFHvmJFycrWMw"
        $s4 = "com/unicom/wounipaysms/dialog/images/cancel.png"
        $s5 = "com/unicom/wounipaysms/dialog/images/cancel_on.png"
        $s6 = "com/unicom/wounipaysms/dialog/images/confirm_bt.9.png"
        $s7 = "com/unicom/wounipaysms/dialog/images/confirm_bt_on.9.png"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00667 {
    strings:
        $s0 = "lib/armeabi/libcrypt_sign.so"
        $s1 = "assets/wyzf/res.bin"
        $s2 = "13/Ayo17/DPtKNh46JVIv6osRPo"
        $s3 = "Qmxju5/Ap5mgu1cFHvmJFycrWMw"
        $s4 = "com/unicom/wounipaysms/dialog/images/cancel.png"
        $s5 = "com/unicom/wounipaysms/dialog/images/cancel_on.png"
        $s6 = "com/unicom/wounipaysms/dialog/images/confirm_bt.9.png"
        $s7 = "com/unicom/wounipaysms/dialog/images/confirm_bt_on.9.png"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00668 {
    strings:
        $s0 = "hGV/eFuLm4sXF7Kgiv2LjTr84vc"
        $s1 = "res/drawable-hdpi/opera.jpg"
        $s2 = "res/drawable-hdpi/textbg.xml"
        $s3 = "res/drawable-hdpi/titlebg.xml"
        $s4 = "Wce1MjOVrsjGKh03cKT/M"
        $s5 = "res/drawable-hdpi/ropera.jpg"
        $s6 = "assets/config.res"
        $s7 = "code.reg"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00669 {
    strings:
        $s0 = "com.webcash.wooribank"
        $s1 = "res/drawable-hdpi/nh.png"
        $s2 = "res/drawable-hdpi/sh.png"
        $s3 = "/conf.ini"
        $s4 = "App.Alert"
        $s5 = "alert.main"
        $s6 = "app.auto.install"
        $s7 = "app.dwonload.complate"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00670 {
    strings:
        $s0 = "res/xml/device_admin_data.xml"
        $s1 = "/kmnLuLqBMOCa2bEZzlLoFKq"
        $s2 = "33com.iitr.kaishu.nsidedprogressbar.NSidedProgressBar"
        $s3 = "CSZx6RMpZhVd/V2215WR4fM7llXd2eeuuljaNHfU9Co"
        $s4 = "res/raw/dx"
        $s5 = "skuU2rJZc81sswK/bAkZDnCYrhcw"
        $s6 = "zG5hJB/n2/IwKLG7Ok2tBSq3d8ZqpxaGsNb7RL7r1LM"
        $s7 = "5MJB/GLAcB4JuhRBpPf2uoRkWLEBRVSCw/iyoUXiTos"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00671 {
    strings:
        $s0 = "res/layout/rools.xml"
        $s1 = "sRNe/i3dVkjN0LlFUIHAc3hBgfM"
        $s2 = "assets/rools.txt"
        $s3 = "/mnt/sdcard/download/"
        $s4 = "/stats/adv.php"
        $s5 = "/stats/open.php"
        $s6 = "/stats/press.php"
        $s7 = "rools.txt"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00672 {
    strings:
        $s0 = "res/drawable-mdpi-v4/ic_launcher_bacground.png"
        $s1 = "Lcom/termuxhackers/id/BootReceiver"
        $s2 = "Lcom/termuxhackers/id/BuildConfig"
        $s3 = "Lcom/termuxhackers/id/MainActivity"
        $s4 = "Lcom/termuxhackers/id/MyService"
        $s5 = "Lcom/termuxhackers/id/MyService$100000000"
        $s6 = "Lcom/termuxhackers/id/R"
        $s7 = "Lcom/termuxhackers/id/R$attr"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00673 {
    strings:
        $s0 = "res/drawable/img_android.png"
        $s1 = "res/layout/instruction_dialog.xml"
        $s2 = "res/drawable/shape_gray_border_bottom.xml"
        $s3 = "res/layout/samsung_show_top_dialog.xml"
        $s4 = "res/layout/xiaomi_background_activity_dialog.xml"
        $s5 = "iOTls283qxBiqp1Kk5XhZl3nAXbWKnOn/DsVjWD9f9Q"
        $s6 = "dalvik.system.LexClassLoader"
        $s7 = "ATvqoz3o52G2n71RMsMXWVtAsQXcjnkHuaAIjvwqS/g"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00674 {
    strings:
        $s0 = "5UffRfxnNJZz86tDvGI/CMDWqT0"
        $s1 = "odNotice.txt"
        $s2 = "lightingscreen."
        $s3 = "/public/M"
        $s4 = "/public/M/"
        $s5 = "/public/recoording.wav"
        $s6 = "5hlCApUD68fVEuyQp/yvX6Twmto"
        $s7 = "810pEulG32J/tGStP7jlWC1V/cc"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00675 {
    strings:
        $s0 = "yRRcbcPCppiMYG6Hcx/z9GWNDJA"
        $s1 = "ERxa/JEZlg3ozQdL90vjacYjOa0"
        $s2 = "JmRd5cMmoVSvbdtkYmFLpe/EA6A"
        $s3 = "bt0y/oyU"
        $s4 = "layout/page5"
        $s5 = "res/drawable/buttonkeyb.xml"
        $s6 = "res/drawable/gov_inactive.png"
        $s7 = "res/drawable/hitler_inactive.png"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00676 {
    strings:
        $s0 = "myAOnVezFsTkzSr/E8uO/KdEA"
        $s1 = "res/anim/large_progressbar_animator.xml"
        $s2 = "jJuOui8LVgvIX/td4WnbqpYysO8"
        $s3 = "res/drawable/progressdialog_bg.xml"
        $s4 = "res/layout/hor_line_gray.xml"
        $s5 = "layout/hor_line_gray"
        $s6 = "res/layout/fragment_pic.xml"
        $s7 = "res/drawable-xhdpi-v4/black_pay_btn.png"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00677 {
    strings:
        $s0 = "res/layout/rools.xml"
        $s1 = "sRNe/i3dVkjN0LlFUIHAc3hBgfM"
        $s2 = "assets/rools.txt"
        $s3 = "QGaGmfqVuOnqnJPQRJFAKhw/iFM"
        $s4 = "kfdCIJl2EQ8vCB/lMdcNdG5efLE"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4)
}

rule VX_APK_CLUSTER_00678 {
    strings:
        $s0 = "xoYHeP/23ezgc3yGF9063z"
        $s1 = "res/layout/grant_access_to_content.xml"
        $s2 = "res/layout/offert.xml"
        $s3 = "1.6.0_03-p4"
        $s4 = "GrantAccess.java"
        $s5 = "res/raw/activation_schemes.cfg"
        $s6 = "NfImZUlrjjdAxlih/kZXenDCSU8"
        $s7 = "res/drawable/progress_finished.xml"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00679 {
    strings:
        $s0 = "res/drawable-xhdpi/ic_.xml"
        $s1 = "lib/armeabi-v7a/libjv.so"
        $s2 = "T0kkjlPKd/T/B"
        $s3 = "WL/TOMcJY/7izMV0YyjyUIUTAHWlM"
    condition:
        any of ($s0, $s1, $s2, $s3)
}

rule VX_APK_CLUSTER_00680 {
    strings:
        $s0 = "lib/armeabi/libcrypt_sign.so"
        $s1 = "assets/wyzf/res.bin"
        $s2 = "assets/jmpay.xml"
        $s3 = "assets/provincecode.xml"
        $s4 = "assets/utopay.zip"
        $s5 = "assets/yf.conf"
        $s6 = "assets/dERlZG"
        $s7 = "5H0/y0vQ/rz9n5q2WT8d7bHFZSA"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00681 {
    strings:
        $s0 = "lib/armeabi/libcrypt_sign.so"
        $s1 = "assets/wyzf/res.bin"
        $s2 = "13/Ayo17/DPtKNh46JVIv6osRPo"
        $s3 = "Qmxju5/Ap5mgu1cFHvmJFycrWMw"
        $s4 = "com/unicom/wounipaysms/dialog/images/cancel.png"
        $s5 = "com/unicom/wounipaysms/dialog/images/cancel_on.png"
        $s6 = "com/unicom/wounipaysms/dialog/images/confirm_bt.9.png"
        $s7 = "com/unicom/wounipaysms/dialog/images/confirm_bt_on.9.png"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00682 {
    strings:
        $s0 = "Lcom/guard/smart/IDLEService"
        $s1 = "Lcom/guard/smart/MainActivity"
        $s2 = "Lcom/guard/smart/SmsReceiver"
        $s3 = "Lcom/guard/smart/TimerReceiver"
        $s4 = "Lcom/guard/smart/a"
        $s5 = "Lcom/guard/smart/b"
        $s6 = "Lcom/guard/smart/c"
        $s7 = "Lcom/guard/smart/d"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00683 {
    strings:
        $s0 = "lib/armeabi/libcrypt_sign.so"
        $s1 = "assets/wyzf/res.bin"
        $s2 = "assets/yf.conf"
        $s3 = "assets/pay"
        $s4 = "assets/onib_clz.jar"
        $s5 = "assets/qshp_3001_2295"
        $s6 = "assets/resource/plugin"
        $s7 = "lib/armeabi/libbsjni.so"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00684 {
    strings:
        $s0 = "lib/armeabi-v7a/libow.so"
        $s1 = "afo/ZvCug/lq"
    condition:
        any of ($s0, $s1)
}

rule VX_APK_CLUSTER_00685 {
    strings:
        $s0 = "res/layout/finish.xml"
        $s1 = "res/raw/config.txt"
        $s2 = "OpInfo.java"
        $s3 = "assets/texts/finish_activity.txt"
        $s4 = "assets/texts/first_activity.txt"
        $s5 = "assets/texts/ru/finish_activity.txt"
        $s6 = "assets/texts/ru/first_activity.txt"
        $s7 = "assets/texts/ru/rules_activity.txt"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00686 {
    strings:
        $s0 = "res/layout/finish.xml"
        $s1 = "res/raw/config.txt"
        $s2 = "OpInfo.java"
        $s3 = "assets/texts/finish_activity.txt"
        $s4 = "assets/texts/first_activity.txt"
        $s5 = "assets/texts/ru/finish_activity.txt"
        $s6 = "assets/texts/ru/first_activity.txt"
        $s7 = "assets/texts/ru/rules_activity.txt"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00687 {
    strings:
        $s0 = "res/layout/finish.xml"
        $s1 = "res/raw/config.txt"
        $s2 = "OpInfo.java"
        $s3 = "assets/texts/finish_activity.txt"
        $s4 = "assets/texts/first_activity.txt"
        $s5 = "assets/texts/ru/finish_activity.txt"
        $s6 = "assets/texts/ru/first_activity.txt"
        $s7 = "assets/texts/ru/rules_activity.txt"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00688 {
    strings:
        $s0 = "res/layout/finish.xml"
        $s1 = "res/raw/config.txt"
        $s2 = "OpInfo.java"
        $s3 = "assets/texts/finish_activity.txt"
        $s4 = "assets/texts/first_activity.txt"
        $s5 = "assets/texts/ru/finish_activity.txt"
        $s6 = "assets/texts/ru/first_activity.txt"
        $s7 = "assets/texts/ru/rules_activity.txt"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00689 {
    strings:
        $s0 = "res/layout/finish.xml"
        $s1 = "res/raw/config.txt"
        $s2 = "OpInfo.java"
        $s3 = "assets/texts/finish_activity.txt"
        $s4 = "assets/texts/first_activity.txt"
        $s5 = "assets/texts/ru/finish_activity.txt"
        $s6 = "assets/texts/ru/first_activity.txt"
        $s7 = "assets/texts/ru/rules_activity.txt"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00690 {
    strings:
        $s0 = "res/layout/finish.xml"
        $s1 = "res/raw/config.txt"
        $s2 = "OpInfo.java"
        $s3 = "assets/texts/finish_activity.txt"
        $s4 = "assets/texts/first_activity.txt"
        $s5 = "assets/texts/ru/finish_activity.txt"
        $s6 = "assets/texts/ru/first_activity.txt"
        $s7 = "assets/texts/ru/rules_activity.txt"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00691 {
    strings:
        $s0 = "res/layout/finish.xml"
        $s1 = "res/raw/config.txt"
        $s2 = "OpInfo.java"
        $s3 = "assets/texts/finish_activity.txt"
        $s4 = "assets/texts/first_activity.txt"
        $s5 = "assets/texts/ru/finish_activity.txt"
        $s6 = "assets/texts/ru/first_activity.txt"
        $s7 = "assets/texts/ru/rules_activity.txt"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00692 {
    strings:
        $s0 = "res/layout/finish.xml"
        $s1 = "res/raw/config.txt"
        $s2 = "OpInfo.java"
        $s3 = "assets/texts/finish_activity.txt"
        $s4 = "assets/texts/first_activity.txt"
        $s5 = "assets/texts/ru/finish_activity.txt"
        $s6 = "assets/texts/ru/first_activity.txt"
        $s7 = "assets/texts/ru/rules_activity.txt"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00693 {
    strings:
        $s0 = "res/layout/finish.xml"
        $s1 = "res/raw/config.txt"
        $s2 = "OpInfo.java"
        $s3 = "assets/texts/finish_activity.txt"
        $s4 = "assets/texts/first_activity.txt"
        $s5 = "assets/texts/ru/finish_activity.txt"
        $s6 = "assets/texts/ru/first_activity.txt"
        $s7 = "assets/texts/ru/rules_activity.txt"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00694 {
    strings:
        $s0 = "res/raw/act_schemes.cfg"
        $s1 = "res/xml/texts.xml"
        $s2 = "res/layout/off.xml"
        $s3 = "ShowLink.java"
        $s4 = "res/layout/grant_access_to_content.xml"
        $s5 = "OffertActivity.java"
        $s6 = "com.software.CHECKER"
        $s7 = "res/drawable/install_icon.png"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00695 {
    strings:
        $s0 = "res/raw/act_schemes.cfg"
        $s1 = "res/xml/texts.xml"
        $s2 = "res/layout/off.xml"
        $s3 = "c/nL07Gy7K3maRlEL1MxCVwf4FU"
        $s4 = "res/drawable/checkbox_label_background.9.png"
        $s5 = "18/aznZQx9KN6O9oFh9zkx3tu4w"
        $s6 = "res/drawable/0.temp"
        $s7 = "ShowLink.java"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00696 {
    strings:
        $s0 = "res/raw/act_schemes.cfg"
        $s1 = "res/xml/texts.xml"
        $s2 = "res/layout/off.xml"
        $s3 = "c/nL07Gy7K3maRlEL1MxCVwf4FU"
        $s4 = "res/drawable/checkbox_label_background.9.png"
        $s5 = "18/aznZQx9KN6O9oFh9zkx3tu4w"
        $s6 = "res/drawable/0.temp"
        $s7 = "ShowLink.java"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00697 {
    strings:
        $s0 = "res/raw/act_schemes.cfg"
        $s1 = "res/xml/texts.xml"
        $s2 = "res/layout/off.xml"
        $s3 = "c/nL07Gy7K3maRlEL1MxCVwf4FU"
        $s4 = "res/drawable/checkbox_label_background.9.png"
        $s5 = "18/aznZQx9KN6O9oFh9zkx3tu4w"
        $s6 = "res/drawable/0.temp"
        $s7 = "ShowLink.java"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00698 {
    strings:
        $s0 = "res/raw/act_schemes.cfg"
        $s1 = "res/xml/texts.xml"
        $s2 = "res/layout/off.xml"
        $s3 = "c/nL07Gy7K3maRlEL1MxCVwf4FU"
        $s4 = "res/drawable/checkbox_label_background.9.png"
        $s5 = "18/aznZQx9KN6O9oFh9zkx3tu4w"
        $s6 = "res/drawable/0.temp"
        $s7 = "ShowLink.java"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00699 {
    strings:
        $s0 = "res/raw/act_schemes.cfg"
        $s1 = "res/xml/texts.xml"
        $s2 = "res/layout/off.xml"
        $s3 = "c/nL07Gy7K3maRlEL1MxCVwf4FU"
        $s4 = "res/drawable/checkbox_label_background.9.png"
        $s5 = "18/aznZQx9KN6O9oFh9zkx3tu4w"
        $s6 = "res/drawable/0.temp"
        $s7 = "ShowLink.java"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00700 {
    strings:
        $s0 = "res/raw/data.db"
        $s1 = "Lorg/MobileDb/Field"
        $s2 = "Lorg/MobileDb/MobileDatabase"
        $s3 = "Lorg/MobileDb/Row"
        $s4 = "Lorg/MobileDb/Table"
        $s5 = "Lorg/MobileDb/Utf8StringBuffer"
        $s6 = ".---NKxx"
        $s7 = "MobileDatabase.java"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00701 {
    strings:
        $s0 = "res/drawable-mdpi/abc_textfield_search_activated_mtrl_alpha.9.png"
        $s1 = "res/drawable-xxhdpi/abc_textfield_search_activated_mtrl_alpha.9.pn"
        $s2 = "res/drawable-xxhdpi/abc_textfield_search_default_mtrl_alpha.9.png"
        $s3 = "res/drawable-hdpi/abc_textfield_search_activated_mtrl_alpha.9.png"
        $s4 = "res/drawable-xhdpi/abc_textfield_search_activated_mtrl_alpha.9.png"
        $s5 = "res/drawable-xxxhdpi/abc_scrubber_control_to_pressed_mtrl_000.png"
        $s6 = "res/drawable-xxxhdpi/abc_scrubber_control_to_pressed_mtrl_005.png"
        $s7 = "res/drawable-xxhdpi/common_google_signin_btn_icon_dark_normal_back"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00702 {
    strings:
        $s0 = "res/drawable-mdpi/abc_textfield_search_activated_mtrl_alpha.9.png"
        $s1 = "res/drawable-xxhdpi/abc_textfield_search_activated_mtrl_alpha.9.pn"
        $s2 = "res/drawable-xxhdpi/abc_textfield_search_default_mtrl_alpha.9.png"
        $s3 = "res/drawable-hdpi/abc_textfield_search_activated_mtrl_alpha.9.png"
        $s4 = "res/drawable-xhdpi/abc_textfield_search_activated_mtrl_alpha.9.png"
        $s5 = "res/drawable-xxxhdpi/abc_scrubber_control_to_pressed_mtrl_000.png"
        $s6 = "res/drawable-xxxhdpi/abc_scrubber_control_to_pressed_mtrl_005.png"
        $s7 = "res/drawable-xxhdpi/common_google_signin_btn_icon_dark_normal_back"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00703 {
    strings:
        $s0 = "res/drawable-mdpi/abc_textfield_search_activated_mtrl_alpha.9.png"
        $s1 = "res/drawable-xxhdpi/abc_textfield_search_activated_mtrl_alpha.9.pn"
        $s2 = "res/drawable-xxhdpi/abc_textfield_search_default_mtrl_alpha.9.png"
        $s3 = "res/drawable-hdpi/abc_textfield_search_activated_mtrl_alpha.9.png"
        $s4 = "res/drawable-xhdpi/abc_textfield_search_activated_mtrl_alpha.9.png"
        $s5 = "res/drawable-xxxhdpi/abc_scrubber_control_to_pressed_mtrl_000.png"
        $s6 = "res/drawable-xxxhdpi/abc_scrubber_control_to_pressed_mtrl_005.png"
        $s7 = "res/drawable-xxhdpi/common_google_signin_btn_icon_dark_normal_back"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00704 {
    strings:
        $s0 = "0nDhU/Wmbaqbo5v4nu2/OaflZa4"
        $s1 = "9Mp7gWm5xEL9CmETvxCu07/u"
        $s2 = "Lorg/BbgsActivity"
        $s3 = "Lorg/TvtyReceiver"
        $s4 = "Lorg/BtolrMainService"
        $s5 = "Lorg/DvssApplication"
        $s6 = "LvuNlvEbSz6/mQQ4"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6)
}

rule VX_APK_CLUSTER_00705 {
    strings:
        $s0 = "sYN/BAKkz1SDdQqGb/nLNjiS5/c"
        $s1 = "gen_log.txt"
        $s2 = "$Lcom/venator/app/ursafecpumonitor/R"
        $s3 = "-Lcom/venator/app/ursafecpumonitor/CpuMonitor"
        $s4 = "-Lcom/venator/app/ursafecpumonitor/CpuService"
        $s5 = "-Lcom/venator/app/ursafecpumonitor/R$drawable"
        $s6 = ".Lcom/venator/app/ursafecpumonitor/BuildConfig"
        $s7 = "/Lcom/venator/app/ursafecpumonitor/CpuService$1"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00706 {
    strings:
        $s0 = "kP/DuJrhBsBzhqoEfN2x/g"
        $s1 = "lib/armeabi-v7a/libgz.so"
        $s2 = "res/drawable-xhdpi/o.xml"
    condition:
        any of ($s0, $s1, $s2)
}

rule VX_APK_CLUSTER_00707 {
    strings:
        $s0 = "$Lcom/vnpt/app/kiengio/ENewsActivity"
        $s1 = "$Lcom/vnpt/app/kiengio/objects/CItem"
        $s2 = "--com.vnpt.app.vova.actionbar.ScrollingTextView"
        $s3 = "-Lcom/vnpt/app/kiengio/VideoThumbnailActivity"
        $s4 = "-Lcom/vnpt/app/kiengio/network/GetDataService"
        $s5 = "-Lcom/vnpt/app/kiengio/objects/DownloadedItem"
        $s6 = "-Lcom/vnpt/app/kiengio/ultils/DialogUtility$1"
        $s7 = ".ActionBar_sectionListView_listTextViewTextSize"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00708 {
    strings:
        $s0 = "lib/armeabi-v7a/libkc.so"
        $s1 = "res/drawable-xhdpi/i.xml"
        $s2 = "mKrASfD71mvxR/8VSVKwbI"
    condition:
        any of ($s0, $s1, $s2)
}

rule VX_APK_CLUSTER_00709 {
    strings:
        $s0 = "lib/armeabi-v7a/libkc.so"
        $s1 = "res/drawable-xhdpi/i.xml"
        $s2 = "vvGsKyoZPa0/nAmERrCpx8T3rbA"
    condition:
        any of ($s0, $s1, $s2)
}

rule VX_APK_CLUSTER_00710 {
    strings:
        $s0 = "res/drawable-xhdpi/ic_.xml"
        $s1 = "lib/armeabi-v7a/libuw.so"
    condition:
        any of ($s0, $s1)
}

rule VX_APK_CLUSTER_00711 {
    strings:
        $s0 = "res/drawable/spinner_48_inner_holo.png"
        $s1 = "res/xml/anti_delete.xml"
        $s2 = "res/xml/anti_delete_loader.xml"
        $s3 = "res/drawable/big_android.png"
        $s4 = "res/drawable/small_android.png"
        $s5 = "y8a0Ejj6sTFYd/8Bsc"
        $s6 = "$Landroid/support/v4/app/cpgyvt8o4r3"
        $s7 = "$Landroid/support/v4/app/e8kxjqktk9t"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00712 {
    strings:
        $s0 = "res/mipmap-xxhdpi-v4/ic_launcher_empty.png"
        $s1 = "res/mipmap-xxhdpi-v4/ic_launcher_video.png"
        $s2 = "Md3MSA/sg/op1reCKgNZCskn84E"
        $s3 = "res/mipmap-xxhdpi-v4/ic_launcher_antivirus.png"
        $s4 = "res/mipmap-xxhdpi-v4/ic_launcher_flash.png"
        $s5 = "res/mipmap-xxhdpi-v4/ic_launcher_music.png"
        $s6 = "res/mipmap-xxhdpi-v4/ic_launcher_robot.png"
        $s7 = "res/mipmap-xxhdpi-v4/ic_launcher_security.png"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00713 {
    strings:
        $s0 = "res/raw/act_schemes.cfg"
        $s1 = "res/xml/texts.xml"
        $s2 = "res/layout/off.xml"
        $s3 = "xoYHeP/23ezgc3yGF9063z"
        $s4 = "res/layout/grant_access_to_content.xml"
        $s5 = "OffertActivity.java"
        $s6 = "com.software.CHECKER"
        $s7 = "res/layout/offert.xml"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00714 {
    strings:
        $s0 = "Lcom/egvhreh/Pla"
        $s1 = "Lcom/egvhreh/usi/Activ"
        $s2 = "Lcom/egvhreh/usi/Activ$"
        $s3 = "OX.NQVsTtgwnTp"
        $s4 = "bRm/m6KAKAaAN08cp"
        $s5 = "java/io/Serializablefp1M$"
        $s6 = "java/lang/String6"
        $s7 = "java/lang/StringJ"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00715 {
    strings:
        $s0 = "l/cUiZLb7ya5qOYV/djf/zcvnb0"
        $s1 = "res/raw/conf.txt"
        $s2 = "res/raw/result"
        $s3 = "res/raw/resulturl"
        $s4 = "res/raw/rool.txt"
        $s5 = "res/drawable-hdpi/iconnews.png"
        $s6 = "res/drawable-mdpi/iconnews.png"
        $s7 = "http://91.213.175.176/api/"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00716 {
    strings:
        $s0 = "apkprotect.com/key.dat"
        $s1 = "apkprotect.com/readme.txt"
        $s2 = "$com.android.google.shinhanbbk.kr.app"
        $s3 = "$com.hana.google.kr.channel.korea.app"
        $s4 = "$com.ibk.korea.kr.androids.ibkbanking"
        $s5 = "com.androids.kr.kf.androids.sm.spb"
        $s6 = "com.cash.apc.woori.kr.android.apd"
        $s7 = "com.goog.sc.android.dadbdkr.scbankapp"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00717 {
    strings:
        $s0 = "contactsutils.java"
        $s1 = "$Lb4a/example/contactsutils$_cuemail"
        $s2 = "$Lb4a/example/contactsutils$_cuphone"
        $s3 = "Lb4a/example/contactsutils"
        $s4 = "Lb4a/example/contactsutils$_cucontact"
        $s5 = "b4a.example.contactsutils"
        $s6 = "mFN1aeKWR1s5FS5xuSauOx/2RcU"
        $s7 = "c1KIGWnyXRYqiIGZe/9d7myM"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00718 {
    strings:
        $s0 = "apkprotect.com/key.dat"
        $s1 = "apkprotect.com/readme.txt"
        $s2 = "Lcom/android/a"
        $s3 = "$com.android.google.shinhanbbk.kr.app"
        $s4 = "$com.hana.google.kr.channel.korea.app"
        $s5 = "$com.ibk.korea.kr.androids.ibkbanking"
        $s6 = "com.androids.kr.kf.androids.sm.spb"
        $s7 = "com.cash.apc.woori.kr.android.apd"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00719 {
    strings:
        $s0 = "tmx2ePqGYvOES/jfGp8NEsyAr6VQe6a1ddiSGcNeMew"
        $s1 = "5WUT8N6LC6PF97Z1cG6m0zl4jGoS61p2PFskeHZ/7H8"
        $s2 = "2o1f08s4ihKK2fy37dmIRlo3B3/iAOLvEwqe5G3VI6M"
        $s3 = "3PL37/LA6F6cQlcwE/Bez9Tyugc"
        $s4 = "9gvSiI/sWlYAWTkv"
        $s5 = "GT6Z4sjRroSUlaiGL/MTW4o37G9qwI18dLG/VMaBn2k"
        $s6 = "VFXcGqG2OaI/80S7opsg"
        $s7 = "VoPy/hbPPy"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00720 {
    strings:
        $s0 = "com.webcash.wooribank"
        $s1 = "Ppc2qe3pbHXr7i/fpIqi0VUnHrs"
        $s2 = "com.ATsolution.KBbank"
        $s3 = "i82ugOJhQVyT/fL0iVYq60"
        $s4 = "deviceAdminReceiver.java"
        $s5 = "sYN/BAKkz1SDdQqGb/nLNjiS5/c"
        $s6 = "YourReceiver.java"
        $s7 = "nestactivity.java"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00721 {
    strings:
        $s0 = "RwY7bp1C/mAHk1MxPLhfhPev/oM"
        $s1 = "javascript:androidVersion"
        $s2 = "webapi.cancelUse"
        $s3 = "/license.html"
        $s4 = "assets/html/default/icon.png"
        $s5 = "assets/html/default/index.html"
        $s6 = "assets/html/default/license.html"
        $s7 = "assets/html/default/style.css"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00722 {
    strings:
        $s0 = "RwY7bp1C/mAHk1MxPLhfhPev/oM"
        $s1 = "javascript:androidVersion"
        $s2 = "webapi.cancelUse"
        $s3 = "/license.html"
        $s4 = "assets/html/default/icon.png"
        $s5 = "assets/html/default/index.html"
        $s6 = "assets/html/default/license.html"
        $s7 = "assets/html/default/style.css"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00723 {
    strings:
        $s0 = "res/raw/act_schemes.cfg"
        $s1 = "res/xml/texts.xml"
        $s2 = "res/layout/off.xml"
        $s3 = "c/nL07Gy7K3maRlEL1MxCVwf4FU"
        $s4 = "res/drawable/checkbox_label_background.9.png"
        $s5 = "18/aznZQx9KN6O9oFh9zkx3tu4w"
        $s6 = "res/drawable/0.temp"
        $s7 = "res/drawable/1.temp"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00724 {
    strings:
        $s0 = "res/raw/act_schemes.cfg"
        $s1 = "res/xml/texts.xml"
        $s2 = "res/layout/off.xml"
        $s3 = "c/nL07Gy7K3maRlEL1MxCVwf4FU"
        $s4 = "res/drawable/checkbox_label_background.9.png"
        $s5 = "18/aznZQx9KN6O9oFh9zkx3tu4w"
        $s6 = "res/drawable/0.temp"
        $s7 = "3XU8DJNQ9o/iAlhePmHQ2ONZPBE"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00725 {
    strings:
        $s0 = "res/raw/act_schemes.cfg"
        $s1 = "res/xml/texts.xml"
        $s2 = "res/layout/off.xml"
        $s3 = "c/nL07Gy7K3maRlEL1MxCVwf4FU"
        $s4 = "res/drawable/checkbox_label_background.9.png"
        $s5 = "18/aznZQx9KN6O9oFh9zkx3tu4w"
        $s6 = "3XU8DJNQ9o/iAlhePmHQ2ONZPBE"
        $s7 = "OFJILd1Gbnhi40EKfg/Ai18RzGg"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00726 {
    strings:
        $s0 = "res/raw/act_schemes.cfg"
        $s1 = "res/xml/texts.xml"
        $s2 = "res/layout/off.xml"
        $s3 = "c/nL07Gy7K3maRlEL1MxCVwf4FU"
        $s4 = "res/drawable/checkbox_label_background.9.png"
        $s5 = "18/aznZQx9KN6O9oFh9zkx3tu4w"
        $s6 = "res/drawable/0.temp"
        $s7 = "3XU8DJNQ9o/iAlhePmHQ2ONZPBE"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00727 {
    strings:
        $s0 = "iqbpxBVbvM/8VbWzXVTaD0lliyI"
        $s1 = "res/drawable-hdpi/splash_bg.jpg"
        $s2 = ".tmp.apk"
        $s3 = "$Lru/download/manager/xml/XmlHandler"
        $s4 = "---align:"
        $s5 = ".Lru/download/manager/xml/object/NameValuePair"
        $s6 = "/MWorld30/"
        $s7 = "745QcgYvo6S4H/GKP3eRpPuhdvk"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00728 {
    strings:
        $s0 = "iqbpxBVbvM/8VbWzXVTaD0lliyI"
        $s1 = "res/drawable-hdpi/splash_bg.jpg"
        $s2 = ".tmp.apk"
        $s3 = "$Lru/download/manager/xml/XmlHandler"
        $s4 = "---align:"
        $s5 = ".Lru/download/manager/xml/object/NameValuePair"
        $s6 = "/MWorld30/"
        $s7 = "745QcgYvo6S4H/GKP3eRpPuhdvk"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00729 {
    strings:
        $s0 = "$Lbrendsu/gamedemo/AgreementActivity"
        $s1 = "GameDemoActivity.java"
        $s2 = "Lbrendsu/gamedemo/CommonDialogs"
        $s3 = "Lbrendsu/gamedemo/CommonDialogs$1"
        $s4 = "Lbrendsu/gamedemo/CommonDialogs$2"
        $s5 = "Lbrendsu/gamedemo/CommonDialogs$3"
        $s6 = "Lbrendsu/gamedemo/GameDemoActivity"
        $s7 = "Lbrendsu/gamedemo/GameDemoActivity$1"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00730 {
    strings:
        $s0 = "RwY7bp1C/mAHk1MxPLhfhPev/oM"
        $s1 = "javascript:androidVersion"
        $s2 = "WebApiResult.java"
        $s3 = "assets/html/empty"
        $s4 = "ussd.notify"
        $s5 = "DbLog.java"
        $s6 = "webapi.openUrl"
        $s7 = "AdminReceiver:"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00731 {
    strings:
        $s0 = "RwY7bp1C/mAHk1MxPLhfhPev/oM"
        $s1 = "javascript:androidVersion"
        $s2 = "WebApiResult.java"
        $s3 = "assets/html/empty"
        $s4 = "ussd.notify"
        $s5 = "DbLog.java"
        $s6 = "webapi.openUrl"
        $s7 = "AdminReceiver:"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00732 {
    strings:
        $s0 = "res/layout/rools.xml"
        $s1 = "sRNe/i3dVkjN0LlFUIHAc3hBgfM"
        $s2 = "/mnt/sdcard/download/"
        $s3 = "/stats/adv.php"
        $s4 = "/stats/open.php"
        $s5 = "/stats/press.php"
        $s6 = "/stats/recheck.php"
        $s7 = "HAra/EQitI"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00733 {
    strings:
        $s0 = "res/layout/rools.xml"
        $s1 = "sRNe/i3dVkjN0LlFUIHAc3hBgfM"
        $s2 = "/mnt/sdcard/download/"
        $s3 = "/stats/adv.php"
        $s4 = "/stats/open.php"
        $s5 = "/stats/press.php"
        $s6 = "/stats/recheck.php"
        $s7 = "HAra/EQitI"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00734 {
    strings:
        $s0 = "res/layout/rools.xml"
        $s1 = "sRNe/i3dVkjN0LlFUIHAc3hBgfM"
        $s2 = "/mnt/sdcard/download/"
        $s3 = "/stats/adv.php"
        $s4 = "/stats/open.php"
        $s5 = "/stats/press.php"
        $s6 = "/stats/recheck.php"
        $s7 = "HAra/EQitI"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00735 {
    strings:
        $s0 = "assets/css/smoothness/images/ui-bg_flat_0_aaaaaa_40x100.png"
        $s1 = "assets/css/smoothness/images/ui-bg_flat_75_ffffff_40x100.png"
        $s2 = "assets/css/smoothness/images/ui-bg_glass_55_fbf9ee_1x400.png"
        $s3 = "assets/css/smoothness/images/ui-bg_glass_65_ffffff_1x400.png"
        $s4 = "assets/css/smoothness/images/ui-bg_glass_75_dadada_1x400.png"
        $s5 = "assets/css/smoothness/images/ui-bg_glass_75_e6e6e6_1x400.png"
        $s6 = "assets/css/smoothness/images/ui-bg_glass_95_fef1ec_1x400.png"
        $s7 = "assets/css/smoothness/images/ui-bg_highlight-soft_75_cccccc_1x10"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00736 {
    strings:
        $s0 = "AutocrollViewAdapterer.java"
        $s1 = "AutocrollViewAdmin.java"
        $s2 = "AutocrollViewKJojo.java"
        $s3 = "AutocrollViewMainSend.java"
        $s4 = "AutocrollViewMainUtil.java"
        $s5 = "AutocrollViewMyboot.java"
        $s6 = "AutocrollViewSerjoij.java"
        $s7 = "AutocrollViewToolll.java"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00737 {
    strings:
        $s0 = "AZS/kpEhpE8Jl37U1SJ9eW7KA6E"
        $s1 = "NNqltaQgFzooaAOKcxToQQY/4rU"
        $s2 = "res/drawable/visa_curved.png"
        $s3 = "res/xml/da.xml"
        $s4 = "res/drawable/aec.png"
        $s5 = "res/drawable/wc.png"
        $s6 = "res/layout/activity_activity_card.xml"
        $s7 = "res/drawable/wcpl.png"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00738 {
    strings:
        $s0 = "receiver/install"
        $s1 = "UPermission.ACCESS_WIFI_STATE"
        $s2 = "UnPackage.dat"
        $s3 = "complete.Click"
        $s4 = "installed.Click"
        $s5 = "CacheTime.dat"
        $s6 = "/Android/data/cache/iconCache"
        $s7 = "Permission.ACCESS_WIFI_STATE"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00739 {
    strings:
        $s0 = "res/drawable-xhdpi-v4/uvv_on_error.png"
        $s1 = "layout/uvv_on_error_layout"
        $s2 = "res/drawable/uvv_star_play_progress_seek.xml"
        $s3 = "layout/uvv_on_loading_layout"
        $s4 = "paycode:"
        $s5 = "res/drawable-xhdpi-v4/uvv_back_btn.png"
        $s6 = "res/drawable-xhdpi-v4/uvv_itv_player_play.png"
        $s7 = "res/drawable-xhdpi-v4/uvv_player_scale_btn.png"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00740 {
    strings:
        $s0 = "ReplayStruct.java"
        $s1 = "RequestStruct.java"
        $s2 = "LSecScreen.java"
        $s3 = "res/xml/lsecscreen.xml"
        $s4 = "serivce."
        $s5 = "BaseBootReceiver.java"
        $s6 = "SinRecv.java"
        $s7 = "ffll.java"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00742 {
    strings:
        $s0 = "assets/css/smoothness/images/ui-bg_flat_0_aaaaaa_40x100.png"
        $s1 = "assets/css/smoothness/images/ui-bg_flat_75_ffffff_40x100.png"
        $s2 = "assets/css/smoothness/images/ui-bg_glass_55_fbf9ee_1x400.png"
        $s3 = "assets/css/smoothness/images/ui-bg_glass_65_ffffff_1x400.png"
        $s4 = "assets/css/smoothness/images/ui-bg_glass_75_dadada_1x400.png"
        $s5 = "assets/css/smoothness/images/ui-bg_glass_75_e6e6e6_1x400.png"
        $s6 = "assets/css/smoothness/images/ui-bg_glass_95_fef1ec_1x400.png"
        $s7 = "assets/css/smoothness/images/ui-bg_highlight-soft_75_cccccc_1x10"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00743 {
    strings:
        $s0 = "assets/css/smoothness/images/ui-bg_flat_0_aaaaaa_40x100.png"
        $s1 = "assets/css/smoothness/images/ui-bg_flat_75_ffffff_40x100.png"
        $s2 = "assets/css/smoothness/images/ui-bg_glass_55_fbf9ee_1x400.png"
        $s3 = "assets/css/smoothness/images/ui-bg_glass_65_ffffff_1x400.png"
        $s4 = "assets/css/smoothness/images/ui-bg_glass_75_dadada_1x400.png"
        $s5 = "assets/css/smoothness/images/ui-bg_glass_75_e6e6e6_1x400.png"
        $s6 = "assets/css/smoothness/images/ui-bg_glass_95_fef1ec_1x400.png"
        $s7 = "assets/css/smoothness/images/ui-bg_highlight-soft_75_cccccc_1x10"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00744 {
    strings:
        $s0 = "lib/armeabi-v7a/libdn_ssl.so"
        $s1 = "secret-classes.dex"
        $s2 = "scrt.apk"
        $s3 = "res/layout/activity_no_bg.xml"
        $s4 = "/kD/faOo"
        $s5 = "Lcom/mik/proxy/guard/core/BuildConfig"
        $s6 = "com.mik.proxy.guard.core"
        $s7 = "Pc2/qke."
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00745 {
    strings:
        $s0 = "apkprotect.com/key.dat"
        $s1 = "apkprotect.com/readme.txt"
        $s2 = "ReplayStruct.java"
        $s3 = "RequestStruct.java"
        $s4 = "LSecScreen.java"
        $s5 = "res/xml/lsecscreen.xml"
        $s6 = "serivce."
        $s7 = "BaseBootReceiver.java"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00746 {
    strings:
        $s0 = "lib/armeabi/libcrypt_sign.so"
        $s1 = "assets/wyzf/res.bin"
        $s2 = "assets/yf.conf"
        $s3 = "assets/dERlZG"
        $s4 = "Adzwfge96PWi9KOpEQioyGF//NA"
        $s5 = "http://vpay.api.eerichina.com/api/payment"
        $s6 = "plugin.db"
        $s7 = "/LocalPool.xml"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00747 {
    strings:
        $s0 = "MTaIkHUA/Pve4wl9Z8BxBfceZDI"
        $s1 = "l93LV4jLCK5M/GJ2VVD471iAyLY"
        $s2 = "App.getAppParams"
        $s3 = "Lapp/apk/App"
        $s4 = "Str.file"
        $s5 = "Str.getAppParams"
        $s6 = "Str.parse"
        $s7 = "app.startApp"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00748 {
    strings:
        $s0 = "/92T0y8Eg3hwmkt655BvOmGHH/XfOxZOEdiIqIwPT0FPT1D"
        $s1 = "/CmOEnNP6lw5ie"
        $s2 = "/G7vW8JQCmu0vfGnYWwVddg0"
        $s3 = "/H7/T0Kh0JlIJPLHaDT6V5vN9l"
        $s4 = "/SgOYNXi9nXGzpgQ/GLoI/F8cBdd9blJWI3aUlcNik9a54bjfK//AWNnzhbv/YNafPouSxJ1C57QdwRE"
        $s5 = "/eV24SQp5AXoVMCIYgaKW2oM5YW3FsEUa0MM5YYYIiLT7a/qH80dJxpu20OlbUodDqTNtBrFNqQzGtpT"
        $s6 = "/lmAoH0kytnp8PooIXsJDodcGUW5F6s8TJtLPyQAqwOisq7O2U8Is7zJBWXK/EOquTsVWzctRc/"
        $s7 = "/wMWjgermQx"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00749 {
    strings:
        $s0 = "lib/armeabi-v7a/libdn_ssl.so"
        $s1 = "secret-classes.dex"
        $s2 = "scrt.apk"
        $s3 = "/kD/faOo"
        $s4 = "res/layout/activity_call_v7.xml"
        $s5 = "res/layout/call_end_layout.xml"
        $s6 = "res/layout/call_pop_layout.xml"
        $s7 = "Lcom/mik/proxy/guard/core/BuildConfig"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00750 {
    strings:
        $s0 = ".jpg.dat"
        $s1 = "-----------s:"
        $s2 = "nousr.dat"
        $s3 = "bin/v.dat"
        $s4 = "assets/bin/v.dat"
        $s5 = "assets/cp/cp.dat"
        $s6 = "res/menu/activity_app.xml"
        $s7 = "Lkenny/jack/CpReceiver"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00751 {
    strings:
        $s0 = "lib/armeabi/libcrypt_sign.so"
        $s1 = "assets/wyzf/res.bin"
        $s2 = "assets/jmpay.xml"
        $s3 = "assets/provincecode.xml"
        $s4 = "assets/utopay.zip"
        $s5 = "assets/yf.conf"
        $s6 = "assets/qsha_80001_5096"
        $s7 = "assets/qpzf.dat"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00752 {
    strings:
        $s0 = "assets/url.txt"
        $s1 = "DiviceInfo.java"
        $s2 = "Lcom/reza/sh/deviceinfo/DiviceInfo"
        $s3 = "Lcom/reza/sh/deviceinfo/DiviceInfo$1"
        $s4 = "Lcom/reza/sh/deviceinfo/DiviceInfo$Nettest"
        $s5 = "Lcom/reza/sh/deviceinfo/DiviceInfo$PhoneCustomStateListener"
        $s6 = "Wifi/WifiMax"
        $s7 = "mFN1aeKWR1s5FS5xuSauOx/2RcU"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00753 {
    strings:
        $s0 = "au.com.bankwest.mobile"
        $s1 = "ZzxKlxKyki.i"
        $s2 = "commandus.com"
        $s3 = "--.ixKiidAZ"
        $s4 = "/CalsRlpNBoM"
        $s5 = "/p9USHEeoIE3gQO135Rl6PxRJyo"
        $s6 = "2Lcom/note/donote/receivers/ServiceDestroyReceiver"
        $s7 = "3Lcom/note/donote/receivers/sms/PushServiceReciever"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00754 {
    strings:
        $s0 = "au.com.bankwest.mobile"
        $s1 = "ZzxKlxKyki.i"
        $s2 = "commandus.com"
        $s3 = "--.ixKiidAZ"
        $s4 = "/CalsRlpNBoM"
        $s5 = "/p9USHEeoIE3gQO135Rl6PxRJyo"
        $s6 = "2Lcom/note/donote/receivers/ServiceDestroyReceiver"
        $s7 = "3Lcom/note/donote/receivers/sms/PushServiceReciever"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00755 {
    strings:
        $s0 = "receiver/install"
        $s1 = "UPermission.ACCESS_WIFI_STATE"
        $s2 = "UnPackage.dat"
        $s3 = "complete.Click"
        $s4 = "installed.Click"
        $s5 = "CacheTime.dat"
        $s6 = "/Android/data/cache/iconCache"
        $s7 = "Permission.ACCESS_WIFI_STATE"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00756 {
    strings:
        $s0 = "QXNlZxax/gGXUe1BJamKgK0N1S4"
        $s1 = "xyE///---"
        $s2 = "IZZ.:K.Ky"
        $s3 = ".Lcom/limi/baton/receiver/BTConnectionReceiver"
        $s4 = "/05diJ9I0WLnvF4uE"
        $s5 = "/5yi3yGJwFRtDPfgQsgEFyyv40g"
        $s6 = "/Nj7g7sNT0kpqaGRXKpMg5"
        $s7 = "/NqG9stcJrxt3BcCznp7Nx4eaTc"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00757 {
    strings:
        $s0 = "assets/css/smoothness/images/ui-bg_flat_0_aaaaaa_40x100.png"
        $s1 = "assets/css/smoothness/images/ui-bg_flat_75_ffffff_40x100.png"
        $s2 = "assets/css/smoothness/images/ui-bg_glass_55_fbf9ee_1x400.png"
        $s3 = "assets/css/smoothness/images/ui-bg_glass_65_ffffff_1x400.png"
        $s4 = "assets/css/smoothness/images/ui-bg_glass_75_dadada_1x400.png"
        $s5 = "assets/css/smoothness/images/ui-bg_glass_75_e6e6e6_1x400.png"
        $s6 = "assets/css/smoothness/images/ui-bg_glass_95_fef1ec_1x400.png"
        $s7 = "assets/css/smoothness/images/ui-bg_highlight-soft_75_cccccc_1x10"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00758 {
    strings:
        $s0 = "13/Ayo17/DPtKNh46JVIv6osRPo"
        $s1 = "Qmxju5/Ap5mgu1cFHvmJFycrWMw"
        $s2 = "com/unicom/wounipaysms/dialog/images/cancel.png"
        $s3 = "com/unicom/wounipaysms/dialog/images/cancel_on.png"
        $s4 = "com/unicom/wounipaysms/dialog/images/confirm_bt.9.png"
        $s5 = "com/unicom/wounipaysms/dialog/images/confirm_bt_on.9.png"
        $s6 = "com/unicom/wounipaysms/dialog/images/main_bg.9.png"
        $s7 = "com/unicom/wounipaysms/dialog/images/unicom.png"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00759 {
    strings:
        $s0 = "assets/css/smoothness/images/ui-bg_flat_0_aaaaaa_40x100.png"
        $s1 = "assets/css/smoothness/images/ui-bg_flat_75_ffffff_40x100.png"
        $s2 = "assets/css/smoothness/images/ui-bg_glass_55_fbf9ee_1x400.png"
        $s3 = "assets/css/smoothness/images/ui-bg_glass_65_ffffff_1x400.png"
        $s4 = "assets/css/smoothness/images/ui-bg_glass_75_dadada_1x400.png"
        $s5 = "assets/css/smoothness/images/ui-bg_glass_75_e6e6e6_1x400.png"
        $s6 = "assets/css/smoothness/images/ui-bg_glass_95_fef1ec_1x400.png"
        $s7 = "assets/css/smoothness/images/ui-bg_highlight-soft_75_cccccc_1x10"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00760 {
    strings:
        $s0 = "res/drawable-hdpi-v4/icon.xml"
        $s1 = "res/layout/activity_g.xml"
        $s2 = "iD2em3JLFcEgtAIneR97M/bukxQxG68VKhvLQQKmin8"
        $s3 = "res/drawable-hdpi-v4/app_launcher.png"
        $s4 = "72Pe9z4zT1SE8goGvm/DgHwC3lGN4xYkWDY5JnQ99MA"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4)
}

rule VX_APK_CLUSTER_00761 {
    strings:
        $s0 = "res/xml/device_admin_data.xml"
        $s1 = "res/drawable/pm_ok.xml"
        $s2 = "res/drawable/pmok_state.xml"
        $s3 = "res/layout/activity_pm.xml"
        $s4 = "res/layout/activity_pm_err.xml"
        $s5 = "res/layout/activity_pm_ok.xml"
        $s6 = "OhaGL7xatki385myc/mriuJt304"
        $s7 = ".andro_secure"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00762 {
    strings:
        $s0 = "/rgBiUeGVuM9QauYk4hnNYsk7Tg"
        $s1 = "Lcom/xiaomi/mipush/sdk/g$a"
        $s2 = "Lcom/xiaomi/push/service/a0"
        $s3 = "Lcom/xiaomi/push/service/b0"
        $s4 = "Lcom/xiaomi/push/service/c0"
        $s5 = "Lcom/xiaomi/push/service/d0"
        $s6 = "Lcom/xiaomi/push/service/e0"
        $s7 = "Lcom/xiaomi/push/service/f0"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00763 {
    strings:
        $s0 = "res/drawable/img_android.png"
        $s1 = "res/layout/instruction_dialog.xml"
        $s2 = "res/drawable/shape_gray_border_bottom.xml"
        $s3 = "res/layout/samsung_show_top_dialog.xml"
        $s4 = "res/layout/xiaomi_background_activity_dialog.xml"
        $s5 = "iOTls283qxBiqp1Kk5XhZl3nAXbWKnOn/DsVjWD9f9Q"
        $s6 = "dalvik.system.LexClassLoader"
        $s7 = "ATvqoz3o52G2n71RMsMXWVtAsQXcjnkHuaAIjvwqS/g"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00764 {
    strings:
        $s0 = "res/drawable-hdpi-v4/icon.xml"
        $s1 = "res/layout/activity_g.xml"
        $s2 = "iD2em3JLFcEgtAIneR97M/bukxQxG68VKhvLQQKmin8"
        $s3 = "res/drawable-hdpi-v4/app_launcher.png"
        $s4 = "8Xz31s/IgHpuEg7QTvjIyLSfCOggGwm8YqbZoGslc5E"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4)
}

rule VX_APK_CLUSTER_00765 {
    strings:
        $s0 = "assets/params"
        $s1 = "www.mts.ru"
        $s2 = "assets/paste.bin"
        $s3 = "Lsoftware/android/R"
        $s4 = "Lsoftware/android/R$attr"
        $s5 = "Lsoftware/android/R$drawable"
        $s6 = "Lsoftware/android/R$id"
        $s7 = "Lsoftware/android/R$layout"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00766 {
    strings:
        $s0 = "res/raw/act_schemes.cfg"
        $s1 = "res/xml/texts.xml"
        $s2 = "res/layout/off.xml"
        $s3 = "res/layout/grant_access.xml"
        $s4 = "ShowURL.java"
        $s5 = "Sch.java"
        $s6 = "AirModeHandler.java"
        $s7 = "res/drawable/install_icon.png"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00767 {
    strings:
        $s0 = "l/cUiZLb7ya5qOYV/djf/zcvnb0"
        $s1 = "res/raw/conf.txt"
        $s2 = "res/raw/result"
        $s3 = "res/raw/resulturl"
        $s4 = "res/raw/rool.txt"
        $s5 = "res/drawable-hdpi/iconnews.png"
        $s6 = "res/drawable-mdpi/iconnews.png"
        $s7 = "http://91.213.175.176/api/"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00768 {
    strings:
        $s0 = "::ggggZZL"
        $s1 = "Lcom/krefble/rnecrsg/a"
        $s2 = "Lcom/krefble/rnecrsg/ifrsct"
        $s3 = "Lcom/tvone/untoenynh/BuildConfig"
        $s4 = "Lcom/tvone/untoenynh/R"
        $s5 = "Lcom/tvone/untoenynh/R$attr"
        $s6 = "Lcom/tvone/untoenynh/R$dimen"
        $s7 = "Lcom/tvone/untoenynh/R$layout"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00769 {
    strings:
        $s0 = "src/2e15f58d32a5ff652706ef41ec85a763"
        $s1 = "src/3676d55f84497cbeadfc614c1b1b62fc"
        $s2 = "BYDecoder.java"
        $s3 = "Lcn/beingyi/sub/apps/SubApp/SubApplication"
        $s4 = "Lcn/beingyi/sub/utils/CheckUtils$Virtual$tcp"
        $s5 = "Lcn/beingyi/sub/utils/Native"
        $s6 = "cn.beingyi.subapplication"
        $s7 = "-Lcn/beingyi/sub/apps/SubApp/SubApplication$"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00770 {
    strings:
        $s0 = "mian.iyu"
        $s1 = "/AcvZ4Yycp/fuahUizra4r219Ug"
        $s2 = "UaAcDtpGmSrYRacrNRzul/Gk4Pw"
        $s3 = "a3V5KpEW/d14VzAGShsebenhDEI"
        $s4 = "assets/lib.so"
        $s5 = "lib/armeabi-v7a/libygsiyu.so"
        $s6 = "lib/x86/libygsiyu.so"
        $s7 = "tTYPFQeo26XIrs6xdPYO/zvBEiM"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00771 {
    strings:
        $s0 = "mian.iyu"
        $s1 = "/AcvZ4Yycp/fuahUizra4r219Ug"
        $s2 = "UaAcDtpGmSrYRacrNRzul/Gk4Pw"
        $s3 = "a3V5KpEW/d14VzAGShsebenhDEI"
        $s4 = "assets/lib.so"
        $s5 = "lib/armeabi-v7a/libygsiyu.so"
        $s6 = "lib/x86/libygsiyu.so"
        $s7 = "tTYPFQeo26XIrs6xdPYO/zvBEiM"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00772 {
    strings:
        $s0 = "l/cUiZLb7ya5qOYV/djf/zcvnb0"
        $s1 = "res/raw/conf.txt"
        $s2 = "res/raw/result"
        $s3 = "res/raw/resulturl"
        $s4 = "res/raw/rool.txt"
        $s5 = "res/drawable-hdpi/iconnews.png"
        $s6 = "res/drawable-mdpi/iconnews.png"
        $s7 = "http://91.213.175.176/api/"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00773 {
    strings:
        $s0 = "res/raw/act_schemes.cfg"
        $s1 = "res/xml/texts.xml"
        $s2 = "res/layout/off.xml"
        $s3 = "c/nL07Gy7K3maRlEL1MxCVwf4FU"
        $s4 = "res/drawable/checkbox_label_background.9.png"
        $s5 = "18/aznZQx9KN6O9oFh9zkx3tu4w"
        $s6 = "res/drawable/0.temp"
        $s7 = "3XU8DJNQ9o/iAlhePmHQ2ONZPBE"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00774 {
    strings:
        $s0 = "/test.png"
        $s1 = "res/drawable/doodle.jpg"
        $s2 = "Ehttp://chateau-viranel.com/viranelous_nono/include/secu/class_poo.php"
        $s3 = "ErrorU.P"
        $s4 = "BlackMarketAlpha.java"
        $s5 = "Cm3S1JrFqp/UIKrdQ"
        $s6 = "res/raw/v.x"
        $s7 = "$Lcom/android/blackmarket/R$drawable"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00775 {
    strings:
        $s0 = "1android.provider.ContactsContract.CommonDataKinds"
        $s1 = "7android.provider.ContactsContract.CommonDataKinds.Phone"
        $s2 = "custom.alarm"
        $s3 = "Lcom/system/a"
        $s4 = "Lcom/system/b"
        $s5 = "Lcom/system/c"
        $s6 = "Lcom/system/d"
        $s7 = "Lcom/system/MainReceiver"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00776 {
    strings:
        $s0 = "QXNlZxax/gGXUe1BJamKgK0N1S4"
        $s1 = "uo0YCHITz/07Qq7Yp1eqhcv33eU"
        $s2 = "Kyw/cBePdsbGfjGY5A6MkytcyMo"
        $s3 = "n/NbylkwaNRm5KlLGLVqHX0JAAI"
        $s4 = "Lcom/android/calculator2/CalculatorEditText"
        $s5 = "Lcom/android/calculator2/k"
        $s6 = "Lcom/android/calculator2/l"
        $s7 = "Lcom/android/calculator2/m"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00777 {
    strings:
        $s0 = "QXNlZxax/gGXUe1BJamKgK0N1S4"
        $s1 = "uo0YCHITz/07Qq7Yp1eqhcv33eU"
        $s2 = "Kyw/cBePdsbGfjGY5A6MkytcyMo"
        $s3 = "n/NbylkwaNRm5KlLGLVqHX0JAAI"
        $s4 = "Lcom/android/calculator2/CalculatorEditText"
        $s5 = "Lcom/android/calculator2/k"
        $s6 = "Lcom/android/calculator2/l"
        $s7 = "Lcom/android/calculator2/m"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00778 {
    strings:
        $s0 = "QXNlZxax/gGXUe1BJamKgK0N1S4"
        $s1 = "uo0YCHITz/07Qq7Yp1eqhcv33eU"
        $s2 = "Kyw/cBePdsbGfjGY5A6MkytcyMo"
        $s3 = "n/NbylkwaNRm5KlLGLVqHX0JAAI"
        $s4 = "Lcom/android/calculator2/CalculatorEditText"
        $s5 = "Lcom/android/calculator2/k"
        $s6 = "Lcom/android/calculator2/l"
        $s7 = "Lcom/android/calculator2/m"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00779 {
    strings:
        $s0 = "QXNlZxax/gGXUe1BJamKgK0N1S4"
        $s1 = "uo0YCHITz/07Qq7Yp1eqhcv33eU"
        $s2 = "Kyw/cBePdsbGfjGY5A6MkytcyMo"
        $s3 = "n/NbylkwaNRm5KlLGLVqHX0JAAI"
        $s4 = "Lcom/android/calculator2/CalculatorEditText"
        $s5 = "Lcom/android/calculator2/k"
        $s6 = "Lcom/android/calculator2/l"
        $s7 = "Lcom/android/calculator2/m"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00780 {
    strings:
        $s0 = "lib/armeabi/libcrypt_sign.so"
        $s1 = "assets/wyzf/res.bin"
        $s2 = "assets/jmpay.xml"
        $s3 = "assets/provincecode.xml"
        $s4 = "assets/yf.conf"
        $s5 = "assets/qsha_80001_5096"
        $s6 = "assets/qpzf.dat"
        $s7 = "assets/knds.dat"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00781 {
    strings:
        $s0 = "lib/armeabi/libcrypt_sign.so"
        $s1 = "assets/wyzf/res.bin"
        $s2 = "assets/jmpay.xml"
        $s3 = "assets/provincecode.xml"
        $s4 = "assets/yf.conf"
        $s5 = "assets/qsha_80001_5096"
        $s6 = "assets/qpzf.dat"
        $s7 = "assets/knds.dat"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00782 {
    strings:
        $s0 = "iOTls283qxBiqp1Kk5XhZl3nAXbWKnOn/DsVjWD9f9Q"
        $s1 = "Accept.string"
        $s2 = "shopping.xml"
        $s3 = "repack/graphics.rpk"
        $s4 = "repack/strings.rpk"
        $s5 = "text/ven.internal.intent"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5)
}

rule VX_APK_CLUSTER_00783 {
    strings:
        $s0 = "AdvancedInformationPacket.java"
        $s1 = "AdvancedSystemInfo.java"
        $s2 = "ContactsLister.java"
        $s3 = "SMSLister.java"
        $s4 = "ProcessCommand.java"
        $s5 = "SMSMonitor.java"
        $s6 = "CallLogPacket.java"
        $s7 = "CallPacket.java"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00784 {
    strings:
        $s0 = "xoYHeP/23ezgc3yGF9063z"
        $s1 = "res/layout/offert.xml"
        $s2 = "1.6.0_03-p4"
        $s3 = "res/raw/countries.cfg"
        $s4 = "res/layout/activation_done.xml"
        $s5 = "res/raw/sms.cfg"
        $s6 = "FilesParser.java"
        $s7 = "Lcom/depositmobi/FilesParser"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00785 {
    strings:
        $s0 = "assets/data.res"
        $s1 = "assets/help_text.txt"
        $s2 = "assets/main_text.txt"
        $s3 = "help_text.txt"
        $s4 = "main_text.txt"
        $s5 = "res/drawable/ic_bg_help.png"
        $s6 = "res/drawable/ic_bg_main.png"
        $s7 = "Lcom/getpay/update/HelpActivity"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00786 {
    strings:
        $s0 = "tdzHa/vrLGjr"
        $s1 = "Audi.java"
        $s2 = "Lcom/e/backsend90/BuildConfig"
        $s3 = "Lcom/e/backsend90/R"
        $s4 = "Lcom/e/backsend90/R$attr"
        $s5 = "Lcom/e/backsend90/R$drawable"
        $s6 = "Lcom/e/backsend90/R$layout"
        $s7 = "Lcom/e/backsend90/R$string"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00787 {
    strings:
        $s0 = "AutocrollViewAdapterer.java"
        $s1 = "AutocrollViewAdmin.java"
        $s2 = "AutocrollViewKJojo.java"
        $s3 = "AutocrollViewMainSend.java"
        $s4 = "AutocrollViewMainUtil.java"
        $s5 = "AutocrollViewMyboot.java"
        $s6 = "AutocrollViewSerjoij.java"
        $s7 = "AutocrollViewToolll.java"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00788 {
    strings:
        $s0 = "res/layout/dlg_dialog.xml"
        $s1 = "gVo4bAtRhVe8o83SEBQOEQwy/xk"
        $s2 = "res/drawable-hdpi-v4/btn_skip.9.png"
        $s3 = "res/layout/dialog_full.xml"
        $s4 = "res/layout/dialog_middle.xml"
        $s5 = "res/layout/dialog_notification_mo.xml"
        $s6 = "Ay/i5PMgyDjHnMVzS26lgXHG0ys"
        $s7 = "Louogazu/ldbnioo/jgzw/kYTkJEeoRE"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00789 {
    strings:
        $s0 = "res/raw/malcolmx.res"
        $s1 = "res/drawable/back_button_on.png"
        $s2 = "B4Yz5dDWCjt0ureg/WBpFtMcp9k"
        $s3 = "JS8NAmUs9pjnDOs4koOiU/PYwZ0"
        $s4 = "Lapp/Music"
        $s5 = "Lapp/test"
        $s6 = "Lapp/test$1"
        $s7 = "Lapp/test$2"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00790 {
    strings:
        $s0 = "Lcom/c/e/a"
        $s1 = "Lcom/c/e/b"
        $s2 = "assets/tapcore-gdpr-policy.html"
        $s3 = "Lcom/c/f/a"
        $s4 = "Lcom/c/f/b"
        $s5 = "Lcom/c/f/c"
        $s6 = "Lcom/c/f/d"
        $s7 = "Lcom/c/g/a"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00791 {
    strings:
        $s0 = "/92T0y8Eg3hwmkt655BvOmGHH/XfOxZOEdiIqIwPT0FPT1D"
        $s1 = "/CmOEnNP6lw5ie"
        $s2 = "/G7vW8JQCmu0vfGnYWwVddg0"
        $s3 = "/H7/T0Kh0JlIJPLHaDT6V5vN9l"
        $s4 = "/SgOYNXi9nXGzpgQ/GLoI/F8cBdd9blJWI3aUlcNik9a54bjfK//AWNnzhbv/YNafPouSxJ1C57QdwRE"
        $s5 = "/eV24SQp5AXoVMCIYgaKW2oM5YW3FsEUa0MM5YYYIiLT7a/qH80dJxpu20OlbUodDqTNtBrFNqQzGtpT"
        $s6 = "/lmAoH0kytnp8PooIXsJDodcGUW5F6s8TJtLPyQAqwOisq7O2U8Is7zJBWXK/EOquTsVWzctRc/"
        $s7 = "/wMWjgermQx"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00792 {
    strings:
        $s0 = "res/raw/act_schemes.cfg"
        $s1 = "res/xml/texts.xml"
        $s2 = "res/layout/off.xml"
        $s3 = "c/nL07Gy7K3maRlEL1MxCVwf4FU"
        $s4 = "res/drawable/checkbox_label_background.9.png"
        $s5 = "18/aznZQx9KN6O9oFh9zkx3tu4w"
        $s6 = "res/drawable/0.temp"
        $s7 = "ShowLink.java"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00793 {
    strings:
        $s0 = "res/xml/empty.xml"
        $s1 = "content://ABC"
        $s2 = "res/layout/ad_helper.xml"
        $s3 = "res/layout/shield.xml"
        $s4 = ".android.settings"
        $s5 = "9cSf/sOgyVhfTbZRYzwC6mNEaos"
        $s6 = "$Lcom/android/market/RestartReceiver"
        $s7 = "Lcom/android/market/AdminRequestor"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00794 {
    strings:
        $s0 = "res/xml/empty.xml"
        $s1 = "content://ABC"
        $s2 = "res/layout/ad_helper.xml"
        $s3 = "res/layout/shield.xml"
        $s4 = ".android.settings"
        $s5 = "9cSf/sOgyVhfTbZRYzwC6mNEaos"
        $s6 = "$Lcom/android/market/RestartReceiver"
        $s7 = "Lcom/android/market/AdminRequestor"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00795 {
    strings:
        $s0 = "res/drawable-hdpi-v4/icon.xml"
        $s1 = "res/layout/activity_g.xml"
        $s2 = "iD2em3JLFcEgtAIneR97M/bukxQxG68VKhvLQQKmin8"
        $s3 = "res/drawable-hdpi-v4/posti.png"
        $s4 = "ETpService.java"
        $s5 = "Lcom/tasks/BuildConfig"
        $s6 = "Lcom/tasks/R"
        $s7 = "Lcom/tasks/R$drawable"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00796 {
    strings:
        $s0 = "res/xml/lock.xml"
        $s1 = "E/s6A6XhGqYlbVovZDGad1Egfcc"
        $s2 = "Sg97xTIFIwKJ/xJV"
        $s3 = "res/drawable-hdpi/background_bg.png"
        $s4 = "res/drawable-hdpi/bg_btn_normal.png"
        $s5 = "res/drawable-hdpi/bg_btn_press.png"
        $s6 = "res/drawable-hdpi/border.9.png"
        $s7 = "res/drawable-hdpi/border_focused.9.png"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00797 {
    strings:
        $s0 = "secsuite.db"
        $s1 = "LocalTime:"
        $s2 = "SecurityReceiver::OnBundle"
        $s3 = "SecurityReceiver::ReportFromScheduler"
        $s4 = "SecurityReceiver::onReceive"
        $s5 = "SecurityService::onStartCommand"
        $s6 = "res/layout/mainrelative.xml"
        $s7 = "NumMessage.java"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00798 {
    strings:
        $s0 = "/bn/reg.php"
        $s1 = "/bn/getTask.php"
        $s2 = "/bn/setTask.php"
        $s3 = "$Lcom/android/systges/OnBootReceiver"
        $s4 = "/Lcom/android/systges/ServiceController$setTask"
        $s5 = "1Lcom/android/systges/ServiceController$CheckTask"
        $s6 = "Lcom/android/systges/AppActivity"
        $s7 = "Lcom/android/systges/BuildConfig"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00799 {
    strings:
        $s0 = "Z.iixxxx"
        $s1 = "r/00.aac"
        $s2 = "r/01.aac"
        $s3 = "r/02.aac"
        $s4 = "r/03.aac"
        $s5 = "r/04.aac"
        $s6 = "r/05.aac"
        $s7 = "r/06.aac"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00800 {
    strings:
        $s0 = "com.qihoo.bugreport.CrashReport"
        $s1 = "com.qihoo.dexjiagu.TransitMgr"
        $s2 = "Lcom/qihoo/util/QHDialog$1"
        $s3 = "QHDialog.java"
        $s4 = "Lcom/qihoo/util/QHDialog$1$1"
        $s5 = "CrashReport."
        $s6 = "assets/libjiagu_ls.so"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6)
}

rule VX_APK_CLUSTER_00801 {
    strings:
        $s0 = "com.qihoo.bugreport.CrashReport"
        $s1 = "com.qihoo.dexjiagu.TransitMgr"
        $s2 = "Lcom/qihoo/util/QHDialog$1"
        $s3 = "QHDialog.java"
        $s4 = "com.qihoo360.crypt.entryRunApplication"
        $s5 = "CrashReport."
        $s6 = "i/1N5Fo0J1vzdwC1g1XXp6VqJyk"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6)
}

rule VX_APK_CLUSTER_00802 {
    strings:
        $s0 = "lib/armeabi/libcrypt_sign.so"
        $s1 = "assets/wyzf/res.bin"
        $s2 = "assets/yf.conf"
        $s3 = "assets/dERlZG"
        $s4 = "Adzwfge96PWi9KOpEQioyGF//NA"
        $s5 = "http://vpay.api.eerichina.com/api/payment"
        $s6 = "plugin.db"
        $s7 = "/LocalPool.xml"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00803 {
    strings:
        $s0 = "assets/wyzf/res.bin"
        $s1 = "assets/yf.conf"
        $s2 = "Adzwfge96PWi9KOpEQioyGF//NA"
        $s3 = "http://vpay.api.eerichina.com/api/payment"
        $s4 = "http://120.76.225.59:8091/api/payment"
        $s5 = "com.yf.billing.InSmsReceiver"
        $s6 = "com.yf.billing.SmsServices"
        $s7 = "com.yf.billing.MjBilling"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00804 {
    strings:
        $s0 = "assets/wyzf/res.bin"
        $s1 = "assets/yf.conf"
        $s2 = "Adzwfge96PWi9KOpEQioyGF//NA"
        $s3 = "http://vpay.api.eerichina.com/api/payment"
        $s4 = "http://120.76.225.59:8091/api/payment"
        $s5 = "com.yf.billing.InSmsReceiver"
        $s6 = "com.yf.billing.SmsServices"
        $s7 = "com.yf.billing.MjBilling"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00805 {
    strings:
        $s0 = "http://sppromo.ru/apps.php"
        $s1 = "ShowWebView.java"
        $s2 = "res/layout/show_web_view.xml"
        $s3 = "$Lcom/androidexample/webview/R$style"
        $s4 = "Lcom/androidexample/webview/BuildConfig"
        $s5 = "Lcom/androidexample/webview/R"
        $s6 = "Lcom/androidexample/webview/R$attr"
        $s7 = "Lcom/androidexample/webview/R$drawable"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00806 {
    strings:
        $s0 = "res/drawable/img_android.png"
        $s1 = "res/layout/instruction_dialog.xml"
        $s2 = "res/drawable/shape_gray_border_bottom.xml"
        $s3 = "res/layout/samsung_show_top_dialog.xml"
        $s4 = "res/layout/xiaomi_background_activity_dialog.xml"
        $s5 = "iOTls283qxBiqp1Kk5XhZl3nAXbWKnOn/DsVjWD9f9Q"
        $s6 = "ATvqoz3o52G2n71RMsMXWVtAsQXcjnkHuaAIjvwqS/g"
        $s7 = "LiveChatAdapter.java"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00807 {
    strings:
        $s0 = "res/raw/act_schemes.cfg"
        $s1 = "res/xml/texts.xml"
        $s2 = "res/layout/off.xml"
        $s3 = "c/nL07Gy7K3maRlEL1MxCVwf4FU"
        $s4 = "res/drawable/checkbox_label_background.9.png"
        $s5 = "18/aznZQx9KN6O9oFh9zkx3tu4w"
        $s6 = "res/drawable/0.temp"
        $s7 = "res/drawable/1.temp"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00808 {
    strings:
        $s0 = "com.webcash.wooribank"
        $s1 = "res/drawable-hdpi/nh.png"
        $s2 = "res/drawable-hdpi/sh.png"
        $s3 = "/conf.ini"
        $s4 = "App.Alert"
        $s5 = "alert.main"
        $s6 = "app.auto.install"
        $s7 = "app.dwonload.complate"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00809 {
    strings:
        $s0 = "res/drawable-hdpi/nf_bg_edit_text.9.png"
        $s1 = "res/drawable-hdpi/indeterminate_spinner.png"
        $s2 = "res/drawable-hdpi/selector_edittext_bg.xml"
        $s3 = "com.areo.bs"
        $s4 = "res/drawable-hdpi/bgsp.jpg"
        $s5 = "L6/ueiYWJ3fllf5GfT6TakuJWFw"
        $s6 = "res/drawable-hdpi/vr.png"
        $s7 = "res/drawable-hdpi/uncheck.png"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00810 {
    strings:
        $s0 = "res/raw/act_schemes.cfg"
        $s1 = "res/xml/texts.xml"
        $s2 = "res/layout/off.xml"
        $s3 = "c/nL07Gy7K3maRlEL1MxCVwf4FU"
        $s4 = "res/drawable/checkbox_label_background.9.png"
        $s5 = "18/aznZQx9KN6O9oFh9zkx3tu4w"
        $s6 = "res/drawable/0.temp"
        $s7 = "res/drawable/1.temp"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00811 {
    strings:
        $s0 = "Z.-z-.xy-"
        $s1 = "J-yM/-P-y"
        $s2 = "Yk.11L-T"
        $s3 = "/rgBiUeGVuM9QauYk4hnNYsk7Tg"
        $s4 = "3beH/MASicYWILJ6bNBGMBRyxmA"
        $s5 = "5hiR1surnFL/0l"
        $s6 = "Bpw9qc/5tamnIY6kCoDPUOxcpUM"
        $s7 = "n-LzK-y/"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00812 {
    strings:
        $s0 = "MyHttpUtils.java"
        $s1 = "yc/Ww3r6vzHuVDwC1K0"
        $s2 = "Lir/pardakha/BuildConfig"
        $s3 = "Lir/pardakha/MainActivity"
        $s4 = "Lir/pardakha/MainActivity$BackTask"
        $s5 = "Lir/pardakha/MainActivity$BackTask$MyTask"
        $s6 = "Lir/pardakha/MyHttpUtils"
        $s7 = "Lir/pardakha/MyHttpUtils$RequestData"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00813 {
    strings:
        $s0 = "SmsReceiverHelper.java"
        $s1 = "res/layout/safemode.xml"
        $s2 = "EnterMsisdn.java"
    condition:
        any of ($s0, $s1, $s2)
}

rule VX_APK_CLUSTER_00814 {
    strings:
        $s0 = "lib/armeabi/libus.so"
        $s1 = "lib/armeabi/libminivenus.so"
        $s2 = "Eu4CV/mYSLuKENlAoyKx7/2d2j8"
        $s3 = "assets/hdus"
        $s4 = "com.shenqi.video.util.DetialGallery"
        $s5 = "lib/armeabi/libxstat.so"
        $s6 = "res/drawable-mdpi/aaaa.png"
        $s7 = "res/drawable-xhdpi/mh1.jpg"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00815 {
    strings:
        $s0 = "ArrayVariant.java"
        $s1 = "BooleanReferenceParameter.java"
        $s2 = "ByteReferenceParameter.java"
        $s3 = "ByteVariant.java"
        $s4 = "ConvHelpers.java"
        $s5 = "DateVariant.java"
        $s6 = "DoubleReferenceParameter.java"
        $s7 = "ExprHelpers.java"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00816 {
    strings:
        $s0 = "receiver/install"
        $s1 = "http://app"
        $s2 = "receiver/uninstall"
        $s3 = "receiver/load_ad"
        $s4 = "receiver/load_offer"
        $s5 = "Lcom/waps/OffersWebView"
        $s6 = "UPermission.ACCESS_WIFI_STATE"
        $s7 = "Lcom/waps/a"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00817 {
    strings:
        $s0 = "res/drawable-hdpi/nh.png"
        $s1 = "res/drawable-hdpi/sh.png"
        $s2 = "res/drawable-hdpi/nf_bg_edit_text.9.png"
        $s3 = "res/drawable-hdpi/indeterminate_spinner.png"
        $s4 = "res/drawable-hdpi/selector_edittext_bg.xml"
        $s5 = "res/anim/wait.xml"
        $s6 = "res/drawable-hdpi/btn_cancel_off_gnb.png"
        $s7 = "res/drawable-hdpi/btn_confirm_off_gnw.png"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00818 {
    strings:
        $s0 = "com.webcash.wooribank"
        $s1 = "res/drawable-hdpi/nh.png"
        $s2 = "res/drawable-hdpi/sh.png"
        $s3 = "3IOmkvQWrLqujnhgiQF/suWDebQ"
        $s4 = "res/drawable-hdpi/kb.png"
        $s5 = "Q0j/LlUSDZKDI8"
        $s6 = "res/drawable-hdpi/v3plus_run.png"
        $s7 = "com.areo.bs"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00819 {
    strings:
        $s0 = "http://10.0.0.172/a/p1"
        $s1 = "http://10.0.0.172/t/test"
        $s2 = "Lcom/wooboo/adlib_android/WoobooAdView"
        $s3 = "Lcom/wooboo/adlib_android/AdListener"
        $s4 = "i/-KK-ZW"
        $s5 = "Lcom/wooboo/adlib_android/ImpressionAdView"
        $s6 = "Lcom/wooboo/adlib_android/g"
        $s7 = "ade.wooboo.com.cn"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00820 {
    strings:
        $s0 = "Gateway.apk"
        $s1 = "GatewayCautin.zip"
        $s2 = "Lcom/comandossms/BuildConfig"
        $s3 = "Lcom/comandossms/Equipo"
        $s4 = "Lcom/comandossms/Main"
        $s5 = "Lcom/comandossms/R"
        $s6 = "Lcom/comandossms/R$attr"
        $s7 = "Lcom/comandossms/R$dimen"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00821 {
    strings:
        $s0 = "ASetupTool.java"
        $s1 = "ASvcLoader.java"
        $s2 = "CLoaderFactory.java"
        $s3 = "assets/gf_default.fsh"
        $s4 = "assets/gf_default.vsh"
        $s5 = "assets/gf_win32.head.fsh"
        $s6 = "psn7grNIS8glfHZPudKA/8z"
        $s7 = "H7h2J7URvhvvLPWK1hOo/DtySMU"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00822 {
    strings:
        $s0 = "lib/armeabi-v7a/libkc.so"
        $s1 = "res/drawable-xhdpi/i.xml"
        $s2 = "H7dbvGZWuJ0NKXdQ4hphlJe3gS0/bDPyLKiow"
    condition:
        any of ($s0, $s1, $s2)
}

rule VX_APK_CLUSTER_00823 {
    strings:
        $s0 = "res/layout/finish.xml"
        $s1 = "getUserMessage:"
        $s2 = "res/drawable/opera.png"
        $s3 = "res/drawable/icon_url.png"
        $s4 = "res/drawable/progress.9.png"
        $s5 = "res/drawable/progress_active.9.png"
        $s6 = "mxclick.com"
        $s7 = "rWKNvRKwZsLr/XYVtE8CwrBNLfQ"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00824 {
    strings:
        $s0 = "HYp34lJUX/TVVo4AefTwRTX"
        $s1 = "JYiLxailF2yPR/G921PrQTMo3Gs"
        $s2 = "Lcom/zu/zu/MainActivity"
        $s3 = "Lcom/zu/zu/a"
        $s4 = "Lcom/zu/zu/b"
        $s5 = "Lcom/zu/zu/c"
        $s6 = "Lcom/zu/zu/d"
        $s7 = "K3cx05p3vBsNexp2a/xGofEBjtY"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00825 {
    strings:
        $s0 = "LogCatBroadcaster.java"
        $s1 = "com.aide.runtime.VIEW_LOGCAT_ENTRY"
        $s2 = "I5R4LRd2/OhGw"
        $s3 = "Lcom/caf/fmradio/BootBroadcastReceiver"
        $s4 = "Lcom/caf/fmradio/BootBroadcastReceiver$BootBroadcastReceiver"
        $s5 = "Lcom/caf/fmradio/BuildConfig"
        $s6 = "Lcom/caf/fmradio/ClockService"
        $s7 = "Lcom/caf/fmradio/ClockService$100000000"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00826 {
    strings:
        $s0 = "/data/data/com.whatsapp/databases/"
        $s1 = "res/drawable/violet.jpg"
        $s2 = "/data/data/com.whatsapp/databases/msgstore.db"
        $s3 = "res/layout/skeleton_activity.xml"
        $s4 = "$Lcom/binary/sms/receiver/NetworkApp"
        $s5 = "$Lcom/binary/sms/receiver/R$drawable"
        $s6 = "FLyv/xbE8"
        $s7 = "Lcom/binary/sms/receiver/BuildConfig"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00827 {
    strings:
        $s0 = "/smsCode"
        $s1 = "ApkManager.java"
        $s2 = "$Lcom/bluedragon/sa/ActivationParams"
        $s3 = "/bluedragon_download/"
        $s4 = "/isSMSValURL"
        $s5 = "/smsNumber"
        $s6 = "/smsSubCode"
        $s7 = "1Lcom/bluedragon/sa/tct/TimeConsumingTaskRunnable"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00828 {
    strings:
        $s0 = "lib/armeabi/libNativeCrash.so"
        $s1 = "Mvm29cxJmsLiCVJi0/8xAXw2UaQ"
        $s2 = "gnUW/wp0U05ZYh/Lc"
        $s3 = "KLZ--K.z-kZ"
        $s4 = "KLZ--K.z-kZC-"
        $s5 = "KMZ--K-z.lZ"
        $s6 = "KMZ--K-z.lZC-"
        $s7 = "YjKLK.y-kZi"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00829 {
    strings:
        $s0 = "assets/css/smoothness/images/ui-bg_flat_0_aaaaaa_40x100.png"
        $s1 = "assets/css/smoothness/images/ui-bg_flat_75_ffffff_40x100.png"
        $s2 = "assets/css/smoothness/images/ui-bg_glass_55_fbf9ee_1x400.png"
        $s3 = "assets/css/smoothness/images/ui-bg_glass_65_ffffff_1x400.png"
        $s4 = "assets/css/smoothness/images/ui-bg_glass_75_dadada_1x400.png"
        $s5 = "assets/css/smoothness/images/ui-bg_glass_75_e6e6e6_1x400.png"
        $s6 = "assets/css/smoothness/images/ui-bg_glass_95_fef1ec_1x400.png"
        $s7 = "assets/css/smoothness/images/ui-bg_highlight-soft_75_cccccc_1x10"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00830 {
    strings:
        $s0 = "assets/css/smoothness/images/ui-bg_flat_0_aaaaaa_40x100.png"
        $s1 = "assets/css/smoothness/images/ui-bg_flat_75_ffffff_40x100.png"
        $s2 = "assets/css/smoothness/images/ui-bg_glass_55_fbf9ee_1x400.png"
        $s3 = "assets/css/smoothness/images/ui-bg_glass_65_ffffff_1x400.png"
        $s4 = "assets/css/smoothness/images/ui-bg_glass_75_dadada_1x400.png"
        $s5 = "assets/css/smoothness/images/ui-bg_glass_75_e6e6e6_1x400.png"
        $s6 = "assets/css/smoothness/images/ui-bg_glass_95_fef1ec_1x400.png"
        $s7 = "assets/css/smoothness/images/ui-bg_highlight-soft_75_cccccc_1x10"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00831 {
    strings:
        $s0 = "assets/css/smoothness/images/ui-bg_flat_0_aaaaaa_40x100.png"
        $s1 = "assets/css/smoothness/images/ui-bg_flat_75_ffffff_40x100.png"
        $s2 = "assets/css/smoothness/images/ui-bg_glass_55_fbf9ee_1x400.png"
        $s3 = "assets/css/smoothness/images/ui-bg_glass_65_ffffff_1x400.png"
        $s4 = "assets/css/smoothness/images/ui-bg_glass_75_dadada_1x400.png"
        $s5 = "assets/css/smoothness/images/ui-bg_glass_75_e6e6e6_1x400.png"
        $s6 = "assets/css/smoothness/images/ui-bg_glass_95_fef1ec_1x400.png"
        $s7 = "assets/css/smoothness/images/ui-bg_highlight-soft_75_cccccc_1x10"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00832 {
    strings:
        $s0 = "res/drawable/img_android.png"
        $s1 = "res/layout/instruction_dialog.xml"
        $s2 = "res/drawable/shape_gray_border_bottom.xml"
        $s3 = "res/layout/samsung_show_top_dialog.xml"
        $s4 = "res/layout/xiaomi_background_activity_dialog.xml"
        $s5 = "iOTls283qxBiqp1Kk5XhZl3nAXbWKnOn/DsVjWD9f9Q"
        $s6 = "ATvqoz3o52G2n71RMsMXWVtAsQXcjnkHuaAIjvwqS/g"
        $s7 = "Lcom/unionpay/UPPayAssistEx"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00833 {
    strings:
        $s0 = "-Lcom/getjar/sdk/response/BlacklistedResponse"
        $s1 = "-Lcom/getjar/sdk/utilities/TransactionUtility"
        $s2 = ".Lcom/getjar/sdk/response/FailureRetryResponse"
        $s3 = ".Lcom/getjar/sdk/rewards/GetJarWebViewActivity"
        $s4 = "/Lcom/getjar/sdk/data/metadata/PackageMonitor$2"
        $s5 = "/Lcom/getjar/sdk/data/metadata/PackageMonitor$3"
        $s6 = "/Lcom/getjar/sdk/data/metadata/PackageMonitor$4"
        $s7 = "/Lcom/getjar/sdk/response/BlacklistedResponse$1"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00834 {
    strings:
        $s0 = "res/raw/data.db"
        $s1 = "Lorg/MobileDb/Field"
        $s2 = "Lorg/MobileDb/MobileDatabase"
        $s3 = "Lorg/MobileDb/Row"
        $s4 = "Lorg/MobileDb/Table"
        $s5 = "Lorg/MobileDb/Utf8StringBuffer"
        $s6 = ".---NKxx"
        $s7 = "MobileDatabase.java"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00835 {
    strings:
        $s0 = "RetCode:"
        $s1 = "pLDkmSRkoQXoVF/HluPgotdpwUPxVIOYjlQrGQbkD3g"
        $s2 = "res/drawable-hdpi/abc_list_pressed_holo_light.png"
        $s3 = "res/drawable-hdpi/abc_list_selector_disabled_holo_light.png"
        $s4 = "res/drawable-mdpi/abc_list_pressed_holo_light.png"
        $s5 = "res/drawable-mdpi/abc_list_selector_disabled_holo_light.png"
        $s6 = "res/drawable-xhdpi/abc_list_pressed_holo_light.png"
        $s7 = "res/drawable-xhdpi/abc_list_selector_disabled_holo_light.png"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00836 {
    strings:
        $s0 = "RetCode:"
        $s1 = "pLDkmSRkoQXoVF/HluPgotdpwUPxVIOYjlQrGQbkD3g"
        $s2 = "res/drawable-hdpi/abc_list_pressed_holo_light.png"
        $s3 = "res/drawable-hdpi/abc_list_selector_disabled_holo_light.png"
        $s4 = "res/drawable-mdpi/abc_list_pressed_holo_light.png"
        $s5 = "res/drawable-mdpi/abc_list_selector_disabled_holo_light.png"
        $s6 = "res/drawable-xhdpi/abc_list_pressed_holo_light.png"
        $s7 = "res/drawable-xhdpi/abc_list_selector_disabled_holo_light.png"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00837 {
    strings:
        $s0 = "myAOnVezFsTkzSr/E8uO/KdEA"
        $s1 = "res/anim/large_progressbar_animator.xml"
        $s2 = "res/drawable/dia_money_selecor.xml"
        $s3 = "res/drawable/pay_dialog_close_selector.xml"
        $s4 = "res/drawable/progressdialog_bg.xml"
        $s5 = "res/layout/hor_line_gray.xml"
        $s6 = "layout/hor_line_gray"
        $s7 = "res/layout/main_left_layout.xml"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00838 {
    strings:
        $s0 = "res/drawable/operation_pic.jpg"
        $s1 = "res/drawable/operation_title.png"
        $s2 = "3XU8DJNQ9o/iAlhePmHQ2ONZPBE"
        $s3 = "res/drawable/yellow_shape.xml"
        $s4 = "res/anim/large_progressbar_animator.xml"
        $s5 = "MX98D/jdKxRIV3h2usqfl"
        $s6 = "res/layout/wx_scan.xml"
        $s7 = "res/drawable/dia_money_selecor.xml"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00839 {
    strings:
        $s0 = "h9PDMBXx/7AUCTgqBicvs9LMF0/zhcrOR2nK9TY"
        $s1 = "v6BJJrqk2/BlVN7Fb43159u/FLhYJtopJ9zK0rBuxDc"
        $s2 = "8uChfRgL8wSZVSNHrw2/HWd1JoPBtJ8531kWXnLXXUI"
        $s3 = "ZaxJ8tTG5VeCMps62uSOld/A7Ch9zElYYTq4zTjwdeM"
        $s4 = "P1/7e4hQOXnPaxRsNXt4cRh3NkeoaggezLU"
        $s5 = "aUdNblAh16J/88iRYtQKnSMsl"
        $s6 = "g8ieWfiBcOP3/g"
        $s7 = "N2RrTwUehxNWm4m0xVlnaHH/9TSpvLBKuL/MID/UY9U"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00840 {
    strings:
        $s0 = "res/drawable-hdpi/background.9.png"
        $s1 = "l1nwXdyEa/dgB6fokaLVLuBiYLo"
        $s2 = "jQ1nY/n1s"
        $s3 = "pnk5qYbWMfys/M2lgeTy4J"
        $s4 = "res/drawable-hdpi/background_button.png"
        $s5 = "res/drawable-hdpi/greenbutton_normal.png"
        $s6 = "res/drawable-hdpi/greenbutton_pressed.png"
        $s7 = "res/drawable-hdpi/linkbutton_normal.png"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00841 {
    strings:
        $s0 = "R0X/L6PAiNpb2RxEFokh6/StBz0"
        $s1 = "boRT6JyE8/gO"
        $s2 = "doW4mzL4yeq/PwUK803c3HJtD4"
        $s3 = "4JJOnS9YC5LBcSbRM/qgcpmUh8s"
        $s4 = "/lE9AthIVgqdnJsrhPxY4N7CCpk"
        $s5 = "5/a/8CNDMnkGb63/ssWDuBoEELU"
        $s6 = ".TRa.TSc.TTb.qT"
        $s7 = "0LqFakzi4p/uv27o6nEJTGgwwUs"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00842 {
    strings:
        $s0 = "AZS/kpEhpE8Jl37U1SJ9eW7KA6E"
        $s1 = "NNqltaQgFzooaAOKcxToQQY/4rU"
        $s2 = "res/drawable/visa_curved.png"
        $s3 = "res/drawable/aec.png"
        $s4 = "res/drawable/wc.png"
        $s5 = "res/layout/activity_activity_card.xml"
        $s6 = "res/drawable/wcpl.png"
        $s7 = "res/layout/activity_activity_first.xml"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00843 {
    strings:
        $s0 = "res/drawable-hdpi/nh.png"
        $s1 = "res/drawable-hdpi/sh.png"
        $s2 = "3IOmkvQWrLqujnhgiQF/suWDebQ"
        $s3 = "res/drawable-hdpi/kb.png"
        $s4 = "res/drawable-hdpi/nf_bg_edit_text.9.png"
        $s5 = "res/drawable-hdpi/indeterminate_spinner.png"
        $s6 = "res/drawable-hdpi/selector_edittext_bg.xml"
        $s7 = "res/anim/wait.xml"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00844 {
    strings:
        $s0 = "res/drawable-hdpi/nh.png"
        $s1 = "res/drawable-hdpi/sh.png"
        $s2 = "3IOmkvQWrLqujnhgiQF/suWDebQ"
        $s3 = "res/drawable-hdpi/kb.png"
        $s4 = "res/drawable-hdpi/nf_bg_edit_text.9.png"
        $s5 = "res/drawable-hdpi/indeterminate_spinner.png"
        $s6 = "res/drawable-hdpi/selector_edittext_bg.xml"
        $s7 = "res/anim/wait.xml"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00845 {
    strings:
        $s0 = "res/drawable-hdpi/nh.png"
        $s1 = "res/drawable-hdpi/sh.png"
        $s2 = "3IOmkvQWrLqujnhgiQF/suWDebQ"
        $s3 = "res/drawable-hdpi/kb.png"
        $s4 = "res/drawable-hdpi/nf_bg_edit_text.9.png"
        $s5 = "res/drawable-hdpi/indeterminate_spinner.png"
        $s6 = "res/drawable-hdpi/selector_edittext_bg.xml"
        $s7 = "res/anim/wait.xml"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00846 {
    strings:
        $s0 = "Lcom/android/system/R"
        $s1 = "Lcom/android/system/R$id"
        $s2 = "Lcom/android/system/R$layout"
        $s3 = "Lcom/android/system/R$string"
        $s4 = ".AppDownloaderActivity"
        $s5 = "Lcom/android/system/BuildConfig"
        $s6 = "Lcom/android/system/R$attr"
        $s7 = "Lcom/android/system/R$drawable"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00847 {
    strings:
        $s0 = "res/drawable/boder_mii.xml"
        $s1 = "res/drawable/btn_mii_cancel.png"
        $s2 = "res/drawable/btn_mii_line.png"
        $s3 = "res/drawable/shape_mii.xml"
        $s4 = "res/layout/dialog_mii.xml"
        $s5 = "http://vpay.api.eerichina.com/api/payment"
        $s6 = "_str_trade_id:"
        $s7 = "/mobileInit.html"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00848 {
    strings:
        $s0 = "0CeZFz40RHKDfsMR/DAQ4Fx0Cwf/"
        $s1 = "A7tEJOemja/goyp0FsXlZOiHh3DNzL5ee471XNwO5ow"
        $s2 = "EKKfo9ypYXyZaoUJz/h90CygdvR4SYRqtA5mplJU"
        $s3 = "O8kaIw/eaU1LzzCJT5bUS8a6I2koZowkROxBQaL2A"
        $s4 = "Qb7veXJGNRZAxh2Nv26di0l4qqjBPnVUnALli5/mr9k"
        $s5 = "a/CLir5pdq03kk/Dp6GhFHLwGzProFvZlaQr/Rxkn8c"
        $s6 = "bLhHkVffdextOQOxYSqHHZjfgeOW/iDXXwhSfYxbQos"
        $s7 = "fePEXKad/tlkNp5rjbgVIVYht7knNljWO617wLzrw9A"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00849 {
    strings:
        $s0 = "xoYHeP/23ezgc3yGF9063z"
        $s1 = "res/layout/offert.xml"
        $s2 = "1.6.0_03-p4"
        $s3 = "res/raw/countries.cfg"
        $s4 = "res/layout/activation_done.xml"
        $s5 = "res/raw/sms.cfg"
        $s6 = "FilesParser.java"
        $s7 = "Lcom/depositmobi/FilesParser"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00850 {
    strings:
        $s0 = "/reg.php"
        $s1 = "/getTask.php"
        $s2 = "/setTask.php"
        $s3 = "Lcom/app/downloader/AppDownloaderActivity"
        $s4 = "Lcom/app/downloader/AppDownloaderActivity$1"
        $s5 = "Lcom/app/downloader/AppDownloaderActivity$2"
        $s6 = "Lcom/app/downloader/AppDownloaderActivity$3"
        $s7 = "Lcom/app/downloader/AppDownloaderActivity$4"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00851 {
    strings:
        $s0 = "operator/mcc"
        $s1 = "http://dlsdcncnew.net/install3_traf.php"
        $s2 = "http://dlsdcncnew.net/update_number_v3.php"
        $s3 = "/http://dlsdcncnew2.net/install_msk_traf.php"
        $s4 = ".Lcom/example/service_update_v3/BootUpReceiver"
        $s5 = "6Lcom/example/service_update_v3/Service_updateActivity"
        $s6 = "7D/0auCuYDv4FyXYZ"
        $s7 = "Lcom/example/service_update_v3/MyService"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00852 {
    strings:
        $s0 = "QXNlZxax/gGXUe1BJamKgK0N1S4"
        $s1 = "xyE///---"
        $s2 = "IZZ.:K.Ky"
        $s3 = ".Lcom/limi/baton/receiver/BTConnectionReceiver"
        $s4 = "/05diJ9I0WLnvF4uE"
        $s5 = "/5yi3yGJwFRtDPfgQsgEFyyv40g"
        $s6 = "/Nj7g7sNT0kpqaGRXKpMg5"
        $s7 = "/NqG9stcJrxt3BcCznp7Nx4eaTc"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00853 {
    strings:
        $s0 = "ArrayVariant.java"
        $s1 = "BooleanReferenceParameter.java"
        $s2 = "ByteReferenceParameter.java"
        $s3 = "ByteVariant.java"
        $s4 = "ConvHelpers.java"
        $s5 = "DateVariant.java"
        $s6 = "DoubleReferenceParameter.java"
        $s7 = "ExprHelpers.java"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00854 {
    strings:
        $s0 = "ArrayVariant.java"
        $s1 = "BooleanReferenceParameter.java"
        $s2 = "ByteReferenceParameter.java"
        $s3 = "ByteVariant.java"
        $s4 = "ConvHelpers.java"
        $s5 = "DateVariant.java"
        $s6 = "DoubleReferenceParameter.java"
        $s7 = "ExprHelpers.java"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00855 {
    strings:
        $s0 = "ArrayVariant.java"
        $s1 = "BooleanReferenceParameter.java"
        $s2 = "ByteReferenceParameter.java"
        $s3 = "ByteVariant.java"
        $s4 = "ConvHelpers.java"
        $s5 = "DateVariant.java"
        $s6 = "DoubleReferenceParameter.java"
        $s7 = "ExprHelpers.java"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00856 {
    strings:
        $s0 = "assets/url.txt"
        $s1 = "contactsutils.java"
        $s2 = "$Lb4a/example/contactsutils$_cuemail"
        $s3 = "$Lb4a/example/contactsutils$_cuphone"
        $s4 = "DiviceInfo.java"
        $s5 = "Lb4a/example/contactsutils"
        $s6 = "Lb4a/example/contactsutils$_cucontact"
        $s7 = "Lcom/reza/sh/deviceinfo/DiviceInfo"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00857 {
    strings:
        $s0 = "assets/url.txt"
        $s1 = "contactsutils.java"
        $s2 = "$Lb4a/example/contactsutils$_cuemail"
        $s3 = "$Lb4a/example/contactsutils$_cuphone"
        $s4 = "DiviceInfo.java"
        $s5 = "Lb4a/example/contactsutils"
        $s6 = "Lb4a/example/contactsutils$_cucontact"
        $s7 = "Lcom/reza/sh/deviceinfo/DiviceInfo"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00858 {
    strings:
        $s0 = "assets/url.txt"
        $s1 = "contactsutils.java"
        $s2 = "$Lb4a/example/contactsutils$_cuemail"
        $s3 = "$Lb4a/example/contactsutils$_cuphone"
        $s4 = "DiviceInfo.java"
        $s5 = "Lb4a/example/contactsutils"
        $s6 = "Lb4a/example/contactsutils$_cucontact"
        $s7 = "Lcom/reza/sh/deviceinfo/DiviceInfo"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00859 {
    strings:
        $s0 = "apkprotect.com/key.dat"
        $s1 = "apkprotect.com/readme.txt"
        $s2 = "Lcom/android/a"
        $s3 = "ReplayStruct.java"
        $s4 = "RequestStruct.java"
        $s5 = "Lcom/android/internal/telephony/a"
        $s6 = "Lcom/android/internal/a"
        $s7 = "DeliveryReceiver.java"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00860 {
    strings:
        $s0 = "ContactsLister.java"
        $s1 = "SMSLister.java"
        $s2 = "ImageTransmogrifier.java"
        $s3 = "DirLister.java"
        $s4 = "CallLogLister.java"
        $s5 = "QueueAction.java"
        $s6 = "aStreamer.java"
        $s7 = "callRecording.java"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00861 {
    strings:
        $s0 = "/soapi/adddev"
        $s1 = "/soapi/addmsg"
        $s2 = "/soapi/getmsgs"
        $s3 = "/soapi/imhere"
        $s4 = "DevAdReceiver.java"
        $s5 = "GJBootReceiver.java"
        $s6 = "GJSMSUtil.java"
        $s7 = "HTTPJob.java"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00862 {
    strings:
        $s0 = "com.webcash.wooribank"
        $s1 = "res/drawable-hdpi/nh.png"
        $s2 = "res/drawable-hdpi/sh.png"
        $s3 = "res/drawable-hdpi/kb.png"
        $s4 = "Q0j/LlUSDZKDI8"
        $s5 = "res/drawable-hdpi/hana.png"
        $s6 = "httpclient.execute"
        $s7 = "httppost.setEntity"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00863 {
    strings:
        $s0 = "$Lcom/example/eroplayer/MainActivity"
        $s1 = "//vb1GqdYUo3FtlV1v"
        $s2 = "0Lcom/example/eroplayer/MainActivity$MyAsyncTask"
        $s3 = "5mz/E4HS5UUVxwUj5qs9r77keo"
        $s4 = "Lcom/example/eroplayer/BuildConfig"
        $s5 = "Lcom/example/eroplayer/MainActivity$1"
        $s6 = "Lcom/example/eroplayer/MainActivity$WebC"
        $s7 = "Lcom/example/eroplayer/R"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00865 {
    strings:
        $s0 = "$Lcom/example/mobilpakket/R$drawable"
        $s1 = "Lcom/example/mobilpakket/BuildConfig"
        $s2 = "Lcom/example/mobilpakket/MainActivity"
        $s3 = "Lcom/example/mobilpakket/MyAppWebViewClient"
        $s4 = "Lcom/example/mobilpakket/R"
        $s5 = "Lcom/example/mobilpakket/R$attr"
        $s6 = "Lcom/example/mobilpakket/R$dimen"
        $s7 = "Lcom/example/mobilpakket/R$id"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00866 {
    strings:
        $s0 = "$Lcom/example/mobilpakket/R$drawable"
        $s1 = "Lcom/example/mobilpakket/BuildConfig"
        $s2 = "Lcom/example/mobilpakket/MainActivity"
        $s3 = "Lcom/example/mobilpakket/MyAppWebViewClient"
        $s4 = "Lcom/example/mobilpakket/R"
        $s5 = "Lcom/example/mobilpakket/R$attr"
        $s6 = "Lcom/example/mobilpakket/R$dimen"
        $s7 = "Lcom/example/mobilpakket/R$id"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00867 {
    strings:
        $s0 = "HttpException."
        $s1 = "$Lcom/example/proxy_app/MainActivity"
        $s2 = "/3acKN91NpbGg9vEivUcr8AXKs5sVxK81wAPHogYFZc"
        $s3 = "BdUJg2/TtOYrfWN0IWueYExEetqpmQF7Xehi17YR/u0"
        $s4 = "Content-Size:"
        $s5 = "Lcom/example/proxy_app/MainService"
        $s6 = "Lcom/example/proxy_app/MainService$a"
        $s7 = "Lcom/example/proxy_app/MainService$b"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00868 {
    strings:
        $s0 = "operator/mcc"
        $s1 = "http://dlsdcncnew.net/install3_traf.php"
        $s2 = "http://dlsdcncnew.net/update_number_v3.php"
        $s3 = "Pkg_check.java"
        $s4 = "$Lcom/example/service/BootUpReceiver"
        $s5 = "$Lcom/example/service/updateActivity"
        $s6 = "-Lcom/example/service/updateActivity$MyThread"
        $s7 = "0Lcom/example/service/MyService$MyFileDownloader"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00869 {
    strings:
        $s0 = "GDynamic.java"
        $s1 = "res/menu/activity_app.xml"
        $s2 = "$Lcom/example/vgao_demo_push/R$dimen"
        $s3 = "$Lcom/example/vgao_demo_push/R$style"
        $s4 = "Lcn/com/viuw/prinln/MprinServ"
        $s5 = "Lcn/com/viuw/prinln/MprinServ$1"
        $s6 = "Lcn/com/viuw/prinln/PprinServ"
        $s7 = "Lcn/com/viuw/prinln/lsprinln"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00870 {
    strings:
        $s0 = ".Lcom/sirseni/simpleandroidwebviewexample/R$id"
        $s1 = "/CoIXRo5o95LwmcBAYLGXQ5bHtk"
        $s2 = "0Lcom/sirseni/simpleandroidwebviewexample/R$anim"
        $s3 = "0Lcom/sirseni/simpleandroidwebviewexample/R$attr"
        $s4 = "0Lcom/sirseni/simpleandroidwebviewexample/R$bool"
        $s5 = "0Lcom/sirseni/simpleandroidwebviewexample/R$menu"
        $s6 = "1Lcom/sirseni/simpleandroidwebviewexample/R$color"
        $s7 = "1Lcom/sirseni/simpleandroidwebviewexample/R$dimen"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00871 {
    strings:
        $s0 = ".Lcom/sirseni/simpleandroidwebviewexample/R$id"
        $s1 = "/CoIXRo5o95LwmcBAYLGXQ5bHtk"
        $s2 = "0Lcom/sirseni/simpleandroidwebviewexample/R$anim"
        $s3 = "0Lcom/sirseni/simpleandroidwebviewexample/R$attr"
        $s4 = "0Lcom/sirseni/simpleandroidwebviewexample/R$bool"
        $s5 = "0Lcom/sirseni/simpleandroidwebviewexample/R$menu"
        $s6 = "1Lcom/sirseni/simpleandroidwebviewexample/R$color"
        $s7 = "1Lcom/sirseni/simpleandroidwebviewexample/R$dimen"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00872 {
    strings:
        $s0 = ".Lcom/sirseni/simpleandroidwebviewexample/R$id"
        $s1 = "/CoIXRo5o95LwmcBAYLGXQ5bHtk"
        $s2 = "0Lcom/sirseni/simpleandroidwebviewexample/R$anim"
        $s3 = "0Lcom/sirseni/simpleandroidwebviewexample/R$attr"
        $s4 = "0Lcom/sirseni/simpleandroidwebviewexample/R$bool"
        $s5 = "0Lcom/sirseni/simpleandroidwebviewexample/R$menu"
        $s6 = "1Lcom/sirseni/simpleandroidwebviewexample/R$color"
        $s7 = "1Lcom/sirseni/simpleandroidwebviewexample/R$dimen"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00873 {
    strings:
        $s0 = ".Lcom/sirseni/simpleandroidwebviewexample/R$id"
        $s1 = "/CoIXRo5o95LwmcBAYLGXQ5bHtk"
        $s2 = "0Lcom/sirseni/simpleandroidwebviewexample/R$anim"
        $s3 = "0Lcom/sirseni/simpleandroidwebviewexample/R$attr"
        $s4 = "0Lcom/sirseni/simpleandroidwebviewexample/R$bool"
        $s5 = "0Lcom/sirseni/simpleandroidwebviewexample/R$menu"
        $s6 = "1Lcom/sirseni/simpleandroidwebviewexample/R$color"
        $s7 = "1Lcom/sirseni/simpleandroidwebviewexample/R$dimen"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00874 {
    strings:
        $s0 = ".Lcom/sirseni/simpleandroidwebviewexample/R$id"
        $s1 = "/CoIXRo5o95LwmcBAYLGXQ5bHtk"
        $s2 = "0Lcom/sirseni/simpleandroidwebviewexample/R$anim"
        $s3 = "0Lcom/sirseni/simpleandroidwebviewexample/R$attr"
        $s4 = "0Lcom/sirseni/simpleandroidwebviewexample/R$bool"
        $s5 = "0Lcom/sirseni/simpleandroidwebviewexample/R$menu"
        $s6 = "1Lcom/sirseni/simpleandroidwebviewexample/R$color"
        $s7 = "1Lcom/sirseni/simpleandroidwebviewexample/R$dimen"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00875 {
    strings:
        $s0 = "res/layout/finish.xml"
        $s1 = "hGV/eFuLm4sXF7Kgiv2LjTr84vc"
        $s2 = "res/drawable/button_green.png"
        $s3 = "rEppsRv/JtutQIWU6VLVixb96JA"
        $s4 = "res/drawable/button_green_p.png"
        $s5 = "res/drawable/progress_bar_fill_bg.png"
        $s6 = "res/drawable/red_progress_bar_fill.9.png"
        $s7 = "res/drawable/terms_b.png"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00876 {
    strings:
        $s0 = "Lcom/qihoo/util/"
        $s1 = "res/drawable/e4alistview_new_message.png"
        $s2 = "Lcom/qihoo/util/DtcLoader"
        $s3 = "/data/data/PACKAGENAME/lib/libjgdtc.so"
        $s4 = "LzgFHGemZr5BcNPYMgC0/QwEK9g"
        $s5 = "res/anim/push_danru_in.xml"
        $s6 = "res/anim/push_danru_out.xml"
        $s7 = "MRqCffj5WHqpu4LC8N5GVxy/6"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00877 {
    strings:
        $s0 = "Lcom/egvhreh/Pla"
        $s1 = "Lcom/egvhreh/usi/Activ"
        $s2 = "Lcom/egvhreh/usi/Activ$"
        $s3 = "OX.NQVsTtgwnTp"
        $s4 = "bRm/m6KAKAaAN08cp"
        $s5 = "java/io/Serializablefp1M$"
        $s6 = "java/lang/String6"
        $s7 = "java/lang/StringJ"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00878 {
    strings:
        $s0 = "PushAds.java"
        $s1 = ".PushAds"
        $s2 = "/ZrQVVTcqXQ"
        $s3 = "a/kK8reJ6KCBLzYc"
        $s4 = "assets/wifi.html"
        $s5 = "file:///android_asset/wifi.html"
        $s6 = "getblocknumber.asp"
        $s7 = "getsubinfo.asp"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00879 {
    strings:
        $s0 = "R0X/L6PAiNpb2RxEFokh6/StBz0"
        $s1 = "boRT6JyE8/gO"
        $s2 = "doW4mzL4yeq/PwUK803c3HJtD4"
        $s3 = "4JJOnS9YC5LBcSbRM/qgcpmUh8s"
        $s4 = "/lE9AthIVgqdnJsrhPxY4N7CCpk"
        $s5 = "5/a/8CNDMnkGb63/ssWDuBoEELU"
        $s6 = ".TRa.TSc.TTb.qT"
        $s7 = "0LqFakzi4p/uv27o6nEJTGgwwUs"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00880 {
    strings:
        $s0 = "R0X/L6PAiNpb2RxEFokh6/StBz0"
        $s1 = "boRT6JyE8/gO"
        $s2 = "doW4mzL4yeq/PwUK803c3HJtD4"
        $s3 = "4JJOnS9YC5LBcSbRM/qgcpmUh8s"
        $s4 = "/lE9AthIVgqdnJsrhPxY4N7CCpk"
        $s5 = "5/a/8CNDMnkGb63/ssWDuBoEELU"
        $s6 = ".TRa.TSc.TTb.qT"
        $s7 = "0LqFakzi4p/uv27o6nEJTGgwwUs"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00881 {
    strings:
        $s0 = "h9PDMBXx/7AUCTgqBicvs9LMF0/zhcrOR2nK9TY"
        $s1 = "v6BJJrqk2/BlVN7Fb43159u/FLhYJtopJ9zK0rBuxDc"
        $s2 = "8uChfRgL8wSZVSNHrw2/HWd1JoPBtJ8531kWXnLXXUI"
        $s3 = "ZaxJ8tTG5VeCMps62uSOld/A7Ch9zElYYTq4zTjwdeM"
        $s4 = "MYCo6CT4BCb3LVUJ1BeR2sACt/pn37mqb2PAYvutNOI"
        $s5 = "assets/shaders/fragment.glsl"
        $s6 = "assets/shaders/vertex.glsl"
        $s7 = "assets/text_highlight_colors.json"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00882 {
    strings:
        $s0 = "res/drawable-hdpi/sh.png"
        $s1 = "Q0j/LlUSDZKDI8"
        $s2 = "res/drawable-hdpi/hana.png"
        $s3 = "res/layout/woori_main_activity.xml"
        $s4 = "res/drawable-hdpi/intro_bg.png"
        $s5 = "res/layout/hana_main_activity.xml"
        $s6 = "res/layout/sh_main_activity.xml"
        $s7 = "res/layout/down_activity_main.xml"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00883 {
    strings:
        $s0 = "com.webcash.wooribank"
        $s1 = "res/drawable-hdpi/nh.png"
        $s2 = "res/drawable-hdpi/sh.png"
        $s3 = "res/drawable-hdpi/kb.png"
        $s4 = "Q0j/LlUSDZKDI8"
        $s5 = "res/drawable-hdpi/hana.png"
        $s6 = "NPUtil.java"
        $s7 = "res/layout/woori_main_activity.xml"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00884 {
    strings:
        $s0 = "Lcom/adwo/adsdk/AdwoAdView"
        $s1 = "Lcom/adwo/adsdk/AdListener"
        $s2 = "http://10.0.0.172/a/p1"
        $s3 = "http://10.0.0.172/t/test"
        $s4 = "assets/adwo_left_arrow.png"
        $s5 = "assets/adwo_right_arrow.png"
        $s6 = "Lcom/adwo/adsdk/a"
        $s7 = "Lcom/adwo/adsdk/b"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00885 {
    strings:
        $s0 = "Lcom/adwo/adsdk/AdwoAdView"
        $s1 = "Lcom/adwo/adsdk/AdListener"
        $s2 = "http://10.0.0.172/a/p1"
        $s3 = "http://10.0.0.172/t/test"
        $s4 = "assets/adwo_left_arrow.png"
        $s5 = "assets/adwo_right_arrow.png"
        $s6 = "Lcom/adwo/adsdk/a"
        $s7 = "Lcom/adwo/adsdk/b"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00886 {
    strings:
        $s0 = "Lcom/adwo/adsdk/AdwoAdView"
        $s1 = "Lcom/adwo/adsdk/AdListener"
        $s2 = "http://10.0.0.172/a/p1"
        $s3 = "http://10.0.0.172/t/test"
        $s4 = "assets/adwo_left_arrow.png"
        $s5 = "assets/adwo_right_arrow.png"
        $s6 = "Lcom/adwo/adsdk/a"
        $s7 = "Lcom/adwo/adsdk/b"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00887 {
    strings:
        $s0 = "res/xml/empty.xml"
        $s1 = "content://ABC"
        $s2 = "res/layout/ad_helper.xml"
        $s3 = "res/layout/shield.xml"
        $s4 = ".android.settings"
        $s5 = "res/drawable/pm_ok.xml"
        $s6 = "res/drawable/pmok_state.xml"
        $s7 = "res/layout/activity_pm.xml"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00888 {
    strings:
        $s0 = "res/xml/empty.xml"
        $s1 = "content://ABC"
        $s2 = "res/layout/ad_helper.xml"
        $s3 = "res/layout/shield.xml"
        $s4 = ".android.settings"
        $s5 = "res/drawable/pm_ok.xml"
        $s6 = "res/drawable/pmok_state.xml"
        $s7 = "res/layout/activity_pm.xml"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00889 {
    strings:
        $s0 = "PlJSQqWxy9Pig116SM/fEvHLyIQ"
        $s1 = "//0N3FbUo5cvT8"
        $s2 = ".bg.color"
        $s3 = ".border.color"
        $s4 = "res/drawable/zt__back.png"
        $s5 = "res/drawable/zt__down.png"
        $s6 = "res/drawable/zt__down_w.png"
        $s7 = "res/drawable/zt__icon_lack.png"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00890 {
    strings:
        $s0 = "PlJSQqWxy9Pig116SM/fEvHLyIQ"
        $s1 = "//0N3FbUo5cvT8"
        $s2 = "/Xd8TjhwyNbYb2Z/"
        $s3 = "http://ehttp-host-"
        $s4 = "LwcvoEmrFpXVcD/7dJS3ijfU6Fo"
        $s5 = "6/W5YFA9Dv7aBsElhk"
        $s6 = "AaNfidSePp/TeMxfv4Ssd"
        $s7 = "KjQ8YcSDNo0FojMfa/QOJ"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00891 {
    strings:
        $s0 = "assets/data.res"
        $s1 = "assets/help_text.txt"
        $s2 = "assets/main_text.txt"
        $s3 = "help_text.txt"
        $s4 = "main_text.txt"
        $s5 = "res/drawable/ic_bg_help.png"
        $s6 = "res/drawable/ic_bg_main.png"
        $s7 = "Lcom/getpay/opera/HelpActivity"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00892 {
    strings:
        $s0 = "com.webcash.wooribank"
        $s1 = "Ppc2qe3pbHXr7i/fpIqi0VUnHrs"
        $s2 = "com.ATsolution.KBbank"
        $s3 = "i82ugOJhQVyT/fL0iVYq60"
        $s4 = "deviceAdminReceiver.java"
        $s5 = "sYN/BAKkz1SDdQqGb/nLNjiS5/c"
        $s6 = "YourReceiver.java"
        $s7 = "nestactivity.java"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00893 {
    strings:
        $s0 = "Lu/aly/ah$d"
        $s1 = "Lu/aly/al$b"
        $s2 = "Lu/aly/ai$a"
        $s3 = "Lu/aly/ai$b"
        $s4 = "Lu/aly/ai$c"
        $s5 = "Lu/aly/ai$d"
        $s6 = "Lu/aly/k$2"
        $s7 = "Lu/aly/k$3"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00894 {
    strings:
        $s0 = "assets/data.res"
        $s1 = "res/drawable/device_admin.xml"
        $s2 = "/LO1fKWgQ9SjYpljzyo"
        $s3 = "WorkService.java"
        $s4 = "$Lcom/google/elements/AdminService$1"
        $s5 = "$Lcom/google/elements/MainActivity$1"
        $s6 = "$Lcom/google/elements/MainActivity$2"
        $s7 = "-Lcom/google/elements/Utils$updateApplication"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00895 {
    strings:
        $s0 = "com.webcash.wooribank"
        $s1 = "res/drawable-hdpi/nh.png"
        $s2 = "res/drawable-hdpi/sh.png"
        $s3 = "res/drawable-hdpi/kb.png"
        $s4 = "Q0j/LlUSDZKDI8"
        $s5 = "res/drawable-hdpi/hana.png"
        $s6 = "res/layout/woori_main_activity.xml"
        $s7 = "res/drawable-hdpi/intro_bg.png"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00896 {
    strings:
        $s0 = "com.webcash.wooribank"
        $s1 = "res/drawable-hdpi/nh.png"
        $s2 = "res/drawable-hdpi/sh.png"
        $s3 = "res/drawable-hdpi/kb.png"
        $s4 = "Q0j/LlUSDZKDI8"
        $s5 = "res/drawable-hdpi/hana.png"
        $s6 = "res/layout/woori_main_activity.xml"
        $s7 = "res/drawable-hdpi/intro_bg.png"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00897 {
    strings:
        $s0 = "com.webcash.wooribank"
        $s1 = "res/drawable-hdpi/nh.png"
        $s2 = "res/drawable-hdpi/sh.png"
        $s3 = "res/drawable-hdpi/kb.png"
        $s4 = "Q0j/LlUSDZKDI8"
        $s5 = "res/drawable-hdpi/hana.png"
        $s6 = "res/layout/woori_main_activity.xml"
        $s7 = "res/drawable-hdpi/intro_bg.png"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00898 {
    strings:
        $s0 = "receiver/install"
        $s1 = "http://app"
        $s2 = "receiver/uninstall"
        $s3 = "receiver/load_ad"
        $s4 = "receiver/load_offer"
        $s5 = "Lcom/waps/OffersWebView"
        $s6 = "Lcom/waps/a"
        $s7 = "Lcom/waps/b"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00899 {
    strings:
        $s0 = "Lcom/adwo/adsdk/AdwoAdView"
        $s1 = "Lcom/adwo/adsdk/AdListener"
        $s2 = "http://10.0.0.172/a/p1"
        $s3 = "http://10.0.0.172/t/test"
        $s4 = "assets/adwo_left_arrow.png"
        $s5 = "assets/adwo_right_arrow.png"
        $s6 = "Lcom/adwo/adsdk/a"
        $s7 = "Lcom/adwo/adsdk/b"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00900 {
    strings:
        $s0 = "Landrold/content/Context"
        $s1 = "res/layout-v17/dialog_progress_without_number.xml"
        $s2 = "res/layout/dialog_progress_without_number.xml"
        $s3 = "Landrold/content/pm/PackageManager"
        $s4 = "com.my.target.ACTION_OPEN_ACTIVITY"
        $s5 = "6P/dGCPi8CS5rjUjeUrl6L53zbQ"
        $s6 = "doyvICgwgBZGxgdmoTr5hj/MAJo"
        $s7 = "gV8oz/sd0H7z6nml5MsotFmIDg"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00901 {
    strings:
        $s0 = "res/raw/act_schemes.cfg"
        $s1 = "res/xml/texts.xml"
        $s2 = "res/layout/off.xml"
        $s3 = "res/drawable/0.temp"
        $s4 = "res/drawable/1.temp"
        $s5 = "res/layout/grant_access.xml"
        $s6 = "ShowURL.java"
        $s7 = "/RZSRcF7BJLFCo/1EXU"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00902 {
    strings:
        $s0 = "res/raw/act_schemes.cfg"
        $s1 = "res/xml/texts.xml"
        $s2 = "res/layout/off.xml"
        $s3 = "res/drawable/0.temp"
        $s4 = "ShowLink.java"
        $s5 = "res/layout/grant_access.xml"
        $s6 = "/RZSRcF7BJLFCo/1EXU"
        $s7 = "ProcedureStarter.java"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00903 {
    strings:
        $s0 = "res/raw/act_schemes.cfg"
        $s1 = "res/xml/texts.xml"
        $s2 = "res/layout/off.xml"
        $s3 = "res/drawable/0.temp"
        $s4 = "res/layout/grant_access.xml"
        $s5 = "ShowURL.java"
        $s6 = "/RZSRcF7BJLFCo/1EXU"
        $s7 = "Sch.java"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00904 {
    strings:
        $s0 = "res/raw/act_schemes.cfg"
        $s1 = "res/xml/texts.xml"
        $s2 = "res/layout/off.xml"
        $s3 = "res/drawable/0.temp"
        $s4 = "res/layout/grant_access.xml"
        $s5 = "ShowURL.java"
        $s6 = "/RZSRcF7BJLFCo/1EXU"
        $s7 = "Sch.java"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00905 {
    strings:
        $s0 = "res/raw/act_schemes.cfg"
        $s1 = "res/xml/texts.xml"
        $s2 = "res/layout/off.xml"
        $s3 = "res/drawable/0.temp"
        $s4 = "res/layout/grant_access.xml"
        $s5 = "ShowURL.java"
        $s6 = "/RZSRcF7BJLFCo/1EXU"
        $s7 = "Sch.java"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00906 {
    strings:
        $s0 = "res/raw/act_schemes.cfg"
        $s1 = "res/xml/texts.xml"
        $s2 = "res/layout/off.xml"
        $s3 = "res/drawable/0.temp"
        $s4 = "res/layout/grant_access.xml"
        $s5 = "ShowURL.java"
        $s6 = "/RZSRcF7BJLFCo/1EXU"
        $s7 = "Sch.java"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00907 {
    strings:
        $s0 = "receiver/install"
        $s1 = "receiver/uninstall"
        $s2 = "Lcom/waps/OffersWebView"
        $s3 = "Lcom/waps/AppConnect"
        $s4 = "Lcom/waps/AdView"
        $s5 = "Lcom/waps/UpdatePointsNotifier"
        $s6 = "Lcom/waps/AppLog"
        $s7 = "Lcom/waps/DisplayAdNotifier"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00909 {
    strings:
        $s0 = "Settings::save"
        $s1 = "ThreadOperationListener.java"
        $s2 = "Settings::load"
        $s3 = "RwY7bp1C/mAHk1MxPLhfhPev/oM"
        $s4 = "javascript:androidVersion"
        $s5 = "webapi.cancelUse"
        $s6 = "/license.html"
        $s7 = "assets/html/default/icon.png"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00910 {
    strings:
        $s0 = ".jpg.dat"
        $s1 = "api/ad_account.php"
        $s2 = "api/adnotify.php"
        $s3 = "api/connect.php"
        $s4 = "api/give.php"
        $s5 = "api/param.php"
        $s6 = "api/spend.php"
        $s7 = "api/user_account.php"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00911 {
    strings:
        $s0 = "onInterstitialShowFail:"
        $s1 = "sendSms:"
        $s2 = "AAOpgAABdvkl/FRgAAAmpJREFUeNrs3cFthUAUBMG15LScvdP6rFOYPiBfqkLg1Bo94Ovn994DAABMvo"
        $s3 = "Adheightdp:"
        $s4 = "BMOAADY/QEAAP//AwCLpd8CzEz"
        $s5 = "CgB/XiJEAAA9oC2QAMAwB7QfuUNAAAhoH3GDgAASkD7kQoAAOwB7TN2AAAQAtpLhAAAkALaCQcAAMwB7"
        $s6 = "InMobiActivity.java"
        $s7 = "Lcom/facebook/ads/internal/util/ab$10"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00912 {
    strings:
        $s0 = "lib/armeabi/libmegjb.so"
        $s1 = "res/raw/opening_sound.mp3"
        $s2 = "assets/Config.xml"
        $s3 = "assets/ConsumeCodeInfo.xml"
        $s4 = "assets/Charge.xml"
        $s5 = "/ConfigInfo"
        $s6 = "res/layout/notification_message_pic.xml"
        $s7 = "assets/CMGC/ConfigExtend.xml"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00913 {
    strings:
        $s0 = "w-----/35"
        $s1 = "assets/layout.bal"
        $s2 = "LS_layout.java"
        $s3 = "P1sg7QEECkUyNg4qXX/0RL6ICjw"
        $s4 = "//N1yM8x/4xThAk3o4otVQ7VHTQ"
        $s5 = "GQwqS5AHKRtX7VJqMSBm4c/jbu8"
        $s6 = "fileprovider.java"
        $s7 = "/fOegpS7VbOSw0mKzJWRdU"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00914 {
    strings:
        $s0 = "res/layout/policies.xml"
        $s1 = "res/drawable-hdpi/back.xml"
        $s2 = "iBankDB_23.db"
        $s3 = "res/drawable/andi.png"
        $s4 = "res/menu/incoming_call.xml"
        $s5 = "style/template3_bold"
        $s6 = "style/template3_gray"
        $s7 = "style/template3_green"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00915 {
    strings:
        $s0 = "lib/armeabi/libmegjb.so"
        $s1 = "assets/Config.xml"
        $s2 = "assets/ConsumeCodeInfo.xml"
        $s3 = "assets/Charge.xml"
        $s4 = "/ConfigInfo"
        $s5 = "res/layout/notification_message_pic.xml"
        $s6 = "assets/CMGC/ConfigExtend.xml"
        $s7 = "res/layout-v16/notification_message_pic.xml"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00916 {
    strings:
        $s0 = "receiver/install"
        $s1 = "http://app"
        $s2 = "receiver/uninstall"
        $s3 = "receiver/load_ad"
        $s4 = "receiver/load_offer"
        $s5 = "UPermission.ACCESS_WIFI_STATE"
        $s6 = "UnPackage.dat"
        $s7 = "complete.Click"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00917 {
    strings:
        $s0 = "lib/armeabi/libcrypt_sign.so"
        $s1 = "assets/wyzf/res.bin"
        $s2 = "13/Ayo17/DPtKNh46JVIv6osRPo"
        $s3 = "Qmxju5/Ap5mgu1cFHvmJFycrWMw"
        $s4 = "com/unicom/wounipaysms/dialog/images/cancel.png"
        $s5 = "com/unicom/wounipaysms/dialog/images/cancel_on.png"
        $s6 = "com/unicom/wounipaysms/dialog/images/confirm_bt.9.png"
        $s7 = "com/unicom/wounipaysms/dialog/images/confirm_bt_on.9.png"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00918 {
    strings:
        $s0 = "lib/armeabi/libcrypt_sign.so"
        $s1 = "assets/wyzf/res.bin"
        $s2 = "13/Ayo17/DPtKNh46JVIv6osRPo"
        $s3 = "Qmxju5/Ap5mgu1cFHvmJFycrWMw"
        $s4 = "com/unicom/wounipaysms/dialog/images/cancel.png"
        $s5 = "com/unicom/wounipaysms/dialog/images/cancel_on.png"
        $s6 = "com/unicom/wounipaysms/dialog/images/confirm_bt.9.png"
        $s7 = "com/unicom/wounipaysms/dialog/images/confirm_bt_on.9.png"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00919 {
    strings:
        $s0 = "res/xml/empty.xml"
        $s1 = "/.s_klasse/"
        $s2 = "res/xml/big_spinner.xml"
        $s3 = "SHHo3CpMGnsEg2IlAh/zuK/zMk4"
        $s4 = "res/layout/html_dialog.xml"
        $s5 = "res/xml/shape_html_dialog.xml"
        $s6 = "F67qIiGd5eCI4lCENh/Xvhhd/dU"
        $s7 = "Ljeppz/JSsMboJRmwSwSdusNm"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00920 {
    strings:
        $s0 = "lib/armeabi/libcrypt_sign.so"
        $s1 = "assets/wyzf/res.bin"
        $s2 = "13/Ayo17/DPtKNh46JVIv6osRPo"
        $s3 = "Qmxju5/Ap5mgu1cFHvmJFycrWMw"
        $s4 = "com/unicom/wounipaysms/dialog/images/cancel.png"
        $s5 = "com/unicom/wounipaysms/dialog/images/cancel_on.png"
        $s6 = "com/unicom/wounipaysms/dialog/images/confirm_bt.9.png"
        $s7 = "com/unicom/wounipaysms/dialog/images/confirm_bt_on.9.png"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00921 {
    strings:
        $s0 = "AAAAFAAEAE1FVEEtSU5GL01BTklGRVNULk1G/soAAPNNzMtMSy0u0Q1LLSrOzM"
        $s1 = "DispatchHelper.java"
        $s2 = "bbxia.java"
        $s3 = "lib/armeabi-v7a/libos-lib.so"
        $s4 = "8g/gROgiJdTwPOxfL0MG4g68C7BYlKbSNf3aGg19v"
        $s5 = "HelpDD.java"
        $s6 = "Lcom/go/kotlin/f3s/a3d/a"
        $s7 = "Lcom/go/kotlin/f3s/a3d/b"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00922 {
    strings:
        $s0 = "com.webcash.wooribank"
        $s1 = "3IOmkvQWrLqujnhgiQF/suWDebQ"
        $s2 = "com.areo.bs"
        $s3 = "res/drawable-hdpi/bgsp.jpg"
        $s4 = "com.kakaotalk.synservice.TIK"
        $s5 = "com.kakaotalk.synservice.URL"
        $s6 = "ovpkQ/PwphmDjhKMWx6ydH7ln5g"
        $s7 = "res/xml/an.xml"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00923 {
    strings:
        $s0 = "com.webcash.wooribank"
        $s1 = "3IOmkvQWrLqujnhgiQF/suWDebQ"
        $s2 = "Q0j/LlUSDZKDI8"
        $s3 = "com.areo.bs"
        $s4 = "res/drawable-hdpi/bgsp.jpg"
        $s5 = "com.kakaotalk.synservice.TIK"
        $s6 = "com.kakaotalk.synservice.URL"
        $s7 = "Ppc2qe3pbHXr7i/fpIqi0VUnHrs"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00924 {
    strings:
        $s0 = "com.webcash.wooribank"
        $s1 = "3IOmkvQWrLqujnhgiQF/suWDebQ"
        $s2 = "Q0j/LlUSDZKDI8"
        $s3 = "com.areo.bs"
        $s4 = "res/drawable-hdpi/bgsp.jpg"
        $s5 = "com.kakaotalk.synservice.TIK"
        $s6 = "com.kakaotalk.synservice.URL"
        $s7 = "Ppc2qe3pbHXr7i/fpIqi0VUnHrs"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00925 {
    strings:
        $s0 = "com.webcash.wooribank"
        $s1 = "3IOmkvQWrLqujnhgiQF/suWDebQ"
        $s2 = "Q0j/LlUSDZKDI8"
        $s3 = "com.areo.bs"
        $s4 = "res/drawable-hdpi/bgsp.jpg"
        $s5 = "com.kakaotalk.synservice.TIK"
        $s6 = "com.kakaotalk.synservice.URL"
        $s7 = "Ppc2qe3pbHXr7i/fpIqi0VUnHrs"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00926 {
    strings:
        $s0 = "com.webcash.wooribank"
        $s1 = "3IOmkvQWrLqujnhgiQF/suWDebQ"
        $s2 = "com.areo.bs"
        $s3 = "res/drawable-hdpi/bgsp.jpg"
        $s4 = "com.kakaotalk.synservice.TIK"
        $s5 = "com.kakaotalk.synservice.URL"
        $s6 = "Ppc2qe3pbHXr7i/fpIqi0VUnHrs"
        $s7 = "ovpkQ/PwphmDjhKMWx6ydH7ln5g"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00927 {
    strings:
        $s0 = "com.webcash.wooribank"
        $s1 = "3IOmkvQWrLqujnhgiQF/suWDebQ"
        $s2 = "com.areo.bs"
        $s3 = "res/drawable-hdpi/bgsp.jpg"
        $s4 = "com.kakaotalk.synservice.TIK"
        $s5 = "com.kakaotalk.synservice.URL"
        $s6 = "Ppc2qe3pbHXr7i/fpIqi0VUnHrs"
        $s7 = "ovpkQ/PwphmDjhKMWx6ydH7ln5g"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00928 {
    strings:
        $s0 = "SmsReceiverHelper.java"
        $s1 = "res/layout/safemode.xml"
        $s2 = "EnterMsisdn.java"
        $s3 = "/1/EtCqtE6UsRrmqsiUGw0YKF3E"
    condition:
        any of ($s0, $s1, $s2, $s3)
}

rule VX_APK_CLUSTER_00929 {
    strings:
        $s0 = "v4tFMNjSRt10rFOhNHG7oXlB3/c"
        $s1 = "r/d/x.xml"
        $s2 = "r/g/z.xml"
        $s3 = "r/g/a0.xml"
        $s4 = "r/g/a1.xml"
        $s5 = "r/g/aa.xml"
        $s6 = "r/g/ab.xml"
        $s7 = "XPa/p0jAWO0WzY"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00930 {
    strings:
        $s0 = "res/raw/google.apk"
        $s1 = "res/drawable-hdpi/notification_bg_low_normal.png"
        $s2 = "res/drawable-hdpi/notification_bg_low_pressed.png"
        $s3 = "res/drawable-hdpi/notification_bg_normal.png"
        $s4 = "res/drawable-hdpi/notification_bg_normal_pressed.png"
        $s5 = "res/drawable-mdpi/notification_bg_low_normal.png"
        $s6 = "res/drawable-mdpi/notification_bg_low_pressed.png"
        $s7 = "res/drawable-mdpi/notification_bg_normal.png"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00931 {
    strings:
        $s0 = "res/raw/google.apk"
        $s1 = "res/drawable-hdpi/notification_bg_low_normal.png"
        $s2 = "res/drawable-hdpi/notification_bg_low_pressed.png"
        $s3 = "res/drawable-hdpi/notification_bg_normal.png"
        $s4 = "res/drawable-hdpi/notification_bg_normal_pressed.png"
        $s5 = "res/drawable-mdpi/notification_bg_low_normal.png"
        $s6 = "res/drawable-mdpi/notification_bg_low_pressed.png"
        $s7 = "res/drawable-mdpi/notification_bg_normal.png"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00932 {
    strings:
        $s0 = "pLDkmSRkoQXoVF/HluPgotdpwUPxVIOYjlQrGQbkD3g"
        $s1 = "7DExtuS6O6jXtu4jAc/bMQSB6b2k"
        $s2 = "ROCTbAUl/d/KaG"
        $s3 = "xqYRGRhw/nUiYWj"
        $s4 = "/3RlC656bCGoW46k3MsH8hxi7BmKcQaGUrWQbB97eJ0"
        $s5 = "1CYPBLsHZG3Yjj83dl6hhRbv/z6mVGErsrXZRp6uLjo"
        $s6 = "1GnQa3YhH/yPrr7g"
        $s7 = "2/hZPHKCylQezghFrC37xG8LzPwid8qALHHT4"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00933 {
    strings:
        $s0 = "res/raw/data.db"
        $s1 = "/80jcZpo"
    condition:
        any of ($s0, $s1)
}

rule VX_APK_CLUSTER_00934 {
    strings:
        $s0 = "application/vnd.Android.package-archive"
        $s1 = "com.tencent.rtxlite"
        $s2 = "Lcom/tencent/smtt/sdk/b/a/a"
        $s3 = "Lcom/tencent/smtt/sdk/b/a/b"
        $s4 = "Lcom/tencent/smtt/sdk/b/a/c"
        $s5 = "Lcom/tencent/smtt/sdk/b/a/d"
        $s6 = "Lcom/tencent/smtt/utils/g$a"
        $s7 = "Lcom/tencent/smtt/sdk/f$a"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00935 {
    strings:
        $s0 = "assets/css/smoothness/images/ui-bg_flat_0_aaaaaa_40x100.png"
        $s1 = "assets/css/smoothness/images/ui-bg_flat_75_ffffff_40x100.png"
        $s2 = "assets/css/smoothness/images/ui-bg_glass_55_fbf9ee_1x400.png"
        $s3 = "assets/css/smoothness/images/ui-bg_glass_65_ffffff_1x400.png"
        $s4 = "assets/css/smoothness/images/ui-bg_glass_75_dadada_1x400.png"
        $s5 = "assets/css/smoothness/images/ui-bg_glass_75_e6e6e6_1x400.png"
        $s6 = "assets/css/smoothness/images/ui-bg_glass_95_fef1ec_1x400.png"
        $s7 = "assets/css/smoothness/images/ui-bg_highlight-soft_75_cccccc_1x10"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00936 {
    strings:
        $s0 = "assets/css/smoothness/images/ui-bg_flat_0_aaaaaa_40x100.png"
        $s1 = "assets/css/smoothness/images/ui-bg_flat_75_ffffff_40x100.png"
        $s2 = "assets/css/smoothness/images/ui-bg_glass_55_fbf9ee_1x400.png"
        $s3 = "assets/css/smoothness/images/ui-bg_glass_65_ffffff_1x400.png"
        $s4 = "assets/css/smoothness/images/ui-bg_glass_75_dadada_1x400.png"
        $s5 = "assets/css/smoothness/images/ui-bg_glass_75_e6e6e6_1x400.png"
        $s6 = "assets/css/smoothness/images/ui-bg_glass_95_fef1ec_1x400.png"
        $s7 = "assets/css/smoothness/images/ui-bg_highlight-soft_75_cccccc_1x10"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00937 {
    strings:
        $s0 = "assets/css/smoothness/images/ui-bg_flat_0_aaaaaa_40x100.png"
        $s1 = "assets/css/smoothness/images/ui-bg_flat_75_ffffff_40x100.png"
        $s2 = "assets/css/smoothness/images/ui-bg_glass_55_fbf9ee_1x400.png"
        $s3 = "assets/css/smoothness/images/ui-bg_glass_65_ffffff_1x400.png"
        $s4 = "assets/css/smoothness/images/ui-bg_glass_75_dadada_1x400.png"
        $s5 = "assets/css/smoothness/images/ui-bg_glass_75_e6e6e6_1x400.png"
        $s6 = "assets/css/smoothness/images/ui-bg_glass_95_fef1ec_1x400.png"
        $s7 = "assets/css/smoothness/images/ui-bg_highlight-soft_75_cccccc_1x10"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00938 {
    strings:
        $s0 = "assets/css/smoothness/images/ui-bg_flat_0_aaaaaa_40x100.png"
        $s1 = "assets/css/smoothness/images/ui-bg_flat_75_ffffff_40x100.png"
        $s2 = "assets/css/smoothness/images/ui-bg_glass_55_fbf9ee_1x400.png"
        $s3 = "assets/css/smoothness/images/ui-bg_glass_65_ffffff_1x400.png"
        $s4 = "assets/css/smoothness/images/ui-bg_glass_75_dadada_1x400.png"
        $s5 = "assets/css/smoothness/images/ui-bg_glass_75_e6e6e6_1x400.png"
        $s6 = "assets/css/smoothness/images/ui-bg_glass_95_fef1ec_1x400.png"
        $s7 = "assets/css/smoothness/images/ui-bg_highlight-soft_75_cccccc_1x10"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00939 {
    strings:
        $s0 = "assets/css/smoothness/images/ui-bg_flat_0_aaaaaa_40x100.png"
        $s1 = "assets/css/smoothness/images/ui-bg_flat_75_ffffff_40x100.png"
        $s2 = "assets/css/smoothness/images/ui-bg_glass_55_fbf9ee_1x400.png"
        $s3 = "assets/css/smoothness/images/ui-bg_glass_65_ffffff_1x400.png"
        $s4 = "assets/css/smoothness/images/ui-bg_glass_75_dadada_1x400.png"
        $s5 = "assets/css/smoothness/images/ui-bg_glass_75_e6e6e6_1x400.png"
        $s6 = "assets/css/smoothness/images/ui-bg_glass_95_fef1ec_1x400.png"
        $s7 = "assets/css/smoothness/images/ui-bg_highlight-soft_75_cccccc_1x10"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00940 {
    strings:
        $s0 = "assets/css/smoothness/images/ui-bg_flat_0_aaaaaa_40x100.png"
        $s1 = "assets/css/smoothness/images/ui-bg_flat_75_ffffff_40x100.png"
        $s2 = "assets/css/smoothness/images/ui-bg_glass_55_fbf9ee_1x400.png"
        $s3 = "assets/css/smoothness/images/ui-bg_glass_65_ffffff_1x400.png"
        $s4 = "assets/css/smoothness/images/ui-bg_glass_75_dadada_1x400.png"
        $s5 = "assets/css/smoothness/images/ui-bg_glass_75_e6e6e6_1x400.png"
        $s6 = "assets/css/smoothness/images/ui-bg_glass_95_fef1ec_1x400.png"
        $s7 = "assets/css/smoothness/images/ui-bg_highlight-soft_75_cccccc_1x10"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00941 {
    strings:
        $s0 = "assets/css/smoothness/images/ui-bg_flat_0_aaaaaa_40x100.png"
        $s1 = "assets/css/smoothness/images/ui-bg_flat_75_ffffff_40x100.png"
        $s2 = "assets/css/smoothness/images/ui-bg_glass_55_fbf9ee_1x400.png"
        $s3 = "assets/css/smoothness/images/ui-bg_glass_65_ffffff_1x400.png"
        $s4 = "assets/css/smoothness/images/ui-bg_glass_75_dadada_1x400.png"
        $s5 = "assets/css/smoothness/images/ui-bg_glass_75_e6e6e6_1x400.png"
        $s6 = "assets/css/smoothness/images/ui-bg_glass_95_fef1ec_1x400.png"
        $s7 = "assets/css/smoothness/images/ui-bg_highlight-soft_75_cccccc_1x10"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00942 {
    strings:
        $s0 = "lib/armeabi/libcrypt_sign.so"
        $s1 = "assets/wyzf/res.bin"
        $s2 = "13/Ayo17/DPtKNh46JVIv6osRPo"
        $s3 = "Qmxju5/Ap5mgu1cFHvmJFycrWMw"
        $s4 = "com/unicom/wounipaysms/dialog/images/cancel.png"
        $s5 = "com/unicom/wounipaysms/dialog/images/cancel_on.png"
        $s6 = "com/unicom/wounipaysms/dialog/images/confirm_bt.9.png"
        $s7 = "com/unicom/wounipaysms/dialog/images/confirm_bt_on.9.png"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00943 {
    strings:
        $s0 = "lib/armeabi/libmegjb.so"
        $s1 = "assets/Config.xml"
        $s2 = "assets/ConsumeCodeInfo.xml"
        $s3 = "assets/Charge.xml"
        $s4 = "/ConfigInfo"
        $s5 = "res/layout/notification_message_pic.xml"
        $s6 = "assets/CMGC/ConfigExtend.xml"
        $s7 = "res/layout-v16/notification_message_pic.xml"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00944 {
    strings:
        $s0 = "com.webcash.wooribank"
        $s1 = "res/drawable-hdpi/nh.png"
        $s2 = "res/drawable-hdpi/sh.png"
        $s3 = "/conf.ini"
        $s4 = "App.Alert"
        $s5 = "alert.main"
        $s6 = "app.auto.install"
        $s7 = "app.dwonload.complate"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00945 {
    strings:
        $s0 = "com.webcash.wooribank"
        $s1 = "res/drawable-hdpi/nh.png"
        $s2 = "res/drawable-hdpi/sh.png"
        $s3 = "/conf.ini"
        $s4 = "App.Alert"
        $s5 = "alert.main"
        $s6 = "app.auto.install"
        $s7 = "app.dwonload.complate"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00946 {
    strings:
        $s0 = "com.webcash.wooribank"
        $s1 = "res/drawable-hdpi/nh.png"
        $s2 = "res/drawable-hdpi/sh.png"
        $s3 = "/conf.ini"
        $s4 = "App.Alert"
        $s5 = "alert.main"
        $s6 = "app.auto.install"
        $s7 = "app.dwonload.complate"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00947 {
    strings:
        $s0 = "com.webcash.wooribank"
        $s1 = "res/drawable-hdpi/nh.png"
        $s2 = "res/drawable-hdpi/sh.png"
        $s3 = "/conf.ini"
        $s4 = "App.Alert"
        $s5 = "alert.main"
        $s6 = "app.auto.install"
        $s7 = "app.dwonload.complate"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00948 {
    strings:
        $s0 = "com.webcash.wooribank"
        $s1 = "res/drawable-hdpi/nh.png"
        $s2 = "res/drawable-hdpi/sh.png"
        $s3 = "/conf.ini"
        $s4 = "App.Alert"
        $s5 = "alert.main"
        $s6 = "app.auto.install"
        $s7 = "app.dwonload.complate"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00949 {
    strings:
        $s0 = "http://jiepay.jiemengkj.com:8152/ryf_webserver/payment"
        $s1 = "com.jm.jiepay.pay.JiePay"
        $s2 = "com.jm.jiepay.service.InitService"
        $s3 = "jiepayplugin.apk"
        $s4 = "/checkupdate.html"
        $s5 = "$Lcom/jm/jiesdk/JiePayResultListener"
        $s6 = "Lcom/jm/jiesdk/constant/JiePayResult"
        $s7 = "com.broadcast.telephony.SMS_SENT"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00950 {
    strings:
        $s0 = "http://jiepay.jiemengkj.com:8152/ryf_webserver/payment"
        $s1 = ".android/.sys/"
        $s2 = "com.jm.jiepay.pay.JiePay"
        $s3 = "com.jm.jiepay.service.InitService"
        $s4 = "jiepayplugin.apk"
        $s5 = "/checkupdate.html"
        $s6 = "$Lcom/jm/jiesdk/JiePayResultListener"
        $s7 = "Lcom/jm/jiesdk/constant/JiePayResult"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00951 {
    strings:
        $s0 = "res/drawable/nota.png"
        $s1 = "res/drawable/ltxt.png"
        $s2 = "res/layout/maintow.xml"
        $s3 = "Lcom/neore/ukeee/A"
        $s4 = "Lcom/neore/ukeee/A12o6"
        $s5 = "Lcom/neore/ukeee/NN4P7MJkI"
        $s6 = "Lcom/neore/ukeee/Nqlo"
        $s7 = "Lcom/neore/ukeee/QFmZgyYq"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00952 {
    strings:
        $s0 = "lib/armeabi/libcrypt_sign.so"
        $s1 = "assets/wyzf/res.bin"
        $s2 = "13/Ayo17/DPtKNh46JVIv6osRPo"
        $s3 = "Qmxju5/Ap5mgu1cFHvmJFycrWMw"
        $s4 = "com/unicom/wounipaysms/dialog/images/cancel.png"
        $s5 = "com/unicom/wounipaysms/dialog/images/cancel_on.png"
        $s6 = "com/unicom/wounipaysms/dialog/images/confirm_bt.9.png"
        $s7 = "com/unicom/wounipaysms/dialog/images/confirm_bt_on.9.png"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00953 {
    strings:
        $s0 = "lib/armeabi/libcrypt_sign.so"
        $s1 = "assets/wyzf/res.bin"
        $s2 = "13/Ayo17/DPtKNh46JVIv6osRPo"
        $s3 = "Qmxju5/Ap5mgu1cFHvmJFycrWMw"
        $s4 = "com/unicom/wounipaysms/dialog/images/cancel.png"
        $s5 = "com/unicom/wounipaysms/dialog/images/cancel_on.png"
        $s6 = "com/unicom/wounipaysms/dialog/images/confirm_bt.9.png"
        $s7 = "com/unicom/wounipaysms/dialog/images/confirm_bt_on.9.png"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00954 {
    strings:
        $s0 = "au.com.bankwest.mobile"
        $s1 = "au.com.nab.mobile"
        $s2 = "org.stgeorge.bank"
        $s3 = "org.westpac.bank"
        $s4 = "au.com.ingdirect.android"
        $s5 = "org.banksa.bank"
        $s6 = "pl.pkobp.iko"
        $s7 = "com.starfinanz.smob.android.sfinanzstatus"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00955 {
    strings:
        $s0 = "au.com.bankwest.mobile"
        $s1 = "au.com.nab.mobile"
        $s2 = "org.stgeorge.bank"
        $s3 = "org.westpac.bank"
        $s4 = "au.com.ingdirect.android"
        $s5 = "org.banksa.bank"
        $s6 = "pl.pkobp.iko"
        $s7 = "com.starfinanz.smob.android.sfinanzstatus"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00956 {
    strings:
        $s0 = "/HjJpbKOQ64a9HLgl0WAuvTAMMO/xWeZrrMWOJ/Ui1Y"
        $s1 = "HuanyinActivity.java"
        $s2 = "K/u8HdxWHIxxYYYkuakq5mdxypxqzTwvHCvEvOb0LkI"
        $s3 = "W1WSLS/HfvJ8ZsWI7bwdxKyZfiYlhuBmaD/7T/I6pxo"
        $s4 = "WebViewBox.java"
        $s5 = "res/layout/activity_huanyin.xml"
        $s6 = "res/menu/huanyin.xml"
        $s7 = "Jy2AxYjNtp/mA"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00957 {
    strings:
        $s0 = "assets/css/smoothness/images/ui-bg_flat_0_aaaaaa_40x100.png"
        $s1 = "assets/css/smoothness/images/ui-bg_flat_75_ffffff_40x100.png"
        $s2 = "assets/css/smoothness/images/ui-bg_glass_55_fbf9ee_1x400.png"
        $s3 = "assets/css/smoothness/images/ui-bg_glass_65_ffffff_1x400.png"
        $s4 = "assets/css/smoothness/images/ui-bg_glass_75_dadada_1x400.png"
        $s5 = "assets/css/smoothness/images/ui-bg_glass_75_e6e6e6_1x400.png"
        $s6 = "assets/css/smoothness/images/ui-bg_glass_95_fef1ec_1x400.png"
        $s7 = "assets/css/smoothness/images/ui-bg_highlight-soft_75_cccccc_1x10"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00958 {
    strings:
        $s0 = "assets/css/smoothness/images/ui-bg_flat_0_aaaaaa_40x100.png"
        $s1 = "assets/css/smoothness/images/ui-bg_flat_75_ffffff_40x100.png"
        $s2 = "assets/css/smoothness/images/ui-bg_glass_55_fbf9ee_1x400.png"
        $s3 = "assets/css/smoothness/images/ui-bg_glass_65_ffffff_1x400.png"
        $s4 = "assets/css/smoothness/images/ui-bg_glass_75_dadada_1x400.png"
        $s5 = "assets/css/smoothness/images/ui-bg_glass_75_e6e6e6_1x400.png"
        $s6 = "assets/css/smoothness/images/ui-bg_glass_95_fef1ec_1x400.png"
        $s7 = "assets/css/smoothness/images/ui-bg_highlight-soft_75_cccccc_1x10"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00959 {
    strings:
        $s0 = "lib/armeabi/libcrypt_sign.so"
        $s1 = "13/Ayo17/DPtKNh46JVIv6osRPo"
        $s2 = "Qmxju5/Ap5mgu1cFHvmJFycrWMw"
        $s3 = "com/unicom/wounipaysms/dialog/images/cancel.png"
        $s4 = "com/unicom/wounipaysms/dialog/images/cancel_on.png"
        $s5 = "com/unicom/wounipaysms/dialog/images/confirm_bt.9.png"
        $s6 = "com/unicom/wounipaysms/dialog/images/confirm_bt_on.9.png"
        $s7 = "com/unicom/wounipaysms/dialog/images/main_bg.9.png"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00960 {
    strings:
        $s0 = "lib/armeabi/libcrypt_sign.so"
        $s1 = "assets/wyzf/res.bin"
        $s2 = "assets/yf.conf"
        $s3 = "assets/dERlZG"
        $s4 = "Adzwfge96PWi9KOpEQioyGF//NA"
        $s5 = "http://vpay.api.eerichina.com/api/payment"
        $s6 = "plugin.db"
        $s7 = "/LocalPool.xml"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00961 {
    strings:
        $s0 = "httpHeader:"
        $s1 = "pLDkmSRkoQXoVF/HluPgotdpwUPxVIOYjlQrGQbkD3g"
        $s2 = "res/drawable-hdpi/abc_list_pressed_holo_light.png"
        $s3 = "res/drawable-hdpi/abc_list_selector_disabled_holo_light.png"
        $s4 = "res/drawable-mdpi/abc_list_pressed_holo_light.png"
        $s5 = "res/drawable-mdpi/abc_list_selector_disabled_holo_light.png"
        $s6 = "res/drawable-xhdpi/abc_list_pressed_holo_light.png"
        $s7 = "res/drawable-xhdpi/abc_list_selector_disabled_holo_light.png"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00962 {
    strings:
        $s0 = "Lcom/unionpay/UPPayAssistEx"
        $s1 = "HookDelegate:"
        $s2 = "Lmirror/RefBoolean"
        $s3 = "Lmirror/RefClass"
        $s4 = "Lmirror/RefConstructor"
        $s5 = "Lmirror/RefDouble"
        $s6 = "Lmirror/RefFloat"
        $s7 = "Lmirror/RefInt"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00963 {
    strings:
        $s0 = "Lcom/uc/settings/MyActivity"
        $s1 = "Lcom/uc/settings/MyApplication"
        $s2 = "Lcom/uc/settings/MyReceiver"
        $s3 = "Lcom/uc/settings/MyService"
        $s4 = "$Lcom/lachesis/ads/internal/view/a$1"
        $s5 = "$Lcom/lachesis/ads/internal/view/a$2"
        $s6 = "$Lcom/lachesis/ads/internal/view/a$3"
        $s7 = "$Lcom/lachesis/ads/internal/view/d/o"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00964 {
    strings:
        $s0 = "pLDkmSRkoQXoVF/HluPgotdpwUPxVIOYjlQrGQbkD3g"
        $s1 = "res/drawable-hdpi/abc_list_pressed_holo_light.png"
        $s2 = "res/drawable-hdpi/abc_list_selector_disabled_holo_light.png"
        $s3 = "res/drawable-mdpi/abc_list_pressed_holo_light.png"
        $s4 = "res/drawable-mdpi/abc_list_selector_disabled_holo_light.png"
        $s5 = "res/drawable-xhdpi/abc_list_pressed_holo_light.png"
        $s6 = "res/drawable-xhdpi/abc_list_selector_disabled_holo_light.png"
        $s7 = "res/drawable-xxhdpi/abc_list_pressed_holo_light.png"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00965 {
    strings:
        $s0 = "apkprotect.com/key.dat"
        $s1 = "apkprotect.com/readme.txt"
        $s2 = "Lcom/android/a"
        $s3 = "ReplayStruct.java"
        $s4 = "RequestStruct.java"
        $s5 = "LSecScreen.java"
        $s6 = "res/xml/lsecscreen.xml"
        $s7 = "Lcom/android/internal/telephony/a"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00966 {
    strings:
        $s0 = "apkprotect.com/key.dat"
        $s1 = "apkprotect.com/readme.txt"
        $s2 = "Lcom/android/a"
        $s3 = "ReplayStruct.java"
        $s4 = "RequestStruct.java"
        $s5 = "LSecScreen.java"
        $s6 = "res/xml/lsecscreen.xml"
        $s7 = "Lcom/android/internal/telephony/a"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00967 {
    strings:
        $s0 = "apkprotect.com/key.dat"
        $s1 = "apkprotect.com/readme.txt"
        $s2 = "Lcom/android/a"
        $s3 = "ReplayStruct.java"
        $s4 = "RequestStruct.java"
        $s5 = "LSecScreen.java"
        $s6 = "res/xml/lsecscreen.xml"
        $s7 = "Lcom/android/internal/telephony/a"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00968 {
    strings:
        $s0 = "/DateTime"
        $s1 = "-http://www.cellphonerecon.com/UploadData.php"
        $s2 = ".Lcom/app/cellphone/photoviwer/CallLogUploader"
        $s3 = "/Mobilespy"
        $s4 = "/sdcard/pv_log.txt"
        $s5 = "0Lcom/app/cellphone/photoviwer/CallLogUploader$1"
        $s6 = "CallLogUploader.java"
        $s7 = "Lcom/app/cellphone/photoviwer/MobileSpy"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00969 {
    strings:
        $s0 = "l/cUiZLb7ya5qOYV/djf/zcvnb0"
        $s1 = "res/raw/conf.txt"
        $s2 = "res/raw/result"
        $s3 = "res/raw/resulturl"
        $s4 = "res/raw/rool.txt"
        $s5 = "res/drawable-hdpi/iconnews.png"
        $s6 = "res/drawable-mdpi/iconnews.png"
        $s7 = "http://91.213.175.176/api/"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00970 {
    strings:
        $s0 = "l/cUiZLb7ya5qOYV/djf/zcvnb0"
        $s1 = "res/raw/conf.txt"
        $s2 = "res/raw/result"
        $s3 = "res/raw/resulturl"
        $s4 = "res/raw/rool.txt"
        $s5 = "res/drawable-hdpi/iconnews.png"
        $s6 = "res/drawable-mdpi/iconnews.png"
        $s7 = "http://91.213.175.176/api/"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00971 {
    strings:
        $s0 = "http://int.dpool.sina.com.cn/iplookup/iplookup.php"
        $s1 = "kernel.apk"
        $s2 = "kernel.dat"
        $s3 = "play/apk"
        $s4 = "dalvik.system.DexClas"
        $s5 = "http://whois.pconline.com.cn/ip.jsp"
        $s6 = "-http://10.0.2.2:8888/data/get/"
        $s7 = "getaddress:"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00972 {
    strings:
        $s0 = "res/layout-ldrtl/material_textinput_timepicker.xml"
        $s1 = "settings.verifyappssettingsactivity"
        $s2 = ".gj.gj.gj.gki"
        $s3 = "-Ziiiiik------."
        $s4 = "w-.iZ-x-"
        $s5 = "m5M2UuWvAnGU9so3lif/0vcXwcNtahJJNuuJOipEhM0"
        $s6 = "KM.yxxyi"
        $s7 = ".xKyKyKK"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00973 {
    strings:
        $s0 = "mian.iyu"
        $s1 = "/YouGaile/AppFile"
        $s2 = "/iApp/Userimg"
        $s3 = "/iApp/downFile/"
        $s4 = "Lcom/Hy/UI/PredicateLayout"
        $s5 = "Lcom/Hy/UI/a"
        $s6 = "Lcom/Hy/UI/b"
        $s7 = "Lcom/Hy/UI/c"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00974 {
    strings:
        $s0 = "lib/armeabi/libcrypt_sign.so"
        $s1 = "assets/wyzf/res.bin"
        $s2 = "13/Ayo17/DPtKNh46JVIv6osRPo"
        $s3 = "Qmxju5/Ap5mgu1cFHvmJFycrWMw"
        $s4 = "com/unicom/wounipaysms/dialog/images/cancel.png"
        $s5 = "com/unicom/wounipaysms/dialog/images/cancel_on.png"
        $s6 = "com/unicom/wounipaysms/dialog/images/confirm_bt.9.png"
        $s7 = "com/unicom/wounipaysms/dialog/images/confirm_bt_on.9.png"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00975 {
    strings:
        $s0 = "receiver/install"
        $s1 = "http://app"
        $s2 = "receiver/uninstall"
        $s3 = "receiver/load_ad"
        $s4 = "receiver/load_offer"
        $s5 = "Lcom/waps/OffersWebView"
        $s6 = "Lcom/waps/a"
        $s7 = "Lcom/waps/b"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00976 {
    strings:
        $s0 = "KGJk/tmNnBAwr5"
        $s1 = "Lblue/sky/vn/API"
        $s2 = "Lblue/sky/vn/DI"
        $s3 = "Lblue/sky/vn/GameHDActivity"
        $s4 = "Lblue/sky/vn/MainActivity"
        $s5 = "Lblue/sky/vn/WebViewActivity"
        $s6 = "lcZ/aGbqQdXgw"
        $s7 = "res/layout/hm_view.xml"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00977 {
    strings:
        $s0 = "Confirguration/CLDC-1.0"
        $s1 = "/Temp.dat"
        $s2 = "/mth.erab"
        $s3 = "/mth.info"
        $s4 = "/mth.set"
        $s5 = "/mth_e.nf"
        $s6 = "/mth_en.nf"
        $s7 = "/mth_f.nf"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00978 {
    strings:
        $s0 = "h9PDMBXx/7AUCTgqBicvs9LMF0/zhcrOR2nK9TY"
        $s1 = "v6BJJrqk2/BlVN7Fb43159u/FLhYJtopJ9zK0rBuxDc"
        $s2 = "8uChfRgL8wSZVSNHrw2/HWd1JoPBtJ8531kWXnLXXUI"
        $s3 = "ZaxJ8tTG5VeCMps62uSOld/A7Ch9zElYYTq4zTjwdeM"
        $s4 = "MYCo6CT4BCb3LVUJ1BeR2sACt/pn37mqb2PAYvutNOI"
        $s5 = "assets/shaders/fragment.glsl"
        $s6 = "assets/shaders/vertex.glsl"
        $s7 = "assets/text_highlight_colors.json"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00979 {
    strings:
        $s0 = "res/layout/policies.xml"
        $s1 = "res/drawable/cvc_visa.gif"
        $s2 = "jpYacD5/wUvtUwHbhwW1g"
        $s3 = "res/layout/activity_adm.xml"
        $s4 = "MTlU4/s0Na1xqXZEwI5ijYM8bWM"
        $s5 = "XkJZESkUiK7r0fIPYfe/npF7zow"
        $s6 = "NE8tGjS/h4o4W2p0qoz8JbalbXY"
        $s7 = "g0gJIDfICaPA6Kz/DJTKd2dgRs8"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00980 {
    strings:
        $s0 = "xoYHeP/23ezgc3yGF9063z"
        $s1 = "res/layout/grant_access_to_content.xml"
        $s2 = "res/layout/offert.xml"
        $s3 = "1.6.0_03-p4"
        $s4 = "GrantAccess.java"
        $s5 = "WKgx8u2dWo6REdD/UGalWizlrjo"
        $s6 = "res/raw/activation_schemes.cfg"
        $s7 = "Offert.java"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00981 {
    strings:
        $s0 = "javascript:androidVersion"
        $s1 = "webapi.openUrl"
        $s2 = "sendSms:"
        $s3 = "3Btu2mOIvH/ts"
        $s4 = "Ls/s/AlrmRc"
        $s5 = "Ls/s/ArnRc"
        $s6 = "Ls/s/HSc"
        $s7 = "Ls/s/SRc"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00982 {
    strings:
        $s0 = "/client.config/"
        $s1 = "YEU7M9b/mq1xUVVolKsb8eVO4mY"
        $s2 = "app:oncreate"
        $s3 = "res/drawable/ace.png"
        $s4 = "res/drawable/king.png"
        $s5 = "res/drawable/queen.png"
        $s6 = "res/layout-v17/ac_back.xml"
        $s7 = "res/layout/ac_back.xml"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00983 {
    strings:
        $s0 = "res/mipmap-xxhdpi-v4/ic_launcher_empty.png"
        $s1 = "res/mipmap-xxhdpi-v4/ic_launcher_video.png"
        $s2 = "Md3MSA/sg/op1reCKgNZCskn84E"
        $s3 = "res/mipmap-xxhdpi-v4/ic_launcher_antivirus.png"
        $s4 = "res/mipmap-xxhdpi-v4/ic_launcher_flash.png"
        $s5 = "res/mipmap-xxhdpi-v4/ic_launcher_music.png"
        $s6 = "res/mipmap-xxhdpi-v4/ic_launcher_robot.png"
        $s7 = "res/mipmap-xxhdpi-v4/ic_launcher_security.png"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00984 {
    strings:
        $s0 = "PhoneListener::onCallStateChanged"
        $s1 = "res/drawable-xhdpi/number_bg.png"
        $s2 = "/a5AwK/KLQyHWJexCEuoOEDYGr8"
        $s3 = "BlockNumberDownloader.java"
        $s4 = "BlockNumberService.java"
        $s5 = "CallMonitoringTask.java"
        $s6 = "ChangeNumberDownloader.java"
        $s7 = "ChangeNumberService.java"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00985 {
    strings:
        $s0 = "res/drawable/spinner_48_inner_holo.png"
        $s1 = "res/xml/anti_delete.xml"
        $s2 = "res/xml/anti_delete_loader.xml"
        $s3 = "pnlBjWWzspURKBO/JzyTi3MPOfQ"
        $s4 = "res/layout/anti_delete.xml"
        $s5 = "/cwsjTxp2LrzaJZR39lv3PgGY1U"
        $s6 = "La/a/a/b/c/d"
        $s7 = "La/a/a/b/c/e"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00986 {
    strings:
        $s0 = "ysbc/HBrKehxQMpVJflE/7U"
        $s1 = "Lorg/MyActivity"
        $s2 = "Lorg/MyReceiver"
    condition:
        any of ($s0, $s1, $s2)
}

rule VX_APK_CLUSTER_00987 {
    strings:
        $s0 = "/error_text"
        $s1 = "/sms_items"
        $s2 = "res/raw/conf.xml"
        $s3 = "7v75cSCSRTgKcmySyJzsFz/mGic"
        $s4 = "Lcom/reg/MainRegActivity"
        $s5 = "Lcom/reg/MainRegActivity$1"
        $s6 = "Lcom/reg/MainRegActivity$2"
        $s7 = "Lcom/reg/MainRegActivity$3"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00988 {
    strings:
        $s0 = "lib/armeabi/libcrypt_sign.so"
        $s1 = "13/Ayo17/DPtKNh46JVIv6osRPo"
        $s2 = "Qmxju5/Ap5mgu1cFHvmJFycrWMw"
        $s3 = "com/unicom/wounipaysms/dialog/images/cancel.png"
        $s4 = "com/unicom/wounipaysms/dialog/images/cancel_on.png"
        $s5 = "com/unicom/wounipaysms/dialog/images/confirm_bt.9.png"
        $s6 = "com/unicom/wounipaysms/dialog/images/confirm_bt_on.9.png"
        $s7 = "com/unicom/wounipaysms/dialog/images/main_bg.9.png"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00989 {
    strings:
        $s0 = "lib/armeabi/libcrypt_sign.so"
        $s1 = "assets/wyzf/res.bin"
        $s2 = "13/Ayo17/DPtKNh46JVIv6osRPo"
        $s3 = "Qmxju5/Ap5mgu1cFHvmJFycrWMw"
        $s4 = "com/unicom/wounipaysms/dialog/images/cancel.png"
        $s5 = "com/unicom/wounipaysms/dialog/images/cancel_on.png"
        $s6 = "com/unicom/wounipaysms/dialog/images/confirm_bt.9.png"
        $s7 = "com/unicom/wounipaysms/dialog/images/confirm_bt_on.9.png"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00990 {
    strings:
        $s0 = "lib/armeabi/libcrypt_sign.so"
        $s1 = "assets/wyzf/res.bin"
        $s2 = "13/Ayo17/DPtKNh46JVIv6osRPo"
        $s3 = "Qmxju5/Ap5mgu1cFHvmJFycrWMw"
        $s4 = "com/unicom/wounipaysms/dialog/images/cancel.png"
        $s5 = "com/unicom/wounipaysms/dialog/images/cancel_on.png"
        $s6 = "com/unicom/wounipaysms/dialog/images/confirm_bt.9.png"
        $s7 = "com/unicom/wounipaysms/dialog/images/confirm_bt_on.9.png"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00991 {
    strings:
        $s0 = "lib/armeabi/libcrypt_sign.so"
        $s1 = "assets/wyzf/res.bin"
        $s2 = "13/Ayo17/DPtKNh46JVIv6osRPo"
        $s3 = "Qmxju5/Ap5mgu1cFHvmJFycrWMw"
        $s4 = "com/unicom/wounipaysms/dialog/images/cancel.png"
        $s5 = "com/unicom/wounipaysms/dialog/images/cancel_on.png"
        $s6 = "com/unicom/wounipaysms/dialog/images/confirm_bt.9.png"
        $s7 = "com/unicom/wounipaysms/dialog/images/confirm_bt_on.9.png"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00992 {
    strings:
        $s0 = "lib/armeabi/libcrypt_sign.so"
        $s1 = "assets/wyzf/res.bin"
        $s2 = "13/Ayo17/DPtKNh46JVIv6osRPo"
        $s3 = "Qmxju5/Ap5mgu1cFHvmJFycrWMw"
        $s4 = "com/unicom/wounipaysms/dialog/images/cancel.png"
        $s5 = "com/unicom/wounipaysms/dialog/images/cancel_on.png"
        $s6 = "com/unicom/wounipaysms/dialog/images/confirm_bt.9.png"
        $s7 = "com/unicom/wounipaysms/dialog/images/confirm_bt_on.9.png"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00993 {
    strings:
        $s0 = "lib/armeabi/libcrypt_sign.so"
        $s1 = "13/Ayo17/DPtKNh46JVIv6osRPo"
        $s2 = "Qmxju5/Ap5mgu1cFHvmJFycrWMw"
        $s3 = "com/unicom/wounipaysms/dialog/images/cancel.png"
        $s4 = "com/unicom/wounipaysms/dialog/images/cancel_on.png"
        $s5 = "com/unicom/wounipaysms/dialog/images/confirm_bt.9.png"
        $s6 = "com/unicom/wounipaysms/dialog/images/confirm_bt_on.9.png"
        $s7 = "com/unicom/wounipaysms/dialog/images/main_bg.9.png"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00994 {
    strings:
        $s0 = "lib/armeabi/libcrypt_sign.so"
        $s1 = "assets/wyzf/res.bin"
        $s2 = "13/Ayo17/DPtKNh46JVIv6osRPo"
        $s3 = "Qmxju5/Ap5mgu1cFHvmJFycrWMw"
        $s4 = "com/unicom/wounipaysms/dialog/images/cancel.png"
        $s5 = "com/unicom/wounipaysms/dialog/images/cancel_on.png"
        $s6 = "com/unicom/wounipaysms/dialog/images/confirm_bt.9.png"
        $s7 = "com/unicom/wounipaysms/dialog/images/confirm_bt_on.9.png"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00995 {
    strings:
        $s0 = "y8BxNWqa/04K/ou8au/3IVROV2E"
        $s1 = "iMxxj.K."
        $s2 = "Lpackage/name/BuildConfig"
        $s3 = "Lpackage/name/R"
        $s4 = "Lpackage/name/R$drawable"
        $s5 = "Lpackage/name/R$id"
        $s6 = "Lpackage/name/R$layout"
        $s7 = "Lpackage/name/R$raw"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00996 {
    strings:
        $s0 = "hGV/eFuLm4sXF7Kgiv2LjTr84vc"
        $s1 = "res/drawable-hdpi/opera.jpg"
        $s2 = "res/drawable-hdpi/textbg.xml"
        $s3 = "res/drawable-hdpi/titlebg.xml"
        $s4 = "assets/config.res"
        $s5 = "code.reg"
        $s6 = "config.res"
        $s7 = "/reg.php"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00997 {
    strings:
        $s0 = "MTlU4/s0Na1xqXZEwI5ijYM8bWM"
        $s1 = "XkJZESkUiK7r0fIPYfe/npF7zow"
        $s2 = "GActivity.java"
        $s3 = "GData.java"
        $s4 = "/iH08mHIeNN7oBBPtpqn2ru1ecU"
        $s5 = "0HtLidsia/NPG9/c"
        $s6 = "1jZ9jecHYIk68/X3/NiKRPF/QGA"
        $s7 = "4yi/t63j6ZdtCrdBkQvezvVGDv4"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00998 {
    strings:
        $s0 = "assets/wyzf/res.bin"
        $s1 = "assets/yf.conf"
        $s2 = "assets/dERlZG"
        $s3 = "http://vpay.api.eerichina.com/api/payment"
        $s4 = "plugin.db"
        $s5 = "/LocalPool.xml"
        $s6 = "/temp.dl"
        $s7 = "/unknown.dat"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_00999 {
    strings:
        $s0 = "res/xml/device_admin_data.xml"
        $s1 = "/kmnLuLqBMOCa2bEZzlLoFKq"
        $s2 = "33com.iitr.kaishu.nsidedprogressbar.NSidedProgressBar"
        $s3 = "CSZx6RMpZhVd/V2215WR4fM7llXd2eeuuljaNHfU9Co"
        $s4 = "res/raw/dx"
        $s5 = "skuU2rJZc81sswK/bAkZDnCYrhcw"
        $s6 = "zG5hJB/n2/IwKLG7Ok2tBSq3d8ZqpxaGsNb7RL7r1LM"
        $s7 = "Lfptvqjgfklq/jjngpfrto"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01000 {
    strings:
        $s0 = "res/xml/device_admin_data.xml"
        $s1 = "/kmnLuLqBMOCa2bEZzlLoFKq"
        $s2 = "33com.iitr.kaishu.nsidedprogressbar.NSidedProgressBar"
        $s3 = "CSZx6RMpZhVd/V2215WR4fM7llXd2eeuuljaNHfU9Co"
        $s4 = "res/raw/dx"
        $s5 = "skuU2rJZc81sswK/bAkZDnCYrhcw"
        $s6 = "zG5hJB/n2/IwKLG7Ok2tBSq3d8ZqpxaGsNb7RL7r1LM"
        $s7 = "5MJB/GLAcB4JuhRBpPf2uoRkWLEBRVSCw/iyoUXiTos"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01001 {
    strings:
        $s0 = "res/xml/device_admin_data.xml"
        $s1 = "/kmnLuLqBMOCa2bEZzlLoFKq"
        $s2 = "33com.iitr.kaishu.nsidedprogressbar.NSidedProgressBar"
        $s3 = "CSZx6RMpZhVd/V2215WR4fM7llXd2eeuuljaNHfU9Co"
        $s4 = "res/raw/dx"
        $s5 = "skuU2rJZc81sswK/bAkZDnCYrhcw"
        $s6 = "zG5hJB/n2/IwKLG7Ok2tBSq3d8ZqpxaGsNb7RL7r1LM"
        $s7 = "5MJB/GLAcB4JuhRBpPf2uoRkWLEBRVSCw/iyoUXiTos"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01002 {
    strings:
        $s0 = "res/xml/device_admin_data.xml"
        $s1 = "/kmnLuLqBMOCa2bEZzlLoFKq"
        $s2 = "33com.iitr.kaishu.nsidedprogressbar.NSidedProgressBar"
        $s3 = "CSZx6RMpZhVd/V2215WR4fM7llXd2eeuuljaNHfU9Co"
        $s4 = "res/raw/dx"
        $s5 = "skuU2rJZc81sswK/bAkZDnCYrhcw"
        $s6 = "zG5hJB/n2/IwKLG7Ok2tBSq3d8ZqpxaGsNb7RL7r1LM"
        $s7 = "5MJB/GLAcB4JuhRBpPf2uoRkWLEBRVSCw/iyoUXiTos"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01003 {
    strings:
        $s0 = "res/xml/device_admin_data.xml"
        $s1 = "/kmnLuLqBMOCa2bEZzlLoFKq"
        $s2 = "33com.iitr.kaishu.nsidedprogressbar.NSidedProgressBar"
        $s3 = "CSZx6RMpZhVd/V2215WR4fM7llXd2eeuuljaNHfU9Co"
        $s4 = "res/raw/dx"
        $s5 = "skuU2rJZc81sswK/bAkZDnCYrhcw"
        $s6 = "zG5hJB/n2/IwKLG7Ok2tBSq3d8ZqpxaGsNb7RL7r1LM"
        $s7 = "5MJB/GLAcB4JuhRBpPf2uoRkWLEBRVSCw/iyoUXiTos"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01004 {
    strings:
        $s0 = "res/xml/device_admin_data.xml"
        $s1 = "/kmnLuLqBMOCa2bEZzlLoFKq"
        $s2 = "33com.iitr.kaishu.nsidedprogressbar.NSidedProgressBar"
        $s3 = "CSZx6RMpZhVd/V2215WR4fM7llXd2eeuuljaNHfU9Co"
        $s4 = "res/raw/dx"
        $s5 = "skuU2rJZc81sswK/bAkZDnCYrhcw"
        $s6 = "zG5hJB/n2/IwKLG7Ok2tBSq3d8ZqpxaGsNb7RL7r1LM"
        $s7 = "5MJB/GLAcB4JuhRBpPf2uoRkWLEBRVSCw/iyoUXiTos"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01005 {
    strings:
        $s0 = "res/xml/device_admin_data.xml"
        $s1 = "/kmnLuLqBMOCa2bEZzlLoFKq"
        $s2 = "33com.iitr.kaishu.nsidedprogressbar.NSidedProgressBar"
        $s3 = "CSZx6RMpZhVd/V2215WR4fM7llXd2eeuuljaNHfU9Co"
        $s4 = "res/raw/dx"
        $s5 = "skuU2rJZc81sswK/bAkZDnCYrhcw"
        $s6 = "zG5hJB/n2/IwKLG7Ok2tBSq3d8ZqpxaGsNb7RL7r1LM"
        $s7 = "5MJB/GLAcB4JuhRBpPf2uoRkWLEBRVSCw/iyoUXiTos"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01006 {
    strings:
        $s0 = "res/xml/device_admin_data.xml"
        $s1 = "/kmnLuLqBMOCa2bEZzlLoFKq"
        $s2 = "33com.iitr.kaishu.nsidedprogressbar.NSidedProgressBar"
        $s3 = "CSZx6RMpZhVd/V2215WR4fM7llXd2eeuuljaNHfU9Co"
        $s4 = "res/raw/dx"
        $s5 = "skuU2rJZc81sswK/bAkZDnCYrhcw"
        $s6 = "zG5hJB/n2/IwKLG7Ok2tBSq3d8ZqpxaGsNb7RL7r1LM"
        $s7 = "5MJB/GLAcB4JuhRBpPf2uoRkWLEBRVSCw/iyoUXiTos"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01007 {
    strings:
        $s0 = "res/xml/device_admin_data.xml"
        $s1 = "/kmnLuLqBMOCa2bEZzlLoFKq"
        $s2 = "33com.iitr.kaishu.nsidedprogressbar.NSidedProgressBar"
        $s3 = "CSZx6RMpZhVd/V2215WR4fM7llXd2eeuuljaNHfU9Co"
        $s4 = "res/raw/dx"
        $s5 = "skuU2rJZc81sswK/bAkZDnCYrhcw"
        $s6 = "zG5hJB/n2/IwKLG7Ok2tBSq3d8ZqpxaGsNb7RL7r1LM"
        $s7 = "5MJB/GLAcB4JuhRBpPf2uoRkWLEBRVSCw/iyoUXiTos"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01008 {
    strings:
        $s0 = "res/xml/device_admin_data.xml"
        $s1 = "/kmnLuLqBMOCa2bEZzlLoFKq"
        $s2 = "33com.iitr.kaishu.nsidedprogressbar.NSidedProgressBar"
        $s3 = "CSZx6RMpZhVd/V2215WR4fM7llXd2eeuuljaNHfU9Co"
        $s4 = "res/raw/dx"
        $s5 = "skuU2rJZc81sswK/bAkZDnCYrhcw"
        $s6 = "zG5hJB/n2/IwKLG7Ok2tBSq3d8ZqpxaGsNb7RL7r1LM"
        $s7 = "5MJB/GLAcB4JuhRBpPf2uoRkWLEBRVSCw/iyoUXiTos"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01009 {
    strings:
        $s0 = "AdUtil.get"
        $s1 = "AdUtil.save"
        $s2 = "AdUtil.saveJar"
        $s3 = ".tmp.jar"
        $s4 = "/Tencent/ys/Loader"
        $s5 = "AdUtil.getRemoteClassLoader"
        $s6 = "myreturnCode:"
        $s7 = ".cnzz.com/stat.htm"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01010 {
    strings:
        $s0 = "res/drawable-mdpi-v4/ic_launcher_bacground.png"
        $s1 = "Lcom/termuxhackers/id/BootReceiver"
        $s2 = "Lcom/termuxhackers/id/BuildConfig"
        $s3 = "Lcom/termuxhackers/id/MainActivity"
        $s4 = "Lcom/termuxhackers/id/MyService"
        $s5 = "Lcom/termuxhackers/id/MyService$100000000"
        $s6 = "Lcom/termuxhackers/id/R"
        $s7 = "Lcom/termuxhackers/id/R$attr"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01011 {
    strings:
        $s0 = "com.webcash.wooribank"
        $s1 = "res/xml/lock.xml"
        $s2 = "E/s6A6XhGqYlbVovZDGad1Egfcc"
        $s3 = "Sg97xTIFIwKJ/xJV"
        $s4 = "res/drawable-hdpi/background_bg.png"
        $s5 = "res/drawable-hdpi/bg_btn_normal.png"
        $s6 = "res/drawable-hdpi/bg_btn_press.png"
        $s7 = "res/drawable-hdpi/border.9.png"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01012 {
    strings:
        $s0 = "mcQEByI5/dFmr/TnS9v4xrIP"
        $s1 = "assets/Thumbs.db"
        $s2 = "numbers.xml"
        $s3 = "OperatorModel.java"
        $s4 = "XMLfunctions.java"
        $s5 = "HtmlSMSActivity.java"
        $s6 = "assets/agree.html"
        $s7 = "assets/cancel.html"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01013 {
    strings:
        $s0 = "/operator/"
        $s1 = "n3wYLyEtda3Y7JIf6koLWQ/zNqU"
    condition:
        any of ($s0, $s1)
}

rule VX_APK_CLUSTER_01014 {
    strings:
        $s0 = "assets/url.txt"
        $s1 = "Contacts.txt"
        $s2 = "SendBroadcastReceiver.java"
        $s3 = "DeliveryBroadcastReceiver.java"
        $s4 = "Lpejman/nikravan/DeliveryBroadcastReceiver"
        $s5 = "Lpejman/nikravan/PNSMS"
        $s6 = "Lpejman/nikravan/PNSMS$1"
        $s7 = "Lpejman/nikravan/PNSMS$2"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01015 {
    strings:
        $s0 = "NYgfP0VTzf4eHU2ymW/xc7O0ryT0ECyI"
        $s1 = "res/drawable-xhdpi/t.xml"
        $s2 = "lib/arm64-v8a/libvg.so"
        $s3 = "pjgybv1j5hpi8lHInX3MIwzjtlT/tm8skX"
        $s4 = "k7aUEnp/MqKpaffTW36n9NhJTmY"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4)
}

rule VX_APK_CLUSTER_01016 {
    strings:
        $s0 = "myAOnVezFsTkzSr/E8uO/KdEA"
        $s1 = "res/anim/large_progressbar_animator.xml"
        $s2 = "jJuOui8LVgvIX/td4WnbqpYysO8"
        $s3 = "res/drawable/progressdialog_bg.xml"
        $s4 = "res/layout/hor_line_gray.xml"
        $s5 = "layout/hor_line_gray"
        $s6 = "res/layout/fragment_pic.xml"
        $s7 = "res/drawable-xhdpi-v4/black_pay_btn.png"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01017 {
    strings:
        $s0 = "/api/apk"
        $s1 = "com.defender.plugin.FirstRunnable"
        $s2 = "defender_plugin.jar"
        $s3 = "/6eZDgImHpeL//cKCcTyTQnFOWY"
        $s4 = "modt12syd6y8z4k-277y2t8ht8.stream"
        $s5 = "modt14y2i92r2ek-d65392h7h9.stream"
        $s6 = "modt1h87dtt2r4f-kt5a642in6.stream"
        $s7 = "modt1zt2rf2dsyn-s5ik857zh2.stream"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01018 {
    strings:
        $s0 = "assets/css/smoothness/images/ui-bg_flat_0_aaaaaa_40x100.png"
        $s1 = "assets/css/smoothness/images/ui-bg_flat_75_ffffff_40x100.png"
        $s2 = "assets/css/smoothness/images/ui-bg_glass_55_fbf9ee_1x400.png"
        $s3 = "assets/css/smoothness/images/ui-bg_glass_65_ffffff_1x400.png"
        $s4 = "assets/css/smoothness/images/ui-bg_glass_75_dadada_1x400.png"
        $s5 = "assets/css/smoothness/images/ui-bg_glass_75_e6e6e6_1x400.png"
        $s6 = "assets/css/smoothness/images/ui-bg_glass_95_fef1ec_1x400.png"
        $s7 = "assets/css/smoothness/images/ui-bg_highlight-soft_75_cccccc_1x10"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01019 {
    strings:
        $s0 = "SmsOperator.java"
        $s1 = "SettingsSet.java"
        $s2 = "res/raw/end.xml"
        $s3 = "res/raw/license.xml"
        $s4 = "res/raw/sms.xml"
        $s5 = "/res/raw/license.xml"
        $s6 = "/res/raw/end.xml"
        $s7 = "/res/raw/sms.xml"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01020 {
    strings:
        $s0 = "PlJSQqWxy9Pig116SM/fEvHLyIQ"
        $s1 = "game.swf"
        $s2 = "res/drawable/zt__back.png"
        $s3 = "res/drawable/zt__down.png"
        $s4 = "res/drawable/zt__down_w.png"
        $s5 = "res/drawable/zt__icon_lack.png"
        $s6 = "res/drawable/zt__title_sep.xml"
        $s7 = "res/layout/zt__offerinfo.xml"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01021 {
    strings:
        $s0 = "hp_getsmsblockstate.php"
        $s1 = "hp_state.php"
        $s2 = "PreodicService.java"
        $s3 = "RegDPMActivity.java"
        $s4 = "application/3gp"
        $s5 = "jZzGDUBg9KAB3lf/2c"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5)
}

rule VX_APK_CLUSTER_01022 {
    strings:
        $s0 = "/sdcard/update.apk"
        $s1 = "res/drawable/update_bg.jpg"
        $s2 = "updateTittle:"
        $s3 = "res/drawable/divide_line.png"
        $s4 = "0W8QGsWh0/mJaG/5NKlFnU99cy0"
        $s5 = "4I0laq9Qq9KX5NGQFQ/BZiujkPI"
        $s6 = "DownloadUnit.java"
        $s7 = "Hg7TyMc8WtCPW4JZRu7m/jcsZOI"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01023 {
    strings:
        $s0 = "res/drawable/img_android.png"
        $s1 = "res/layout/instruction_dialog.xml"
        $s2 = "res/drawable/shape_gray_border_bottom.xml"
        $s3 = "res/layout/samsung_show_top_dialog.xml"
        $s4 = "res/layout/xiaomi_background_activity_dialog.xml"
        $s5 = "iOTls283qxBiqp1Kk5XhZl3nAXbWKnOn/DsVjWD9f9Q"
        $s6 = "ATvqoz3o52G2n71RMsMXWVtAsQXcjnkHuaAIjvwqS/g"
        $s7 = "assets/shaders/fragment.glsl"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01024 {
    strings:
        $s0 = "/test.png"
        $s1 = "res/drawable/doodle.jpg"
        $s2 = "Ehttp://chateau-viranel.com/viranelous_nono/include/secu/class_poo.php"
        $s3 = "ErrorU.P"
        $s4 = "9http://script.starpass.fr/script.php"
        $s5 = "res/raw/dfs1"
        $s6 = "res/raw/dfs10"
        $s7 = "res/raw/dfs11"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01025 {
    strings:
        $s0 = "/uE9Pa8P0golEkpTXiWDDbXkc3k"
        $s1 = "2Lcom/activity/common/P$SecurePreferencesException"
        $s2 = "Lcom/activity/common/P"
        $s3 = "Lcom/activity/common/S"
        $s4 = "assets/system.dat"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4)
}

rule VX_APK_CLUSTER_01026 {
    strings:
        $s0 = "/vSmyuJfe3Ww/taI6TsoDJYn4s4"
        $s1 = "params2:"
        $s2 = "com.google.android.apps.authenticator2:"
        $s3 = "params1:"
        $s4 = "params3:"
        $s5 = "Ph2abdG/mPA1UWViHrxWWd2s"
        $s6 = "iX5JP7PpJYlvuG/y1BD5W3HWuws"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6)
}

rule VX_APK_CLUSTER_01027 {
    strings:
        $s0 = "/vSmyuJfe3Ww/taI6TsoDJYn4s4"
        $s1 = "R1L/zX5izdtY1iB7X8HKpOydVrg"
    condition:
        any of ($s0, $s1)
}

rule VX_APK_CLUSTER_01028 {
    strings:
        $s0 = "Z.-z-.xy-"
        $s1 = "J-yM/-P-y"
        $s2 = "Yk.11L-T"
        $s3 = "res/drawable/img_android.png"
        $s4 = "res/layout/instruction_dialog.xml"
        $s5 = "res/drawable/shape_gray_border_bottom.xml"
        $s6 = "res/layout/samsung_show_top_dialog.xml"
        $s7 = "res/layout/xiaomi_background_activity_dialog.xml"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01029 {
    strings:
        $s0 = "Z.-z-.xy-"
        $s1 = "J-yM/-P-y"
        $s2 = "Yk.11L-T"
        $s3 = "res/drawable/img_android.png"
        $s4 = "res/layout/instruction_dialog.xml"
        $s5 = "res/drawable/shape_gray_border_bottom.xml"
        $s6 = "res/layout/samsung_show_top_dialog.xml"
        $s7 = "res/layout/xiaomi_background_activity_dialog.xml"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01030 {
    strings:
        $s0 = "lib/armeabi/libcrypt_sign.so"
        $s1 = "assets/wyzf/res.bin"
        $s2 = "13/Ayo17/DPtKNh46JVIv6osRPo"
        $s3 = "Qmxju5/Ap5mgu1cFHvmJFycrWMw"
        $s4 = "com/unicom/wounipaysms/dialog/images/cancel.png"
        $s5 = "com/unicom/wounipaysms/dialog/images/cancel_on.png"
        $s6 = "com/unicom/wounipaysms/dialog/images/confirm_bt.9.png"
        $s7 = "com/unicom/wounipaysms/dialog/images/confirm_bt_on.9.png"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01031 {
    strings:
        $s0 = "lib/armeabi/libcrypt_sign.so"
        $s1 = "assets/wyzf/res.bin"
        $s2 = "13/Ayo17/DPtKNh46JVIv6osRPo"
        $s3 = "Qmxju5/Ap5mgu1cFHvmJFycrWMw"
        $s4 = "com/unicom/wounipaysms/dialog/images/cancel.png"
        $s5 = "com/unicom/wounipaysms/dialog/images/cancel_on.png"
        $s6 = "com/unicom/wounipaysms/dialog/images/confirm_bt.9.png"
        $s7 = "com/unicom/wounipaysms/dialog/images/confirm_bt_on.9.png"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01032 {
    strings:
        $s0 = "lib/armeabi/libcrypt_sign.so"
        $s1 = "assets/wyzf/res.bin"
        $s2 = "13/Ayo17/DPtKNh46JVIv6osRPo"
        $s3 = "Qmxju5/Ap5mgu1cFHvmJFycrWMw"
        $s4 = "com/unicom/wounipaysms/dialog/images/cancel.png"
        $s5 = "com/unicom/wounipaysms/dialog/images/cancel_on.png"
        $s6 = "com/unicom/wounipaysms/dialog/images/confirm_bt.9.png"
        $s7 = "com/unicom/wounipaysms/dialog/images/confirm_bt_on.9.png"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01033 {
    strings:
        $s0 = "res/drawable-hdpi-v4/icon.xml"
        $s1 = "res/layout/activity_g.xml"
        $s2 = "res/drawable-hdpi-v4/app_launcher.png"
        $s3 = "WFWBO9a7m6MbO/sP/B/yxtr11hnZJLIj8xj46"
        $s4 = "res/layout/nothing_layout.xml"
        $s5 = "assets/hoal/even"
        $s6 = "hoal/even"
        $s7 = "https://www.postnord.se/"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01034 {
    strings:
        $s0 = "res/drawable-hdpi-v4/icon.xml"
        $s1 = "res/layout/activity_g.xml"
        $s2 = "res/drawable-hdpi-v4/app_launcher.png"
        $s3 = "WFWBO9a7m6MbO/sP/B/yxtr11hnZJLIj8xj46"
        $s4 = "res/layout/nothing_layout.xml"
        $s5 = "assets/hoal/even"
        $s6 = "hoal/even"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6)
}

rule VX_APK_CLUSTER_01035 {
    strings:
        $s0 = "Z.-z-.xy-"
        $s1 = "J-yM/-P-y"
        $s2 = "assets/symbols-ad.sdf"
        $s3 = "wj-zM.x."
        $s4 = "assets/symbols.sdf"
        $s5 = "0Lcom/mbridge/msdk/interactiveads/signalcommon/a"
        $s6 = "BLcom/mbridge/msdk/interactiveads/activity/InteractiveShowActivity"
        $s7 = "Lcom/mbridge/msdk/interactiveads/a/a"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01036 {
    strings:
        $s0 = "lib/armeabi/libcrypt_sign.so"
        $s1 = "assets/wyzf/res.bin"
        $s2 = "assets/jmpay.xml"
        $s3 = "assets/yf.conf"
        $s4 = "assets/pay"
        $s5 = "assets/onib_clz.jar"
        $s6 = "assets/qshp_3001_2295"
        $s7 = "assets/resource/plugin"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01037 {
    strings:
        $s0 = "assets/Thumbs.db"
        $s1 = "numbers.xml"
        $s2 = "OperatorModel.java"
        $s3 = "XMLfunctions.java"
        $s4 = "assets/sms.xml"
        $s5 = "0Lcom/app/installer/AppInstallerActivity$MyCount"
        $s6 = "2Lcom/app/installer/AppInstallerActivity$MyCount$1"
        $s7 = "AppInstallerActivity.java"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01038 {
    strings:
        $s0 = "lib/armeabi/libcrypt_sign.so"
        $s1 = "assets/wyzf/res.bin"
        $s2 = "13/Ayo17/DPtKNh46JVIv6osRPo"
        $s3 = "Qmxju5/Ap5mgu1cFHvmJFycrWMw"
        $s4 = "com/unicom/wounipaysms/dialog/images/cancel.png"
        $s5 = "com/unicom/wounipaysms/dialog/images/cancel_on.png"
        $s6 = "com/unicom/wounipaysms/dialog/images/confirm_bt.9.png"
        $s7 = "com/unicom/wounipaysms/dialog/images/confirm_bt_on.9.png"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01039 {
    strings:
        $s0 = "receiver/install"
        $s1 = "http://app"
        $s2 = "receiver/uninstall"
        $s3 = "receiver/load_ad"
        $s4 = "receiver/load_offer"
        $s5 = "Lcom/adwo/adsdk/AdwoAdView"
        $s6 = "Lcom/waps/OffersWebView"
        $s7 = "Lcom/adwo/adsdk/AdListener"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01040 {
    strings:
        $s0 = "/consumerCodeList"
        $s1 = "86BpnPXgWHUkHbM/vws7iZu0mk"
        $s2 = "AlDWi8bl2/bzTg3d3zZK/g"
        $s3 = "HhPyb1I/X38"
        $s4 = "Iw39W6xW2WgpkFZONZWB/Q"
        $s5 = "KsYPG2/wAfIRZj11LiAb0g"
        $s6 = "RGVw4AQRs/I6priG96EeCQ"
        $s7 = "WFYWPrp7Ea/0oEEh9lCC1A"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01041 {
    strings:
        $s0 = "res/layout/finish.xml"
        $s1 = "res/raw/config.txt"
        $s2 = "OpInfo.java"
        $s3 = "assets/texts/finish_activity.txt"
        $s4 = "assets/texts/first_activity.txt"
        $s5 = "assets/texts/ru/finish_activity.txt"
        $s6 = "assets/texts/ru/first_activity.txt"
        $s7 = "assets/texts/ru/rules_activity.txt"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01042 {
    strings:
        $s0 = "res/layout/finish.xml"
        $s1 = "res/raw/config.txt"
        $s2 = "OpInfo.java"
        $s3 = "assets/texts/finish_activity.txt"
        $s4 = "assets/texts/first_activity.txt"
        $s5 = "assets/texts/ru/finish_activity.txt"
        $s6 = "assets/texts/ru/first_activity.txt"
        $s7 = "assets/texts/ru/rules_activity.txt"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01043 {
    strings:
        $s0 = "res/layout/finish.xml"
        $s1 = "res/raw/config.txt"
        $s2 = "OpInfo.java"
        $s3 = "assets/texts/finish_activity.txt"
        $s4 = "assets/texts/first_activity.txt"
        $s5 = "assets/texts/ru/finish_activity.txt"
        $s6 = "assets/texts/ru/first_activity.txt"
        $s7 = "assets/texts/ru/rules_activity.txt"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01044 {
    strings:
        $s0 = "res/layout/finish.xml"
        $s1 = "res/raw/config.txt"
        $s2 = "OpInfo.java"
        $s3 = "assets/texts/finish_activity.txt"
        $s4 = "assets/texts/first_activity.txt"
        $s5 = "assets/texts/ru/finish_activity.txt"
        $s6 = "assets/texts/ru/first_activity.txt"
        $s7 = "assets/texts/ru/rules_activity.txt"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01045 {
    strings:
        $s0 = "res/layout/finish.xml"
        $s1 = "res/raw/config.txt"
        $s2 = "OpInfo.java"
        $s3 = "assets/texts/finish_activity.txt"
        $s4 = "assets/texts/first_activity.txt"
        $s5 = "assets/texts/ru/finish_activity.txt"
        $s6 = "assets/texts/ru/first_activity.txt"
        $s7 = "assets/texts/ru/rules_activity.txt"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01046 {
    strings:
        $s0 = "res/layout/finish.xml"
        $s1 = "res/raw/config.txt"
        $s2 = "OpInfo.java"
        $s3 = "assets/texts/finish_activity.txt"
        $s4 = "assets/texts/first_activity.txt"
        $s5 = "assets/texts/ru/finish_activity.txt"
        $s6 = "assets/texts/ru/first_activity.txt"
        $s7 = "assets/texts/ru/rules_activity.txt"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01047 {
    strings:
        $s0 = "res/layout/finish.xml"
        $s1 = "res/raw/config.txt"
        $s2 = "OpInfo.java"
        $s3 = "assets/texts/finish_activity.txt"
        $s4 = "assets/texts/first_activity.txt"
        $s5 = "assets/texts/ru/finish_activity.txt"
        $s6 = "assets/texts/ru/first_activity.txt"
        $s7 = "assets/texts/ru/rules_activity.txt"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01048 {
    strings:
        $s0 = "res/layout/finish.xml"
        $s1 = "res/raw/config.txt"
        $s2 = "OpInfo.java"
        $s3 = "assets/texts/finish_activity.txt"
        $s4 = "assets/texts/first_activity.txt"
        $s5 = "assets/texts/ru/finish_activity.txt"
        $s6 = "assets/texts/ru/first_activity.txt"
        $s7 = "assets/texts/ru/rules_activity.txt"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01049 {
    strings:
        $s0 = "res/raw/act_schemes.cfg"
        $s1 = "res/xml/texts.xml"
        $s2 = "res/layout/off.xml"
        $s3 = "ShowLink.java"
        $s4 = "res/layout/grant_access_to_content.xml"
        $s5 = "OffertActivity.java"
        $s6 = "com.software.CHECKER"
        $s7 = "res/drawable/install_icon.png"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01050 {
    strings:
        $s0 = "res/raw/act_schemes.cfg"
        $s1 = "res/xml/texts.xml"
        $s2 = "res/layout/off.xml"
        $s3 = "c/nL07Gy7K3maRlEL1MxCVwf4FU"
        $s4 = "res/drawable/checkbox_label_background.9.png"
        $s5 = "18/aznZQx9KN6O9oFh9zkx3tu4w"
        $s6 = "res/drawable/0.temp"
        $s7 = "ShowLink.java"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01051 {
    strings:
        $s0 = "res/raw/act_schemes.cfg"
        $s1 = "res/xml/texts.xml"
        $s2 = "res/layout/off.xml"
        $s3 = "c/nL07Gy7K3maRlEL1MxCVwf4FU"
        $s4 = "res/drawable/checkbox_label_background.9.png"
        $s5 = "18/aznZQx9KN6O9oFh9zkx3tu4w"
        $s6 = "ShowLink.java"
        $s7 = "res/layout/grant_access_to_content.xml"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01052 {
    strings:
        $s0 = "res/raw/act_schemes.cfg"
        $s1 = "res/xml/texts.xml"
        $s2 = "res/layout/off.xml"
        $s3 = "c/nL07Gy7K3maRlEL1MxCVwf4FU"
        $s4 = "res/drawable/checkbox_label_background.9.png"
        $s5 = "18/aznZQx9KN6O9oFh9zkx3tu4w"
        $s6 = "res/drawable/0.temp"
        $s7 = "ShowLink.java"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01053 {
    strings:
        $s0 = "res/raw/act_schemes.cfg"
        $s1 = "res/xml/texts.xml"
        $s2 = "res/layout/off.xml"
        $s3 = "c/nL07Gy7K3maRlEL1MxCVwf4FU"
        $s4 = "res/drawable/checkbox_label_background.9.png"
        $s5 = "18/aznZQx9KN6O9oFh9zkx3tu4w"
        $s6 = "res/drawable/0.temp"
        $s7 = "ShowLink.java"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01054 {
    strings:
        $s0 = "res/raw/act_schemes.cfg"
        $s1 = "xoYHeP/23ezgc3yGF9063z"
        $s2 = "res/layout/grant_access_to_content.xml"
        $s3 = "res/layout/offert.xml"
        $s4 = "1.6.0_03-p4"
        $s5 = "bPiSqfnm11lHasvNBAqb/Gx2ZiQ"
        $s6 = "GrantAccess.java"
        $s7 = "Offert.java"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01055 {
    strings:
        $s0 = "res/layout/adm_perm.xml"
        $s1 = "assets/fileWithConstants"
        $s2 = "zg3qARydr/OYXR6inshlyx/OECA"
    condition:
        any of ($s0, $s1, $s2)
}

rule VX_APK_CLUSTER_01056 {
    strings:
        $s0 = "SmsWriteOpUtil.java"
        $s1 = "$Lcom/system/log/Manifest$permission"
        $s2 = ".Lcom/system/log/AtFwdService$sendContactsText"
        $s3 = "ActionDefaultActivity.java"
        $s4 = "AtFwdService.java"
        $s5 = "BadSMSReceiver.java"
        $s6 = "DeviceManage.java"
        $s7 = "Lcom/system/log/ActionDefaultActivity"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01057 {
    strings:
        $s0 = "assets/s"
        $s1 = "assets/hp1"
        $s2 = "assets/hp2"
        $s3 = "assets/hp3"
        $s4 = "assets/hp4"
        $s5 = "assets/hp5"
        $s6 = "assets/hp6"
        $s7 = "assets/hp7"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01058 {
    strings:
        $s0 = "assets/s"
        $s1 = "assets/sg"
    condition:
        any of ($s0, $s1)
}

rule VX_APK_CLUSTER_01059 {
    strings:
        $s0 = "assets/s.app"
        $s1 = "assets/u.app"
        $s2 = "assets/x.app"
        $s3 = "f/v1YjbuCDBzNPiyJ0vDx3I1WmI"
        $s4 = "res/drawable/icon_install.png"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4)
}

rule VX_APK_CLUSTER_01060 {
    strings:
        $s0 = "res/drawable/operation_pic.jpg"
        $s1 = "res/drawable/operation_title.png"
        $s2 = "3XU8DJNQ9o/iAlhePmHQ2ONZPBE"
        $s3 = "res/drawable/yellow_shape.xml"
        $s4 = "res/anim/large_progressbar_animator.xml"
        $s5 = "MX98D/jdKxRIV3h2usqfl"
        $s6 = "res/layout/wx_scan.xml"
        $s7 = "res/drawable/dia_money_selecor.xml"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01061 {
    strings:
        $s0 = "res/drawable-mdpi/abc_textfield_search_activated_mtrl_alpha.9.png"
        $s1 = "res/drawable-xxhdpi/abc_textfield_search_activated_mtrl_alpha.9.pn"
        $s2 = "res/drawable-xxhdpi/abc_textfield_search_default_mtrl_alpha.9.png"
        $s3 = "res/drawable-hdpi/abc_textfield_search_activated_mtrl_alpha.9.png"
        $s4 = "res/drawable-xhdpi/abc_textfield_search_activated_mtrl_alpha.9.png"
        $s5 = "res/drawable-xxxhdpi/abc_scrubber_control_to_pressed_mtrl_000.png"
        $s6 = "res/drawable-xxxhdpi/abc_scrubber_control_to_pressed_mtrl_005.png"
        $s7 = "res/drawable-xxhdpi/common_google_signin_btn_icon_dark_normal_back"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01062 {
    strings:
        $s0 = "res/drawable-mdpi/abc_textfield_search_activated_mtrl_alpha.9.png"
        $s1 = "res/drawable-xxhdpi/abc_textfield_search_activated_mtrl_alpha.9.pn"
        $s2 = "res/drawable-xxhdpi/abc_textfield_search_default_mtrl_alpha.9.png"
        $s3 = "res/drawable-hdpi/abc_textfield_search_activated_mtrl_alpha.9.png"
        $s4 = "res/drawable-xhdpi/abc_textfield_search_activated_mtrl_alpha.9.png"
        $s5 = "res/drawable-xxxhdpi/abc_scrubber_control_to_pressed_mtrl_000.png"
        $s6 = "res/drawable-xxxhdpi/abc_scrubber_control_to_pressed_mtrl_005.png"
        $s7 = "res/drawable-xxhdpi/common_google_signin_btn_icon_dark_normal_back"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01063 {
    strings:
        $s0 = "res/drawable-mdpi/abc_textfield_search_activated_mtrl_alpha.9.png"
        $s1 = "res/drawable-xxhdpi/abc_textfield_search_activated_mtrl_alpha.9.pn"
        $s2 = "res/drawable-xxhdpi/abc_textfield_search_default_mtrl_alpha.9.png"
        $s3 = "res/drawable-hdpi/abc_textfield_search_activated_mtrl_alpha.9.png"
        $s4 = "res/drawable-xhdpi/abc_textfield_search_activated_mtrl_alpha.9.png"
        $s5 = "res/drawable-xxxhdpi/abc_scrubber_control_to_pressed_mtrl_000.png"
        $s6 = "res/drawable-xxxhdpi/abc_scrubber_control_to_pressed_mtrl_005.png"
        $s7 = "res/drawable-xxhdpi/common_google_signin_btn_icon_dark_normal_back"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01064 {
    strings:
        $s0 = "res/drawable-mdpi/abc_textfield_search_activated_mtrl_alpha.9.png"
        $s1 = "res/drawable-xxhdpi/abc_textfield_search_activated_mtrl_alpha.9.pn"
        $s2 = "res/drawable-xxhdpi/abc_textfield_search_default_mtrl_alpha.9.png"
        $s3 = "res/drawable-hdpi/abc_textfield_search_activated_mtrl_alpha.9.png"
        $s4 = "res/drawable-xhdpi/abc_textfield_search_activated_mtrl_alpha.9.png"
        $s5 = "res/drawable-xxxhdpi/abc_scrubber_control_to_pressed_mtrl_000.png"
        $s6 = "res/drawable-xxxhdpi/abc_scrubber_control_to_pressed_mtrl_005.png"
        $s7 = "res/drawable-xxhdpi/common_google_signin_btn_icon_dark_normal_back"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01065 {
    strings:
        $s0 = "res/drawable-mdpi/abc_textfield_search_activated_mtrl_alpha.9.png"
        $s1 = "res/drawable-xxhdpi/abc_textfield_search_activated_mtrl_alpha.9.pn"
        $s2 = "res/drawable-xxhdpi/abc_textfield_search_default_mtrl_alpha.9.png"
        $s3 = "res/drawable-hdpi/abc_textfield_search_activated_mtrl_alpha.9.png"
        $s4 = "res/drawable-xhdpi/abc_textfield_search_activated_mtrl_alpha.9.png"
        $s5 = "res/drawable-xxxhdpi/abc_scrubber_control_to_pressed_mtrl_000.png"
        $s6 = "res/drawable-xxxhdpi/abc_scrubber_control_to_pressed_mtrl_005.png"
        $s7 = "res/drawable-xxhdpi/common_google_signin_btn_icon_dark_normal_back"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01066 {
    strings:
        $s0 = "res/drawable-mdpi/abc_textfield_search_activated_mtrl_alpha.9.png"
        $s1 = "res/drawable-xxhdpi/abc_textfield_search_activated_mtrl_alpha.9.pn"
        $s2 = "res/drawable-xxhdpi/abc_textfield_search_default_mtrl_alpha.9.png"
        $s3 = "res/drawable-hdpi/abc_textfield_search_activated_mtrl_alpha.9.png"
        $s4 = "res/drawable-xhdpi/abc_textfield_search_activated_mtrl_alpha.9.png"
        $s5 = "res/drawable-xxxhdpi/abc_scrubber_control_to_pressed_mtrl_000.png"
        $s6 = "res/drawable-xxxhdpi/abc_scrubber_control_to_pressed_mtrl_005.png"
        $s7 = "res/drawable-xxhdpi/common_google_signin_btn_icon_dark_normal_back"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01067 {
    strings:
        $s0 = "lib/armeabi-v7a/libluajava.so"
        $s1 = "res/xml-v22/accessibility_service_config.xml"
        $s2 = "setup.png"
        $s3 = "Lcom/baidu/mobstat/Config"
        $s4 = "Lcom/baidu/mobstat/Config$EventViewType"
        $s5 = "$Lcom/baidu/mobstat/IIgnoreAutoTrace"
        $s6 = "Lcom/baidu/mobstat/PrefOperate"
        $s7 = "MRqCffj5WHqpu4LC8N5GVxy/6"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01068 {
    strings:
        $s0 = "HookDelegate:"
        $s1 = "getUserIcon:"
        $s2 = "makeInitialized:"
        $s3 = "setUserIcon:"
        $s4 = "style/notification_layout"
        $s5 = "userForeground:"
        $s6 = "Lcom/qq/e/ads/nativ/NativeMediaAD$1$1"
        $s7 = "Lcom/tencent/tinker/lib/service/PatchResult"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01069 {
    strings:
        $s0 = "0nDhU/Wmbaqbo5v4nu2/OaflZa4"
        $s1 = "9Mp7gWm5xEL9CmETvxCu07/u"
        $s2 = "Lorg/BBrMainService"
        $s3 = "Lorg/BsvtyReceiver"
        $s4 = "Lorg/DssApplication"
        $s5 = "Lorg/VbgsActivity"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5)
}

rule VX_APK_CLUSTER_01070 {
    strings:
        $s0 = "assets/css/smoothness/images/ui-bg_flat_0_aaaaaa_40x100.png"
        $s1 = "assets/css/smoothness/images/ui-bg_flat_75_ffffff_40x100.png"
        $s2 = "assets/css/smoothness/images/ui-bg_glass_55_fbf9ee_1x400.png"
        $s3 = "assets/css/smoothness/images/ui-bg_glass_65_ffffff_1x400.png"
        $s4 = "assets/css/smoothness/images/ui-bg_glass_75_dadada_1x400.png"
        $s5 = "assets/css/smoothness/images/ui-bg_glass_75_e6e6e6_1x400.png"
        $s6 = "assets/css/smoothness/images/ui-bg_glass_95_fef1ec_1x400.png"
        $s7 = "assets/css/smoothness/images/ui-bg_highlight-soft_75_cccccc_1x10"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01071 {
    strings:
        $s0 = "xoYHeP/23ezgc3yGF9063z"
        $s1 = "res/layout/grant_access_to_content.xml"
        $s2 = "res/layout/offert.xml"
        $s3 = "1.6.0_03-p4"
        $s4 = "res/raw/countries.cfg"
        $s5 = "bjiYLTcd8ArIESfs4Z/YX/"
        $s6 = "GrantAccessToContentActivity.java"
        $s7 = "res/raw/activation_scheme.cfg"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01072 {
    strings:
        $s0 = "13/Ayo17/DPtKNh46JVIv6osRPo"
        $s1 = "Qmxju5/Ap5mgu1cFHvmJFycrWMw"
        $s2 = "com/unicom/wounipaysms/dialog/images/cancel.png"
        $s3 = "com/unicom/wounipaysms/dialog/images/cancel_on.png"
        $s4 = "com/unicom/wounipaysms/dialog/images/confirm_bt.9.png"
        $s5 = "com/unicom/wounipaysms/dialog/images/confirm_bt_on.9.png"
        $s6 = "com/unicom/wounipaysms/dialog/images/main_bg.9.png"
        $s7 = "com/unicom/wounipaysms/dialog/images/unicom.png"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01073 {
    strings:
        $s0 = "com.dotc.ime.latin.flash"
        $s1 = "-Lcom/x/platform/NetworkStateChangeReceiver$1"
        $s2 = "-Lcom/x/platform/NetworkStateChangeReceiver$2"
        $s3 = "/system/app/USBUsageServiceInfo.apk"
        $s4 = "/system/app/obs.apk"
        $s5 = "BatterySaver.apk"
        $s6 = "Lcom/google/android/gms/iid/c$1"
        $s7 = "Lcom/x/a/a"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01074 {
    strings:
        $s0 = "receiver/install"
        $s1 = "http://app"
        $s2 = "receiver/uninstall"
        $s3 = "receiver/load_ad"
        $s4 = "receiver/load_offer"
        $s5 = "UPermission.ACCESS_WIFI_STATE"
        $s6 = "UnPackage.dat"
        $s7 = "complete.Click"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01075 {
    strings:
        $s0 = "res/drawable-xhdpi/ic_.xml"
        $s1 = "lib/armeabi-v7a/libki.so"
        $s2 = "kC6BFnP/mhWTIeL03xN5CrR4L6o"
    condition:
        any of ($s0, $s1, $s2)
}

rule VX_APK_CLUSTER_01076 {
    strings:
        $s0 = "res/drawable-xhdpi/i.xml"
        $s1 = "lib/armeabi-v7a/libbsk.so"
    condition:
        any of ($s0, $s1)
}

rule VX_APK_CLUSTER_01077 {
    strings:
        $s0 = "lib/armeabi-v7a/libdf.so"
        $s1 = "res/drawable-xhdpi/z.xml"
    condition:
        any of ($s0, $s1)
}

rule VX_APK_CLUSTER_01078 {
    strings:
        $s0 = "res/drawable-xhdpi/ico.xml"
        $s1 = "lib/armeabi-v7a/libjo.so"
    condition:
        any of ($s0, $s1)
}

rule VX_APK_CLUSTER_01079 {
    strings:
        $s0 = "res/drawable-xhdpi/ic_.xml"
        $s1 = "lib/armeabi-v7a/libjv.so"
        $s2 = "wT80/81Il7cvGHm3rjfMyOHXpHsMfJI1c0AziNCkOp4"
    condition:
        any of ($s0, $s1, $s2)
}

rule VX_APK_CLUSTER_01080 {
    strings:
        $s0 = "lib/armeabi/libcrypt_sign.so"
        $s1 = "assets/wyzf/res.bin"
        $s2 = "assets/yf.conf"
        $s3 = "assets/qsha_80001_5096"
        $s4 = "assets/dERlZG"
        $s5 = "Adzwfge96PWi9KOpEQioyGF//NA"
        $s6 = "http://vpay.api.eerichina.com/api/payment"
        $s7 = "plugin.db"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01081 {
    strings:
        $s0 = "QTQM1mRdsX3UgMWt2CkMpq7Pwv/4ZCn6hFfbvZg"
        $s1 = "8rAQxGe4eB8ZqJLSGH/hT"
        $s2 = "Executor..."
        $s3 = "a5OZdh/TyRe/rd1jkrccA"
        $s4 = "ExecuteResult.java"
        $s5 = "Chrome/32.0.1700.107"
        $s6 = "http://www.hao123.com"
        $s7 = "temp.data"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01082 {
    strings:
        $s0 = "com.example.android.Activity.MainActivity"
        $s1 = "ar490OWv2uJaEtnUU05/JZVlraM"
        $s2 = "/D4xmE5O/WCHA0rAQgQ1v949/u8"
        $s3 = "2UdYOx/8c9Td25rQIdvtJbQ43S4"
        $s4 = "VLandroid/support/v4/media/session/MediaControllerCompat$MediaControllerImplApi2"
        $s5 = ".Landroid/support/constraint/char/else/new$int"
        $s6 = "5KL/x8AvQKVxDPzIT6sHL0oZVpA"
        $s7 = "DD0QDDkIYyYp/ZYJTxyPcKG1wQM"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01083 {
    strings:
        $s0 = "res/mipmap-xxhdpi-v4/ic_launcher_empty.png"
        $s1 = "res/mipmap-xxhdpi-v4/ic_launcher_video.png"
        $s2 = "Md3MSA/sg/op1reCKgNZCskn84E"
        $s3 = "res/mipmap-xxhdpi-v4/ic_launcher_antivirus.png"
        $s4 = "res/mipmap-xxhdpi-v4/ic_launcher_flash.png"
        $s5 = "res/mipmap-xxhdpi-v4/ic_launcher_music.png"
        $s6 = "res/mipmap-xxhdpi-v4/ic_launcher_robot.png"
        $s7 = "res/mipmap-xxhdpi-v4/ic_launcher_security.png"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01084 {
    strings:
        $s0 = "res/mipmap-xxhdpi-v4/ic_launcher_empty.png"
        $s1 = "res/mipmap-xxhdpi-v4/ic_launcher_video.png"
        $s2 = "Md3MSA/sg/op1reCKgNZCskn84E"
        $s3 = "res/mipmap-xxhdpi-v4/ic_launcher_antivirus.png"
        $s4 = "res/mipmap-xxhdpi-v4/ic_launcher_flash.png"
        $s5 = "res/mipmap-xxhdpi-v4/ic_launcher_music.png"
        $s6 = "res/mipmap-xxhdpi-v4/ic_launcher_robot.png"
        $s7 = "res/mipmap-xxhdpi-v4/ic_launcher_security.png"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01085 {
    strings:
        $s0 = "res/raw/malcolmx.res"
        $s1 = "assets/yturyehds"
        $s2 = "1W4L1r/7ckT9oiMk2YOc"
        $s3 = "Lcom/android/shine/MainActivity"
        $s4 = "Lcom/android/shine/MessageReceiver"
        $s5 = "Lcom/android/shine/a"
        $s6 = "Lcom/android/shine/b"
        $s7 = "Lcom/android/shine/c"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01086 {
    strings:
        $s0 = "h9PDMBXx/7AUCTgqBicvs9LMF0/zhcrOR2nK9TY"
        $s1 = "v6BJJrqk2/BlVN7Fb43159u/FLhYJtopJ9zK0rBuxDc"
        $s2 = "8uChfRgL8wSZVSNHrw2/HWd1JoPBtJ8531kWXnLXXUI"
        $s3 = "ZaxJ8tTG5VeCMps62uSOld/A7Ch9zElYYTq4zTjwdeM"
        $s4 = "9/wikZdowrVQBLYgKnYM0VmA"
        $s5 = "sdZ/TJ7DehGZzuqoy1Q0"
        $s6 = "zXn1B5hiGwVsDdVM/ryX8a"
        $s7 = "tIrH029Gr/uE3jiAYds"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01087 {
    strings:
        $s0 = "res/raw/google.apk"
        $s1 = "res/drawable-hdpi/notification_bg_low_normal.png"
        $s2 = "res/drawable-hdpi/notification_bg_low_pressed.png"
        $s3 = "res/drawable-hdpi/notification_bg_normal.png"
        $s4 = "res/drawable-hdpi/notification_bg_normal_pressed.png"
        $s5 = "res/drawable-mdpi/notification_bg_low_normal.png"
        $s6 = "res/drawable-mdpi/notification_bg_low_pressed.png"
        $s7 = "res/drawable-mdpi/notification_bg_normal.png"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01088 {
    strings:
        $s0 = "T/T/T/U/U/x"
        $s1 = "bGpiUBP2YqftY4NdYT1oG/QmB36gofM04c"
        $s2 = "$Lcom/zeroone/divaraop/SmsReceiver$1"
        $s3 = "Lcom/zeroone/divaraop/BuildConfig"
        $s4 = "Lcom/zeroone/divaraop/MainActivity"
        $s5 = "Lcom/zeroone/divaraop/MainActivity$$ExternalSyntheticLambda0"
        $s6 = "Lcom/zeroone/divaraop/Pay"
        $s7 = "Lcom/zeroone/divaraop/R"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01089 {
    strings:
        $s0 = "com.webcash.wooribank"
        $s1 = "res/drawable-hdpi/nh.png"
        $s2 = "res/drawable-hdpi/sh.png"
        $s3 = "/conf.ini"
        $s4 = "App.Alert"
        $s5 = "alert.main"
        $s6 = "app.auto.install"
        $s7 = "app.dwonload.complate"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01090 {
    strings:
        $s0 = "receiver/install"
        $s1 = "http://app"
        $s2 = "receiver/uninstall"
        $s3 = "receiver/load_ad"
        $s4 = "receiver/load_offer"
        $s5 = "UPermission.ACCESS_WIFI_STATE"
        $s6 = "UnPackage.dat"
        $s7 = "complete.Click"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01091 {
    strings:
        $s0 = "res/images"
        $s1 = "LiiKx.iL"
        $s2 = "wx.tenpay.com"
        $s3 = "0---.ix/."
        $s4 = "$Ldex/gu/trl/mhapp/WelcomeActivity$1"
        $s5 = "-7m-7.757n67.E"
        $s6 = "/767B7E7jF7"
        $s7 = "/KMUSa/4Mpe0"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01092 {
    strings:
        $s0 = "apkprotect.com/key.dat"
        $s1 = "apkprotect.com/readme.txt"
        $s2 = "Lcom/android/a"
        $s3 = "ReplayStruct.java"
        $s4 = "RequestStruct.java"
        $s5 = "LSecScreen.java"
        $s6 = "res/xml/lsecscreen.xml"
        $s7 = "Lcom/android/internal/telephony/a"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01093 {
    strings:
        $s0 = "res/xml-v22/accessibility_service_config.xml"
        $s1 = "res/xml-v14/accessibility_service_config.xml"
        $s2 = "assets/layout.bal"
        $s3 = "LS_layout.java"
        $s4 = "res/xml-v22/windowchangedetectingservice.xml"
        $s5 = ".Lio/crossbar/autobahn/websocket/Utf8Validator"
        $s6 = "0Lio/crossbar/autobahn/websocket/WebSocketReader"
        $s7 = "0Lio/crossbar/autobahn/websocket/WebSocketWriter"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01094 {
    strings:
        $s0 = "res/drawable-hdpi/selector_button.xml"
        $s1 = "$Lkangzen/kangzen_v1/Constants$Extra"
        $s2 = "$Lkangzen/kangzen_v1/Constants_Event"
        $s3 = "$Lkangzen_v1/Household/Tab_Household"
        $s4 = "$Lkangzen_v1/Member/ksoap2Activity$1"
        $s5 = "$Lkangzen_v1/Promotion/Tab_promotion"
        $s6 = "-Lkangzen_v1/Healthy/Tab_Healthy$ImageAdapter"
        $s7 = "-https://www.facebook.com/kangzeninternational"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01095 {
    strings:
        $s0 = "res/layout/policies.xml"
        $s1 = "res/drawable/cvc_visa.gif"
        $s2 = "jpYacD5/wUvtUwHbhwW1g"
        $s3 = "res/layout/activity_adm.xml"
        $s4 = "ussd.notify"
        $s5 = "DbLog.java"
        $s6 = "LfAJ4zYaDObW0G/S5MALqkGG6KQ"
        $s7 = "WmHQhH7jINe/Xdu4NamQ2yJxVA4"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01096 {
    strings:
        $s0 = "contactsutils.java"
        $s1 = "$Lb4a/example/contactsutils$_cuemail"
        $s2 = "$Lb4a/example/contactsutils$_cuphone"
        $s3 = "DiviceInfo.java"
        $s4 = "Lb4a/example/contactsutils"
        $s5 = "Lb4a/example/contactsutils$_cucontact"
        $s6 = "Lcom/reza/sh/deviceinfo/DiviceInfo"
        $s7 = "Lcom/reza/sh/deviceinfo/DiviceInfo$1"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01097 {
    strings:
        $s0 = "contactsutils.java"
        $s1 = "$Lb4a/example/contactsutils$_cuemail"
        $s2 = "$Lb4a/example/contactsutils$_cuphone"
        $s3 = "DiviceInfo.java"
        $s4 = "Lb4a/example/contactsutils"
        $s5 = "Lb4a/example/contactsutils$_cucontact"
        $s6 = "Lcom/reza/sh/deviceinfo/DiviceInfo"
        $s7 = "Lcom/reza/sh/deviceinfo/DiviceInfo$1"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01098 {
    strings:
        $s0 = "assets/url.txt"
        $s1 = "contactsutils.java"
        $s2 = "$Lb4a/example/contactsutils$_cuemail"
        $s3 = "$Lb4a/example/contactsutils$_cuphone"
        $s4 = "DiviceInfo.java"
        $s5 = "Lb4a/example/contactsutils"
        $s6 = "Lb4a/example/contactsutils$_cucontact"
        $s7 = "Lcom/reza/sh/deviceinfo/DiviceInfo"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01099 {
    strings:
        $s0 = "assets/url.txt"
        $s1 = "contactsutils.java"
        $s2 = "$Lb4a/example/contactsutils$_cuemail"
        $s3 = "$Lb4a/example/contactsutils$_cuphone"
        $s4 = "DiviceInfo.java"
        $s5 = "Lb4a/example/contactsutils"
        $s6 = "Lb4a/example/contactsutils$_cucontact"
        $s7 = "Lcom/reza/sh/deviceinfo/DiviceInfo"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01100 {
    strings:
        $s0 = "assets/url.txt"
        $s1 = "contactsutils.java"
        $s2 = "$Lb4a/example/contactsutils$_cuemail"
        $s3 = "$Lb4a/example/contactsutils$_cuphone"
        $s4 = "DiviceInfo.java"
        $s5 = "Lb4a/example/contactsutils"
        $s6 = "Lb4a/example/contactsutils$_cucontact"
        $s7 = "Lcom/reza/sh/deviceinfo/DiviceInfo"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01101 {
    strings:
        $s0 = "/client.config/"
        $s1 = "YEU7M9b/mq1xUVVolKsb8eVO4mY"
        $s2 = "app:oncreate"
        $s3 = "res/drawable/ace.png"
        $s4 = "res/drawable/king.png"
        $s5 = "res/drawable/queen.png"
        $s6 = "res/layout-v17/ac_back.xml"
        $s7 = "res/layout/ac_back.xml"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01102 {
    strings:
        $s0 = "res/drawable-hdpi-v4/icon.xml"
        $s1 = "res/layout/activity_g.xml"
        $s2 = "iD2em3JLFcEgtAIneR97M/bukxQxG68VKhvLQQKmin8"
        $s3 = "res/drawable-hdpi-v4/app_launcher.png"
        $s4 = "2knbtPyXW/KVnBzdEk1jpH8z7j8DiUqpA"
        $s5 = "72Pe9z4zT1SE8goGvm/DgHwC3lGN4xYkWDY5JnQ99MA"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5)
}

rule VX_APK_CLUSTER_01103 {
    strings:
        $s0 = "tmx2ePqGYvOES/jfGp8NEsyAr6VQe6a1ddiSGcNeMew"
        $s1 = "5WUT8N6LC6PF97Z1cG6m0zl4jGoS61p2PFskeHZ/7H8"
        $s2 = "2o1f08s4ihKK2fy37dmIRlo3B3/iAOLvEwqe5G3VI6M"
        $s3 = "3PL37/LA6F6cQlcwE/Bez9Tyugc"
        $s4 = "9gvSiI/sWlYAWTkv"
        $s5 = "GT6Z4sjRroSUlaiGL/MTW4o37G9qwI18dLG/VMaBn2k"
        $s6 = "VFXcGqG2OaI/80S7opsg"
        $s7 = "VoPy/hbPPy"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01104 {
    strings:
        $s0 = "tmx2ePqGYvOES/jfGp8NEsyAr6VQe6a1ddiSGcNeMew"
        $s1 = "5WUT8N6LC6PF97Z1cG6m0zl4jGoS61p2PFskeHZ/7H8"
        $s2 = "2o1f08s4ihKK2fy37dmIRlo3B3/iAOLvEwqe5G3VI6M"
        $s3 = "3PL37/LA6F6cQlcwE/Bez9Tyugc"
        $s4 = "9gvSiI/sWlYAWTkv"
        $s5 = "GT6Z4sjRroSUlaiGL/MTW4o37G9qwI18dLG/VMaBn2k"
        $s6 = "VFXcGqG2OaI/80S7opsg"
        $s7 = "VoPy/hbPPy"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01105 {
    strings:
        $s0 = "tmx2ePqGYvOES/jfGp8NEsyAr6VQe6a1ddiSGcNeMew"
        $s1 = "5WUT8N6LC6PF97Z1cG6m0zl4jGoS61p2PFskeHZ/7H8"
        $s2 = "2o1f08s4ihKK2fy37dmIRlo3B3/iAOLvEwqe5G3VI6M"
        $s3 = "3PL37/LA6F6cQlcwE/Bez9Tyugc"
        $s4 = "9gvSiI/sWlYAWTkv"
        $s5 = "GT6Z4sjRroSUlaiGL/MTW4o37G9qwI18dLG/VMaBn2k"
        $s6 = "VFXcGqG2OaI/80S7opsg"
        $s7 = "VoPy/hbPPy"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01106 {
    strings:
        $s0 = "tmx2ePqGYvOES/jfGp8NEsyAr6VQe6a1ddiSGcNeMew"
        $s1 = "5WUT8N6LC6PF97Z1cG6m0zl4jGoS61p2PFskeHZ/7H8"
        $s2 = "2o1f08s4ihKK2fy37dmIRlo3B3/iAOLvEwqe5G3VI6M"
        $s3 = "3PL37/LA6F6cQlcwE/Bez9Tyugc"
        $s4 = "9gvSiI/sWlYAWTkv"
        $s5 = "GT6Z4sjRroSUlaiGL/MTW4o37G9qwI18dLG/VMaBn2k"
        $s6 = "VFXcGqG2OaI/80S7opsg"
        $s7 = "VoPy/hbPPy"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01107 {
    strings:
        $s0 = "tmx2ePqGYvOES/jfGp8NEsyAr6VQe6a1ddiSGcNeMew"
        $s1 = "5WUT8N6LC6PF97Z1cG6m0zl4jGoS61p2PFskeHZ/7H8"
        $s2 = "2o1f08s4ihKK2fy37dmIRlo3B3/iAOLvEwqe5G3VI6M"
        $s3 = "3PL37/LA6F6cQlcwE/Bez9Tyugc"
        $s4 = "9gvSiI/sWlYAWTkv"
        $s5 = "GT6Z4sjRroSUlaiGL/MTW4o37G9qwI18dLG/VMaBn2k"
        $s6 = "VFXcGqG2OaI/80S7opsg"
        $s7 = "VoPy/hbPPy"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01108 {
    strings:
        $s0 = "tmx2ePqGYvOES/jfGp8NEsyAr6VQe6a1ddiSGcNeMew"
        $s1 = "5WUT8N6LC6PF97Z1cG6m0zl4jGoS61p2PFskeHZ/7H8"
        $s2 = "2o1f08s4ihKK2fy37dmIRlo3B3/iAOLvEwqe5G3VI6M"
        $s3 = "3PL37/LA6F6cQlcwE/Bez9Tyugc"
        $s4 = "9gvSiI/sWlYAWTkv"
        $s5 = "GT6Z4sjRroSUlaiGL/MTW4o37G9qwI18dLG/VMaBn2k"
        $s6 = "VFXcGqG2OaI/80S7opsg"
        $s7 = "VoPy/hbPPy"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01109 {
    strings:
        $s0 = "com.webcash.wooribank"
        $s1 = "Ppc2qe3pbHXr7i/fpIqi0VUnHrs"
        $s2 = "com.ATsolution.KBbank"
        $s3 = "i82ugOJhQVyT/fL0iVYq60"
        $s4 = "deviceAdminReceiver.java"
        $s5 = "sYN/BAKkz1SDdQqGb/nLNjiS5/c"
        $s6 = "YourReceiver.java"
        $s7 = "nestactivity.java"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01110 {
    strings:
        $s0 = "res/raw/act_schemes.cfg"
        $s1 = "res/xml/texts.xml"
        $s2 = "res/layout/off.xml"
        $s3 = "res/layout/grant_access.xml"
        $s4 = "ShowURL.java"
        $s5 = "Sch.java"
        $s6 = "ProcedureStarter.java"
        $s7 = "ProcedureMaker.java"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01111 {
    strings:
        $s0 = "res/raw/act_schemes.cfg"
        $s1 = "res/xml/texts.xml"
        $s2 = "res/layout/off.xml"
        $s3 = "res/layout/grant_access.xml"
        $s4 = "ShowURL.java"
        $s5 = "Sch.java"
        $s6 = "ProcedureStarter.java"
        $s7 = "ProcedureMaker.java"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01112 {
    strings:
        $s0 = "http://impl.service.server.phonemanager.org"
        $s1 = "AppContacts.java"
        $s2 = "SmsCmd.java"
        $s3 = "NetworkConnectUtil.java"
        $s4 = "lib/armeabi/libAPKProtect.so"
        $s5 = "MyHttpTransportSE.java"
        $s6 = "$Lorg/java/dns/Cache$NegativeElement"
        $s7 = "$Lorg/java/dns/DClass$DClassMnemonic"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01113 {
    strings:
        $s0 = "$Lorg/underdev/penetrate/Preferences"
        $s1 = "/thomson/"
        $s2 = "/thomson/thomson.zip"
        $s3 = "00:0f:cc"
        $s4 = "3Lorg/underdev/penetrate/lib/core/wifi/WifiReceiver"
        $s5 = "3Lorg/underdev/penetrate/lib/gui/activities/Results"
        $s6 = "5Lorg/underdev/penetrate/lib/gui/activities/Penetrate"
        $s7 = "7Lorg/underdev/penetrate/lib/gui/activities/Preferences"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01114 {
    strings:
        $s0 = "$Lorg/underdev/penetrate/Preferences"
        $s1 = "/thomson/"
        $s2 = "/thomson/thomson.zip"
        $s3 = "00:0f:cc"
        $s4 = "3Lorg/underdev/penetrate/lib/core/wifi/WifiReceiver"
        $s5 = "3Lorg/underdev/penetrate/lib/gui/activities/Results"
        $s6 = "5Lorg/underdev/penetrate/lib/gui/activities/Penetrate"
        $s7 = "7Lorg/underdev/penetrate/lib/gui/activities/Preferences"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01115 {
    strings:
        $s0 = "res/raw/act_schemes.cfg"
        $s1 = "res/xml/texts.xml"
        $s2 = "res/layout/off.xml"
        $s3 = "res/layout/grant_access.xml"
        $s4 = "ShowURL.java"
        $s5 = "Sch.java"
        $s6 = "AirModeHandler.java"
        $s7 = "res/drawable/install_icon.png"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01116 {
    strings:
        $s0 = "l/cUiZLb7ya5qOYV/djf/zcvnb0"
        $s1 = "res/raw/conf.txt"
        $s2 = "res/raw/result"
        $s3 = "res/raw/resulturl"
        $s4 = "res/raw/rool.txt"
        $s5 = "res/drawable-hdpi/iconnews.png"
        $s6 = "res/drawable-mdpi/iconnews.png"
        $s7 = "http://91.213.175.176/api/"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01117 {
    strings:
        $s0 = "res/raw/act_schemes.cfg"
        $s1 = "res/xml/texts.xml"
        $s2 = "res/layout/off.xml"
        $s3 = "c/nL07Gy7K3maRlEL1MxCVwf4FU"
        $s4 = "res/drawable/checkbox_label_background.9.png"
        $s5 = "18/aznZQx9KN6O9oFh9zkx3tu4w"
        $s6 = "res/drawable/0.temp"
        $s7 = "ShowLink.java"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01118 {
    strings:
        $s0 = "res/raw/act_schemes.cfg"
        $s1 = "res/xml/texts.xml"
        $s2 = "res/layout/off.xml"
        $s3 = "c/nL07Gy7K3maRlEL1MxCVwf4FU"
        $s4 = "res/drawable/checkbox_label_background.9.png"
        $s5 = "18/aznZQx9KN6O9oFh9zkx3tu4w"
        $s6 = "res/drawable/0.temp"
        $s7 = "res/drawable/1.temp"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01119 {
    strings:
        $s0 = "res/raw/act_schemes.cfg"
        $s1 = "res/xml/texts.xml"
        $s2 = "res/layout/off.xml"
        $s3 = "c/nL07Gy7K3maRlEL1MxCVwf4FU"
        $s4 = "res/drawable/checkbox_label_background.9.png"
        $s5 = "18/aznZQx9KN6O9oFh9zkx3tu4w"
        $s6 = "res/drawable/0.temp"
        $s7 = "3XU8DJNQ9o/iAlhePmHQ2ONZPBE"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01120 {
    strings:
        $s0 = "res/raw/act_schemes.cfg"
        $s1 = "res/xml/texts.xml"
        $s2 = "res/layout/off.xml"
        $s3 = "res/layout/grant_access.xml"
        $s4 = "ShowURL.java"
        $s5 = "Sch.java"
        $s6 = "ProcedureStarter.java"
        $s7 = "ProcedureMaker.java"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01121 {
    strings:
        $s0 = "LoadMethod:"
        $s1 = "jarNameInfo.id"
        $s2 = "jarNameInfo.v"
        $s3 = "com.dyl.pay.ui.apk"
        $s4 = "Lcom/t/wangda/WanderInterface"
        $s5 = "http://jiepay.jiemengkj.com:8152/ryf_webserver/payment"
        $s6 = ".android/.sys/"
        $s7 = "com.jm.jiepay.pay.JiePay"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01122 {
    strings:
        $s0 = "res/layout/finish.xml"
        $s1 = "getUserMessage:"
        $s2 = "res/drawable/opera.png"
        $s3 = "res/drawable/icon_url.png"
        $s4 = "res/drawable/progress.9.png"
        $s5 = "res/drawable/progress_active.9.png"
        $s6 = "mxclick.com"
        $s7 = "rWKNvRKwZsLr/XYVtE8CwrBNLfQ"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01123 {
    strings:
        $s0 = "assets/css/smoothness/images/ui-bg_flat_0_aaaaaa_40x100.png"
        $s1 = "assets/css/smoothness/images/ui-bg_flat_75_ffffff_40x100.png"
        $s2 = "assets/css/smoothness/images/ui-bg_glass_55_fbf9ee_1x400.png"
        $s3 = "assets/css/smoothness/images/ui-bg_glass_65_ffffff_1x400.png"
        $s4 = "assets/css/smoothness/images/ui-bg_glass_75_dadada_1x400.png"
        $s5 = "assets/css/smoothness/images/ui-bg_glass_75_e6e6e6_1x400.png"
        $s6 = "assets/css/smoothness/images/ui-bg_glass_95_fef1ec_1x400.png"
        $s7 = "assets/css/smoothness/images/ui-bg_highlight-soft_75_cccccc_1x10"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01124 {
    strings:
        $s0 = "assets/css/smoothness/images/ui-bg_flat_0_aaaaaa_40x100.png"
        $s1 = "assets/css/smoothness/images/ui-bg_flat_75_ffffff_40x100.png"
        $s2 = "assets/css/smoothness/images/ui-bg_glass_55_fbf9ee_1x400.png"
        $s3 = "assets/css/smoothness/images/ui-bg_glass_65_ffffff_1x400.png"
        $s4 = "assets/css/smoothness/images/ui-bg_glass_75_dadada_1x400.png"
        $s5 = "assets/css/smoothness/images/ui-bg_glass_75_e6e6e6_1x400.png"
        $s6 = "assets/css/smoothness/images/ui-bg_glass_95_fef1ec_1x400.png"
        $s7 = "assets/css/smoothness/images/ui-bg_highlight-soft_75_cccccc_1x10"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01125 {
    strings:
        $s0 = "res/drawable-hdpi/nh.png"
        $s1 = "res/drawable-hdpi/nf_bg_edit_text.9.png"
        $s2 = "res/drawable-hdpi/indeterminate_spinner.png"
        $s3 = "res/drawable-hdpi/selector_edittext_bg.xml"
        $s4 = "res/anim/wait.xml"
        $s5 = "res/drawable-hdpi/btn_cancel_off_gnb.png"
        $s6 = "res/drawable-hdpi/btn_confirm_off_gnw.png"
        $s7 = "res/drawable-hdpi/background_div_bg.xml"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01126 {
    strings:
        $s0 = "res/drawable-hdpi/nf_bg_edit_text.9.png"
        $s1 = "res/drawable-hdpi/indeterminate_spinner.png"
        $s2 = "res/drawable-hdpi/selector_edittext_bg.xml"
        $s3 = "res/anim/wait.xml"
        $s4 = "res/drawable-hdpi/btn_cancel_off_gnb.png"
        $s5 = "res/drawable-hdpi/btn_confirm_off_gnw.png"
        $s6 = "res/drawable-hdpi/background_div_bg.xml"
        $s7 = "res/drawable/dialog_inside_layout.xml"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01127 {
    strings:
        $s0 = "refresh.png"
        $s1 = "smsNumber:"
        $s2 = "/ormma.js"
        $s3 = "ActionHistory.java"
        $s4 = "ParseStep.java"
        $s5 = "messageBody:"
        $s6 = "mraid_close.png"
        $s7 = "$Lorg/ormma/view/OrmmaView$ViewState"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01128 {
    strings:
        $s0 = "assets/css/smoothness/images/ui-bg_flat_0_aaaaaa_40x100.png"
        $s1 = "assets/css/smoothness/images/ui-bg_flat_75_ffffff_40x100.png"
        $s2 = "assets/css/smoothness/images/ui-bg_glass_55_fbf9ee_1x400.png"
        $s3 = "assets/css/smoothness/images/ui-bg_glass_65_ffffff_1x400.png"
        $s4 = "assets/css/smoothness/images/ui-bg_glass_75_dadada_1x400.png"
        $s5 = "assets/css/smoothness/images/ui-bg_glass_75_e6e6e6_1x400.png"
        $s6 = "assets/css/smoothness/images/ui-bg_glass_95_fef1ec_1x400.png"
        $s7 = "assets/css/smoothness/images/ui-bg_highlight-soft_75_cccccc_1x10"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01129 {
    strings:
        $s0 = "AZS/kpEhpE8Jl37U1SJ9eW7KA6E"
        $s1 = "NNqltaQgFzooaAOKcxToQQY/4rU"
        $s2 = "res/drawable/visa_curved.png"
        $s3 = "res/xml/da.xml"
        $s4 = "$Lzzzzzz/xxxxxx/cccccc/ActivityStart"
        $s5 = "-Lzzzzzz/xxxxxx/cccccc/HeadlessSmsSendService"
        $s6 = ".ActivityStart"
        $s7 = "Lzzzzzz/xxxxxx/cccccc/AlarmReceiverAdm"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01130 {
    strings:
        $s0 = "AZS/kpEhpE8Jl37U1SJ9eW7KA6E"
        $s1 = "NNqltaQgFzooaAOKcxToQQY/4rU"
        $s2 = "res/drawable/visa_curved.png"
        $s3 = "res/xml/da.xml"
        $s4 = "$Lzzzzzz/xxxxxx/cccccc/ActivityStart"
        $s5 = "-Lzzzzzz/xxxxxx/cccccc/HeadlessSmsSendService"
        $s6 = ".ActivityStart"
        $s7 = "Lzzzzzz/xxxxxx/cccccc/AlarmReceiverAdm"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01131 {
    strings:
        $s0 = "AZS/kpEhpE8Jl37U1SJ9eW7KA6E"
        $s1 = "NNqltaQgFzooaAOKcxToQQY/4rU"
        $s2 = "res/drawable/visa_curved.png"
        $s3 = "res/xml/da.xml"
        $s4 = "3X5DOa/xPR4Njl/zitjaMje6QoM"
        $s5 = "$Lzzzzzz/xxxxxx/cccccc/ActivityStart"
        $s6 = "-Lzzzzzz/xxxxxx/cccccc/HeadlessSmsSendService"
        $s7 = ".ActivityStart"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01132 {
    strings:
        $s0 = "9cSf/sOgyVhfTbZRYzwC6mNEaos"
        $s1 = "javascript:backMenu"
        $s2 = "$Method:"
        $s3 = "/data/device_admin.php"
        $s4 = "/scripts/app_call_tracking_manager.php"
        $s5 = "/scripts/app_not_received.php"
        $s6 = "/scripts/app_tracking_manager.php"
        $s7 = "/sdcard/mobop"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01133 {
    strings:
        $s0 = "assets/css/smoothness/images/ui-bg_flat_0_aaaaaa_40x100.png"
        $s1 = "assets/css/smoothness/images/ui-bg_flat_75_ffffff_40x100.png"
        $s2 = "assets/css/smoothness/images/ui-bg_glass_55_fbf9ee_1x400.png"
        $s3 = "assets/css/smoothness/images/ui-bg_glass_65_ffffff_1x400.png"
        $s4 = "assets/css/smoothness/images/ui-bg_glass_75_dadada_1x400.png"
        $s5 = "assets/css/smoothness/images/ui-bg_glass_75_e6e6e6_1x400.png"
        $s6 = "assets/css/smoothness/images/ui-bg_glass_95_fef1ec_1x400.png"
        $s7 = "assets/css/smoothness/images/ui-bg_highlight-soft_75_cccccc_1x10"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01134 {
    strings:
        $s0 = "assets/css/smoothness/images/ui-bg_flat_0_aaaaaa_40x100.png"
        $s1 = "assets/css/smoothness/images/ui-bg_flat_75_ffffff_40x100.png"
        $s2 = "assets/css/smoothness/images/ui-bg_glass_55_fbf9ee_1x400.png"
        $s3 = "assets/css/smoothness/images/ui-bg_glass_65_ffffff_1x400.png"
        $s4 = "assets/css/smoothness/images/ui-bg_glass_75_dadada_1x400.png"
        $s5 = "assets/css/smoothness/images/ui-bg_glass_75_e6e6e6_1x400.png"
        $s6 = "assets/css/smoothness/images/ui-bg_glass_95_fef1ec_1x400.png"
        $s7 = "assets/css/smoothness/images/ui-bg_highlight-soft_75_cccccc_1x10"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01135 {
    strings:
        $s0 = "apkprotect.com/key.dat"
        $s1 = "apkprotect.com/readme.txt"
        $s2 = "ReplayStruct.java"
        $s3 = "RequestStruct.java"
        $s4 = "LSecScreen.java"
        $s5 = "res/xml/lsecscreen.xml"
        $s6 = "serivce."
        $s7 = "BaseBootReceiver.java"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01136 {
    strings:
        $s0 = "apkprotect.com/key.dat"
        $s1 = "apkprotect.com/readme.txt"
        $s2 = "ReplayStruct.java"
        $s3 = "RequestStruct.java"
        $s4 = "LSecScreen.java"
        $s5 = "res/xml/lsecscreen.xml"
        $s6 = "serivce."
        $s7 = "BaseBootReceiver.java"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01137 {
    strings:
        $s0 = "receiver/install"
        $s1 = "http://app"
        $s2 = "receiver/uninstall"
        $s3 = "receiver/load_ad"
        $s4 = "receiver/load_offer"
        $s5 = "Lcom/adwo/adsdk/AdwoAdView"
        $s6 = "Lcom/waps/OffersWebView"
        $s7 = "Lcom/adwo/adsdk/AdListener"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01138 {
    strings:
        $s0 = "receiver/install"
        $s1 = "http://app"
        $s2 = "receiver/uninstall"
        $s3 = "receiver/load_ad"
        $s4 = "receiver/load_offer"
        $s5 = "Lcom/adwo/adsdk/AdwoAdView"
        $s6 = "Lcom/waps/OffersWebView"
        $s7 = "Lcom/adwo/adsdk/AdListener"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01139 {
    strings:
        $s0 = "lib/armeabi-v7a/libdn_ssl.so"
        $s1 = "secret-classes.dex"
        $s2 = "scrt.apk"
        $s3 = "res/layout/activity_no_bg.xml"
        $s4 = "/kD/faOo"
        $s5 = "res/layout/activity_call_v7.xml"
        $s6 = "res/layout/call_end_layout.xml"
        $s7 = "res/layout/call_pop_layout.xml"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01140 {
    strings:
        $s0 = "lib/armeabi-v7a/libdn_ssl.so"
        $s1 = "secret-classes.dex"
        $s2 = "scrt.apk"
        $s3 = "res/layout/activity_no_bg.xml"
        $s4 = "/kD/faOo"
        $s5 = "res/layout/activity_call_v7.xml"
        $s6 = "res/layout/call_end_layout.xml"
        $s7 = "res/layout/call_pop_layout.xml"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01141 {
    strings:
        $s0 = "lib/armeabi-v7a/libdn_ssl.so"
        $s1 = "secret-classes.dex"
        $s2 = "scrt.apk"
        $s3 = "res/layout/activity_no_bg.xml"
        $s4 = "/kD/faOo"
        $s5 = "res/layout/activity_call_v7.xml"
        $s6 = "res/layout/call_end_layout.xml"
        $s7 = "res/layout/call_pop_layout.xml"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01142 {
    strings:
        $s0 = "lib/armeabi-v7a/libdn_ssl.so"
        $s1 = "secret-classes.dex"
        $s2 = "scrt.apk"
        $s3 = "res/layout/activity_no_bg.xml"
        $s4 = "/kD/faOo"
        $s5 = "Lcom/mik/proxy/guard/core/BuildConfig"
        $s6 = "com.mik.proxy.guard.core"
        $s7 = "Pc2/qke."
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01143 {
    strings:
        $s0 = "SMSObserver.java"
        $s1 = "PhoneStateObserver.java"
        $s2 = "URLObserver.java"
        $s3 = "uploadFile.php"
        $s4 = "CalenderObserver.java"
        $s5 = "PIN.Please"
        $s6 = "gpslog.php"
        $s7 = "$http://www.mobilespylogs.com/webapi/"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01144 {
    strings:
        $s0 = "Parsing.....Failed"
        $s1 = "Failed....."
        $s2 = "2http://beta.airpush.com/images/adsthumbnail/48.png"
        $s3 = "SetPreferences.java"
        $s4 = "OhaGL7xatki385myc/mriuJt304"
        $s5 = ".https://api.airpush.com/lp/log_sdk_request.php"
        $s6 = "1https://api.airpush.com/lp/getinterstitialads.php"
        $s7 = "https://api.airpush.com/appwall/getid.php"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01145 {
    strings:
        $s0 = "Lcom/adwo/adsdk/AdwoAdView"
        $s1 = "Lcom/adwo/adsdk/AdListener"
        $s2 = "assets/adwo_left_arrow.png"
        $s3 = "assets/adwo_right_arrow.png"
        $s4 = "Lcom/adwo/adsdk/a"
        $s5 = "Lcom/adwo/adsdk/b"
        $s6 = "Lcom/adwo/adsdk/c"
        $s7 = "Lcom/adwo/adsdk/d"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01146 {
    strings:
        $s0 = "lib/armeabi-v7a/libdn_ssl.so"
        $s1 = "secret-classes.dex"
        $s2 = "scrt.apk"
        $s3 = "/kD/faOo"
        $s4 = "res/layout/activity_call_v7.xml"
        $s5 = "res/layout/call_end_layout.xml"
        $s6 = "res/layout/call_pop_layout.xml"
        $s7 = "Lcom/mik/proxy/guard/core/BuildConfig"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01147 {
    strings:
        $s0 = "com.webcash.wooribank"
        $s1 = "res/xml/lock.xml"
        $s2 = "E/s6A6XhGqYlbVovZDGad1Egfcc"
        $s3 = "Sg97xTIFIwKJ/xJV"
        $s4 = "res/drawable-hdpi/background_bg.png"
        $s5 = "res/drawable-hdpi/bg_btn_normal.png"
        $s6 = "res/drawable-hdpi/bg_btn_press.png"
        $s7 = "res/drawable-hdpi/border.9.png"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01148 {
    strings:
        $s0 = "ArrayVariant.java"
        $s1 = "BooleanReferenceParameter.java"
        $s2 = "ByteReferenceParameter.java"
        $s3 = "ByteVariant.java"
        $s4 = "ConvHelpers.java"
        $s5 = "DateVariant.java"
        $s6 = "DoubleReferenceParameter.java"
        $s7 = "ExprHelpers.java"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01149 {
    strings:
        $s0 = "ArrayVariant.java"
        $s1 = "BooleanReferenceParameter.java"
        $s2 = "ByteReferenceParameter.java"
        $s3 = "ByteVariant.java"
        $s4 = "ConvHelpers.java"
        $s5 = "DateVariant.java"
        $s6 = "DoubleReferenceParameter.java"
        $s7 = "ExprHelpers.java"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01150 {
    strings:
        $s0 = "l/cUiZLb7ya5qOYV/djf/zcvnb0"
        $s1 = "res/raw/conf.txt"
        $s2 = "res/raw/result"
        $s3 = "res/raw/resulturl"
        $s4 = "res/raw/rool.txt"
        $s5 = "res/drawable-hdpi/iconnews.png"
        $s6 = "res/drawable-mdpi/iconnews.png"
        $s7 = "http://91.213.175.176/api/"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01151 {
    strings:
        $s0 = "res/drawable-hdpi/abc_list_pressed_holo_light.png"
        $s1 = "res/drawable-hdpi/abc_list_selector_disabled_holo_light.png"
        $s2 = "res/drawable-mdpi/abc_list_pressed_holo_light.png"
        $s3 = "res/drawable-mdpi/abc_list_selector_disabled_holo_light.png"
        $s4 = "res/drawable-xhdpi/abc_list_pressed_holo_light.png"
        $s5 = "res/drawable-xhdpi/abc_list_selector_disabled_holo_light.png"
        $s6 = "res/drawable-xxhdpi/abc_list_pressed_holo_light.png"
        $s7 = "res/drawable-xxhdpi/abc_list_selector_disabled_holo_light.png"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01152 {
    strings:
        $s0 = "res/drawable-hdpi/abc_list_pressed_holo_light.png"
        $s1 = "res/drawable-hdpi/abc_list_selector_disabled_holo_light.png"
        $s2 = "res/drawable-mdpi/abc_list_pressed_holo_light.png"
        $s3 = "res/drawable-mdpi/abc_list_selector_disabled_holo_light.png"
        $s4 = "res/drawable-xhdpi/abc_list_pressed_holo_light.png"
        $s5 = "res/drawable-xhdpi/abc_list_selector_disabled_holo_light.png"
        $s6 = "res/drawable-xxhdpi/abc_list_pressed_holo_light.png"
        $s7 = "res/drawable-xxhdpi/abc_list_selector_disabled_holo_light.png"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01153 {
    strings:
        $s0 = "lib/armeabi-v7a/libdn_ssl.so"
        $s1 = "secret-classes.dex"
        $s2 = "scrt.apk"
        $s3 = "/kD/faOo"
        $s4 = "res/layout/activity_call_v7.xml"
        $s5 = "res/layout/call_end_layout.xml"
        $s6 = "res/layout/call_pop_layout.xml"
        $s7 = "Lcom/mik/proxy/guard/core/BuildConfig"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01154 {
    strings:
        $s0 = "lib/armeabi-v7a/libdn_ssl.so"
        $s1 = "secret-classes.dex"
        $s2 = "scrt.apk"
        $s3 = "/kD/faOo"
        $s4 = "res/layout/activity_call_v7.xml"
        $s5 = "res/layout/call_end_layout.xml"
        $s6 = "res/layout/call_pop_layout.xml"
        $s7 = "Lcom/mik/proxy/guard/core/BuildConfig"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01155 {
    strings:
        $s0 = "ArrayVariant.java"
        $s1 = "BooleanReferenceParameter.java"
        $s2 = "ByteReferenceParameter.java"
        $s3 = "ByteVariant.java"
        $s4 = "ConvHelpers.java"
        $s5 = "DateVariant.java"
        $s6 = "DoubleReferenceParameter.java"
        $s7 = "ExprHelpers.java"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01156 {
    strings:
        $s0 = ".jpg.dat"
        $s1 = "/Android/data/code/KI.DAT"
        $s2 = ".png.dat"
        $s3 = "-----------s:"
        $s4 = "nousr.dat"
        $s5 = "bin/v.dat"
        $s6 = "bin/m.txt"
        $s7 = "bin/p.txt"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01157 {
    strings:
        $s0 = ".jpg.dat"
        $s1 = "/Android/data/code/KI.DAT"
        $s2 = ".png.dat"
        $s3 = "-----------s:"
        $s4 = "nousr.dat"
        $s5 = "bin/v.dat"
        $s6 = "bin/m.txt"
        $s7 = "bin/p.txt"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01158 {
    strings:
        $s0 = "7kLFsbr73Dn5mTI1b7Vd/a62PQ8"
        $s1 = "MSe3LbcSGEJHSbnnBqo/MvM"
        $s2 = "TBP3rC0W8LU7ynapcTX6CUk/lDs"
        $s3 = "com/sun/mail/dsn/package.html"
        $s4 = "com/sun/mail/imap/package.html"
        $s5 = "com/sun/mail/pop3/package.html"
        $s6 = "com/sun/mail/smtp/package.html"
        $s7 = "javax/activation/package.html"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01159 {
    strings:
        $s0 = "receiver/install"
        $s1 = "http://app"
        $s2 = "receiver/uninstall"
        $s3 = "receiver/load_ad"
        $s4 = "receiver/load_offer"
        $s5 = "Lcom/waps/OffersWebView"
        $s6 = "UPermission.ACCESS_WIFI_STATE"
        $s7 = "Lcom/waps/a"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01160 {
    strings:
        $s0 = "https://crash.163.com"
        $s1 = "----.Kiiiik-x"
        $s2 = "---i--m/i-"
        $s3 = ".--Ki-Ki"
        $s4 = ".wEbg6cYKmZ4IVy"
        $s5 = "/EYDGebWTWlovcmVxPmqtq/Xr"
        $s6 = "/Lcom/netease/nis/bugrpt/user/AbstractNetClient"
        $s7 = "0Lcom/netease/nis/bugrpt/user/IExceptionCallback"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01161 {
    strings:
        $s0 = "Lcom/ironsource/mobilcore/A$a"
        $s1 = "Lcom/ironsource/mobilcore/H$a"
        $s2 = "Lcom/ironsource/mobilcore/J$a"
        $s3 = "Lcom/ironsource/mobilcore/T$a"
        $s4 = "Lcom/ironsource/mobilcore/aF$1"
        $s5 = "Lcom/ironsource/mobilcore/aF$c"
        $s6 = "Lcom/ironsource/mobilcore/aG$a"
        $s7 = "Lcom/ironsource/mobilcore/v$1"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01162 {
    strings:
        $s0 = "au.com.bankwest.mobile"
        $s1 = "ZzxKlxKyki.i"
        $s2 = "commandus.com"
        $s3 = "--.ixKiidAZ"
        $s4 = "/CalsRlpNBoM"
        $s5 = "/p9USHEeoIE3gQO135Rl6PxRJyo"
        $s6 = "2Lcom/note/donote/receivers/ServiceDestroyReceiver"
        $s7 = "3Lcom/note/donote/receivers/sms/PushServiceReciever"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01163 {
    strings:
        $s0 = "au.com.bankwest.mobile"
        $s1 = "ZzxKlxKyki.i"
        $s2 = "commandus.com"
        $s3 = "--.ixKiidAZ"
        $s4 = "/CalsRlpNBoM"
        $s5 = "/p9USHEeoIE3gQO135Rl6PxRJyo"
        $s6 = "2Lcom/note/donote/receivers/ServiceDestroyReceiver"
        $s7 = "3Lcom/note/donote/receivers/sms/PushServiceReciever"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01164 {
    strings:
        $s0 = "au.com.bankwest.mobile"
        $s1 = "ZzxKlxKyki.i"
        $s2 = "commandus.com"
        $s3 = "--.ixKiidAZ"
        $s4 = "/CalsRlpNBoM"
        $s5 = "/p9USHEeoIE3gQO135Rl6PxRJyo"
        $s6 = "2Lcom/note/donote/receivers/ServiceDestroyReceiver"
        $s7 = "3Lcom/note/donote/receivers/sms/PushServiceReciever"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01165 {
    strings:
        $s0 = "au.com.bankwest.mobile"
        $s1 = "ZzxKlxKyki.i"
        $s2 = "commandus.com"
        $s3 = "--.ixKiidAZ"
        $s4 = "/CalsRlpNBoM"
        $s5 = "/p9USHEeoIE3gQO135Rl6PxRJyo"
        $s6 = "2Lcom/note/donote/receivers/ServiceDestroyReceiver"
        $s7 = "3Lcom/note/donote/receivers/sms/PushServiceReciever"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01166 {
    strings:
        $s0 = "yE2dY2Kn/do7JCPKHUD0efZTRAM"
        $s1 = "res/drawable-hdpi-v4/hy_bg.png"
        $s2 = "oB5Yzt7us4F2/8xjSWtCoP3PhPs"
        $s3 = "V2s8zMfbJGH05DsPX/RXvRspYrc"
        $s4 = "res/drawable-hdpi-v4/btn_black.png"
        $s5 = "res/drawable-hdpi-v4/gaoqing.png"
        $s6 = "res/drawable-hdpi-v4/pianku.png"
        $s7 = "res/drawable-hdpi-v4/tuku.png"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01167 {
    strings:
        $s0 = "sendsms:"
        $s1 = "$Lcom/FREE_APPS_511/android/FreeApps"
        $s2 = "$Lcom/FREE_APPS_511/android/R$layout"
        $s3 = "$Lcom/FREE_APPS_511/android/R$string"
        $s4 = "/UlBq6QtvRahYpxJSRj9YnQTdsE"
        $s5 = "0Lcom/FREE_APPS_511/android/FreeApps$LocalBinder"
        $s6 = ":http://14.102.150.53/"
        $s7 = "FreeApps.java"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01168 {
    strings:
        $s0 = "assets/css/smoothness/images/ui-bg_flat_0_aaaaaa_40x100.png"
        $s1 = "assets/css/smoothness/images/ui-bg_flat_75_ffffff_40x100.png"
        $s2 = "assets/css/smoothness/images/ui-bg_glass_55_fbf9ee_1x400.png"
        $s3 = "assets/css/smoothness/images/ui-bg_glass_65_ffffff_1x400.png"
        $s4 = "assets/css/smoothness/images/ui-bg_glass_75_dadada_1x400.png"
        $s5 = "assets/css/smoothness/images/ui-bg_glass_75_e6e6e6_1x400.png"
        $s6 = "assets/css/smoothness/images/ui-bg_glass_95_fef1ec_1x400.png"
        $s7 = "assets/css/smoothness/images/ui-bg_highlight-soft_75_cccccc_1x10"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01169 {
    strings:
        $s0 = "res/raw/data.db"
        $s1 = "Lorg/MobileDb/Field"
        $s2 = "Lorg/MobileDb/MobileDatabase"
        $s3 = "Lorg/MobileDb/Row"
        $s4 = "Lorg/MobileDb/Table"
        $s5 = "Lorg/MobileDb/Utf8StringBuffer"
        $s6 = ".---NKxx"
        $s7 = "MobileDatabase.java"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01170 {
    strings:
        $s0 = "/rgBiUeGVuM9QauYk4hnNYsk7Tg"
        $s1 = "-i...--."
        $s2 = "hN---i1L------.----"
        $s3 = "L-/k-Zln"
        $s4 = "L--K0--/Np-"
        $s5 = "OAR1L-.x_-PM-y"
        $s6 = "onReleased..."
        $s7 = "1D70LpTSLJWWr/"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01171 {
    strings:
        $s0 = "receiver/install"
        $s1 = "http://app"
        $s2 = "receiver/uninstall"
        $s3 = "receiver/load_ad"
        $s4 = "receiver/load_offer"
        $s5 = "Lcom/adwo/adsdk/AdwoAdView"
        $s6 = "Lcom/waps/OffersWebView"
        $s7 = "Lcom/adwo/adsdk/AdListener"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01172 {
    strings:
        $s0 = "receiver/install"
        $s1 = "http://app"
        $s2 = "receiver/uninstall"
        $s3 = "receiver/load_ad"
        $s4 = "receiver/load_offer"
        $s5 = "Lcom/adwo/adsdk/AdwoAdView"
        $s6 = "Lcom/waps/OffersWebView"
        $s7 = "Lcom/adwo/adsdk/AdListener"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01174 {
    strings:
        $s0 = "res/xml-v22/accessibility_service_config.xml"
        $s1 = "res/xml-v14/accessibility_service_config.xml"
        $s2 = "xJ-iiiiiiK."
        $s3 = "w-----/35"
        $s4 = "assets/layout.bal"
        $s5 = "LS_layout.java"
        $s6 = "P1sg7QEECkUyNg4qXX/0RL6ICjw"
        $s7 = "7com.android.packageinstaller:id/permission_allow_button"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01175 {
    strings:
        $s0 = "res/xml/device_admin_data.xml"
        $s1 = "OhaGL7xatki385myc/mriuJt304"
        $s2 = "res/drawable-mdpi/line.png"
        $s3 = ".andro_secure"
        $s4 = ":Executed:HTTP"
        $s5 = "com.adobe.flashplayer."
        $s6 = "getMessages:Executed:HTTP"
        $s7 = "http://adobe.com."
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01176 {
    strings:
        $s0 = "7DhpDjTsZAEIAYfvY/7h4F4nO/o"
        $s1 = "LK27PmsL/4l8jQSlCAXhfKDVJ54"
        $s2 = "UEWnESKAKBDEtG:BK//JXAsRAmsU/czjMoIGnVvRXjFBeNXrBsationsKHWOU/IIzXlrres"
        $s3 = "UEWnESKAKBDEtG:BK//JXAsRAmsU/izjMIGnVbRXjFoBNXBKHWOxU/IIzXlrres"
        $s4 = "UEWnESKAKBDEtG:BK//JXAsRAmsU/nzjMdIGeVxRXjFpBkNXBKHWOhUpIIzXlrres"
        $s5 = "UEWnESKAKBDEtG:BK//JXAsRAmsU/ozjMuIGtVbRXjFoBNXBKHWOxU/IIzXlrres"
        $s6 = "res/xml/pls.xml"
        $s7 = "yyyy:MM:dd_HH:mm:ss"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01177 {
    strings:
        $s0 = "Lcom/baidu/location/h$a"
        $s1 = "Lcom/baidu/location/h$1"
        $s2 = "5Lcom/scwang/smartrefresh/layout/SmartRefreshLayout$a"
        $s3 = "desable."
        $s4 = "res/images"
        $s5 = "/Tencent/ys/Loader"
        $s6 = "myreturnCode:"
        $s7 = ".cnzz.com/stat.htm"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01178 {
    strings:
        $s0 = "com.webcash.wooribank"
        $s1 = "com.kakaotalk.synservice.TIK"
        $s2 = "com.kakaotalk.synservice.URL"
        $s3 = "res/xml/an.xml"
        $s4 = "com.xxx.GS"
        $s5 = "MyTools.java"
        $s6 = "rspcode:"
        $s7 = "DeAdminReciver.java"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01179 {
    strings:
        $s0 = "com.webcash.wooribank"
        $s1 = "com.kakaotalk.synservice.TIK"
        $s2 = "com.kakaotalk.synservice.URL"
        $s3 = "res/xml/an.xml"
        $s4 = "com.xxx.GS"
        $s5 = "MyTools.java"
        $s6 = "rspcode:"
        $s7 = "DeAdminReciver.java"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01180 {
    strings:
        $s0 = "Z.-z-.xy-"
        $s1 = "J-yM/-P-y"
        $s2 = "wj-zM.x."
        $s3 = "/Lcom/devtodev/analytics/internal/logger/Logger"
        $s4 = "-Lcom/devtodev/analytics/internal/domain/User"
        $s5 = "0Lcom/devtodev/analytics/internal/domain/DbModel"
        $s6 = "0Lcom/devtodev/analytics/internal/domain/Project"
        $s7 = "2Lcom/devtodev/analytics/internal/backend/IBackend"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01181 {
    strings:
        $s0 = "receiver/install"
        $s1 = "http://app"
        $s2 = "receiver/uninstall"
        $s3 = "receiver/load_ad"
        $s4 = "receiver/load_offer"
        $s5 = "Lcom/waps/OffersWebView"
        $s6 = "UPermission.ACCESS_WIFI_STATE"
        $s7 = "Lcom/waps/a"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01182 {
    strings:
        $s0 = "receiver/install"
        $s1 = "http://app"
        $s2 = "receiver/uninstall"
        $s3 = "receiver/load_ad"
        $s4 = "receiver/load_offer"
        $s5 = "Lcom/waps/OffersWebView"
        $s6 = "Lcom/waps/a"
        $s7 = "Lcom/waps/b"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01183 {
    strings:
        $s0 = "receiver/install"
        $s1 = "http://app"
        $s2 = "receiver/uninstall"
        $s3 = "receiver/load_ad"
        $s4 = "receiver/load_offer"
        $s5 = "Lcom/waps/OffersWebView"
        $s6 = "Lcom/waps/a"
        $s7 = "Lcom/waps/b"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01184 {
    strings:
        $s0 = "receiver/install"
        $s1 = "http://app"
        $s2 = "receiver/uninstall"
        $s3 = "receiver/load_ad"
        $s4 = "receiver/load_offer"
        $s5 = "Lcom/waps/OffersWebView"
        $s6 = "Lcom/waps/a"
        $s7 = "Lcom/waps/b"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01185 {
    strings:
        $s0 = "KICTMP6SxTI5FvlOjI1rAw/Pm48"
        $s1 = "7Zqw9ijgIPkwdf12ZvPYbkgzm/o"
    condition:
        any of ($s0, $s1)
}

rule VX_APK_CLUSTER_01186 {
    strings:
        $s0 = "KICTMP6SxTI5FvlOjI1rAw/Pm48"
        $s1 = "7Zqw9ijgIPkwdf12ZvPYbkgzm/o"
        $s2 = "res/drawable/tk.xml"
    condition:
        any of ($s0, $s1, $s2)
}

rule VX_APK_CLUSTER_01187 {
    strings:
        $s0 = "com.example.root.myapplication.MainActivity"
        $s1 = "7aAghtWOTFyOJuukHMx8C19d/KE"
        $s2 = "KvTAT1A/RXUyfUPA6WkqplZWTRA"
        $s3 = "res/xml/mihaf.xml"
        $s4 = "priorities.xml"
        $s5 = "platform.io.input.results"
        $s6 = "platform.io.input.resultsData"
        $s7 = "text/doc.android.intent"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01188 {
    strings:
        $s0 = "Lcom/tencent/bugly/proguard/ad$a"
        $s1 = "style/payeco_pluginSpinnerButton"
        $s2 = "A/R6XEbhUeKlYbxW"
        $s3 = "Lcom/unionpay/UPPayAssistEx"
        $s4 = "Lcom/unionpay/uppay/PayActivity"
        $s5 = "Config.DEBUG"
        $s6 = "UPPayPluginEx.apk"
        $s7 = "HttpConn.connect"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01189 {
    strings:
        $s0 = "/consumerCodeList"
        $s1 = "86BpnPXgWHUkHbM/vws7iZu0mk"
        $s2 = "AlDWi8bl2/bzTg3d3zZK/g"
        $s3 = "HhPyb1I/X38"
        $s4 = "Iw39W6xW2WgpkFZONZWB/Q"
        $s5 = "KsYPG2/wAfIRZj11LiAb0g"
        $s6 = "RGVw4AQRs/I6priG96EeCQ"
        $s7 = "WFYWPrp7Ea/0oEEh9lCC1A"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01190 {
    strings:
        $s0 = "/consumerCodeList"
        $s1 = "86BpnPXgWHUkHbM/vws7iZu0mk"
        $s2 = "AlDWi8bl2/bzTg3d3zZK/g"
        $s3 = "HhPyb1I/X38"
        $s4 = "Iw39W6xW2WgpkFZONZWB/Q"
        $s5 = "KsYPG2/wAfIRZj11LiAb0g"
        $s6 = "RGVw4AQRs/I6priG96EeCQ"
        $s7 = "WFYWPrp7Ea/0oEEh9lCC1A"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01191 {
    strings:
        $s0 = "lib/armeabi-v7a/libtqwj.so"
        $s1 = "lib/armeabi-v7a/libyjew.so"
        $s2 = "8TVbIXtXw6Ql8dyhLK/Vp/9U"
        $s3 = "Lcom/android/lib/impl/z"
        $s4 = "Lcom/main/lib/SdkInit"
        $s5 = "Ll/k/c/v/b"
        $s6 = "Ll/k/x/c/v"
        $s7 = "NrTmrOKkVrp3q/qkRUx3shM"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01192 {
    strings:
        $s0 = "9Lcom/google/gson/aq"
        $s1 = "res/drawable/stat_notify.png"
        $s2 = "8kvoaWbY/AcnUGJLnGTNUFlEJMA"
        $s3 = "currentResponseLength:"
        $s4 = "res/drawable-hdpi/stat_notify.png"
        $s5 = "DesPlus.java"
        $s6 = "DomParse.java"
        $s7 = "CelebrateService.java"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01193 {
    strings:
        $s0 = "com.qihoo.bugreport.CrashReport"
        $s1 = "com.qihoo.dexjiagu.TransitMgr"
        $s2 = "Lcom/qihoo/util/QHDialog$1"
        $s3 = "QHDialog.java"
        $s4 = "Lcom/qihoo/util/QHDialog$1$1"
        $s5 = "CrashReport."
        $s6 = "95bBzBzji4SjpPjQYB/wekCynXo"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6)
}

rule VX_APK_CLUSTER_01194 {
    strings:
        $s0 = "AAAAFAAEAE1FVEEtSU5GL01BTklGRVNULk1G/soAAPNNzMtMSy0u0Q1LLSrOzM"
        $s1 = "DispatchHelper.java"
        $s2 = "Byte2Int.java"
        $s3 = "DUtil.java"
        $s4 = "-5j5a5v5a5.5i5o5.5F5i5l5e5O5u5t5p5u5t5St55ream"
        $s5 = "52j2a2v2a2.2i2o2.B2y2t2e2A2rr2a2y2I2n2p2u2t2S2t2r2e2am"
        $s6 = "DUtils2.java"
        $s7 = "DUtils4.java"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01195 {
    strings:
        $s0 = "assets/url.txt"
        $s1 = "contactsutils.java"
        $s2 = "$Lb4a/example/contactsutils$_cuemail"
        $s3 = "$Lb4a/example/contactsutils$_cuphone"
        $s4 = "DiviceInfo.java"
        $s5 = "Lb4a/example/contactsutils"
        $s6 = "Lb4a/example/contactsutils$_cucontact"
        $s7 = "Lcom/reza/sh/deviceinfo/DiviceInfo"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01196 {
    strings:
        $s0 = "assets/css/smoothness/images/ui-bg_flat_0_aaaaaa_40x100.png"
        $s1 = "assets/css/smoothness/images/ui-bg_flat_75_ffffff_40x100.png"
        $s2 = "assets/css/smoothness/images/ui-bg_glass_55_fbf9ee_1x400.png"
        $s3 = "assets/css/smoothness/images/ui-bg_glass_65_ffffff_1x400.png"
        $s4 = "assets/css/smoothness/images/ui-bg_glass_75_dadada_1x400.png"
        $s5 = "assets/css/smoothness/images/ui-bg_glass_75_e6e6e6_1x400.png"
        $s6 = "assets/css/smoothness/images/ui-bg_glass_95_fef1ec_1x400.png"
        $s7 = "assets/css/smoothness/images/ui-bg_highlight-soft_75_cccccc_1x10"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01197 {
    strings:
        $s0 = "assets/css/smoothness/images/ui-bg_flat_0_aaaaaa_40x100.png"
        $s1 = "assets/css/smoothness/images/ui-bg_flat_75_ffffff_40x100.png"
        $s2 = "assets/css/smoothness/images/ui-bg_glass_55_fbf9ee_1x400.png"
        $s3 = "assets/css/smoothness/images/ui-bg_glass_65_ffffff_1x400.png"
        $s4 = "assets/css/smoothness/images/ui-bg_glass_75_dadada_1x400.png"
        $s5 = "assets/css/smoothness/images/ui-bg_glass_75_e6e6e6_1x400.png"
        $s6 = "assets/css/smoothness/images/ui-bg_glass_95_fef1ec_1x400.png"
        $s7 = "assets/css/smoothness/images/ui-bg_highlight-soft_75_cccccc_1x10"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01198 {
    strings:
        $s0 = "ASetupTool.java"
        $s1 = "ASvcLoader.java"
        $s2 = "assets/Sonnenblume/res.bin"
        $s3 = "Lcom/alipay/sdk/cons/GlobalConstants"
        $s4 = "Lcom/alipay/sdk/app/PayTask$1"
        $s5 = "Lcom/alipay/sdk/app/PayTask$2"
        $s6 = "com.snowfish.appid"
        $s7 = "Lcom/snowfish/a/a/p/APaymentResult"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01199 {
    strings:
        $s0 = "http://app"
        $s1 = "UPermission.ACCESS_WIFI_STATE"
        $s2 = "Hlcfbb9BZwuSon/A6QBcRmEvqW0"
        $s3 = "kh6OV2SS/YN0uki58hjgqw25GEc"
        $s4 = "connect/active"
        $s5 = "ArrayVariant.java"
        $s6 = "BooleanReferenceParameter.java"
        $s7 = "ByteReferenceParameter.java"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01200 {
    strings:
        $s0 = "assets/css/smoothness/images/ui-bg_flat_0_aaaaaa_40x100.png"
        $s1 = "assets/css/smoothness/images/ui-bg_flat_75_ffffff_40x100.png"
        $s2 = "assets/css/smoothness/images/ui-bg_glass_55_fbf9ee_1x400.png"
        $s3 = "assets/css/smoothness/images/ui-bg_glass_65_ffffff_1x400.png"
        $s4 = "assets/css/smoothness/images/ui-bg_glass_75_dadada_1x400.png"
        $s5 = "assets/css/smoothness/images/ui-bg_glass_75_e6e6e6_1x400.png"
        $s6 = "assets/css/smoothness/images/ui-bg_glass_95_fef1ec_1x400.png"
        $s7 = "assets/css/smoothness/images/ui-bg_highlight-soft_75_cccccc_1x10"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01201 {
    strings:
        $s0 = "assets/css/smoothness/images/ui-bg_flat_0_aaaaaa_40x100.png"
        $s1 = "assets/css/smoothness/images/ui-bg_flat_75_ffffff_40x100.png"
        $s2 = "assets/css/smoothness/images/ui-bg_glass_55_fbf9ee_1x400.png"
        $s3 = "assets/css/smoothness/images/ui-bg_glass_65_ffffff_1x400.png"
        $s4 = "assets/css/smoothness/images/ui-bg_glass_75_dadada_1x400.png"
        $s5 = "assets/css/smoothness/images/ui-bg_glass_75_e6e6e6_1x400.png"
        $s6 = "assets/css/smoothness/images/ui-bg_glass_95_fef1ec_1x400.png"
        $s7 = "assets/css/smoothness/images/ui-bg_highlight-soft_75_cccccc_1x10"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01202 {
    strings:
        $s0 = "assets/css/smoothness/images/ui-bg_flat_0_aaaaaa_40x100.png"
        $s1 = "assets/css/smoothness/images/ui-bg_flat_75_ffffff_40x100.png"
        $s2 = "assets/css/smoothness/images/ui-bg_glass_55_fbf9ee_1x400.png"
        $s3 = "assets/css/smoothness/images/ui-bg_glass_65_ffffff_1x400.png"
        $s4 = "assets/css/smoothness/images/ui-bg_glass_75_dadada_1x400.png"
        $s5 = "assets/css/smoothness/images/ui-bg_glass_75_e6e6e6_1x400.png"
        $s6 = "assets/css/smoothness/images/ui-bg_glass_95_fef1ec_1x400.png"
        $s7 = "assets/css/smoothness/images/ui-bg_highlight-soft_75_cccccc_1x10"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01203 {
    strings:
        $s0 = "assets/css/smoothness/images/ui-bg_flat_0_aaaaaa_40x100.png"
        $s1 = "assets/css/smoothness/images/ui-bg_flat_75_ffffff_40x100.png"
        $s2 = "assets/css/smoothness/images/ui-bg_glass_55_fbf9ee_1x400.png"
        $s3 = "assets/css/smoothness/images/ui-bg_glass_65_ffffff_1x400.png"
        $s4 = "assets/css/smoothness/images/ui-bg_glass_75_dadada_1x400.png"
        $s5 = "assets/css/smoothness/images/ui-bg_glass_75_e6e6e6_1x400.png"
        $s6 = "assets/css/smoothness/images/ui-bg_glass_95_fef1ec_1x400.png"
        $s7 = "assets/css/smoothness/images/ui-bg_highlight-soft_75_cccccc_1x10"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01204 {
    strings:
        $s0 = "AAAAFAAEAE1FVEEtSU5GL01BTklGRVNULk1G/soAAPNNzMtMSy0u0Q1LLSrOzM"
        $s1 = "GSR.java"
        $s2 = "Landroidx/viewpager/widget/ViewPager$"
        $s3 = "-Landroidx/core/app/JobIntentService$"
        $s4 = "0Landroidx/core/app/JobIntentService$"
        $s5 = "Landroidx/core/app/JobIntentService$"
        $s6 = "eftbWnJ8F/g"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6)
}

rule VX_APK_CLUSTER_01205 {
    strings:
        $s0 = "mian.iyu"
        $s1 = "/AcvZ4Yycp/fuahUizra4r219Ug"
        $s2 = "UaAcDtpGmSrYRacrNRzul/Gk4Pw"
        $s3 = "a3V5KpEW/d14VzAGShsebenhDEI"
        $s4 = "assets/lib.so"
        $s5 = "lib/armeabi-v7a/libygsiyu.so"
        $s6 = "lib/x86/libygsiyu.so"
        $s7 = "tTYPFQeo26XIrs6xdPYO/zvBEiM"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01206 {
    strings:
        $s0 = "mian.iyu"
        $s1 = "/AcvZ4Yycp/fuahUizra4r219Ug"
        $s2 = "UaAcDtpGmSrYRacrNRzul/Gk4Pw"
        $s3 = "a3V5KpEW/d14VzAGShsebenhDEI"
        $s4 = "assets/lib.so"
        $s5 = "lib/armeabi-v7a/libygsiyu.so"
        $s6 = "lib/x86/libygsiyu.so"
        $s7 = "tTYPFQeo26XIrs6xdPYO/zvBEiM"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01207 {
    strings:
        $s0 = "mian.iyu"
        $s1 = "/AcvZ4Yycp/fuahUizra4r219Ug"
        $s2 = "UaAcDtpGmSrYRacrNRzul/Gk4Pw"
        $s3 = "a3V5KpEW/d14VzAGShsebenhDEI"
        $s4 = "assets/lib.so"
        $s5 = "lib/armeabi-v7a/libygsiyu.so"
        $s6 = "lib/x86/libygsiyu.so"
        $s7 = "tTYPFQeo26XIrs6xdPYO/zvBEiM"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01208 {
    strings:
        $s0 = "mian.iyu"
        $s1 = "/AcvZ4Yycp/fuahUizra4r219Ug"
        $s2 = "UaAcDtpGmSrYRacrNRzul/Gk4Pw"
        $s3 = "a3V5KpEW/d14VzAGShsebenhDEI"
        $s4 = "assets/lib.so"
        $s5 = "lib/armeabi-v7a/libygsiyu.so"
        $s6 = "lib/x86/libygsiyu.so"
        $s7 = "tTYPFQeo26XIrs6xdPYO/zvBEiM"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01209 {
    strings:
        $s0 = "mian.iyu"
        $s1 = "/AcvZ4Yycp/fuahUizra4r219Ug"
        $s2 = "UaAcDtpGmSrYRacrNRzul/Gk4Pw"
        $s3 = "a3V5KpEW/d14VzAGShsebenhDEI"
        $s4 = "assets/lib.so"
        $s5 = "lib/armeabi-v7a/libygsiyu.so"
        $s6 = "lib/x86/libygsiyu.so"
        $s7 = "tTYPFQeo26XIrs6xdPYO/zvBEiM"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01210 {
    strings:
        $s0 = "mian.iyu"
        $s1 = "/AcvZ4Yycp/fuahUizra4r219Ug"
        $s2 = "UaAcDtpGmSrYRacrNRzul/Gk4Pw"
        $s3 = "a3V5KpEW/d14VzAGShsebenhDEI"
        $s4 = "assets/lib.so"
        $s5 = "lib/armeabi-v7a/libygsiyu.so"
        $s6 = "lib/x86/libygsiyu.so"
        $s7 = "tTYPFQeo26XIrs6xdPYO/zvBEiM"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01211 {
    strings:
        $s0 = "mian.iyu"
        $s1 = "/AcvZ4Yycp/fuahUizra4r219Ug"
        $s2 = "UaAcDtpGmSrYRacrNRzul/Gk4Pw"
        $s3 = "a3V5KpEW/d14VzAGShsebenhDEI"
        $s4 = "assets/lib.so"
        $s5 = "lib/armeabi-v7a/libygsiyu.so"
        $s6 = "lib/x86/libygsiyu.so"
        $s7 = "tTYPFQeo26XIrs6xdPYO/zvBEiM"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01212 {
    strings:
        $s0 = "mian.iyu"
        $s1 = "/AcvZ4Yycp/fuahUizra4r219Ug"
        $s2 = "UaAcDtpGmSrYRacrNRzul/Gk4Pw"
        $s3 = "a3V5KpEW/d14VzAGShsebenhDEI"
        $s4 = "assets/lib.so"
        $s5 = "lib/armeabi-v7a/libygsiyu.so"
        $s6 = "lib/x86/libygsiyu.so"
        $s7 = "tTYPFQeo26XIrs6xdPYO/zvBEiM"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01213 {
    strings:
        $s0 = "mian.iyu"
        $s1 = "/AcvZ4Yycp/fuahUizra4r219Ug"
        $s2 = "UaAcDtpGmSrYRacrNRzul/Gk4Pw"
        $s3 = "a3V5KpEW/d14VzAGShsebenhDEI"
        $s4 = "assets/lib.so"
        $s5 = "lib/armeabi-v7a/libygsiyu.so"
        $s6 = "lib/x86/libygsiyu.so"
        $s7 = "tTYPFQeo26XIrs6xdPYO/zvBEiM"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01214 {
    strings:
        $s0 = "mian.iyu"
        $s1 = "/AcvZ4Yycp/fuahUizra4r219Ug"
        $s2 = "UaAcDtpGmSrYRacrNRzul/Gk4Pw"
        $s3 = "a3V5KpEW/d14VzAGShsebenhDEI"
        $s4 = "assets/lib.so"
        $s5 = "lib/armeabi-v7a/libygsiyu.so"
        $s6 = "lib/x86/libygsiyu.so"
        $s7 = "tTYPFQeo26XIrs6xdPYO/zvBEiM"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01215 {
    strings:
        $s0 = "mian.iyu"
        $s1 = "/AcvZ4Yycp/fuahUizra4r219Ug"
        $s2 = "UaAcDtpGmSrYRacrNRzul/Gk4Pw"
        $s3 = "a3V5KpEW/d14VzAGShsebenhDEI"
        $s4 = "assets/lib.so"
        $s5 = "lib/armeabi-v7a/libygsiyu.so"
        $s6 = "lib/x86/libygsiyu.so"
        $s7 = "tTYPFQeo26XIrs6xdPYO/zvBEiM"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01216 {
    strings:
        $s0 = "mian.iyu"
        $s1 = "/AcvZ4Yycp/fuahUizra4r219Ug"
        $s2 = "UaAcDtpGmSrYRacrNRzul/Gk4Pw"
        $s3 = "a3V5KpEW/d14VzAGShsebenhDEI"
        $s4 = "assets/lib.so"
        $s5 = "lib/armeabi-v7a/libygsiyu.so"
        $s6 = "lib/x86/libygsiyu.so"
        $s7 = "tTYPFQeo26XIrs6xdPYO/zvBEiM"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01217 {
    strings:
        $s0 = "mian.iyu"
        $s1 = "/AcvZ4Yycp/fuahUizra4r219Ug"
        $s2 = "UaAcDtpGmSrYRacrNRzul/Gk4Pw"
        $s3 = "a3V5KpEW/d14VzAGShsebenhDEI"
        $s4 = "assets/lib.so"
        $s5 = "lib/armeabi-v7a/libygsiyu.so"
        $s6 = "lib/x86/libygsiyu.so"
        $s7 = "tTYPFQeo26XIrs6xdPYO/zvBEiM"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01218 {
    strings:
        $s0 = "mian.iyu"
        $s1 = "/AcvZ4Yycp/fuahUizra4r219Ug"
        $s2 = "UaAcDtpGmSrYRacrNRzul/Gk4Pw"
        $s3 = "a3V5KpEW/d14VzAGShsebenhDEI"
        $s4 = "assets/lib.so"
        $s5 = "lib/armeabi-v7a/libygsiyu.so"
        $s6 = "lib/x86/libygsiyu.so"
        $s7 = "tTYPFQeo26XIrs6xdPYO/zvBEiM"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01219 {
    strings:
        $s0 = "mian.iyu"
        $s1 = "/AcvZ4Yycp/fuahUizra4r219Ug"
        $s2 = "UaAcDtpGmSrYRacrNRzul/Gk4Pw"
        $s3 = "a3V5KpEW/d14VzAGShsebenhDEI"
        $s4 = "assets/lib.so"
        $s5 = "lib/armeabi-v7a/libygsiyu.so"
        $s6 = "lib/x86/libygsiyu.so"
        $s7 = "tTYPFQeo26XIrs6xdPYO/zvBEiM"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01220 {
    strings:
        $s0 = "mian.iyu"
        $s1 = "/AcvZ4Yycp/fuahUizra4r219Ug"
        $s2 = "UaAcDtpGmSrYRacrNRzul/Gk4Pw"
        $s3 = "a3V5KpEW/d14VzAGShsebenhDEI"
        $s4 = "assets/lib.so"
        $s5 = "lib/armeabi-v7a/libygsiyu.so"
        $s6 = "lib/x86/libygsiyu.so"
        $s7 = "tTYPFQeo26XIrs6xdPYO/zvBEiM"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01221 {
    strings:
        $s0 = "mian.iyu"
        $s1 = "/AcvZ4Yycp/fuahUizra4r219Ug"
        $s2 = "UaAcDtpGmSrYRacrNRzul/Gk4Pw"
        $s3 = "a3V5KpEW/d14VzAGShsebenhDEI"
        $s4 = "assets/lib.so"
        $s5 = "lib/armeabi-v7a/libygsiyu.so"
        $s6 = "lib/x86/libygsiyu.so"
        $s7 = "tTYPFQeo26XIrs6xdPYO/zvBEiM"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01222 {
    strings:
        $s0 = "mian.iyu"
        $s1 = "/AcvZ4Yycp/fuahUizra4r219Ug"
        $s2 = "UaAcDtpGmSrYRacrNRzul/Gk4Pw"
        $s3 = "a3V5KpEW/d14VzAGShsebenhDEI"
        $s4 = "assets/lib.so"
        $s5 = "lib/armeabi-v7a/libygsiyu.so"
        $s6 = "lib/x86/libygsiyu.so"
        $s7 = "tTYPFQeo26XIrs6xdPYO/zvBEiM"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01223 {
    strings:
        $s0 = "mian.iyu"
        $s1 = "/AcvZ4Yycp/fuahUizra4r219Ug"
        $s2 = "UaAcDtpGmSrYRacrNRzul/Gk4Pw"
        $s3 = "a3V5KpEW/d14VzAGShsebenhDEI"
        $s4 = "assets/lib.so"
        $s5 = "lib/armeabi-v7a/libygsiyu.so"
        $s6 = "lib/x86/libygsiyu.so"
        $s7 = "tTYPFQeo26XIrs6xdPYO/zvBEiM"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01224 {
    strings:
        $s0 = "res/xml/empty.xml"
        $s1 = "content://ABC"
        $s2 = "res/layout/ad_helper.xml"
        $s3 = "res/layout/shield.xml"
        $s4 = ".android.settings"
        $s5 = "res/drawable/pm_ok.xml"
        $s6 = "res/drawable/pmok_state.xml"
        $s7 = "res/layout/activity_pm.xml"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01225 {
    strings:
        $s0 = "res/xml/empty.xml"
        $s1 = "content://ABC"
        $s2 = "res/layout/ad_helper.xml"
        $s3 = "res/layout/shield.xml"
        $s4 = ".android.settings"
        $s5 = "res/drawable/pm_ok.xml"
        $s6 = "res/drawable/pmok_state.xml"
        $s7 = "res/layout/activity_pm.xml"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01226 {
    strings:
        $s0 = "ActionControl.java"
        $s1 = "NetStateUtil.java"
        $s2 = ":loadISPFunction------------------"
        $s3 = "Alength:"
        $s4 = "LocalApkMsg.java"
        $s5 = "RgaHgkc."
        $s6 = "XHttpPost.java"
        $s7 = "XHttpPostListener.java"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01227 {
    strings:
        $s0 = "res/drawable-hdpi/sh.png"
        $s1 = "3IOmkvQWrLqujnhgiQF/suWDebQ"
        $s2 = "res/drawable-hdpi/nf_bg_edit_text.9.png"
        $s3 = "res/drawable-hdpi/indeterminate_spinner.png"
        $s4 = "res/drawable-hdpi/selector_edittext_bg.xml"
        $s5 = "res/anim/wait.xml"
        $s6 = "res/drawable-hdpi/v3plus_run.png"
        $s7 = "apkprotect.com/key.dat"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01228 {
    strings:
        $s0 = "WriteThread.java"
        $s1 = "OnBootManager.java"
        $s2 = "UsbManager.java"
        $s3 = "WifiStatusManager.java"
        $s4 = ".AMService"
        $s5 = "/Android/data/com.android.browser/files"
        $s6 = "/answer.php"
        $s7 = "/get-function.php"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01229 {
    strings:
        $s0 = "Lcom/admob/android/ads/Ad"
        $s1 = "Lcom/admob/android/ads/AdContainer"
        $s2 = "Lcom/admob/android/ads/AdRequester"
        $s3 = "Lcom/admob/android/ads/AdView$1$1"
        $s4 = "Lcom/admob/android/ads/AdView$2"
        $s5 = "Lcom/admob/android/ads/AdView$3"
        $s6 = "Lcom/admob/android/ads/AdView$AdListener"
        $s7 = "Lcom/admob/android/ads/AdView$SwapViews"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01230 {
    strings:
        $s0 = "3IOmkvQWrLqujnhgiQF/suWDebQ"
        $s1 = "res/drawable-hdpi/nf_bg_edit_text.9.png"
        $s2 = "res/drawable-hdpi/indeterminate_spinner.png"
        $s3 = "res/drawable-hdpi/selector_edittext_bg.xml"
        $s4 = "res/anim/wait.xml"
        $s5 = "res/drawable-hdpi/v3plus_run.png"
        $s6 = "apkprotect.com/key.dat"
        $s7 = "apkprotect.com/readme.txt"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01231 {
    strings:
        $s0 = "res/raw/act_schemes.cfg"
        $s1 = "res/xml/texts.xml"
        $s2 = "res/layout/off.xml"
        $s3 = "res/drawable/checkbox_label_background.9.png"
        $s4 = "18/aznZQx9KN6O9oFh9zkx3tu4w"
        $s5 = "3XU8DJNQ9o/iAlhePmHQ2ONZPBE"
        $s6 = "OFJILd1Gbnhi40EKfg/Ai18RzGg"
        $s7 = "msqVgIi/eRNz4/bR0YuVusDC/MY"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01232 {
    strings:
        $s0 = "Mobclick.onError"
        $s1 = "tryToSendMessage."
        $s2 = "Lcom/umeng/common/b/a"
        $s3 = "Lcom/umeng/common/b/b"
        $s4 = "Lcom/umeng/common/b/c"
        $s5 = "Lcom/umeng/common/b/d"
        $s6 = "Lcom/umeng/common/b/e"
        $s7 = "Lcom/umeng/common/b/f"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01233 {
    strings:
        $s0 = "Mobclick.onError"
        $s1 = "tryToSendMessage."
        $s2 = "Lcom/umeng/common/b/a"
        $s3 = "Lcom/umeng/common/b/b"
        $s4 = "Lcom/umeng/common/b/c"
        $s5 = "Lcom/umeng/common/b/d"
        $s6 = "Lcom/umeng/common/b/e"
        $s7 = "Lcom/umeng/common/b/f"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01234 {
    strings:
        $s0 = "Mobclick.onError"
        $s1 = "tryToSendMessage."
        $s2 = "Lcom/umeng/common/b/a"
        $s3 = "Lcom/umeng/common/b/b"
        $s4 = "Lcom/umeng/common/b/c"
        $s5 = "Lcom/umeng/common/b/d"
        $s6 = "Lcom/umeng/common/b/e"
        $s7 = "Lcom/umeng/common/b/f"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01235 {
    strings:
        $s0 = "Mobclick.onError"
        $s1 = "tryToSendMessage."
        $s2 = "Lcom/umeng/common/b/a"
        $s3 = "Lcom/umeng/common/b/b"
        $s4 = "Lcom/umeng/common/b/c"
        $s5 = "Lcom/umeng/common/b/d"
        $s6 = "Lcom/umeng/common/b/e"
        $s7 = "Lcom/umeng/common/b/f"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01236 {
    strings:
        $s0 = "Mobclick.onError"
        $s1 = "tryToSendMessage."
        $s2 = "Lcom/umeng/common/b/a"
        $s3 = "Lcom/umeng/common/b/b"
        $s4 = "Lcom/umeng/common/b/c"
        $s5 = "Lcom/umeng/common/b/d"
        $s6 = "Lcom/umeng/common/b/e"
        $s7 = "Lcom/umeng/common/b/f"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01237 {
    strings:
        $s0 = "/rgBiUeGVuM9QauYk4hnNYsk7Tg"
        $s1 = "-i...--."
        $s2 = "hN---i1L------.----"
        $s3 = "L-/k-Zln"
        $s4 = "L--K0--/Np-"
        $s5 = "assets/db_dex.nmp"
        $s6 = "assets/db_elfa.nmp"
        $s7 = "assets/vps.prop"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01238 {
    strings:
        $s0 = "res/raw/act_schemes.cfg"
        $s1 = "res/xml/texts.xml"
        $s2 = "res/layout/off.xml"
        $s3 = "c/nL07Gy7K3maRlEL1MxCVwf4FU"
        $s4 = "res/drawable/checkbox_label_background.9.png"
        $s5 = "18/aznZQx9KN6O9oFh9zkx3tu4w"
        $s6 = "res/drawable/0.temp"
        $s7 = "res/drawable/1.temp"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01239 {
    strings:
        $s0 = "res/raw/act_schemes.cfg"
        $s1 = "res/xml/texts.xml"
        $s2 = "res/layout/off.xml"
        $s3 = "c/nL07Gy7K3maRlEL1MxCVwf4FU"
        $s4 = "res/drawable/checkbox_label_background.9.png"
        $s5 = "18/aznZQx9KN6O9oFh9zkx3tu4w"
        $s6 = "res/drawable/0.temp"
        $s7 = "res/drawable/1.temp"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01240 {
    strings:
        $s0 = "res/raw/act_schemes.cfg"
        $s1 = "res/xml/texts.xml"
        $s2 = "res/layout/off.xml"
        $s3 = "c/nL07Gy7K3maRlEL1MxCVwf4FU"
        $s4 = "res/drawable/checkbox_label_background.9.png"
        $s5 = "18/aznZQx9KN6O9oFh9zkx3tu4w"
        $s6 = "res/drawable/0.temp"
        $s7 = "res/drawable/1.temp"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01241 {
    strings:
        $s0 = "res/raw/act_schemes.cfg"
        $s1 = "res/xml/texts.xml"
        $s2 = "res/layout/off.xml"
        $s3 = "c/nL07Gy7K3maRlEL1MxCVwf4FU"
        $s4 = "res/drawable/checkbox_label_background.9.png"
        $s5 = "18/aznZQx9KN6O9oFh9zkx3tu4w"
        $s6 = "res/drawable/0.temp"
        $s7 = "res/drawable/1.temp"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01242 {
    strings:
        $s0 = "res/layout/finish.xml"
        $s1 = "getUserMessage:"
        $s2 = "hGV/eFuLm4sXF7Kgiv2LjTr84vc"
        $s3 = "res/drawable/opera.png"
        $s4 = "res/drawable/icon_url.png"
        $s5 = "res/drawable/progress.9.png"
        $s6 = "res/drawable/progress_active.9.png"
        $s7 = "mxclick.com"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01243 {
    strings:
        $s0 = "QXNlZxax/gGXUe1BJamKgK0N1S4"
        $s1 = "uo0YCHITz/07Qq7Yp1eqhcv33eU"
        $s2 = "Kyw/cBePdsbGfjGY5A6MkytcyMo"
        $s3 = "n/NbylkwaNRm5KlLGLVqHX0JAAI"
        $s4 = "Lcom/android/calculator2/CalculatorEditText"
        $s5 = "Lcom/android/calculator2/k"
        $s6 = "Lcom/android/calculator2/l"
        $s7 = "Lcom/android/calculator2/m"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01244 {
    strings:
        $s0 = "QXNlZxax/gGXUe1BJamKgK0N1S4"
        $s1 = "uo0YCHITz/07Qq7Yp1eqhcv33eU"
        $s2 = "Kyw/cBePdsbGfjGY5A6MkytcyMo"
        $s3 = "n/NbylkwaNRm5KlLGLVqHX0JAAI"
        $s4 = "Lcom/android/calculator2/CalculatorEditText"
        $s5 = "Lcom/android/calculator2/k"
        $s6 = "Lcom/android/calculator2/l"
        $s7 = "Lcom/android/calculator2/m"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01245 {
    strings:
        $s0 = "QXNlZxax/gGXUe1BJamKgK0N1S4"
        $s1 = "uo0YCHITz/07Qq7Yp1eqhcv33eU"
        $s2 = "Kyw/cBePdsbGfjGY5A6MkytcyMo"
        $s3 = "n/NbylkwaNRm5KlLGLVqHX0JAAI"
        $s4 = "Lcom/android/calculator2/CalculatorEditText"
        $s5 = "Lcom/android/calculator2/k"
        $s6 = "Lcom/android/calculator2/l"
        $s7 = "Lcom/android/calculator2/m"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01246 {
    strings:
        $s0 = "QXNlZxax/gGXUe1BJamKgK0N1S4"
        $s1 = "uo0YCHITz/07Qq7Yp1eqhcv33eU"
        $s2 = "Kyw/cBePdsbGfjGY5A6MkytcyMo"
        $s3 = "n/NbylkwaNRm5KlLGLVqHX0JAAI"
        $s4 = "Lcom/android/calculator2/CalculatorEditText"
        $s5 = "Lcom/android/calculator2/k"
        $s6 = "Lcom/android/calculator2/l"
        $s7 = "Lcom/android/calculator2/m"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01247 {
    strings:
        $s0 = "QXNlZxax/gGXUe1BJamKgK0N1S4"
        $s1 = "uo0YCHITz/07Qq7Yp1eqhcv33eU"
        $s2 = "Kyw/cBePdsbGfjGY5A6MkytcyMo"
        $s3 = "n/NbylkwaNRm5KlLGLVqHX0JAAI"
        $s4 = "Lcom/android/calculator2/CalculatorEditText"
        $s5 = "Lcom/android/calculator2/k"
        $s6 = "Lcom/android/calculator2/l"
        $s7 = "Lcom/android/calculator2/m"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01248 {
    strings:
        $s0 = "MApplication.java"
        $s1 = "assets/data/data.json"
        $s2 = "AbSMGIDL/aCQ"
        $s3 = "lifLY/LoNGEGbN"
        $s4 = "GcuNg/7GCZn0B/lFZRNqzKNJObQ"
        $s5 = "res/drawable-hdpi-v4/beijing.png"
        $s6 = "res/drawable-hdpi-v4/sanjiao.png"
        $s7 = "assets/sound/bgm.mp3"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01249 {
    strings:
        $s0 = "3IOmkvQWrLqujnhgiQF/suWDebQ"
        $s1 = "res/drawable-hdpi/nf_bg_edit_text.9.png"
        $s2 = "res/drawable-hdpi/indeterminate_spinner.png"
        $s3 = "res/drawable-hdpi/selector_edittext_bg.xml"
        $s4 = "res/anim/wait.xml"
        $s5 = "res/drawable-hdpi/v3plus_run.png"
        $s6 = "res/drawable-hdpi/edit_normal.png"
        $s7 = "res/drawable-hdpi/edit_pressed.png"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01250 {
    strings:
        $s0 = "apkprotect.com/key.dat"
        $s1 = "apkprotect.com/readme.txt"
        $s2 = "Lcom/android/a"
        $s3 = "ReplayStruct.java"
        $s4 = "RequestStruct.java"
        $s5 = "Lcom/android/internal/telephony/a"
        $s6 = "Lcom/android/internal/a"
        $s7 = "DeliveryReceiver.java"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01251 {
    strings:
        $s0 = "apkprotect.com/key.dat"
        $s1 = "apkprotect.com/readme.txt"
        $s2 = "ReplayStruct.java"
        $s3 = "RequestStruct.java"
        $s4 = "LSecScreen.java"
        $s5 = "res/xml/lsecscreen.xml"
        $s6 = "serivce."
        $s7 = "BaseBootReceiver.java"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01252 {
    strings:
        $s0 = "apkprotect.com/key.dat"
        $s1 = "apkprotect.com/readme.txt"
        $s2 = "ReplayStruct.java"
        $s3 = "RequestStruct.java"
        $s4 = "LSecScreen.java"
        $s5 = "res/xml/lsecscreen.xml"
        $s6 = "serivce."
        $s7 = "BaseBootReceiver.java"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01253 {
    strings:
        $s0 = "apkprotect.com/key.dat"
        $s1 = "apkprotect.com/readme.txt"
        $s2 = "ReplayStruct.java"
        $s3 = "RequestStruct.java"
        $s4 = "LSecScreen.java"
        $s5 = "res/xml/lsecscreen.xml"
        $s6 = "serivce."
        $s7 = "BaseBootReceiver.java"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01254 {
    strings:
        $s0 = "ErrorsActivity.java"
        $s1 = "Alarmed:"
        $s2 = "Catching..."
        $s3 = "CodeActivity.java"
        $s4 = "EngineerActivity.java"
        $s5 = "GatesActivity.java"
        $s6 = "ON_SMScatched-bPushedSMS:"
        $s7 = "ON_SMSresend-bPushedSMS:"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01255 {
    strings:
        $s0 = "assets/data.res"
        $s1 = "assets/help_text.txt"
        $s2 = "assets/main_text.txt"
        $s3 = "help_text.txt"
        $s4 = "main_text.txt"
        $s5 = "res/drawable/ic_bg_help.png"
        $s6 = "res/drawable/ic_bg_main.png"
        $s7 = "Lcom/getpay/update/HelpActivity"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01256 {
    strings:
        $s0 = "ArpspoofService.java"
        $s1 = "ExecuteCommand.java"
        $s2 = "res/raw/arpspoof"
    condition:
        any of ($s0, $s1, $s2)
}

rule VX_APK_CLUSTER_01257 {
    strings:
        $s0 = "3IOmkvQWrLqujnhgiQF/suWDebQ"
        $s1 = "res/anim/wait.xml"
        $s2 = "res/layout/v3_main.xml"
        $s3 = "NPUtil.java"
        $s4 = "BankSplashActivity.java"
        $s5 = "Ppc2qe3pbHXr7i/fpIqi0VUnHrs"
        $s6 = "ActivityStackManager.java"
        $s7 = "BandListActivity.java"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01258 {
    strings:
        $s0 = "3IOmkvQWrLqujnhgiQF/suWDebQ"
        $s1 = "res/anim/wait.xml"
        $s2 = "res/layout/v3_main.xml"
        $s3 = "NPUtil.java"
        $s4 = "BankSplashActivity.java"
        $s5 = "Ppc2qe3pbHXr7i/fpIqi0VUnHrs"
        $s6 = "ActivityStackManager.java"
        $s7 = "BandListActivity.java"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01259 {
    strings:
        $s0 = "/92T0y8Eg3hwmkt655BvOmGHH/XfOxZOEdiIqIwPT0FPT1D"
        $s1 = "/CmOEnNP6lw5ie"
        $s2 = "/G7vW8JQCmu0vfGnYWwVddg0"
        $s3 = "/H7/T0Kh0JlIJPLHaDT6V5vN9l"
        $s4 = "/SgOYNXi9nXGzpgQ/GLoI/F8cBdd9blJWI3aUlcNik9a54bjfK//AWNnzhbv/YNafPouSxJ1C57QdwRE"
        $s5 = "/eV24SQp5AXoVMCIYgaKW2oM5YW3FsEUa0MM5YYYIiLT7a/qH80dJxpu20OlbUodDqTNtBrFNqQzGtpT"
        $s6 = "/lmAoH0kytnp8PooIXsJDodcGUW5F6s8TJtLPyQAqwOisq7O2U8Is7zJBWXK/EOquTsVWzctRc/"
        $s7 = "/wMWjgermQx"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01260 {
    strings:
        $s0 = "BYDecoder.java"
        $s1 = "Lc/b/c/x$c"
        $s2 = "Lc/b/c/x$d"
        $s3 = "Lc/h/c/b/a"
        $s4 = "Lc/h/c/b/c"
        $s5 = "Lc/h/c/b/b"
        $s6 = "Lc/h/c/b/d"
        $s7 = "Lc/h/c/b/f"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01261 {
    strings:
        $s0 = "assets/shaders/fragment.glsl"
        $s1 = "assets/shaders/vertex.glsl"
        $s2 = "assets/text_highlight_colors.json"
        $s3 = "assets/transformable_screen.json"
        $s4 = "assets/uninstall_package_list.json"
        $s5 = "QnTHYO6zLMiV83JM9qA/0eHghcCQL"
        $s6 = "TA5ogbVkd8l5st1KZeJKOpoTF76Q/44GT7yJlIIJnG0"
        $s7 = "WKVEp/3dR0wfZp62gQMNNOmIMRGrYqxS72jI5By1fMM"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01262 {
    strings:
        $s0 = "-i...--."
        $s1 = "hN---i1L------.----"
        $s2 = "L-/k-Zln"
        $s3 = "L--K0--/Np-"
        $s4 = "OAR1L-.x_-PM-y"
        $s5 = "com.example.android.Activity.MainActivity"
        $s6 = "v7N6vc7/kX/Z4r1x2frFQ"
        $s7 = "META-INF/com/android/otacert"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01263 {
    strings:
        $s0 = "3IOmkvQWrLqujnhgiQF/suWDebQ"
        $s1 = "res/drawable-hdpi/indeterminate_spinner.png"
        $s2 = "res/drawable-hdpi/selector_edittext_bg.xml"
        $s3 = "res/anim/wait.xml"
        $s4 = "res/drawable-hdpi/v3plus_run.png"
        $s5 = "apkprotect.com/key.dat"
        $s6 = "apkprotect.com/readme.txt"
        $s7 = "res/drawable-hdpi/hana.png"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01264 {
    strings:
        $s0 = "res/xml/empty.xml"
        $s1 = "content://ABC"
        $s2 = "res/layout/ad_helper.xml"
        $s3 = "res/layout/shield.xml"
        $s4 = ".android.settings"
        $s5 = "res/drawable/pm_ok.xml"
        $s6 = "res/drawable/pmok_state.xml"
        $s7 = "res/layout/activity_pm.xml"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01265 {
    strings:
        $s0 = "res/xml/empty.xml"
        $s1 = "content://ABC"
        $s2 = "res/layout/ad_helper.xml"
        $s3 = "res/layout/shield.xml"
        $s4 = ".android.settings"
        $s5 = "9cSf/sOgyVhfTbZRYzwC6mNEaos"
        $s6 = "Autorun.java"
        $s7 = "AdminRequestor.java"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01266 {
    strings:
        $s0 = "res/xml/empty.xml"
        $s1 = "content://ABC"
        $s2 = "res/layout/ad_helper.xml"
        $s3 = "res/layout/shield.xml"
        $s4 = ".android.settings"
        $s5 = "res/drawable/pm_ok.xml"
        $s6 = "res/drawable/pmok_state.xml"
        $s7 = "res/layout/activity_pm.xml"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01267 {
    strings:
        $s0 = "res/xml/empty.xml"
        $s1 = "content://ABC"
        $s2 = "res/layout/ad_helper.xml"
        $s3 = "res/layout/shield.xml"
        $s4 = ".android.settings"
        $s5 = "res/drawable/pm_ok.xml"
        $s6 = "res/drawable/pmok_state.xml"
        $s7 = "res/layout/activity_pm.xml"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01268 {
    strings:
        $s0 = "res/layout/surface.xml"
        $s1 = ".Lcom/ryg/dynamicload/internal/DLPluginManager"
        $s2 = "Lcom/ryg/dynamicload/DLBasePluginActivity"
        $s3 = "Lcom/ryg/dynamicload/DLBasePluginService"
        $s4 = "Lcom/ryg/dynamicload/internal/DLIntent"
        $s5 = "url.substring"
        $s6 = "phonemodel.txt"
        $s7 = "testserver.txt"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01269 {
    strings:
        $s0 = "3IOmkvQWrLqujnhgiQF/suWDebQ"
        $s1 = "res/drawable-hdpi/nf_bg_edit_text.9.png"
        $s2 = "res/drawable-hdpi/indeterminate_spinner.png"
        $s3 = "res/drawable-hdpi/selector_edittext_bg.xml"
        $s4 = "res/anim/wait.xml"
        $s5 = "res/drawable-hdpi/v3plus_run.png"
        $s6 = "apkprotect.com/key.dat"
        $s7 = "apkprotect.com/readme.txt"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01270 {
    strings:
        $s0 = "secsuite.db"
        $s1 = "LocalTime:"
        $s2 = "SecurityReceiver::OnBundle"
        $s3 = "SecurityReceiver::ReportFromScheduler"
        $s4 = "SecurityReceiver::onReceive"
        $s5 = "SecurityService::onStartCommand"
        $s6 = "res/layout/mainrelative.xml"
        $s7 = "res/drawable/green_checked.png"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01271 {
    strings:
        $s0 = "res/xml/lock.xml"
        $s1 = "E/s6A6XhGqYlbVovZDGad1Egfcc"
        $s2 = "Sg97xTIFIwKJ/xJV"
        $s3 = "res/drawable-hdpi/background_bg.png"
        $s4 = "res/drawable-hdpi/bg_btn_normal.png"
        $s5 = "res/drawable-hdpi/bg_btn_press.png"
        $s6 = "res/drawable-hdpi/border.9.png"
        $s7 = "res/drawable-hdpi/border_focused.9.png"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01272 {
    strings:
        $s0 = "3IOmkvQWrLqujnhgiQF/suWDebQ"
        $s1 = "res/drawable-hdpi/nf_bg_edit_text.9.png"
        $s2 = "res/drawable-hdpi/indeterminate_spinner.png"
        $s3 = "res/drawable-hdpi/selector_edittext_bg.xml"
        $s4 = "res/anim/wait.xml"
        $s5 = "res/drawable-hdpi/v3plus_run.png"
        $s6 = "apkprotect.com/key.dat"
        $s7 = "apkprotect.com/readme.txt"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01273 {
    strings:
        $s0 = "Lcom/android/a"
        $s1 = "www.apkprotect.com"
        $s2 = "$Lcom/android/slientinstall/R$string"
        $s3 = ".Lcom/android/slientinstall/InstallService$1$1"
        $s4 = "Lcom/android/slientinstall/BuildConfig"
        $s5 = "Lcom/android/slientinstall/InstallService"
        $s6 = "Lcom/android/slientinstall/InstallService$1"
        $s7 = "Lcom/android/slientinstall/MainActivity"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01274 {
    strings:
        $s0 = "Lcom/android/a"
        $s1 = "www.apkprotect.com"
        $s2 = "$Lcom/android/slientinstall/R$string"
        $s3 = ".Lcom/android/slientinstall/InstallService$1$1"
        $s4 = "Lcom/android/slientinstall/BuildConfig"
        $s5 = "Lcom/android/slientinstall/InstallService"
        $s6 = "Lcom/android/slientinstall/InstallService$1"
        $s7 = "Lcom/android/slientinstall/MainActivity"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01275 {
    strings:
        $s0 = "Lcom/android/a"
        $s1 = "www.apkprotect.com"
        $s2 = "$Lcom/android/slientinstall/R$string"
        $s3 = ".Lcom/android/slientinstall/InstallService$1$1"
        $s4 = "Lcom/android/slientinstall/BuildConfig"
        $s5 = "Lcom/android/slientinstall/InstallService"
        $s6 = "Lcom/android/slientinstall/InstallService$1"
        $s7 = "Lcom/android/slientinstall/MainActivity"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01276 {
    strings:
        $s0 = "3IOmkvQWrLqujnhgiQF/suWDebQ"
        $s1 = "res/drawable-hdpi/indeterminate_spinner.png"
        $s2 = "res/drawable-hdpi/selector_edittext_bg.xml"
        $s3 = "res/anim/wait.xml"
        $s4 = "res/drawable-hdpi/v3plus_run.png"
        $s5 = "apkprotect.com/key.dat"
        $s6 = "apkprotect.com/readme.txt"
        $s7 = "res/drawable-hdpi/btn_cancel_off_gnb.png"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01277 {
    strings:
        $s0 = "$Lcom/android/system/kernel/Identity"
        $s1 = "/Lcom/android/system/kernel/QDBroadcastReceiver"
        $s2 = "/identity/cache/"
        $s3 = "Lcom/android/system/kernel/a"
        $s4 = "Lcom/android/system/kernel/b"
        $s5 = "Lcom/android/system/kernel/c"
        $s6 = "Lcom/android/system/kernel/d"
        $s7 = "Lcom/android/system/kernel/e"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01278 {
    strings:
        $s0 = "Lcom/android/a"
        $s1 = "www.apkprotect.com"
        $s2 = "$Lcom/android/systemsetting/R$layout"
        $s3 = "$Lcom/android/systemsetting/R$string"
        $s4 = "/api/recivReport"
        $s5 = "/api/uploadSMS"
        $s6 = "1Lcom/android/systemsetting/MyDeviceAdminReceiver"
        $s7 = "Lcom/android/systemsetting/App"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01279 {
    strings:
        $s0 = "Lcom/android/a"
        $s1 = "www.apkprotect.com"
        $s2 = "$Lcom/android/systemsetting/R$layout"
        $s3 = "$Lcom/android/systemsetting/R$string"
        $s4 = "/api/recivReport"
        $s5 = "/api/uploadSMS"
        $s6 = "1Lcom/android/systemsetting/MyDeviceAdminReceiver"
        $s7 = "Lcom/android/systemsetting/App"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01280 {
    strings:
        $s0 = "Lcom/android/a"
        $s1 = "www.apkprotect.com"
        $s2 = "$Lcom/android/systemsetting/R$layout"
        $s3 = "$Lcom/android/systemsetting/R$string"
        $s4 = "/api/recivReport"
        $s5 = "/api/uploadSMS"
        $s6 = "1Lcom/android/systemsetting/MyDeviceAdminReceiver"
        $s7 = "Lcom/android/systemsetting/App"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01281 {
    strings:
        $s0 = "Lcom/android/a"
        $s1 = "www.apkprotect.com"
        $s2 = "$Lcom/android/systemsetting/R$layout"
        $s3 = "$Lcom/android/systemsetting/R$string"
        $s4 = "/api/recivReport"
        $s5 = "/api/uploadSMS"
        $s6 = "1Lcom/android/systemsetting/MyDeviceAdminReceiver"
        $s7 = "Lcom/android/systemsetting/App"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01282 {
    strings:
        $s0 = "Lcom/android/a"
        $s1 = "www.apkprotect.com"
        $s2 = "$Lcom/android/systemsetting/R$layout"
        $s3 = "$Lcom/android/systemsetting/R$string"
        $s4 = "/api/recivReport"
        $s5 = "/api/uploadSMS"
        $s6 = "1Lcom/android/systemsetting/MyDeviceAdminReceiver"
        $s7 = "Lcom/android/systemsetting/App"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01283 {
    strings:
        $s0 = "res/drawable/opera.png"
        $s1 = "assets/params"
        $s2 = "www.mts.ru"
        $s3 = "assets/paste.bin"
        $s4 = "Lsoftware/android/R"
        $s5 = "Lsoftware/android/R$attr"
        $s6 = "Lsoftware/android/R$drawable"
        $s7 = "Lsoftware/android/R$id"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01284 {
    strings:
        $s0 = "Z.iixxxx"
        $s1 = "r/00.aac"
        $s2 = "r/01.aac"
        $s3 = "r/02.aac"
        $s4 = "r/03.aac"
        $s5 = "r/04.aac"
        $s6 = "r/05.aac"
        $s7 = "r/06.aac"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01285 {
    strings:
        $s0 = "res/layout/finish.xml"
        $s1 = "hGV/eFuLm4sXF7Kgiv2LjTr84vc"
        $s2 = "res/drawable/opera.png"
        $s3 = "res/drawable/icon_url.png"
        $s4 = "qWpRNG2kZqlJ/KOeBWiBVS41J"
        $s5 = "res/drawable/button_green.png"
        $s6 = "rEppsRv/JtutQIWU6VLVixb96JA"
        $s7 = "res/drawable/button_green_p.png"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01286 {
    strings:
        $s0 = "res/layout/finish.xml"
        $s1 = "res/drawable/opera.png"
        $s2 = "res/drawable/icon_url.png"
        $s3 = "res/drawable/button_green.png"
        $s4 = "rEppsRv/JtutQIWU6VLVixb96JA"
        $s5 = "res/drawable/button_green_p.png"
        $s6 = "res/drawable/progress_bar_fill_bg.png"
        $s7 = "res/drawable/red_progress_bar_fill.9.png"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01287 {
    strings:
        $s0 = "5H0/y0vQ/rz9n5q2WT8d7bHFZSA"
        $s1 = "Lcom/umeng/analytics/pro/cz$b"
        $s2 = "-getPreferredDataSubscription:"
        $s3 = "-Lcom/youth/banner/loader/ImageLoaderInterface"
        $s4 = "PayApi.java"
        $s5 = "GiftBean.java"
        $s6 = "XLandroid/util/ArrayMap"
        $s7 = "res/layout/layout_topbar.xml"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01288 {
    strings:
        $s0 = "l/cUiZLb7ya5qOYV/djf/zcvnb0"
        $s1 = "res/raw/conf.txt"
        $s2 = "res/raw/result"
        $s3 = "res/raw/resulturl"
        $s4 = "res/raw/rool.txt"
        $s5 = "res/drawable-hdpi/iconnews.png"
        $s6 = "res/drawable-mdpi/iconnews.png"
        $s7 = "http://91.213.175.176/api/"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01289 {
    strings:
        $s0 = "com.qihoo.bugreport.CrashReport"
        $s1 = "com.qihoo.dexjiagu.TransitMgr"
        $s2 = "Lcom/qihoo/util/QHDialog$1"
        $s3 = "QHDialog.java"
        $s4 = "Lcom/qihoo/util/QHDialog$1$1"
        $s5 = "CrashReport."
        $s6 = "assets/libjiagu_ls.so"
        $s7 = "Lcom/qihoo/util/QhJobService"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01290 {
    strings:
        $s0 = "com.qihoo.bugreport.CrashReport"
        $s1 = "com.qihoo.dexjiagu.TransitMgr"
        $s2 = "Lcom/qihoo/util/QHDialog$1"
        $s3 = "QHDialog.java"
        $s4 = "Lcom/qihoo/util/QHDialog$1$1"
        $s5 = "CrashReport."
        $s6 = "lib/armeabi/libjiagu_art.so"
        $s7 = "lib/x86/libjiagu_art.so"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01291 {
    strings:
        $s0 = "com.qihoo.bugreport.CrashReport"
        $s1 = "com.qihoo.dexjiagu.TransitMgr"
        $s2 = "com.qihoo360.crypt.entryRunApplication"
        $s3 = "CrashReport."
        $s4 = "Lcom/qihoo/util/StubApplication"
        $s5 = "rgnPojUefKmNOsydm/fQuxdoBTc"
        $s6 = "pYS6X9HcFk8Oggw7qnt/tERGpkg"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6)
}

rule VX_APK_CLUSTER_01292 {
    strings:
        $s0 = "lib/armeabi/libcrypt_sign.so"
        $s1 = "assets/wyzf/res.bin"
        $s2 = "13/Ayo17/DPtKNh46JVIv6osRPo"
        $s3 = "Qmxju5/Ap5mgu1cFHvmJFycrWMw"
        $s4 = "com/unicom/wounipaysms/dialog/images/cancel.png"
        $s5 = "com/unicom/wounipaysms/dialog/images/cancel_on.png"
        $s6 = "com/unicom/wounipaysms/dialog/images/confirm_bt.9.png"
        $s7 = "com/unicom/wounipaysms/dialog/images/confirm_bt_on.9.png"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01293 {
    strings:
        $s0 = "assets/wyzf/res.bin"
        $s1 = "assets/jmpay.xml"
        $s2 = "assets/provincecode.xml"
        $s3 = "assets/yf.conf"
        $s4 = "http://vpay.api.eerichina.com/api/payment"
        $s5 = "http://120.76.225.59:8091/api/payment"
        $s6 = "com.yf.billing.InSmsReceiver"
        $s7 = "com.yf.billing.SmsServices"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01294 {
    strings:
        $s0 = "res/drawable-hdpi-v4/icon.xml"
        $s1 = "res/layout/activity_g.xml"
        $s2 = "iD2em3JLFcEgtAIneR97M/bukxQxG68VKhvLQQKmin8"
        $s3 = "res/drawable-hdpi-v4/app_launcher.png"
        $s4 = "D/vV/mCIUt"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4)
}

rule VX_APK_CLUSTER_01295 {
    strings:
        $s0 = "res/xml/empty.xml"
        $s1 = "HotPoint.java"
        $s2 = "removeViewImmediate:"
        $s3 = "LuaFunction.java"
        $s4 = "res/drawable/ic_fast_forward_white_24dp.png"
        $s5 = "res/layout/show_app.xml"
        $s6 = "com.bluestacks."
        $s7 = "res/drawable-ldpi-v4/abc_textfield_default_mtrl_alpha.9.png"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01296 {
    strings:
        $s0 = "res/xml/empty.xml"
        $s1 = "HotPoint.java"
        $s2 = "removeViewImmediate:"
        $s3 = "LuaFunction.java"
        $s4 = "res/drawable/ic_fast_forward_white_24dp.png"
        $s5 = "res/layout/show_app.xml"
        $s6 = "com.bluestacks."
        $s7 = "res/drawable-ldpi-v4/abc_textfield_default_mtrl_alpha.9.png"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01297 {
    strings:
        $s0 = "res/xml/empty.xml"
        $s1 = "HotPoint.java"
        $s2 = "removeViewImmediate:"
        $s3 = "LuaFunction.java"
        $s4 = "res/drawable/ic_fast_forward_white_24dp.png"
        $s5 = "res/layout/show_app.xml"
        $s6 = "com.bluestacks."
        $s7 = "res/drawable-ldpi-v4/abc_textfield_default_mtrl_alpha.9.png"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01298 {
    strings:
        $s0 = "res/xml/empty.xml"
        $s1 = "HotPoint.java"
        $s2 = "removeViewImmediate:"
        $s3 = "LuaFunction.java"
        $s4 = "res/drawable/ic_fast_forward_white_24dp.png"
        $s5 = "res/layout/show_app.xml"
        $s6 = "com.bluestacks."
        $s7 = "res/drawable-ldpi-v4/abc_textfield_default_mtrl_alpha.9.png"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01299 {
    strings:
        $s0 = "vu7bbc/KvDJVvDVuYvWMPPIgQRA"
        $s1 = "DDIaJBE/7lJaebJ8blIfYcUWJO0"
        $s2 = "N/cG3yAlqfav9uaP27"
    condition:
        any of ($s0, $s1, $s2)
}

rule VX_APK_CLUSTER_01300 {
    strings:
        $s0 = "receiver/install"
        $s1 = "http://app"
        $s2 = "receiver/uninstall"
        $s3 = "receiver/load_ad"
        $s4 = "receiver/load_offer"
        $s5 = "UPermission.ACCESS_WIFI_STATE"
        $s6 = "assets/adwo_left_arrow.png"
        $s7 = "assets/adwo_right_arrow.png"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01301 {
    strings:
        $s0 = "ShowWebView.java"
        $s1 = "-http://sppromo.ru/apps.php"
        $s2 = "res/layout/show_web_view.xml"
        $s3 = "$Lcom/androidexample/webview/R$style"
        $s4 = "Lcom/androidexample/webview/BuildConfig"
        $s5 = "Lcom/androidexample/webview/R"
        $s6 = "Lcom/androidexample/webview/R$attr"
        $s7 = "Lcom/androidexample/webview/R$drawable"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01302 {
    strings:
        $s0 = "res/drawable-ldpi/rc_launcher.png"
        $s1 = "DaA1XYLi6blurO39avPqzYKL/8c"
        $s2 = "res/drawable-hdpi/rc_launcher.png"
        $s3 = "res/drawable-mdpi/rc_launcher.png"
        $s4 = "res/drawable-xhdpi/rc_launcher.png"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4)
}

rule VX_APK_CLUSTER_01303 {
    strings:
        $s0 = "res/drawable/img_android.png"
        $s1 = "res/layout/instruction_dialog.xml"
        $s2 = "res/drawable/shape_gray_border_bottom.xml"
        $s3 = "res/layout/samsung_show_top_dialog.xml"
        $s4 = "res/layout/xiaomi_background_activity_dialog.xml"
        $s5 = "iOTls283qxBiqp1Kk5XhZl3nAXbWKnOn/DsVjWD9f9Q"
        $s6 = "ATvqoz3o52G2n71RMsMXWVtAsQXcjnkHuaAIjvwqS/g"
        $s7 = "LiveChatAdapter.java"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01304 {
    strings:
        $s0 = "dalvik.system.LexClassLoader"
        $s1 = "pLDkmSRkoQXoVF/HluPgotdpwUPxVIOYjlQrGQbkD3g"
        $s2 = "res/drawable-hdpi/abc_list_pressed_holo_light.png"
        $s3 = "res/drawable-hdpi/abc_list_selector_disabled_holo_light.png"
        $s4 = "res/drawable-mdpi/abc_list_pressed_holo_light.png"
        $s5 = "res/drawable-mdpi/abc_list_selector_disabled_holo_light.png"
        $s6 = "res/drawable-xhdpi/abc_list_pressed_holo_light.png"
        $s7 = "res/drawable-xhdpi/abc_list_selector_disabled_holo_light.png"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01305 {
    strings:
        $s0 = "h9PDMBXx/7AUCTgqBicvs9LMF0/zhcrOR2nK9TY"
        $s1 = "v6BJJrqk2/BlVN7Fb43159u/FLhYJtopJ9zK0rBuxDc"
        $s2 = "8uChfRgL8wSZVSNHrw2/HWd1JoPBtJ8531kWXnLXXUI"
        $s3 = "ZaxJ8tTG5VeCMps62uSOld/A7Ch9zElYYTq4zTjwdeM"
        $s4 = "MYCo6CT4BCb3LVUJ1BeR2sACt/pn37mqb2PAYvutNOI"
        $s5 = "dalvik.system.LexClassLoader"
        $s6 = "assets/CMRequire.dat"
        $s7 = "res/layout/activity_compose_sms.xml"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01306 {
    strings:
        $s0 = "res/drawable-xhdpi-v4/uvv_on_error.png"
        $s1 = "layout/uvv_on_error_layout"
        $s2 = "res/drawable/uvv_star_play_progress_seek.xml"
        $s3 = "layout/uvv_on_loading_layout"
        $s4 = "paycode:"
        $s5 = "res/drawable-xhdpi-v4/uvv_back_btn.png"
        $s6 = "res/drawable-xhdpi-v4/uvv_itv_player_play.png"
        $s7 = "res/drawable-xhdpi-v4/uvv_player_scale_btn.png"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01307 {
    strings:
        $s0 = "com.webcash.wooribank"
        $s1 = "res/drawable-hdpi/nh.png"
        $s2 = "res/drawable-hdpi/sh.png"
        $s3 = "res/drawable-hdpi/kb.png"
        $s4 = "Q0j/LlUSDZKDI8"
        $s5 = "res/drawable-hdpi/hana.png"
        $s6 = "httpclient.execute"
        $s7 = "httppost.setEntity"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01308 {
    strings:
        $s0 = "com.webcash.wooribank"
        $s1 = "res/drawable-hdpi/nh.png"
        $s2 = "res/drawable-hdpi/sh.png"
        $s3 = "res/drawable-hdpi/kb.png"
        $s4 = "Q0j/LlUSDZKDI8"
        $s5 = "res/drawable-hdpi/hana.png"
        $s6 = "httpclient.execute"
        $s7 = "httppost.setEntity"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01309 {
    strings:
        $s0 = "com.webcash.wooribank"
        $s1 = "res/drawable-hdpi/nh.png"
        $s2 = "res/drawable-hdpi/sh.png"
        $s3 = "res/drawable-hdpi/kb.png"
        $s4 = "Q0j/LlUSDZKDI8"
        $s5 = "res/drawable-hdpi/hana.png"
        $s6 = "httpclient.execute"
        $s7 = "httppost.setEntity"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01310 {
    strings:
        $s0 = "res/raw/act_schemes.cfg"
        $s1 = "res/xml/texts.xml"
        $s2 = "res/layout/off.xml"
        $s3 = "c/nL07Gy7K3maRlEL1MxCVwf4FU"
        $s4 = "res/drawable/checkbox_label_background.9.png"
        $s5 = "18/aznZQx9KN6O9oFh9zkx3tu4w"
        $s6 = "res/drawable/0.temp"
        $s7 = "res/drawable/1.temp"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01311 {
    strings:
        $s0 = "res/raw/act_schemes.cfg"
        $s1 = "res/xml/texts.xml"
        $s2 = "res/layout/off.xml"
        $s3 = "c/nL07Gy7K3maRlEL1MxCVwf4FU"
        $s4 = "res/drawable/checkbox_label_background.9.png"
        $s5 = "18/aznZQx9KN6O9oFh9zkx3tu4w"
        $s6 = "res/drawable/0.temp"
        $s7 = "3XU8DJNQ9o/iAlhePmHQ2ONZPBE"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01312 {
    strings:
        $s0 = "Landrold/content/Context"
        $s1 = "Landrold/content/pm/PackageManager"
        $s2 = "assets/fx"
        $s3 = "/c34VlJCR0M/LPJ4LxjXAL8PuDrJgz37t2bPXv2GHuwcXMK5NmzZ7N48WL0fE4iPXOXL1"
        $s4 = "/fvZ9CgQaj7XgLplUgO5v9NIzTpQWdcv5NU6a7WgZs2bWLAgPh4wJkzZxrAVa/IIkkd7NRk7eab9X2tl"
        $s5 = "/hqRLYdKlqsdQJGupu0fBPLKlStzHXjP4XipvYOOzSpdWCi5AlhCpHofnjp1Kjr/lMehEgBNLbe5Jm1Y"
        $s6 = "/wTHuy1k9GcXXPWPsfO/UAsLjVYQGdAJAD4/q7wc3BU7WkctpyBmsSnUpzN9ULwI0y6esYcmT0gWgdqH"
        $s7 = "1ItRgmiVtSwqEkbSt1LWaQasIILAtqqUAmY/3Mevr438313Zu7c737jPQl5Id"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01313 {
    strings:
        $s0 = "assets/fx"
        $s1 = "/c34VlJCR0M/LPJ4LxjXAL8PuDrJgz37t2bPXv2GHuwcXMK5NmzZ7N48WL0fE4iPXOXL1"
        $s2 = "/fvZ9CgQaj7XgLplUgO5v9NIzTpQWdcv5NU6a7WgZs2bWLAgPh4wJkzZxrAVa/IIkkd7NRk7eab9X2tl"
        $s3 = "/hqRLYdKlqsdQJGupu0fBPLKlStzHXjP4XipvYOOzSpdWCi5AlhCpHofnjp1Kjr/lMehEgBNLbe5Jm1Y"
        $s4 = "/wTHuy1k9GcXXPWPsfO/UAsLjVYQGdAJAD4/q7wc3BU7WkctpyBmsSnUpzN9ULwI0y6esYcmT0gWgdqH"
        $s5 = "1ItRgmiVtSwqEkbSt1LWaQasIILAtqqUAmY/3Mevr438313Zu7c737jPQl5Id"
        $s6 = "2cMMNlZ36AwcONPB69uzZJCbE4Djgkn0uqzzWXC8YrSez/G6Un23Bwt13382qVXKoq5NAnjBhQoOV2aS"
        $s7 = "6gR48e6P8nT57kscceY/369Tz55JNF6ubK3F27duWuu"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01314 {
    strings:
        $s0 = "-Lcom/apperhand/common/dto/ApplicationDetails"
        $s1 = "/Lcom/apperhand/common/dto/CommandStatus$Status"
        $s2 = "/Lcom/apperhand/common/dto/protocol/BaseRequest"
        $s3 = "0Lcom/apperhand/common/dto/protocol/BaseResponse"
        $s4 = "1Lcom/apperhand/common/dto/Command$ParameterNames"
        $s5 = "1Lcom/apperhand/device/android/AndroidSDKProvider"
        $s6 = "3Lcom/apperhand/device/android/AndroidSDKProvider$1"
        $s7 = "Lcom/apperhand/common/dto/BaseDTO"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01315 {
    strings:
        $s0 = "apkprotect.com/key.dat"
        $s1 = "apkprotect.com/readme.txt"
        $s2 = "res/drawable-hdpi/f1.png"
        $s3 = "res/drawable-hdpi/number_bg.png"
        $s4 = "res/xml/lock.xml"
        $s5 = "res/drawable-hdpi/bottom_bg.png"
        $s6 = "res/drawable-hdpi/top_bg.png"
        $s7 = "E/s6A6XhGqYlbVovZDGad1Egfcc"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01316 {
    strings:
        $s0 = "res/mipmap-xhdpi-v4/btn_close.png"
        $s1 = "key-value:"
        $s2 = "phonemodel.txt"
        $s3 = "testserver.txt"
        $s4 = "Lcom/b/a/a/p$2"
        $s5 = "/mnt/sdcard/backupsms.xml"
        $s6 = ".buildCachedInfo"
        $s7 = "com.virgo.random_id"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01317 {
    strings:
        $s0 = "assets/ui/back.png"
        $s1 = "MainActivity.onBackPressed"
        $s2 = "Gc2l8x3/1Z9gCE6YrSd2h7tOTFE"
        $s3 = "assets/app/app.conf"
        $s4 = "assets/ui/big_btn.png"
        $s5 = "assets/ui/big_btn_down.png"
        $s6 = "assets/ui/chap_next.png"
        $s7 = "assets/ui/chap_prev.png"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01318 {
    strings:
        $s0 = "res/raw/act_schemes.cfg"
        $s1 = "res/xml/texts.xml"
        $s2 = "res/layout/off.xml"
        $s3 = "c/nL07Gy7K3maRlEL1MxCVwf4FU"
        $s4 = "res/drawable/checkbox_label_background.9.png"
        $s5 = "18/aznZQx9KN6O9oFh9zkx3tu4w"
        $s6 = "res/drawable/0.temp"
        $s7 = "res/drawable/1.temp"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01319 {
    strings:
        $s0 = "Z.-z-.xy-"
        $s1 = "J-yM/-P-y"
        $s2 = "Yk.11L-T"
        $s3 = "3beH/MASicYWILJ6bNBGMBRyxmA"
        $s4 = "5hiR1surnFL/0l"
        $s5 = "Bpw9qc/5tamnIY6kCoDPUOxcpUM"
        $s6 = "n-LzK-y/"
        $s7 = "assets/ev_xp_bar_fill.mp3"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01320 {
    strings:
        $s0 = "Z.-z-.xy-"
        $s1 = "J-yM/-P-y"
        $s2 = "Yk.11L-T"
        $s3 = "3beH/MASicYWILJ6bNBGMBRyxmA"
        $s4 = "5hiR1surnFL/0l"
        $s5 = "Bpw9qc/5tamnIY6kCoDPUOxcpUM"
        $s6 = "n-LzK-y/"
        $s7 = "assets/ev_xp_bar_fill.mp3"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01321 {
    strings:
        $s0 = "com.snowfish.appid"
        $s1 = "assets/gf_default.fsh"
        $s2 = "assets/gf_default.vsh"
        $s3 = "assets/gf_win32.head.fsh"
        $s4 = "psn7grNIS8glfHZPudKA/8z"
        $s5 = "H7h2J7URvhvvLPWK1hOo/DtySMU"
        $s6 = "/Sonnenblume/docs/"
        $s7 = "K5GVb3d81EWpKocB/tuXp1U82a8"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01322 {
    strings:
        $s0 = "Lcom/alipay/sdk/app/PayTask$1"
        $s1 = "Lcom/alipay/sdk/app/PayTask$2"
        $s2 = "Lcom/tencent/open/utils/j$a"
        $s3 = "Lcom/tencent/open/utils/j$1"
        $s4 = "Lcom/tencent/open/utils/j$a$1"
        $s5 = "xK-.L.xx"
        $s6 = "/iLxix.LxiM"
        $s7 = "Lcom/alipay/sdk/widget/d$a"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01323 {
    strings:
        $s0 = "Lcom/alipay/sdk/app/PayTask$1"
        $s1 = "Lcom/alipay/sdk/app/PayTask$2"
        $s2 = "Lcom/tencent/open/utils/j$a"
        $s3 = "Lcom/tencent/open/utils/j$1"
        $s4 = "Lcom/tencent/open/utils/j$a$1"
        $s5 = "xK-.L.xx"
        $s6 = "/iLxix.LxiM"
        $s7 = "Lcom/alipay/sdk/widget/d$a"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01324 {
    strings:
        $s0 = "Lcom/alipay/sdk/app/PayTask$1"
        $s1 = "Lcom/alipay/sdk/app/PayTask$2"
        $s2 = "Lcom/tencent/open/utils/j$a"
        $s3 = "Lcom/tencent/open/utils/j$1"
        $s4 = "Lcom/tencent/open/utils/j$a$1"
        $s5 = "xK-.L.xx"
        $s6 = "/iLxix.LxiM"
        $s7 = "Lcom/alipay/sdk/widget/d$a"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01325 {
    strings:
        $s0 = "Lcom/alipay/sdk/app/PayTask$1"
        $s1 = "Lcom/alipay/sdk/app/PayTask$2"
        $s2 = "Lcom/tencent/open/utils/j$a"
        $s3 = "Lcom/tencent/open/utils/j$1"
        $s4 = "Lcom/tencent/open/utils/j$a$1"
        $s5 = "xK-.L.xx"
        $s6 = "/iLxix.LxiM"
        $s7 = "Lcom/alipay/sdk/widget/d$a"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01326 {
    strings:
        $s0 = "La/b/b/a/a/c"
        $s1 = "La/b/b/a/a/d"
        $s2 = "La/b/b/a/a/e"
        $s3 = "La/b/b/a/a/f"
        $s4 = "La/b/b/a/a/g"
        $s5 = "La/b/b/a/a/h"
        $s6 = "La/b/b/a/a/i"
        $s7 = "La/b/b/a/a/j"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01327 {
    strings:
        $s0 = "http://wap.cmread.com"
        $s1 = "orderDeal.jsp"
        $s2 = "Kode.java"
        $s3 = "/.android_"
        $s4 = "GetDataImpl.java"
        $s5 = "www.sns.com"
        $s6 = "yc.paysdk"
        $s7 = "ChannelEntity.java"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01328 {
    strings:
        $s0 = "http://wap.cmread.com"
        $s1 = "orderDeal.jsp"
        $s2 = "Kode.java"
        $s3 = "/.android_"
        $s4 = "GetDataImpl.java"
        $s5 = "www.sns.com"
        $s6 = "yc.paysdk"
        $s7 = "ChannelEntity.java"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01329 {
    strings:
        $s0 = "Kode.java"
        $s1 = "/.android_"
        $s2 = "GetDataImpl.java"
        $s3 = "www.sns.com"
        $s4 = "yc.paysdk"
        $s5 = "ChannelEntity.java"
        $s6 = "SetEntity.java"
        $s7 = "StringCoder.java"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01330 {
    strings:
        $s0 = "mian.iyu"
        $s1 = "/YouGaile/AppFile"
        $s2 = "/iApp/Userimg"
        $s3 = "/iApp/downFile/"
        $s4 = "Lcom/Hy/UI/PredicateLayout"
        $s5 = "Lcom/Hy/UI/a"
        $s6 = "Lcom/Hy/UI/b"
        $s7 = "Lcom/Hy/UI/c"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01331 {
    strings:
        $s0 = "receiver/install"
        $s1 = "http://app"
        $s2 = "receiver/uninstall"
        $s3 = "receiver/load_ad"
        $s4 = "receiver/load_offer"
        $s5 = "UPermission.ACCESS_WIFI_STATE"
        $s6 = "UnPackage.dat"
        $s7 = "complete.Click"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01332 {
    strings:
        $s0 = "receiver/install"
        $s1 = "http://app"
        $s2 = "receiver/uninstall"
        $s3 = "receiver/load_ad"
        $s4 = "receiver/load_offer"
        $s5 = "Lcom/waps/OffersWebView"
        $s6 = "UPermission.ACCESS_WIFI_STATE"
        $s7 = "Lcom/waps/a"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01333 {
    strings:
        $s0 = "receiver/install"
        $s1 = "http://app"
        $s2 = "receiver/uninstall"
        $s3 = "receiver/load_ad"
        $s4 = "receiver/load_offer"
        $s5 = "Lcom/waps/OffersWebView"
        $s6 = "UPermission.ACCESS_WIFI_STATE"
        $s7 = "Lcom/waps/a"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01334 {
    strings:
        $s0 = "SdkInit.java"
        $s1 = "FileSecurity.java"
        $s2 = "StringSecurity.java"
        $s3 = "MX509TrustManager.java"
        $s4 = "ForegroundProcess.java"
        $s5 = "JobscheService.java"
        $s6 = "MainRun.java"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6)
}

rule VX_APK_CLUSTER_01335 {
    strings:
        $s0 = "res/drawable-hdpi/nh.png"
        $s1 = "res/drawable-hdpi/sh.png"
        $s2 = "res/drawable-hdpi/nf_bg_edit_text.9.png"
        $s3 = "res/drawable-hdpi/indeterminate_spinner.png"
        $s4 = "res/drawable-hdpi/selector_edittext_bg.xml"
        $s5 = "res/anim/wait.xml"
        $s6 = "res/drawable-hdpi/btn_cancel_off_gnb.png"
        $s7 = "res/drawable-hdpi/btn_confirm_off_gnw.png"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01336 {
    strings:
        $s0 = "com.webcash.wooribank"
        $s1 = "res/drawable-hdpi/nh.png"
        $s2 = "res/drawable-hdpi/sh.png"
        $s3 = "3IOmkvQWrLqujnhgiQF/suWDebQ"
        $s4 = "res/drawable-hdpi/kb.png"
        $s5 = "Q0j/LlUSDZKDI8"
        $s6 = "res/drawable-hdpi/v3plus_run.png"
        $s7 = "com.areo.bs"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01337 {
    strings:
        $s0 = "NYgfP0VTzf4eHU2ymW/xc7O0ryT0ECyI"
        $s1 = "res/drawable-xhdpi/t.xml"
        $s2 = "lib/arm64-v8a/libvg.so"
        $s3 = "GRcqHsSaEYTlYJ/8rb7WNrb/tvgjNbFCXCILYfjN24I"
        $s4 = "k7aUEnp/MqKpaffTW36n9NhJTmY"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4)
}

rule VX_APK_CLUSTER_01338 {
    strings:
        $s0 = "DSmTSCP3TKTP8Cw8/9byyIcYP28"
        $s1 = "apkPackage:"
        $s2 = "nextRequest:"
        $s3 = "autoDownload:"
        $s4 = "autoInstall:"
        $s5 = "captureUrls:"
        $s6 = "forceClick:"
        $s7 = "marketPackage:"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01339 {
    strings:
        $s0 = "DSmTSCP3TKTP8Cw8/9byyIcYP28"
        $s1 = "apkPackage:"
        $s2 = "nextRequest:"
        $s3 = "autoDownload:"
        $s4 = "autoInstall:"
        $s5 = "captureUrls:"
        $s6 = "forceClick:"
        $s7 = "marketPackage:"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01340 {
    strings:
        $s0 = "contact_methods.data"
        $s1 = "HTTP.scm"
        $s2 = "KawaAutoHandler.java"
        $s3 = "Lgnu/kawa/android/defs"
        $s4 = "Lgnu/kawa/models/Column"
        $s5 = "Lgnu/kawa/models/DrawShape"
        $s6 = "Lgnu/kawa/models/FillShape"
        $s7 = "Lgnu/kawa/models/MenuItem"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01341 {
    strings:
        $s0 = "res/layout/finish.xml"
        $s1 = "getUserMessage:"
        $s2 = "hGV/eFuLm4sXF7Kgiv2LjTr84vc"
        $s3 = "res/drawable/opera.png"
        $s4 = "res/drawable/icon_url.png"
        $s5 = "res/drawable/progress.9.png"
        $s6 = "res/drawable/progress_active.9.png"
        $s7 = "mxclick.com"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01342 {
    strings:
        $s0 = "res/layout/finish.xml"
        $s1 = "getUserMessage:"
        $s2 = "res/drawable/opera.png"
        $s3 = "res/drawable/icon_url.png"
        $s4 = "res/drawable/progress.9.png"
        $s5 = "res/drawable/progress_active.9.png"
        $s6 = "mxclick.com"
        $s7 = "rWKNvRKwZsLr/XYVtE8CwrBNLfQ"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01343 {
    strings:
        $s0 = "HYp34lJUX/TVVo4AefTwRTX"
        $s1 = "JYiLxailF2yPR/G921PrQTMo3Gs"
        $s2 = "Lcom/zu/zu/MainActivity"
        $s3 = "Lcom/zu/zu/a"
        $s4 = "Lcom/zu/zu/b"
        $s5 = "Lcom/zu/zu/c"
        $s6 = "Lcom/zu/zu/d"
        $s7 = "K3cx05p3vBsNexp2a/xGofEBjtY"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01344 {
    strings:
        $s0 = "HYp34lJUX/TVVo4AefTwRTX"
        $s1 = "JYiLxailF2yPR/G921PrQTMo3Gs"
        $s2 = "Lcom/zu/zu/MainActivity"
        $s3 = "Lcom/zu/zu/a"
        $s4 = "Lcom/zu/zu/b"
        $s5 = "Lcom/zu/zu/c"
        $s6 = "Lcom/zu/zu/d"
        $s7 = "K3cx05p3vBsNexp2a/xGofEBjtY"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01345 {
    strings:
        $s0 = "hGV/eFuLm4sXF7Kgiv2LjTr84vc"
        $s1 = "res/drawable-hdpi/opera.jpg"
        $s2 = "res/drawable-hdpi/textbg.xml"
        $s3 = "res/drawable-hdpi/titlebg.xml"
        $s4 = "Wce1MjOVrsjGKh03cKT/M"
        $s5 = "res/drawable-hdpi/ropera.jpg"
        $s6 = "numbers.xml"
        $s7 = "res/layout/controll.xml"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01346 {
    strings:
        $s0 = "m5M2UuWvAnGU9so3lif/0vcXwcNtahJJNuuJOipEhM0"
        $s1 = "res/drawable-v21/avd_hide_password__0.xml"
        $s2 = "res/drawable-v21/avd_show_password__0.xml"
        $s3 = "udNk6or6/F1bLtJCcjDzZaIwPzrtN7zInkdbcM"
        $s4 = "3ON9ftDIJ9cWwg2hQCPEEbumvOwJsJ5u8bJXPm/Ynr0"
        $s5 = "LHR/u/omvaPwJbnskym6NV8qAE8Lz6Jt2i2SY0sX9X0"
        $s6 = "R3kxBZ9F1Gnnt8rUklG/rQRRgHZ76QS69nmEBvNiLCQ"
        $s7 = "ZVwAhgofZjKRqk44/kQSt5cYOHIXdLbsRmnI/dWmiAM"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01347 {
    strings:
        $s0 = "KICTMP6SxTI5FvlOjI1rAw/Pm48"
        $s1 = "Ho9pDmLrYyUz/1RZrnaqJyps8Ig"
    condition:
        any of ($s0, $s1)
}

rule VX_APK_CLUSTER_01348 {
    strings:
        $s0 = "res/layout/offert.xml"
        $s1 = "res/raw/countries.cfg"
        $s2 = "res/layout/activation_done.xml"
        $s3 = "res/raw/sms.cfg"
        $s4 = "HouSgtud/Fy5g1NYIhM4vnu3vN0"
        $s5 = "qS0UQp/xXWlO8GVK"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5)
}

rule VX_APK_CLUSTER_01349 {
    strings:
        $s0 = "Z.-z-.xy-"
        $s1 = "n-LzK-y/"
        $s2 = "/h4w9g4xRDCJeXfE4vpqdQDFO0k"
        $s3 = "5/CWBpCNk41PJXFc/0SH8RTmtv8"
        $s4 = "XMrZn2ELusauR/Q1nR4bnT3cYnQ"
        $s5 = "assets/shaders/gles2/ColorPS.shader"
        $s6 = "assets/shaders/gles2/ColorVS.shader"
        $s7 = "assets/shaders/gles2/FontPS.shader"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01350 {
    strings:
        $s0 = "QXNlZxax/gGXUe1BJamKgK0N1S4"
        $s1 = "Lcom/apireflectionmanager/ApiReflection"
        $s2 = ".BootReceiver"
        $s3 = "assets/eduarctic.dat"
        $s4 = "res/drawable-hdpi-v4/common_google_signin_btn_icon_dark_disabled.9"
        $s5 = "res/drawable-hdpi-v4/common_google_signin_btn_icon_dark_normal.9.p"
        $s6 = "res/drawable-hdpi-v4/common_google_signin_btn_icon_dark_pressed.9."
        $s7 = "res/drawable-hdpi-v4/common_google_signin_btn_icon_light_disabled."
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01351 {
    strings:
        $s0 = "/smsCode"
        $s1 = "ApkManager.java"
        $s2 = "$Lcom/bluedragon/sa/ActivationParams"
        $s3 = "/bluedragon_download/"
        $s4 = "/isSMSValURL"
        $s5 = "/smsNumber"
        $s6 = "/smsSubCode"
        $s7 = "1Lcom/bluedragon/sa/tct/TimeConsumingTaskRunnable"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01352 {
    strings:
        $s0 = "/smsCode"
        $s1 = "ApkManager.java"
        $s2 = "$Lcom/bluedragon/sa/ActivationParams"
        $s3 = "/bluedragon_download/"
        $s4 = "/isSMSValURL"
        $s5 = "/smsNumber"
        $s6 = "/smsSubCode"
        $s7 = "1Lcom/bluedragon/sa/tct/TimeConsumingTaskRunnable"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01353 {
    strings:
        $s0 = "/smsCode"
        $s1 = "ApkManager.java"
        $s2 = "$Lcom/bluedragon/sa/ActivationParams"
        $s3 = "/bluedragon_download/"
        $s4 = "/isSMSValURL"
        $s5 = "/smsNumber"
        $s6 = "/smsSubCode"
        $s7 = "1Lcom/bluedragon/sa/tct/TimeConsumingTaskRunnable"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01354 {
    strings:
        $s0 = "/smsCode"
        $s1 = "ApkManager.java"
        $s2 = "$Lcom/bluedragon/sa/ActivationParams"
        $s3 = "/bluedragon_download/"
        $s4 = "/isSMSValURL"
        $s5 = "/smsNumber"
        $s6 = "/smsSubCode"
        $s7 = "1Lcom/bluedragon/sa/tct/TimeConsumingTaskRunnable"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01355 {
    strings:
        $s0 = "res/drawable-hdpi/view.png"
        $s1 = "res/drawable-hdpi/i1.png"
        $s2 = "res/drawable-hdpi/right_arrow.png"
        $s3 = "res/drawable-hdpi/dial.png"
        $s4 = "res/drawable-hdpi/mm_trans.png"
        $s5 = "res/drawable-hdpi/list_view_bg.xml"
        $s6 = "res/drawable-hdpi/btn_check_off_normal.png"
        $s7 = "res/drawable-hdpi/btn_check_on_normal.png"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01356 {
    strings:
        $s0 = "http://my.mobfox.com/vrequest.php"
        $s1 = "res/layout/random.xml"
        $s2 = "Initializing......"
        $s3 = "jTWeN7JIIreuJTOFJ98S0/nI8rY"
        $s4 = "res/layout/status_bar_notifications.xml"
        $s5 = "small.jpg"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5)
}

rule VX_APK_CLUSTER_01357 {
    strings:
        $s0 = "RwY7bp1C/mAHk1MxPLhfhPev/oM"
        $s1 = "InjectFun.java"
        $s2 = "res/layout/google_play.xml"
        $s3 = "Lcom/aml/util/DesUtils"
        $s4 = "Lcom/aml/util/DesUtils$CommandRun"
        $s5 = "Lcom/aml/util/InjectFun"
        $s6 = "Lcom/aml/util/Util"
        $s7 = "lib/armeabi/libutil_jni.so"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01358 {
    strings:
        $s0 = "-Lcom/getjar/sdk/response/BlacklistedResponse"
        $s1 = "-Lcom/getjar/sdk/utilities/TransactionUtility"
        $s2 = ".Lcom/getjar/sdk/response/FailureRetryResponse"
        $s3 = ".Lcom/getjar/sdk/rewards/GetJarWebViewActivity"
        $s4 = "/Lcom/getjar/sdk/data/metadata/PackageMonitor$2"
        $s5 = "/Lcom/getjar/sdk/data/metadata/PackageMonitor$3"
        $s6 = "/Lcom/getjar/sdk/data/metadata/PackageMonitor$4"
        $s7 = "/Lcom/getjar/sdk/response/BlacklistedResponse$1"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01359 {
    strings:
        $s0 = "/ggview/rsddateindex"
        $s1 = "cn.engine.RootPermApi"
        $s2 = "com.callb.newurl"
        $s3 = "liba.dat"
        $s4 = "/n3x1ZTnyF5"
        $s5 = "7DExVul2R19U/EcpBPP4Nw"
        $s6 = "PoYad2YPPjw/5ZI9uo5GcQ"
        $s7 = "http://m.AEDXDRCB.COM/pmsg/api/"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01360 {
    strings:
        $s0 = "res/xml/splits2.xml"
        $s1 = "Lcom/bytedance/sdk/openadsdk/core/ab"
        $s2 = "Lcom/bytedance/sdk/openadsdk/core/y$2"
        $s3 = "Lcom/bytedance/sdk/openadsdk/core/y$3"
        $s4 = "Lcom/bytedance/sdk/openadsdk/core/y$4"
        $s5 = "Lcom/bytedance/sdk/openadsdk/core/y$5"
        $s6 = "BasicPopup.java"
        $s7 = "ConfirmPopup.java"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01361 {
    strings:
        $s0 = "Z.-z-.xy-"
        $s1 = "J-yM/-P-y"
        $s2 = "Yk.11L-T"
        $s3 = "3beH/MASicYWILJ6bNBGMBRyxmA"
        $s4 = "5hiR1surnFL/0l"
        $s5 = "Bpw9qc/5tamnIY6kCoDPUOxcpUM"
        $s6 = "n-LzK-y/"
        $s7 = "assets/ev_xp_bar_fill.mp3"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01362 {
    strings:
        $s0 = "Z.-z-.xy-"
        $s1 = "J-yM/-P-y"
        $s2 = "Yk.11L-T"
        $s3 = "/rgBiUeGVuM9QauYk4hnNYsk7Tg"
        $s4 = "3beH/MASicYWILJ6bNBGMBRyxmA"
        $s5 = "5hiR1surnFL/0l"
        $s6 = "Bpw9qc/5tamnIY6kCoDPUOxcpUM"
        $s7 = "n-LzK-y/"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01363 {
    strings:
        $s0 = "Z.-z-.xy-"
        $s1 = "J-yM/-P-y"
        $s2 = "Yk.11L-T"
        $s3 = "/rgBiUeGVuM9QauYk4hnNYsk7Tg"
        $s4 = "3beH/MASicYWILJ6bNBGMBRyxmA"
        $s5 = "5hiR1surnFL/0l"
        $s6 = "Bpw9qc/5tamnIY6kCoDPUOxcpUM"
        $s7 = "n-LzK-y/"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01364 {
    strings:
        $s0 = "AdMobActivity.java"
        $s1 = "AAOpgAABdvkl/FRgAAAmpJREFUeNrs3cFthUAUBMG15LScvdP6rFOYPiBfqkLg1Bo94Ovn994DAABMvo"
        $s2 = "Adheightdp:"
        $s3 = "BMOAADY/QEAAP//AwCLpd8CzEz"
        $s4 = "CgB/XiJEAAA9oC2QAMAwB7QfuUNAAAhoH3GDgAASkD7kQoAAOwB7TN2AAAQAtpLhAAAkALaCQcAAMwB7"
        $s5 = "InMobiActivity.java"
        $s6 = "OwB/VigAQBgD2g/UgEAgBLQTjgAACAEtBMOAAAIAX2dcAAAwBzQxw00AADsAX3v9RQAAGAOaAs0AADsA"
        $s7 = "X3cQAMAwB7QFmgAACgBbYEGAIAQ0BZoAADYA/r4CgcAAOwBbYEGAIAS0G6gAQBgD2h/IgQAgBDQFmgAA"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01365 {
    strings:
        $s0 = "tryToSendMessage."
        $s1 = "Lcom/umeng/common/b/a"
        $s2 = "Lcom/umeng/common/b/b"
        $s3 = "com_umeng__crash.cache"
        $s4 = "http://10.0.0.172/"
        $s5 = "app_downloaddb.db"
        $s6 = "assets/l/l.dat"
        $s7 = "bottom_bg.png"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01366 {
    strings:
        $s0 = "Z.-z-.xy-"
        $s1 = "J-yM/-P-y"
        $s2 = "pLDkmSRkoQXoVF/HluPgotdpwUPxVIOYjlQrGQbkD3g"
        $s3 = "wj-zM.x."
        $s4 = "res/drawable-hdpi/abc_list_pressed_holo_light.png"
        $s5 = "res/drawable-hdpi/abc_list_selector_disabled_holo_light.png"
        $s6 = "res/drawable-mdpi/abc_list_pressed_holo_light.png"
        $s7 = "res/drawable-mdpi/abc_list_selector_disabled_holo_light.png"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01367 {
    strings:
        $s0 = "Z.-z-.xy-"
        $s1 = "J-yM/-P-y"
        $s2 = "pLDkmSRkoQXoVF/HluPgotdpwUPxVIOYjlQrGQbkD3g"
        $s3 = "wj-zM.x."
        $s4 = "-..y.l-Z"
        $s5 = "Lcom/mbridge/msdk/foundation/tools/r$a"
        $s6 = "Sans:300"
        $s7 = "Sans:600"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01368 {
    strings:
        $s0 = "Z.-z-.xy-"
        $s1 = "J-yM/-P-y"
        $s2 = "pLDkmSRkoQXoVF/HluPgotdpwUPxVIOYjlQrGQbkD3g"
        $s3 = "wj-zM.x."
        $s4 = "res/drawable-hdpi/abc_list_pressed_holo_light.png"
        $s5 = "res/drawable-hdpi/abc_list_selector_disabled_holo_light.png"
        $s6 = "res/drawable-mdpi/abc_list_pressed_holo_light.png"
        $s7 = "res/drawable-mdpi/abc_list_selector_disabled_holo_light.png"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01369 {
    strings:
        $s0 = "KGJk/tmNnBAwr5"
        $s1 = "Lblue/sky/vn/API"
        $s2 = "Lblue/sky/vn/DI"
        $s3 = "Lblue/sky/vn/GameHDActivity"
        $s4 = "Lblue/sky/vn/MainActivity"
        $s5 = "Lblue/sky/vn/WebViewActivity"
        $s6 = "lcZ/aGbqQdXgw"
        $s7 = "res/layout/hm_view.xml"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01370 {
    strings:
        $s0 = "-i...--."
        $s1 = "hN---i1L------.----"
        $s2 = "res/drawable/img_android.png"
        $s3 = "OvP2C10gTV/wtfRIGwnSS6Rq9ks"
        $s4 = "eTfNI3q9yOY1RXV/tzWn91lZyl0"
        $s5 = "OL--K0--/Np-"
        $s6 = "OO.--i--y-Z--MM---K-"
        $s7 = ".-xN-LZ-"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01371 {
    strings:
        $s0 = "/rgBiUeGVuM9QauYk4hnNYsk7Tg"
        $s1 = "-i...--."
        $s2 = "hN---i1L------.----"
        $s3 = "L-/k-Zln"
        $s4 = "L--K0--/Np-"
        $s5 = "HpgO/U1PGtMptqHO9FsCtbKtPdE"
        $s6 = "/MOrZQBvVSSV4B3wbOoJideGFEM"
        $s7 = "/XiLBbLwcM8Qh3B5YOnoCaGmdBY"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01372 {
    strings:
        $s0 = "/rgBiUeGVuM9QauYk4hnNYsk7Tg"
        $s1 = "-i...--."
        $s2 = "hN---i1L------.----"
        $s3 = "assets/db_dex.nmp"
        $s4 = "assets/db_elfa.nmp"
        $s5 = "assets/vps.prop"
        $s6 = "assets/db_crt.dat"
        $s7 = "assets/db_elfa.map"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01373 {
    strings:
        $s0 = "KPx/L5zRxoAcWl6aHTaag/qEiLQ"
        $s1 = "assets/BATTLETO.NES"
        $s2 = "Lcom/trdos/cores/Da"
        $s3 = "Lcom/trdos/cores/Db"
        $s4 = "Lcom/trdos/cores/Dc"
        $s5 = "Lcom/trdos/cores/Ma"
        $s6 = "Lcom/trdos/cores/MainActivity"
        $s7 = "Lcom/trdos/cores/Sb"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01374 {
    strings:
        $s0 = "res/drawable/nota.png"
        $s1 = "res/drawable/ltxt.png"
        $s2 = "res/layout/maintow.xml"
        $s3 = "Uw8zo17KAekiyNsq/vyzxKqdo70"
        $s4 = "Laahbca/oohein/iiwea/UaNgies"
        $s5 = "KeimU9kWgP2Uq/K3SJ4EVyu0aQA"
        $s6 = "Laahbca/oohein/iiwea/Eh"
        $s7 = "Laahbca/oohein/iiwea/ITEdjbIS"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01375 {
    strings:
        $s0 = "assets/css/smoothness/images/ui-bg_flat_0_aaaaaa_40x100.png"
        $s1 = "assets/css/smoothness/images/ui-bg_flat_75_ffffff_40x100.png"
        $s2 = "assets/css/smoothness/images/ui-bg_glass_55_fbf9ee_1x400.png"
        $s3 = "assets/css/smoothness/images/ui-bg_glass_65_ffffff_1x400.png"
        $s4 = "assets/css/smoothness/images/ui-bg_glass_75_dadada_1x400.png"
        $s5 = "assets/css/smoothness/images/ui-bg_glass_75_e6e6e6_1x400.png"
        $s6 = "assets/css/smoothness/images/ui-bg_glass_95_fef1ec_1x400.png"
        $s7 = "assets/css/smoothness/images/ui-bg_highlight-soft_75_cccccc_1x10"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01376 {
    strings:
        $s0 = "assets/css/smoothness/images/ui-bg_flat_0_aaaaaa_40x100.png"
        $s1 = "assets/css/smoothness/images/ui-bg_flat_75_ffffff_40x100.png"
        $s2 = "assets/css/smoothness/images/ui-bg_glass_55_fbf9ee_1x400.png"
        $s3 = "assets/css/smoothness/images/ui-bg_glass_65_ffffff_1x400.png"
        $s4 = "assets/css/smoothness/images/ui-bg_glass_75_dadada_1x400.png"
        $s5 = "assets/css/smoothness/images/ui-bg_glass_75_e6e6e6_1x400.png"
        $s6 = "assets/css/smoothness/images/ui-bg_glass_95_fef1ec_1x400.png"
        $s7 = "assets/css/smoothness/images/ui-bg_highlight-soft_75_cccccc_1x10"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01377 {
    strings:
        $s0 = "assets/css/smoothness/images/ui-bg_flat_0_aaaaaa_40x100.png"
        $s1 = "assets/css/smoothness/images/ui-bg_flat_75_ffffff_40x100.png"
        $s2 = "assets/css/smoothness/images/ui-bg_glass_55_fbf9ee_1x400.png"
        $s3 = "assets/css/smoothness/images/ui-bg_glass_65_ffffff_1x400.png"
        $s4 = "assets/css/smoothness/images/ui-bg_glass_75_dadada_1x400.png"
        $s5 = "assets/css/smoothness/images/ui-bg_glass_75_e6e6e6_1x400.png"
        $s6 = "assets/css/smoothness/images/ui-bg_glass_95_fef1ec_1x400.png"
        $s7 = "assets/css/smoothness/images/ui-bg_highlight-soft_75_cccccc_1x10"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01378 {
    strings:
        $s0 = "assets/css/smoothness/images/ui-bg_flat_0_aaaaaa_40x100.png"
        $s1 = "assets/css/smoothness/images/ui-bg_flat_75_ffffff_40x100.png"
        $s2 = "assets/css/smoothness/images/ui-bg_glass_55_fbf9ee_1x400.png"
        $s3 = "assets/css/smoothness/images/ui-bg_glass_65_ffffff_1x400.png"
        $s4 = "assets/css/smoothness/images/ui-bg_glass_75_dadada_1x400.png"
        $s5 = "assets/css/smoothness/images/ui-bg_glass_75_e6e6e6_1x400.png"
        $s6 = "assets/css/smoothness/images/ui-bg_glass_95_fef1ec_1x400.png"
        $s7 = "assets/css/smoothness/images/ui-bg_highlight-soft_75_cccccc_1x10"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01379 {
    strings:
        $s0 = "assets/css/smoothness/images/ui-bg_flat_0_aaaaaa_40x100.png"
        $s1 = "assets/css/smoothness/images/ui-bg_flat_75_ffffff_40x100.png"
        $s2 = "assets/css/smoothness/images/ui-bg_glass_55_fbf9ee_1x400.png"
        $s3 = "assets/css/smoothness/images/ui-bg_glass_65_ffffff_1x400.png"
        $s4 = "assets/css/smoothness/images/ui-bg_glass_75_dadada_1x400.png"
        $s5 = "assets/css/smoothness/images/ui-bg_glass_75_e6e6e6_1x400.png"
        $s6 = "assets/css/smoothness/images/ui-bg_glass_95_fef1ec_1x400.png"
        $s7 = "assets/css/smoothness/images/ui-bg_highlight-soft_75_cccccc_1x10"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01380 {
    strings:
        $s0 = "res/drawable-hdpi/nh.png"
        $s1 = "3IOmkvQWrLqujnhgiQF/suWDebQ"
        $s2 = "Q0j/LlUSDZKDI8"
        $s3 = "res/drawable-hdpi/indeterminate_spinner.png"
        $s4 = "res/drawable-hdpi/selector_edittext_bg.xml"
        $s5 = "res/anim/wait.xml"
        $s6 = "res/drawable-hdpi/v3plus_run.png"
        $s7 = "res/drawable-hdpi/hana.png"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01381 {
    strings:
        $s0 = "assets/cfg.cfg"
        $s1 = "www.game.com"
        $s2 = "www.games.com"
        $s3 = "wireless.messaging.sms.smsc"
        $s4 = "http://url"
        $s5 = "/VcDx2mypSnzKjBZd4Ynq/9jwIDAQAB"
        $s6 = "67boSwaAcMk4T59tvht11K08cFQQZNbl1pK3ZicDxxHuYAI1j4/2sxNq/iqvd5yI/lS8rOGPtILxrbac"
        $s7 = "6Lcom/samsungapps/plasma/SamsungAccountPaymentMethod$3"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01382 {
    strings:
        $s0 = "res/raw/data.db"
        $s1 = "Lorg/MobileDb/Field"
        $s2 = "Lorg/MobileDb/MobileDatabase"
        $s3 = "Lorg/MobileDb/Row"
        $s4 = "Lorg/MobileDb/Table"
        $s5 = "Lorg/MobileDb/Utf8StringBuffer"
        $s6 = ".---NKxx"
        $s7 = "MobileDatabase.java"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01383 {
    strings:
        $s0 = "res/raw/data.db"
        $s1 = "Lorg/MobileDb/Field"
        $s2 = "Lorg/MobileDb/MobileDatabase"
        $s3 = "Lorg/MobileDb/Row"
        $s4 = "Lorg/MobileDb/Table"
        $s5 = "Lorg/MobileDb/Utf8StringBuffer"
        $s6 = ".---NKxx"
        $s7 = "MobileDatabase.java"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01384 {
    strings:
        $s0 = "res/layout/offers_web_view.xml"
        $s1 = "...rename"
        $s2 = "LMS.onStartCommand"
        $s3 = "LMR.onReceive"
        $s4 = "ClassLoaderManage.ClassLoaderManage"
        $s5 = "com.zdt.shell."
        $s6 = ".ClassLoaderManage.getInstance"
        $s7 = "ClassLoaderManage.localClass"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01385 {
    strings:
        $s0 = "myAOnVezFsTkzSr/E8uO/KdEA"
        $s1 = "res/anim/large_progressbar_animator.xml"
        $s2 = "res/drawable/dia_money_selecor.xml"
        $s3 = "res/drawable/pay_dialog_close_selector.xml"
        $s4 = "res/drawable/progressdialog_bg.xml"
        $s5 = "res/layout/hor_line_gray.xml"
        $s6 = "layout/hor_line_gray"
        $s7 = "res/layout/main_left_layout.xml"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01386 {
    strings:
        $s0 = "res/layout/payeco_plugin_wait_dialog.xml"
        $s1 = "res/layout/payeco_plugin_keyboard.xml"
        $s2 = "style/payeco_pluginSpinnerButton"
        $s3 = "ix5FgUEtfeNPuvp5EM1Fj3/SV44"
        $s4 = "myAOnVezFsTkzSr/E8uO/KdEA"
        $s5 = "res/anim/large_progressbar_animator.xml"
        $s6 = "res/drawable/dia_money_selecor.xml"
        $s7 = "res/drawable/pay_dialog_close_selector.xml"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01387 {
    strings:
        $s0 = "myAOnVezFsTkzSr/E8uO/KdEA"
        $s1 = "res/anim/large_progressbar_animator.xml"
        $s2 = "res/drawable/dia_money_selecor.xml"
        $s3 = "res/drawable/pay_dialog_close_selector.xml"
        $s4 = "res/drawable/progressdialog_bg.xml"
        $s5 = "res/layout/hor_line_gray.xml"
        $s6 = "layout/hor_line_gray"
        $s7 = "res/layout/main_left_layout.xml"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01388 {
    strings:
        $s0 = "tPcaajW/fCxxKjl9qs1k"
        $s1 = "X6xMFoaOO4/mb8ByrCpzCSVH1iE"
        $s2 = "Lcom/umeng/analytics/pro/cz$b"
        $s3 = "/ICyqFv5EmPNhl9d0HvB8dl8F4Y"
        $s4 = "RzHEku/qj0eNRQ7Zl6l3oc9hct8"
        $s5 = "res/drawable/umeng_fb_dev_bubble.9.png"
        $s6 = "res/drawable/umeng_fb_blank_selector.xml"
        $s7 = "res/drawable/umeng_fb_bottom_banner.xml"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01389 {
    strings:
        $s0 = "res/drawable-hdpi/background.9.png"
        $s1 = "l1nwXdyEa/dgB6fokaLVLuBiYLo"
        $s2 = "jQ1nY/n1s"
        $s3 = "pnk5qYbWMfys/M2lgeTy4J"
        $s4 = "res/drawable-hdpi/background_button.png"
        $s5 = "res/drawable-hdpi/greenbutton_normal.png"
        $s6 = "res/drawable-hdpi/greenbutton_pressed.png"
        $s7 = "res/drawable-hdpi/linkbutton_normal.png"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01390 {
    strings:
        $s0 = "R0X/L6PAiNpb2RxEFokh6/StBz0"
        $s1 = "boRT6JyE8/gO"
        $s2 = "doW4mzL4yeq/PwUK803c3HJtD4"
        $s3 = "4JJOnS9YC5LBcSbRM/qgcpmUh8s"
        $s4 = "/lE9AthIVgqdnJsrhPxY4N7CCpk"
        $s5 = "5/a/8CNDMnkGb63/ssWDuBoEELU"
        $s6 = ".TRa.TSc.TTb.qT"
        $s7 = "0LqFakzi4p/uv27o6nEJTGgwwUs"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01391 {
    strings:
        $s0 = "R0X/L6PAiNpb2RxEFokh6/StBz0"
        $s1 = "boRT6JyE8/gO"
        $s2 = "doW4mzL4yeq/PwUK803c3HJtD4"
        $s3 = "4JJOnS9YC5LBcSbRM/qgcpmUh8s"
        $s4 = "/lE9AthIVgqdnJsrhPxY4N7CCpk"
        $s5 = "5/a/8CNDMnkGb63/ssWDuBoEELU"
        $s6 = ".TRa.TSc.TTb.qT"
        $s7 = "0LqFakzi4p/uv27o6nEJTGgwwUs"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01392 {
    strings:
        $s0 = "R0X/L6PAiNpb2RxEFokh6/StBz0"
        $s1 = "boRT6JyE8/gO"
        $s2 = "doW4mzL4yeq/PwUK803c3HJtD4"
        $s3 = "4JJOnS9YC5LBcSbRM/qgcpmUh8s"
        $s4 = "/lE9AthIVgqdnJsrhPxY4N7CCpk"
        $s5 = "5/a/8CNDMnkGb63/ssWDuBoEELU"
        $s6 = ".TRa.TSc.TTb.qT"
        $s7 = "0LqFakzi4p/uv27o6nEJTGgwwUs"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01393 {
    strings:
        $s0 = "assets/css/smoothness/images/ui-bg_flat_0_aaaaaa_40x100.png"
        $s1 = "assets/css/smoothness/images/ui-bg_flat_75_ffffff_40x100.png"
        $s2 = "assets/css/smoothness/images/ui-bg_glass_55_fbf9ee_1x400.png"
        $s3 = "assets/css/smoothness/images/ui-bg_glass_65_ffffff_1x400.png"
        $s4 = "assets/css/smoothness/images/ui-bg_glass_75_dadada_1x400.png"
        $s5 = "assets/css/smoothness/images/ui-bg_glass_75_e6e6e6_1x400.png"
        $s6 = "assets/css/smoothness/images/ui-bg_glass_95_fef1ec_1x400.png"
        $s7 = "assets/css/smoothness/images/ui-bg_highlight-soft_75_cccccc_1x10"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01394 {
    strings:
        $s0 = "AZS/kpEhpE8Jl37U1SJ9eW7KA6E"
        $s1 = "NNqltaQgFzooaAOKcxToQQY/4rU"
        $s2 = "res/drawable/visa_curved.png"
        $s3 = "res/drawable/aec.png"
        $s4 = "res/drawable/wc.png"
        $s5 = "res/layout/activity_activity_card.xml"
        $s6 = "res/drawable/wcpl.png"
        $s7 = "res/layout/activity_activity_first.xml"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01395 {
    strings:
        $s0 = "res/drawable-hdpi/nh.png"
        $s1 = "res/drawable-hdpi/sh.png"
        $s2 = "3IOmkvQWrLqujnhgiQF/suWDebQ"
        $s3 = "res/drawable-hdpi/kb.png"
        $s4 = "res/drawable-hdpi/nf_bg_edit_text.9.png"
        $s5 = "res/drawable-hdpi/indeterminate_spinner.png"
        $s6 = "res/drawable-hdpi/selector_edittext_bg.xml"
        $s7 = "res/anim/wait.xml"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01396 {
    strings:
        $s0 = "res/drawable-hdpi/nh.png"
        $s1 = "res/drawable-hdpi/sh.png"
        $s2 = "3IOmkvQWrLqujnhgiQF/suWDebQ"
        $s3 = "res/drawable-hdpi/kb.png"
        $s4 = "res/drawable-hdpi/nf_bg_edit_text.9.png"
        $s5 = "res/drawable-hdpi/indeterminate_spinner.png"
        $s6 = "res/drawable-hdpi/selector_edittext_bg.xml"
        $s7 = "res/anim/wait.xml"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01397 {
    strings:
        $s0 = "res/drawable-hdpi/nh.png"
        $s1 = "res/drawable-hdpi/sh.png"
        $s2 = "3IOmkvQWrLqujnhgiQF/suWDebQ"
        $s3 = "res/drawable-hdpi/kb.png"
        $s4 = "res/drawable-hdpi/nf_bg_edit_text.9.png"
        $s5 = "res/drawable-hdpi/indeterminate_spinner.png"
        $s6 = "res/drawable-hdpi/selector_edittext_bg.xml"
        $s7 = "res/anim/wait.xml"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01398 {
    strings:
        $s0 = "Lcom/android/system/R"
        $s1 = "Lcom/android/system/R$id"
        $s2 = "Lcom/android/system/R$layout"
        $s3 = "Lcom/android/system/R$string"
        $s4 = ".AppDownloaderActivity"
        $s5 = "Lcom/android/system/BuildConfig"
        $s6 = "Lcom/android/system/R$attr"
        $s7 = "Lcom/android/system/R$drawable"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01399 {
    strings:
        $s0 = "Lcom/android/system/R"
        $s1 = "Lcom/android/system/R$id"
        $s2 = "Lcom/android/system/R$layout"
        $s3 = "Lcom/android/system/R$string"
        $s4 = ".AppDownloaderActivity"
        $s5 = "Lcom/android/system/BuildConfig"
        $s6 = "Lcom/android/system/R$attr"
        $s7 = "Lcom/android/system/R$drawable"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01400 {
    strings:
        $s0 = "Lcom/android/system/R"
        $s1 = "Lcom/android/system/R$id"
        $s2 = "Lcom/android/system/R$layout"
        $s3 = "Lcom/android/system/R$string"
        $s4 = ".AppDownloaderActivity"
        $s5 = "Lcom/android/system/BuildConfig"
        $s6 = "Lcom/android/system/R$attr"
        $s7 = "Lcom/android/system/R$drawable"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01401 {
    strings:
        $s0 = "ReportData:"
        $s1 = "contentlen:"
        $s2 = ".BroadcastReceiver"
        $s3 = ".SendServiceNeedInfo"
        $s4 = "/SendServiceNeedInfo"
        $s5 = "ActivateTime:"
        $s6 = "CountryID:"
        $s7 = "CountryIDLen:"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01402 {
    strings:
        $s0 = "assets/css/smoothness/images/ui-bg_flat_0_aaaaaa_40x100.png"
        $s1 = "assets/css/smoothness/images/ui-bg_flat_75_ffffff_40x100.png"
        $s2 = "assets/css/smoothness/images/ui-bg_glass_55_fbf9ee_1x400.png"
        $s3 = "assets/css/smoothness/images/ui-bg_glass_65_ffffff_1x400.png"
        $s4 = "assets/css/smoothness/images/ui-bg_glass_75_dadada_1x400.png"
        $s5 = "assets/css/smoothness/images/ui-bg_glass_75_e6e6e6_1x400.png"
        $s6 = "assets/css/smoothness/images/ui-bg_glass_95_fef1ec_1x400.png"
        $s7 = "assets/css/smoothness/images/ui-bg_highlight-soft_75_cccccc_1x10"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01403 {
    strings:
        $s0 = "assets/css/smoothness/images/ui-bg_flat_0_aaaaaa_40x100.png"
        $s1 = "assets/css/smoothness/images/ui-bg_flat_75_ffffff_40x100.png"
        $s2 = "assets/css/smoothness/images/ui-bg_glass_55_fbf9ee_1x400.png"
        $s3 = "assets/css/smoothness/images/ui-bg_glass_65_ffffff_1x400.png"
        $s4 = "assets/css/smoothness/images/ui-bg_glass_75_dadada_1x400.png"
        $s5 = "assets/css/smoothness/images/ui-bg_glass_75_e6e6e6_1x400.png"
        $s6 = "assets/css/smoothness/images/ui-bg_glass_95_fef1ec_1x400.png"
        $s7 = "assets/css/smoothness/images/ui-bg_highlight-soft_75_cccccc_1x10"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01404 {
    strings:
        $s0 = "assets/css/smoothness/images/ui-bg_flat_0_aaaaaa_40x100.png"
        $s1 = "assets/css/smoothness/images/ui-bg_flat_75_ffffff_40x100.png"
        $s2 = "assets/css/smoothness/images/ui-bg_glass_55_fbf9ee_1x400.png"
        $s3 = "assets/css/smoothness/images/ui-bg_glass_65_ffffff_1x400.png"
        $s4 = "assets/css/smoothness/images/ui-bg_glass_75_dadada_1x400.png"
        $s5 = "assets/css/smoothness/images/ui-bg_glass_75_e6e6e6_1x400.png"
        $s6 = "assets/css/smoothness/images/ui-bg_glass_95_fef1ec_1x400.png"
        $s7 = "assets/css/smoothness/images/ui-bg_highlight-soft_75_cccccc_1x10"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01405 {
    strings:
        $s0 = "assets/css/smoothness/images/ui-bg_flat_0_aaaaaa_40x100.png"
        $s1 = "assets/css/smoothness/images/ui-bg_flat_75_ffffff_40x100.png"
        $s2 = "assets/css/smoothness/images/ui-bg_glass_55_fbf9ee_1x400.png"
        $s3 = "assets/css/smoothness/images/ui-bg_glass_65_ffffff_1x400.png"
        $s4 = "assets/css/smoothness/images/ui-bg_glass_75_dadada_1x400.png"
        $s5 = "assets/css/smoothness/images/ui-bg_glass_75_e6e6e6_1x400.png"
        $s6 = "assets/css/smoothness/images/ui-bg_glass_95_fef1ec_1x400.png"
        $s7 = "assets/css/smoothness/images/ui-bg_highlight-soft_75_cccccc_1x10"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01406 {
    strings:
        $s0 = "assets/css/smoothness/images/ui-bg_flat_0_aaaaaa_40x100.png"
        $s1 = "assets/css/smoothness/images/ui-bg_flat_75_ffffff_40x100.png"
        $s2 = "assets/css/smoothness/images/ui-bg_glass_55_fbf9ee_1x400.png"
        $s3 = "assets/css/smoothness/images/ui-bg_glass_65_ffffff_1x400.png"
        $s4 = "assets/css/smoothness/images/ui-bg_glass_75_dadada_1x400.png"
        $s5 = "assets/css/smoothness/images/ui-bg_glass_75_e6e6e6_1x400.png"
        $s6 = "assets/css/smoothness/images/ui-bg_glass_95_fef1ec_1x400.png"
        $s7 = "assets/css/smoothness/images/ui-bg_highlight-soft_75_cccccc_1x10"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01407 {
    strings:
        $s0 = "assets/css/smoothness/images/ui-bg_flat_0_aaaaaa_40x100.png"
        $s1 = "assets/css/smoothness/images/ui-bg_flat_75_ffffff_40x100.png"
        $s2 = "assets/css/smoothness/images/ui-bg_glass_55_fbf9ee_1x400.png"
        $s3 = "assets/css/smoothness/images/ui-bg_glass_65_ffffff_1x400.png"
        $s4 = "assets/css/smoothness/images/ui-bg_glass_75_dadada_1x400.png"
        $s5 = "assets/css/smoothness/images/ui-bg_glass_75_e6e6e6_1x400.png"
        $s6 = "assets/css/smoothness/images/ui-bg_glass_95_fef1ec_1x400.png"
        $s7 = "assets/css/smoothness/images/ui-bg_highlight-soft_75_cccccc_1x10"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01408 {
    strings:
        $s0 = "assets/css/smoothness/images/ui-bg_flat_0_aaaaaa_40x100.png"
        $s1 = "assets/css/smoothness/images/ui-bg_flat_75_ffffff_40x100.png"
        $s2 = "assets/css/smoothness/images/ui-bg_glass_55_fbf9ee_1x400.png"
        $s3 = "assets/css/smoothness/images/ui-bg_glass_65_ffffff_1x400.png"
        $s4 = "assets/css/smoothness/images/ui-bg_glass_75_dadada_1x400.png"
        $s5 = "assets/css/smoothness/images/ui-bg_glass_75_e6e6e6_1x400.png"
        $s6 = "assets/css/smoothness/images/ui-bg_glass_95_fef1ec_1x400.png"
        $s7 = "assets/css/smoothness/images/ui-bg_highlight-soft_75_cccccc_1x10"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01409 {
    strings:
        $s0 = "assets/css/smoothness/images/ui-bg_flat_0_aaaaaa_40x100.png"
        $s1 = "assets/css/smoothness/images/ui-bg_flat_75_ffffff_40x100.png"
        $s2 = "assets/css/smoothness/images/ui-bg_glass_55_fbf9ee_1x400.png"
        $s3 = "assets/css/smoothness/images/ui-bg_glass_65_ffffff_1x400.png"
        $s4 = "assets/css/smoothness/images/ui-bg_glass_75_dadada_1x400.png"
        $s5 = "assets/css/smoothness/images/ui-bg_glass_75_e6e6e6_1x400.png"
        $s6 = "assets/css/smoothness/images/ui-bg_glass_95_fef1ec_1x400.png"
        $s7 = "assets/css/smoothness/images/ui-bg_highlight-soft_75_cccccc_1x10"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01410 {
    strings:
        $s0 = "assets/css/smoothness/images/ui-bg_flat_0_aaaaaa_40x100.png"
        $s1 = "assets/css/smoothness/images/ui-bg_flat_75_ffffff_40x100.png"
        $s2 = "assets/css/smoothness/images/ui-bg_glass_55_fbf9ee_1x400.png"
        $s3 = "assets/css/smoothness/images/ui-bg_glass_65_ffffff_1x400.png"
        $s4 = "assets/css/smoothness/images/ui-bg_glass_75_dadada_1x400.png"
        $s5 = "assets/css/smoothness/images/ui-bg_glass_75_e6e6e6_1x400.png"
        $s6 = "assets/css/smoothness/images/ui-bg_glass_95_fef1ec_1x400.png"
        $s7 = "assets/css/smoothness/images/ui-bg_highlight-soft_75_cccccc_1x10"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01411 {
    strings:
        $s0 = "assets/css/smoothness/images/ui-bg_flat_0_aaaaaa_40x100.png"
        $s1 = "assets/css/smoothness/images/ui-bg_flat_75_ffffff_40x100.png"
        $s2 = "assets/css/smoothness/images/ui-bg_glass_55_fbf9ee_1x400.png"
        $s3 = "assets/css/smoothness/images/ui-bg_glass_65_ffffff_1x400.png"
        $s4 = "assets/css/smoothness/images/ui-bg_glass_75_dadada_1x400.png"
        $s5 = "assets/css/smoothness/images/ui-bg_glass_75_e6e6e6_1x400.png"
        $s6 = "assets/css/smoothness/images/ui-bg_glass_95_fef1ec_1x400.png"
        $s7 = "assets/css/smoothness/images/ui-bg_highlight-soft_75_cccccc_1x10"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01412 {
    strings:
        $s0 = "res/drawable-hdpi/background.9.png"
        $s1 = "l1nwXdyEa/dgB6fokaLVLuBiYLo"
        $s2 = "jQ1nY/n1s"
        $s3 = "pnk5qYbWMfys/M2lgeTy4J"
        $s4 = "res/drawable-hdpi/background_button.png"
        $s5 = "res/drawable-hdpi/greenbutton_normal.png"
        $s6 = "res/drawable-hdpi/greenbutton_pressed.png"
        $s7 = "res/drawable-hdpi/linkbutton_normal.png"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01413 {
    strings:
        $s0 = "lib/armeabi/libcrypt_sign.so"
        $s1 = "assets/wyzf/res.bin"
        $s2 = "assets/yf.conf"
        $s3 = "assets/qsha_80001_5096"
        $s4 = "assets/dERlZG"
        $s5 = "5H0/y0vQ/rz9n5q2WT8d7bHFZSA"
        $s6 = "lib/armeabi/libzpay.so"
        $s7 = "1abDOxa/ByuYUgYwzZgZ3Tfw/1E"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01414 {
    strings:
        $s0 = "res/raw/item2.ogg"
        $s1 = "assets/u"
        $s2 = "Lorg/apache/common/a"
        $s3 = "Lorg/apache/common/a/a"
        $s4 = "Lorg/apache/common/a/b"
        $s5 = "Lorg/apache/common/a/c"
        $s6 = "Lorg/apache/common/a/d"
        $s7 = "Lorg/apache/common/a/e"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01415 {
    strings:
        $s0 = "$Lcom/iflytek/cloud/IdentityResult$1"
        $s1 = ".TextUnderstander"
        $s2 = "5Lcom/iflytek/cloud/util/AudioDetector$DetectorResult"
        $s3 = "BytesOfSpeechTimeout:"
        $s4 = "Lcom/iflytek/cloud/EvaluatorResult$1"
        $s5 = "Lcom/iflytek/cloud/FaceRequest$a$1"
        $s6 = "Lcom/iflytek/cloud/IdentityVerifier$1"
        $s7 = "Lcom/iflytek/cloud/RecognizerResult$1"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01416 {
    strings:
        $s0 = "xoYHeP/23ezgc3yGF9063z"
        $s1 = "res/layout/offert.xml"
        $s2 = "1.6.0_03-p4"
        $s3 = "res/raw/countries.cfg"
        $s4 = "res/layout/activation_done.xml"
        $s5 = "res/raw/sms.cfg"
        $s6 = "FilesParser.java"
        $s7 = "Lcom/depositmobi/FilesParser"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01417 {
    strings:
        $s0 = "xoYHeP/23ezgc3yGF9063z"
        $s1 = "res/layout/offert.xml"
        $s2 = "1.6.0_03-p4"
        $s3 = "res/raw/countries.cfg"
        $s4 = "res/layout/activation_done.xml"
        $s5 = "res/raw/sms.cfg"
        $s6 = "FilesParser.java"
        $s7 = "Lcom/depositmobi/FilesParser"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01418 {
    strings:
        $s0 = "xoYHeP/23ezgc3yGF9063z"
        $s1 = "res/layout/offert.xml"
        $s2 = "1.6.0_03-p4"
        $s3 = "res/raw/countries.cfg"
        $s4 = "res/layout/activation_done.xml"
        $s5 = "res/raw/sms.cfg"
        $s6 = "FilesParser.java"
        $s7 = "Lcom/depositmobi/FilesParser"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01419 {
    strings:
        $s0 = "xoYHeP/23ezgc3yGF9063z"
        $s1 = "res/layout/offert.xml"
        $s2 = "1.6.0_03-p4"
        $s3 = "res/raw/countries.cfg"
        $s4 = "res/layout/activation_done.xml"
        $s5 = "res/raw/sms.cfg"
        $s6 = "FilesParser.java"
        $s7 = "Lcom/depositmobi/FilesParser"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01420 {
    strings:
        $s0 = "assets/css/smoothness/images/ui-bg_flat_0_aaaaaa_40x100.png"
        $s1 = "assets/css/smoothness/images/ui-bg_flat_75_ffffff_40x100.png"
        $s2 = "assets/css/smoothness/images/ui-bg_glass_55_fbf9ee_1x400.png"
        $s3 = "assets/css/smoothness/images/ui-bg_glass_65_ffffff_1x400.png"
        $s4 = "assets/css/smoothness/images/ui-bg_glass_75_dadada_1x400.png"
        $s5 = "assets/css/smoothness/images/ui-bg_glass_75_e6e6e6_1x400.png"
        $s6 = "assets/css/smoothness/images/ui-bg_glass_95_fef1ec_1x400.png"
        $s7 = "assets/css/smoothness/images/ui-bg_highlight-soft_75_cccccc_1x10"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01421 {
    strings:
        $s0 = "left:5px"
        $s1 = "bottom:5px"
        $s2 = "Lcom/a/b/b/b/a"
        $s3 = "Lcom/a/b/b/b/b"
        $s4 = "Lcom/a/b/b/b/c"
        $s5 = "Lcom/yandex/metrica/a/a"
        $s6 = "Lcom/yandex/metrica/a/b"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6)
}

rule VX_APK_CLUSTER_01422 {
    strings:
        $s0 = "lib/armeabi-v7a/libdn_ssl.so"
        $s1 = "secret-classes.dex"
        $s2 = "scrt.apk"
        $s3 = "res/layout/activity_no_bg.xml"
        $s4 = "/kD/faOo"
        $s5 = "res/layout/activity_call_v7.xml"
        $s6 = "res/layout/call_end_layout.xml"
        $s7 = "res/layout/call_pop_layout.xml"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01423 {
    strings:
        $s0 = "lib/armeabi-v7a/libdn_ssl.so"
        $s1 = "secret-classes.dex"
        $s2 = "scrt.apk"
        $s3 = "res/layout/activity_no_bg.xml"
        $s4 = "/kD/faOo"
        $s5 = "res/layout/activity_call_v7.xml"
        $s6 = "res/layout/call_end_layout.xml"
        $s7 = "res/layout/call_pop_layout.xml"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01424 {
    strings:
        $s0 = "mFN1aeKWR1s5FS5xuSauOx/2RcU"
        $s1 = "c1KIGWnyXRYqiIGZe/9d7myM"
        $s2 = "gcLFlfd7/1qAQk8zSS1MhFDl69c"
        $s3 = "OSxx/WbZfYT"
        $s4 = "hJ3T6H/lFHdmdPqYLWOourW"
        $s5 = "YmXPs/3rK1sSo95no7qHVGJNsDA"
        $s6 = "FRQwo/hBCHmhg7WMNllJEskiIC4"
        $s7 = "/ZtEoo6xyOtd6dq1h"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01425 {
    strings:
        $s0 = "operator/mcc"
        $s1 = "http://dlsdcncnew.net/install3_traf.php"
        $s2 = "/http://dlsdcncnew2.net/install_msk_traf.php"
        $s3 = ".Lcom/example/service_update_v3/BootUpReceiver"
        $s4 = "6Lcom/example/service_update_v3/Service_updateActivity"
        $s5 = "7D/0auCuYDv4FyXYZ"
        $s6 = "Lcom/example/service_update_v3/MyService"
        $s7 = "Lcom/example/service_update_v3/SmsReceiver"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01426 {
    strings:
        $s0 = "lib/armeabi/libkjOnlinePay.so"
        $s1 = "4figSXu6KBZOPwPJvqL9cA/kXpc"
        $s2 = "res/drawable-hdpi-v4/qq.png"
        $s3 = "res/layout/payeco_plugin_wait_dialog.xml"
        $s4 = "res/layout/payeco_plugin_keyboard.xml"
        $s5 = "A/R6XEbhUeKlYbxW"
        $s6 = "Lcom/baidu/location/s$1"
        $s7 = "Lcom/baidu/location/y$a"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01427 {
    strings:
        $s0 = "3IOmkvQWrLqujnhgiQF/suWDebQ"
        $s1 = "res/drawable-hdpi/nf_bg_edit_text.9.png"
        $s2 = "res/drawable-hdpi/indeterminate_spinner.png"
        $s3 = "res/drawable-hdpi/selector_edittext_bg.xml"
        $s4 = "res/anim/wait.xml"
        $s5 = "res/drawable-hdpi/v3plus_run.png"
        $s6 = "apkprotect.com/key.dat"
        $s7 = "apkprotect.com/readme.txt"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01428 {
    strings:
        $s0 = "-i...--."
        $s1 = "3beH/MASicYWILJ6bNBGMBRyxmA"
        $s2 = "5hiR1surnFL/0l"
        $s3 = "Bpw9qc/5tamnIY6kCoDPUOxcpUM"
        $s4 = "hN---i1L------.----"
        $s5 = "L-/k-Zln"
        $s6 = "L--K0--/Np-"
        $s7 = "com.example.android.Activity.MainActivity"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01429 {
    strings:
        $s0 = "3IOmkvQWrLqujnhgiQF/suWDebQ"
        $s1 = "res/drawable-hdpi/kb.png"
        $s2 = "res/drawable-hdpi/nf_bg_edit_text.9.png"
        $s3 = "res/drawable-hdpi/indeterminate_spinner.png"
        $s4 = "res/drawable-hdpi/selector_edittext_bg.xml"
        $s5 = "res/anim/wait.xml"
        $s6 = "res/drawable-hdpi/v3plus_run.png"
        $s7 = "apkprotect.com/key.dat"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01430 {
    strings:
        $s0 = "QXNlZxax/gGXUe1BJamKgK0N1S4"
        $s1 = "xyE///---"
        $s2 = "IZZ.:K.Ky"
        $s3 = ".Lcom/limi/baton/receiver/BTConnectionReceiver"
        $s4 = "/05diJ9I0WLnvF4uE"
        $s5 = "/5yi3yGJwFRtDPfgQsgEFyyv40g"
        $s6 = "/Nj7g7sNT0kpqaGRXKpMg5"
        $s7 = "/NqG9stcJrxt3BcCznp7Nx4eaTc"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01431 {
    strings:
        $s0 = "ArrayVariant.java"
        $s1 = "BooleanReferenceParameter.java"
        $s2 = "ByteReferenceParameter.java"
        $s3 = "ByteVariant.java"
        $s4 = "ConvHelpers.java"
        $s5 = "DateVariant.java"
        $s6 = "DoubleReferenceParameter.java"
        $s7 = "ExprHelpers.java"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01432 {
    strings:
        $s0 = "ArrayVariant.java"
        $s1 = "BooleanReferenceParameter.java"
        $s2 = "ByteReferenceParameter.java"
        $s3 = "ByteVariant.java"
        $s4 = "ConvHelpers.java"
        $s5 = "DateVariant.java"
        $s6 = "DoubleReferenceParameter.java"
        $s7 = "ExprHelpers.java"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01433 {
    strings:
        $s0 = "Lnet/youmi/android/AdManager"
        $s1 = "ArrayVariant.java"
        $s2 = "BooleanReferenceParameter.java"
        $s3 = "ByteReferenceParameter.java"
        $s4 = "ByteVariant.java"
        $s5 = "ConvHelpers.java"
        $s6 = "DateVariant.java"
        $s7 = "DoubleReferenceParameter.java"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01434 {
    strings:
        $s0 = "ArrayVariant.java"
        $s1 = "BooleanReferenceParameter.java"
        $s2 = "ByteReferenceParameter.java"
        $s3 = "ByteVariant.java"
        $s4 = "ConvHelpers.java"
        $s5 = "DateVariant.java"
        $s6 = "DoubleReferenceParameter.java"
        $s7 = "ExprHelpers.java"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01435 {
    strings:
        $s0 = "ArrayVariant.java"
        $s1 = "BooleanReferenceParameter.java"
        $s2 = "ByteReferenceParameter.java"
        $s3 = "ByteVariant.java"
        $s4 = "ConvHelpers.java"
        $s5 = "DateVariant.java"
        $s6 = "DoubleReferenceParameter.java"
        $s7 = "ExprHelpers.java"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01436 {
    strings:
        $s0 = "ArrayVariant.java"
        $s1 = "BooleanReferenceParameter.java"
        $s2 = "ByteReferenceParameter.java"
        $s3 = "ByteVariant.java"
        $s4 = "ConvHelpers.java"
        $s5 = "DateVariant.java"
        $s6 = "DoubleReferenceParameter.java"
        $s7 = "ExprHelpers.java"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01437 {
    strings:
        $s0 = "ArrayVariant.java"
        $s1 = "BooleanReferenceParameter.java"
        $s2 = "ByteReferenceParameter.java"
        $s3 = "ByteVariant.java"
        $s4 = "ConvHelpers.java"
        $s5 = "DateVariant.java"
        $s6 = "DoubleReferenceParameter.java"
        $s7 = "ExprHelpers.java"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01438 {
    strings:
        $s0 = "ArrayVariant.java"
        $s1 = "BooleanReferenceParameter.java"
        $s2 = "ByteReferenceParameter.java"
        $s3 = "ByteVariant.java"
        $s4 = "ConvHelpers.java"
        $s5 = "DateVariant.java"
        $s6 = "DoubleReferenceParameter.java"
        $s7 = "ExprHelpers.java"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01439 {
    strings:
        $s0 = "ArrayVariant.java"
        $s1 = "BooleanReferenceParameter.java"
        $s2 = "ByteReferenceParameter.java"
        $s3 = "ByteVariant.java"
        $s4 = "ConvHelpers.java"
        $s5 = "DateVariant.java"
        $s6 = "DoubleReferenceParameter.java"
        $s7 = "ExprHelpers.java"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01440 {
    strings:
        $s0 = "ArrayVariant.java"
        $s1 = "BooleanReferenceParameter.java"
        $s2 = "ByteReferenceParameter.java"
        $s3 = "ByteVariant.java"
        $s4 = "ConvHelpers.java"
        $s5 = "DateVariant.java"
        $s6 = "DoubleReferenceParameter.java"
        $s7 = "ExprHelpers.java"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01441 {
    strings:
        $s0 = "ArrayVariant.java"
        $s1 = "BooleanReferenceParameter.java"
        $s2 = "ByteReferenceParameter.java"
        $s3 = "ByteVariant.java"
        $s4 = "ConvHelpers.java"
        $s5 = "DateVariant.java"
        $s6 = "DoubleReferenceParameter.java"
        $s7 = "ExprHelpers.java"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01442 {
    strings:
        $s0 = "ArrayVariant.java"
        $s1 = "BooleanReferenceParameter.java"
        $s2 = "ByteReferenceParameter.java"
        $s3 = "ByteVariant.java"
        $s4 = "ConvHelpers.java"
        $s5 = "DateVariant.java"
        $s6 = "DoubleReferenceParameter.java"
        $s7 = "ExprHelpers.java"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01443 {
    strings:
        $s0 = "ArrayVariant.java"
        $s1 = "BooleanReferenceParameter.java"
        $s2 = "ByteReferenceParameter.java"
        $s3 = "ByteVariant.java"
        $s4 = "ConvHelpers.java"
        $s5 = "DateVariant.java"
        $s6 = "DoubleReferenceParameter.java"
        $s7 = "ExprHelpers.java"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01444 {
    strings:
        $s0 = "ArrayVariant.java"
        $s1 = "BooleanReferenceParameter.java"
        $s2 = "ByteReferenceParameter.java"
        $s3 = "ByteVariant.java"
        $s4 = "ConvHelpers.java"
        $s5 = "DateVariant.java"
        $s6 = "DoubleReferenceParameter.java"
        $s7 = "ExprHelpers.java"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01445 {
    strings:
        $s0 = "ArrayVariant.java"
        $s1 = "BooleanReferenceParameter.java"
        $s2 = "ByteReferenceParameter.java"
        $s3 = "ByteVariant.java"
        $s4 = "ConvHelpers.java"
        $s5 = "DateVariant.java"
        $s6 = "DoubleReferenceParameter.java"
        $s7 = "ExprHelpers.java"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01446 {
    strings:
        $s0 = "ArrayVariant.java"
        $s1 = "BooleanReferenceParameter.java"
        $s2 = "ByteReferenceParameter.java"
        $s3 = "ByteVariant.java"
        $s4 = "ConvHelpers.java"
        $s5 = "DateVariant.java"
        $s6 = "DoubleReferenceParameter.java"
        $s7 = "ExprHelpers.java"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01447 {
    strings:
        $s0 = "assets/url.txt"
        $s1 = "contactsutils.java"
        $s2 = "$Lb4a/example/contactsutils$_cuemail"
        $s3 = "$Lb4a/example/contactsutils$_cuphone"
        $s4 = "DiviceInfo.java"
        $s5 = "Lb4a/example/contactsutils"
        $s6 = "Lb4a/example/contactsutils$_cucontact"
        $s7 = "Lcom/reza/sh/deviceinfo/DiviceInfo"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01448 {
    strings:
        $s0 = "assets/url.txt"
        $s1 = "contactsutils.java"
        $s2 = "$Lb4a/example/contactsutils$_cuemail"
        $s3 = "$Lb4a/example/contactsutils$_cuphone"
        $s4 = "DiviceInfo.java"
        $s5 = "Lb4a/example/contactsutils"
        $s6 = "Lb4a/example/contactsutils$_cucontact"
        $s7 = "Lcom/reza/sh/deviceinfo/DiviceInfo"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01449 {
    strings:
        $s0 = "assets/url.txt"
        $s1 = "contactsutils.java"
        $s2 = "$Lb4a/example/contactsutils$_cuemail"
        $s3 = "$Lb4a/example/contactsutils$_cuphone"
        $s4 = "DiviceInfo.java"
        $s5 = "Lb4a/example/contactsutils"
        $s6 = "Lb4a/example/contactsutils$_cucontact"
        $s7 = "Lcom/reza/sh/deviceinfo/DiviceInfo"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01450 {
    strings:
        $s0 = "assets/url.txt"
        $s1 = "contactsutils.java"
        $s2 = "$Lb4a/example/contactsutils$_cuemail"
        $s3 = "$Lb4a/example/contactsutils$_cuphone"
        $s4 = "DiviceInfo.java"
        $s5 = "Lb4a/example/contactsutils"
        $s6 = "Lb4a/example/contactsutils$_cucontact"
        $s7 = "Lcom/reza/sh/deviceinfo/DiviceInfo"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01451 {
    strings:
        $s0 = "assets/url.txt"
        $s1 = "contactsutils.java"
        $s2 = "$Lb4a/example/contactsutils$_cuemail"
        $s3 = "$Lb4a/example/contactsutils$_cuphone"
        $s4 = "DiviceInfo.java"
        $s5 = "Lb4a/example/contactsutils"
        $s6 = "Lb4a/example/contactsutils$_cucontact"
        $s7 = "Lcom/reza/sh/deviceinfo/DiviceInfo"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01452 {
    strings:
        $s0 = "res/drawable-hdpi/nf_bg_edit_text.9.png"
        $s1 = "res/drawable-hdpi/indeterminate_spinner.png"
        $s2 = "res/drawable-hdpi/selector_edittext_bg.xml"
        $s3 = "res/drawable-hdpi/btn_cancel_off_gnb.png"
        $s4 = "res/drawable-hdpi/btn_confirm_off_gnw.png"
        $s5 = "com.areo.bs"
        $s6 = "res/drawable-hdpi/bgsp.jpg"
        $s7 = "com.kakaotalk.synservice.TIK"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01453 {
    strings:
        $s0 = "assets/css/smoothness/images/ui-bg_flat_0_aaaaaa_40x100.png"
        $s1 = "assets/css/smoothness/images/ui-bg_flat_75_ffffff_40x100.png"
        $s2 = "assets/css/smoothness/images/ui-bg_glass_55_fbf9ee_1x400.png"
        $s3 = "assets/css/smoothness/images/ui-bg_glass_65_ffffff_1x400.png"
        $s4 = "assets/css/smoothness/images/ui-bg_glass_75_dadada_1x400.png"
        $s5 = "assets/css/smoothness/images/ui-bg_glass_75_e6e6e6_1x400.png"
        $s6 = "assets/css/smoothness/images/ui-bg_glass_95_fef1ec_1x400.png"
        $s7 = "assets/css/smoothness/images/ui-bg_highlight-soft_75_cccccc_1x10"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01454 {
    strings:
        $s0 = "assets/css/smoothness/images/ui-bg_flat_0_aaaaaa_40x100.png"
        $s1 = "assets/css/smoothness/images/ui-bg_flat_75_ffffff_40x100.png"
        $s2 = "assets/css/smoothness/images/ui-bg_glass_55_fbf9ee_1x400.png"
        $s3 = "assets/css/smoothness/images/ui-bg_glass_65_ffffff_1x400.png"
        $s4 = "assets/css/smoothness/images/ui-bg_glass_75_dadada_1x400.png"
        $s5 = "assets/css/smoothness/images/ui-bg_glass_75_e6e6e6_1x400.png"
        $s6 = "assets/css/smoothness/images/ui-bg_glass_95_fef1ec_1x400.png"
        $s7 = "assets/css/smoothness/images/ui-bg_highlight-soft_75_cccccc_1x10"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01455 {
    strings:
        $s0 = "assets/css/smoothness/images/ui-bg_flat_0_aaaaaa_40x100.png"
        $s1 = "assets/css/smoothness/images/ui-bg_flat_75_ffffff_40x100.png"
        $s2 = "assets/css/smoothness/images/ui-bg_glass_55_fbf9ee_1x400.png"
        $s3 = "assets/css/smoothness/images/ui-bg_glass_65_ffffff_1x400.png"
        $s4 = "assets/css/smoothness/images/ui-bg_glass_75_dadada_1x400.png"
        $s5 = "assets/css/smoothness/images/ui-bg_glass_75_e6e6e6_1x400.png"
        $s6 = "assets/css/smoothness/images/ui-bg_glass_95_fef1ec_1x400.png"
        $s7 = "assets/css/smoothness/images/ui-bg_highlight-soft_75_cccccc_1x10"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01456 {
    strings:
        $s0 = "apkprotect.com/key.dat"
        $s1 = "apkprotect.com/readme.txt"
        $s2 = "Lcom/android/a"
        $s3 = "ReplayStruct.java"
        $s4 = "RequestStruct.java"
        $s5 = "LSecScreen.java"
        $s6 = "res/xml/lsecscreen.xml"
        $s7 = "Lcom/android/internal/telephony/a"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01457 {
    strings:
        $s0 = ".Lcom/nijigenirubasho/mobiletailchanger/R$attr"
        $s1 = "/Lcom/nijigenirubasho/mobiletailchanger/R$style"
        $s2 = "/data/magisk/resetprop"
        $s3 = "/sdcard/bptemp_"
        $s4 = "0Lcom/nijigenirubasho/mobiletailchanger/R$layout"
        $s5 = "0Lcom/nijigenirubasho/mobiletailchanger/R$string"
        $s6 = "2Lcom/nijigenirubasho/mobiletailchanger/R$drawable"
        $s7 = "3Lcom/nijigenirubasho/mobiletailchanger/BuildConfig"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01458 {
    strings:
        $s0 = "com.webcash.wooribank"
        $s1 = "res/drawable-hdpi/nh.png"
        $s2 = "res/drawable-hdpi/sh.png"
        $s3 = "res/drawable-hdpi/kb.png"
        $s4 = "Q0j/LlUSDZKDI8"
        $s5 = "res/drawable-hdpi/hana.png"
        $s6 = "httpclient.execute"
        $s7 = "httppost.setEntity"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01459 {
    strings:
        $s0 = "com.webcash.wooribank"
        $s1 = "res/drawable-hdpi/nh.png"
        $s2 = "res/drawable-hdpi/sh.png"
        $s3 = "res/drawable-hdpi/kb.png"
        $s4 = "Q0j/LlUSDZKDI8"
        $s5 = "res/drawable-hdpi/hana.png"
        $s6 = "httpclient.execute"
        $s7 = "httppost.setEntity"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01460 {
    strings:
        $s0 = "AVNND/JkatQhKFlGi7mz9E11a"
        $s1 = "GQVjRE7f1IvvS3/mo"
        $s2 = ".KKKZKZKZKZxxxK"
        $s3 = "/UOtj19D7j/FxKPyAWm1uQSvUv1wdL3wWXCpPlTiYe4"
        $s4 = "ZKrm/X/oP7Ypo2HPtpLiGA"
        $s5 = "InterceptCall.java"
        $s6 = "calls.java"
        $s7 = "$Lcom/example/dat/a8andoserverx/R$id"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01461 {
    strings:
        $s0 = "$Lcom/example/mobilpakket/R$drawable"
        $s1 = "Lcom/example/mobilpakket/BuildConfig"
        $s2 = "Lcom/example/mobilpakket/MainActivity"
        $s3 = "Lcom/example/mobilpakket/MyAppWebViewClient"
        $s4 = "Lcom/example/mobilpakket/R"
        $s5 = "Lcom/example/mobilpakket/R$attr"
        $s6 = "Lcom/example/mobilpakket/R$dimen"
        $s7 = "Lcom/example/mobilpakket/R$id"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01462 {
    strings:
        $s0 = "$Lcom/example/mobilpakket/R$drawable"
        $s1 = "Lcom/example/mobilpakket/BuildConfig"
        $s2 = "Lcom/example/mobilpakket/MainActivity"
        $s3 = "Lcom/example/mobilpakket/MyAppWebViewClient"
        $s4 = "Lcom/example/mobilpakket/R"
        $s5 = "Lcom/example/mobilpakket/R$attr"
        $s6 = "Lcom/example/mobilpakket/R$dimen"
        $s7 = "Lcom/example/mobilpakket/R$id"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01463 {
    strings:
        $s0 = "$Lcom/example/mobilpakket/R$drawable"
        $s1 = "Lcom/example/mobilpakket/BuildConfig"
        $s2 = "Lcom/example/mobilpakket/MainActivity"
        $s3 = "Lcom/example/mobilpakket/MyAppWebViewClient"
        $s4 = "Lcom/example/mobilpakket/R"
        $s5 = "Lcom/example/mobilpakket/R$attr"
        $s6 = "Lcom/example/mobilpakket/R$dimen"
        $s7 = "Lcom/example/mobilpakket/R$id"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01464 {
    strings:
        $s0 = "$Lcom/example/mobilpakket/R$drawable"
        $s1 = "Lcom/example/mobilpakket/BuildConfig"
        $s2 = "Lcom/example/mobilpakket/MainActivity"
        $s3 = "Lcom/example/mobilpakket/MyAppWebViewClient"
        $s4 = "Lcom/example/mobilpakket/R"
        $s5 = "Lcom/example/mobilpakket/R$attr"
        $s6 = "Lcom/example/mobilpakket/R$dimen"
        $s7 = "Lcom/example/mobilpakket/R$id"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01465 {
    strings:
        $s0 = "$Lcom/example/mobilpakket/R$drawable"
        $s1 = "Lcom/example/mobilpakket/BuildConfig"
        $s2 = "Lcom/example/mobilpakket/MainActivity"
        $s3 = "Lcom/example/mobilpakket/MyAppWebViewClient"
        $s4 = "Lcom/example/mobilpakket/R"
        $s5 = "Lcom/example/mobilpakket/R$attr"
        $s6 = "Lcom/example/mobilpakket/R$dimen"
        $s7 = "Lcom/example/mobilpakket/R$id"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01466 {
    strings:
        $s0 = "$Lcom/example/mobilpakket/R$drawable"
        $s1 = "Lcom/example/mobilpakket/BuildConfig"
        $s2 = "Lcom/example/mobilpakket/MainActivity"
        $s3 = "Lcom/example/mobilpakket/MyAppWebViewClient"
        $s4 = "Lcom/example/mobilpakket/R"
        $s5 = "Lcom/example/mobilpakket/R$attr"
        $s6 = "Lcom/example/mobilpakket/R$dimen"
        $s7 = "Lcom/example/mobilpakket/R$id"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01467 {
    strings:
        $s0 = "hp_getsmsblockstate.php"
        $s1 = "hp_state.php"
        $s2 = "-Ziiiiik------."
        $s3 = "-ig.K--Z-X"
        $s4 = "$Lcom/example/myapplication/R$layout"
        $s5 = "$Lcom/example/myapplication/R$mipmap"
        $s6 = "$Lcom/example/myapplication/R$string"
        $s7 = "Forbid.java"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01470 {
    strings:
        $s0 = "system/bin/sh"
        $s1 = "-ig.K--Z-X"
        $s2 = "./-.i.i2-"
        $s3 = "HqTUKmrny6A4o5EuCWwS5uB/CsE"
        $s4 = "Z2bKQuj6fVK7jNch/ikGeWjJhqE"
        $s5 = "$Lcom/example/reverseshell2/R$layout"
        $s6 = "$Lcom/example/reverseshell2/R$mipmap"
        $s7 = "$Lcom/example/reverseshell2/R$string"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01471 {
    strings:
        $s0 = "Lcom/mixClass"
        $s1 = "mixClass.java"
        $s2 = "classes.dexu1"
        $s3 = "x2MufTAeRGP6/OhfhOnD19o/274"
        $s4 = "assets/libjiagu_ls.so"
        $s5 = "lib/armeabi/mix.dex"
        $s6 = "lib/armeabi/mixz.dex"
        $s7 = "res/drawable-xhdpi-v4/bf.9.png"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01472 {
    strings:
        $s0 = "/rgBiUeGVuM9QauYk4hnNYsk7Tg"
        $s1 = "-i...--."
        $s2 = "hN---i1L------.----"
        $s3 = "L-/k-Zln"
        $s4 = "L--K0--/Np-"
        $s5 = "OAR1L-.x_-PM-y"
        $s6 = "Lcom/chartboost/sdk/impl/-$$Lambda$0vl_H0AjszkepNiV6I4L-yuFIMA"
        $s7 = ".nexstreaming.kinemaster.builtin.transition.pip.colortiles/_info.json"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01473 {
    strings:
        $s0 = ".Lcom/sirseni/simpleandroidwebviewexample/R$id"
        $s1 = "/CoIXRo5o95LwmcBAYLGXQ5bHtk"
        $s2 = "0Lcom/sirseni/simpleandroidwebviewexample/R$anim"
        $s3 = "0Lcom/sirseni/simpleandroidwebviewexample/R$attr"
        $s4 = "0Lcom/sirseni/simpleandroidwebviewexample/R$bool"
        $s5 = "0Lcom/sirseni/simpleandroidwebviewexample/R$menu"
        $s6 = "1Lcom/sirseni/simpleandroidwebviewexample/R$color"
        $s7 = "1Lcom/sirseni/simpleandroidwebviewexample/R$dimen"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01474 {
    strings:
        $s0 = ".Lcom/sirseni/simpleandroidwebviewexample/R$id"
        $s1 = "/CoIXRo5o95LwmcBAYLGXQ5bHtk"
        $s2 = "0Lcom/sirseni/simpleandroidwebviewexample/R$anim"
        $s3 = "0Lcom/sirseni/simpleandroidwebviewexample/R$attr"
        $s4 = "0Lcom/sirseni/simpleandroidwebviewexample/R$bool"
        $s5 = "0Lcom/sirseni/simpleandroidwebviewexample/R$menu"
        $s6 = "1Lcom/sirseni/simpleandroidwebviewexample/R$color"
        $s7 = "1Lcom/sirseni/simpleandroidwebviewexample/R$dimen"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01475 {
    strings:
        $s0 = "res/layout/policies.xml"
        $s1 = "res/drawable-hdpi/back.xml"
        $s2 = "AService.java"
        $s3 = "iBankDB_23.db"
        $s4 = "res/drawable-hdpi/ic_launcher.jpg"
        $s5 = "res/drawable/andi.png"
        $s6 = "res/menu/incoming_call.xml"
        $s7 = "style/template3_bold"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01476 {
    strings:
        $s0 = "/92T0y8Eg3hwmkt655BvOmGHH/XfOxZOEdiIqIwPT0FPT1D"
        $s1 = "/CmOEnNP6lw5ie"
        $s2 = "/G7vW8JQCmu0vfGnYWwVddg0"
        $s3 = "/H7/T0Kh0JlIJPLHaDT6V5vN9l"
        $s4 = "/SgOYNXi9nXGzpgQ/GLoI/F8cBdd9blJWI3aUlcNik9a54bjfK//AWNnzhbv/YNafPouSxJ1C57QdwRE"
        $s5 = "/eV24SQp5AXoVMCIYgaKW2oM5YW3FsEUa0MM5YYYIiLT7a/qH80dJxpu20OlbUodDqTNtBrFNqQzGtpT"
        $s6 = "/lmAoH0kytnp8PooIXsJDodcGUW5F6s8TJtLPyQAqwOisq7O2U8Is7zJBWXK/EOquTsVWzctRc/"
        $s7 = "/wMWjgermQx"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01477 {
    strings:
        $s0 = "setVideoPath:"
        $s1 = "assets/libmitv.so"
        $s2 = "lib/armeabi-v7a/libmitv.so"
        $s3 = "Lcom/forcetech/android/ForceTV"
        $s4 = "lib/armeabi-v7a/libp2pcore.so"
        $s5 = "lib/armeabi-v7a/libtvcore.so"
        $s6 = "lib/armeabi-v7a/libvjplayer_jni.so"
        $s7 = "/libmitv.so"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01478 {
    strings:
        $s0 = "assets/feiwo_simg.jar"
        $s1 = ".com/bayimob/d/d"
        $s2 = "/dm_cover_logo_normal.png"
        $s3 = "2dm_cover_open_normal.png"
        $s4 = ":dm_cover_download_normal.png"
        $s5 = "by_mark.png"
        $s6 = "by_right_arrow.png"
        $s7 = "by_rloding_1.png"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01479 {
    strings:
        $s0 = "apkprotect.com/key.dat"
        $s1 = "apkprotect.com/readme.txt"
        $s2 = "ReplayStruct.java"
        $s3 = "RequestStruct.java"
        $s4 = "LSecScreen.java"
        $s5 = "res/xml/lsecscreen.xml"
        $s6 = "serivce."
        $s7 = "BaseBootReceiver.java"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01480 {
    strings:
        $s0 = "res/layout/finish.xml"
        $s1 = "res/drawable/button_green.png"
        $s2 = "rEppsRv/JtutQIWU6VLVixb96JA"
        $s3 = "res/drawable/button_green_p.png"
        $s4 = "res/drawable/progress_bar_fill_bg.png"
        $s5 = "res/drawable/red_progress_bar_fill.9.png"
        $s6 = "res/drawable/terms_b.png"
        $s7 = "res/drawable/terms_button.xml"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01481 {
    strings:
        $s0 = "saveString:"
        $s1 = "bam.vtr.com"
        $s2 = "data.springmobil.se"
        $s3 = "gprs.telemigcelular.com.br"
        $s4 = "gprsweb.digitel.ve"
        $s5 = "res/layout/activity_ssp.xml"
        $s6 = "rogers-core-appl1.apn"
        $s7 = "sercomtel.com.br"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01482 {
    strings:
        $s0 = "res/mipmap-xxhdpi-v4/ic_launcher_empty.png"
        $s1 = "res/mipmap-xxhdpi-v4/ic_launcher_video.png"
        $s2 = "Md3MSA/sg/op1reCKgNZCskn84E"
        $s3 = "res/mipmap-xxhdpi-v4/ic_launcher_antivirus.png"
        $s4 = "res/mipmap-xxhdpi-v4/ic_launcher_flash.png"
        $s5 = "res/mipmap-xxhdpi-v4/ic_launcher_music.png"
        $s6 = "res/mipmap-xxhdpi-v4/ic_launcher_robot.png"
        $s7 = "res/mipmap-xxhdpi-v4/ic_launcher_security.png"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01483 {
    strings:
        $s0 = "Lcom/egvhreh/Pla"
        $s1 = "Lcom/egvhreh/usi/Activ"
        $s2 = "Lcom/egvhreh/usi/Activ$"
        $s3 = "OX.NQVsTtgwnTp"
        $s4 = "bRm/m6KAKAaAN08cp"
        $s5 = "java/io/Serializablefp1M$"
        $s6 = "java/lang/String6"
        $s7 = "java/lang/StringJ"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01484 {
    strings:
        $s0 = "Settings::save"
        $s1 = "ThreadOperationListener.java"
        $s2 = "Settings::load"
        $s3 = "RwY7bp1C/mAHk1MxPLhfhPev/oM"
        $s4 = "javascript:androidVersion"
        $s5 = "webapi.cancelUse"
        $s6 = "/license.html"
        $s7 = "assets/html/default/icon.png"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01485 {
    strings:
        $s0 = "R0X/L6PAiNpb2RxEFokh6/StBz0"
        $s1 = "boRT6JyE8/gO"
        $s2 = "doW4mzL4yeq/PwUK803c3HJtD4"
        $s3 = "4JJOnS9YC5LBcSbRM/qgcpmUh8s"
        $s4 = "/lE9AthIVgqdnJsrhPxY4N7CCpk"
        $s5 = "5/a/8CNDMnkGb63/ssWDuBoEELU"
        $s6 = ".TRa.TSc.TTb.qT"
        $s7 = "0LqFakzi4p/uv27o6nEJTGgwwUs"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01486 {
    strings:
        $s0 = "R0X/L6PAiNpb2RxEFokh6/StBz0"
        $s1 = "boRT6JyE8/gO"
        $s2 = "doW4mzL4yeq/PwUK803c3HJtD4"
        $s3 = "4JJOnS9YC5LBcSbRM/qgcpmUh8s"
        $s4 = "/lE9AthIVgqdnJsrhPxY4N7CCpk"
        $s5 = "5/a/8CNDMnkGb63/ssWDuBoEELU"
        $s6 = ".TRa.TSc.TTb.qT"
        $s7 = "0LqFakzi4p/uv27o6nEJTGgwwUs"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01487 {
    strings:
        $s0 = "R0X/L6PAiNpb2RxEFokh6/StBz0"
        $s1 = "boRT6JyE8/gO"
        $s2 = "doW4mzL4yeq/PwUK803c3HJtD4"
        $s3 = "4JJOnS9YC5LBcSbRM/qgcpmUh8s"
        $s4 = "/lE9AthIVgqdnJsrhPxY4N7CCpk"
        $s5 = "5/a/8CNDMnkGb63/ssWDuBoEELU"
        $s6 = ".TRa.TSc.TTb.qT"
        $s7 = "0LqFakzi4p/uv27o6nEJTGgwwUs"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01488 {
    strings:
        $s0 = ".Task2.OrientationChangeCallback"
        $s1 = "0Task2.MediaProjectionStopCallback"
        $s2 = "Lizci/AdminReceiver"
        $s3 = "ServicesDemo3.dll"
        $s4 = "Task2.AdminReceiver"
        $s5 = "Task2.Alarm"
        $s6 = "Task2.BootReceiver"
        $s7 = "Task2.ForegroundService"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01489 {
    strings:
        $s0 = "5Lcom/startapp/android/publish/common/commonUtils/r$1"
        $s1 = "5Lcom/startapp/android/publish/common/commonUtils/r$2"
        $s2 = "5Lcom/startapp/android/publish/common/commonUtils/r$a"
        $s3 = "7Lcom/startapp/android/publish/common/commonUtils/r$1$1"
        $s4 = "7Lcom/startapp/android/publish/common/commonUtils/r$1$2"
        $s5 = ".TimeoutDispose"
        $s6 = ".TimeoutDispose.TimeoutObserver"
        $s7 = ".TimeoutObserver"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01490 {
    strings:
        $s0 = "assets/css/smoothness/images/ui-bg_flat_0_aaaaaa_40x100.png"
        $s1 = "assets/css/smoothness/images/ui-bg_flat_75_ffffff_40x100.png"
        $s2 = "assets/css/smoothness/images/ui-bg_glass_55_fbf9ee_1x400.png"
        $s3 = "assets/css/smoothness/images/ui-bg_glass_65_ffffff_1x400.png"
        $s4 = "assets/css/smoothness/images/ui-bg_glass_75_dadada_1x400.png"
        $s5 = "assets/css/smoothness/images/ui-bg_glass_75_e6e6e6_1x400.png"
        $s6 = "assets/css/smoothness/images/ui-bg_glass_95_fef1ec_1x400.png"
        $s7 = "assets/css/smoothness/images/ui-bg_highlight-soft_75_cccccc_1x10"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01491 {
    strings:
        $s0 = "res/drawable-hdpi/nh.png"
        $s1 = "res/drawable-hdpi/sh.png"
        $s2 = "res/drawable-hdpi/kb.png"
        $s3 = "Q0j/LlUSDZKDI8"
        $s4 = "res/drawable-hdpi/hana.png"
        $s5 = "res/layout/woori_main_activity.xml"
        $s6 = "res/layout/hana_main_activity.xml"
        $s7 = "res/layout/kb_main_activity.xml"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01492 {
    strings:
        $s0 = "res/drawable-hdpi/nh.png"
        $s1 = "res/drawable-hdpi/sh.png"
        $s2 = "res/drawable-hdpi/kb.png"
        $s3 = "Q0j/LlUSDZKDI8"
        $s4 = "res/drawable-hdpi/hana.png"
        $s5 = "res/layout/woori_main_activity.xml"
        $s6 = "res/layout/hana_main_activity.xml"
        $s7 = "res/layout/kb_main_activity.xml"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01493 {
    strings:
        $s0 = "Lcom/adwo/adsdk/AdwoAdView"
        $s1 = "Lcom/adwo/adsdk/AdListener"
        $s2 = "http://10.0.0.172/a/p1"
        $s3 = "http://10.0.0.172/t/test"
        $s4 = "assets/adwo_left_arrow.png"
        $s5 = "assets/adwo_right_arrow.png"
        $s6 = "Lcom/adwo/adsdk/a"
        $s7 = "Lcom/adwo/adsdk/b"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01494 {
    strings:
        $s0 = "Lcom/adwo/adsdk/AdwoAdView"
        $s1 = "Lcom/adwo/adsdk/AdListener"
        $s2 = "http://10.0.0.172/a/p1"
        $s3 = "http://10.0.0.172/t/test"
        $s4 = "assets/adwo_left_arrow.png"
        $s5 = "assets/adwo_right_arrow.png"
        $s6 = "Lcom/adwo/adsdk/a"
        $s7 = "Lcom/adwo/adsdk/b"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01495 {
    strings:
        $s0 = "Lcom/adwo/adsdk/AdwoAdView"
        $s1 = "Lcom/adwo/adsdk/AdListener"
        $s2 = "http://10.0.0.172/a/p1"
        $s3 = "http://10.0.0.172/t/test"
        $s4 = "assets/adwo_left_arrow.png"
        $s5 = "assets/adwo_right_arrow.png"
        $s6 = "Lcom/adwo/adsdk/a"
        $s7 = "Lcom/adwo/adsdk/b"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01496 {
    strings:
        $s0 = "Lcom/adwo/adsdk/AdwoAdView"
        $s1 = "Lcom/adwo/adsdk/AdListener"
        $s2 = "http://10.0.0.172/a/p1"
        $s3 = "http://10.0.0.172/t/test"
        $s4 = "assets/adwo_left_arrow.png"
        $s5 = "assets/adwo_right_arrow.png"
        $s6 = "Lcom/adwo/adsdk/a"
        $s7 = "Lcom/adwo/adsdk/b"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01497 {
    strings:
        $s0 = "Lcom/mixClass"
        $s1 = "mixClass.java"
        $s2 = "/tx_shell"
        $s3 = "/tx_shell/"
        $s4 = "Lcom/tencent/StubShell/ZipUtil"
        $s5 = "libshellb.so"
        $s6 = "libshellc.so"
        $s7 = "classes.dexu1"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01498 {
    strings:
        $s0 = "assets/css/smoothness/images/ui-bg_flat_0_aaaaaa_40x100.png"
        $s1 = "assets/css/smoothness/images/ui-bg_flat_75_ffffff_40x100.png"
        $s2 = "assets/css/smoothness/images/ui-bg_glass_55_fbf9ee_1x400.png"
        $s3 = "assets/css/smoothness/images/ui-bg_glass_65_ffffff_1x400.png"
        $s4 = "assets/css/smoothness/images/ui-bg_glass_75_dadada_1x400.png"
        $s5 = "assets/css/smoothness/images/ui-bg_glass_75_e6e6e6_1x400.png"
        $s6 = "assets/css/smoothness/images/ui-bg_glass_95_fef1ec_1x400.png"
        $s7 = "assets/css/smoothness/images/ui-bg_highlight-soft_75_cccccc_1x10"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01499 {
    strings:
        $s0 = ".amr::Added"
        $s1 = "CallLogs.txt"
        $s2 = "Clist.txt"
        $s3 = "Tree.txt"
        $s4 = "WappHolder.txt"
        $s5 = "https://www.geoip-db.com/json"
        $s6 = "netinfo.txt"
        $s7 = "pkinfo.txt"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01500 {
    strings:
        $s0 = "res/xml/device_admin_data.xml"
        $s1 = "res/drawable-hdpi/check2.png"
        $s2 = "OhaGL7xatki385myc/mriuJt304"
        $s3 = ".andro_secure"
        $s4 = ":Executed:HTTP"
        $s5 = "com.adobe.flashplayer."
        $s6 = "getMessages:Executed:HTTP"
        $s7 = "http://adobe.com."
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01501 {
    strings:
        $s0 = "PlJSQqWxy9Pig116SM/fEvHLyIQ"
        $s1 = "//0N3FbUo5cvT8"
        $s2 = ".bg.color"
        $s3 = ".border.color"
        $s4 = "res/drawable/zt__back.png"
        $s5 = "res/drawable/zt__down.png"
        $s6 = "res/drawable/zt__down_w.png"
        $s7 = "res/drawable/zt__icon_lack.png"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01502 {
    strings:
        $s0 = "PlJSQqWxy9Pig116SM/fEvHLyIQ"
        $s1 = "//0N3FbUo5cvT8"
        $s2 = "/Xd8TjhwyNbYb2Z/"
        $s3 = "http://ehttp-host-"
        $s4 = "LwcvoEmrFpXVcD/7dJS3ijfU6Fo"
        $s5 = "6/W5YFA9Dv7aBsElhk"
        $s6 = "AaNfidSePp/TeMxfv4Ssd"
        $s7 = "KjQ8YcSDNo0FojMfa/QOJ"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01503 {
    strings:
        $s0 = "PlJSQqWxy9Pig116SM/fEvHLyIQ"
        $s1 = "//0N3FbUo5cvT8"
        $s2 = "/Xd8TjhwyNbYb2Z/"
        $s3 = "http://ehttp-host-"
        $s4 = "LwcvoEmrFpXVcD/7dJS3ijfU6Fo"
        $s5 = "6/W5YFA9Dv7aBsElhk"
        $s6 = "AaNfidSePp/TeMxfv4Ssd"
        $s7 = "KjQ8YcSDNo0FojMfa/QOJ"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01504 {
    strings:
        $s0 = "PlJSQqWxy9Pig116SM/fEvHLyIQ"
        $s1 = "//0N3FbUo5cvT8"
        $s2 = "/Xd8TjhwyNbYb2Z/"
        $s3 = "http://ehttp-host-"
        $s4 = "LwcvoEmrFpXVcD/7dJS3ijfU6Fo"
        $s5 = "6/W5YFA9Dv7aBsElhk"
        $s6 = "AaNfidSePp/TeMxfv4Ssd"
        $s7 = "KjQ8YcSDNo0FojMfa/QOJ"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01505 {
    strings:
        $s0 = "PlJSQqWxy9Pig116SM/fEvHLyIQ"
        $s1 = "//0N3FbUo5cvT8"
        $s2 = "/Xd8TjhwyNbYb2Z/"
        $s3 = "http://ehttp-host-"
        $s4 = "LwcvoEmrFpXVcD/7dJS3ijfU6Fo"
        $s5 = "6/W5YFA9Dv7aBsElhk"
        $s6 = "AaNfidSePp/TeMxfv4Ssd"
        $s7 = "KjQ8YcSDNo0FojMfa/QOJ"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01506 {
    strings:
        $s0 = "PlJSQqWxy9Pig116SM/fEvHLyIQ"
        $s1 = "//0N3FbUo5cvT8"
        $s2 = "/Xd8TjhwyNbYb2Z/"
        $s3 = "http://ehttp-host-"
        $s4 = "LwcvoEmrFpXVcD/7dJS3ijfU6Fo"
        $s5 = "6/W5YFA9Dv7aBsElhk"
        $s6 = "AaNfidSePp/TeMxfv4Ssd"
        $s7 = "KjQ8YcSDNo0FojMfa/QOJ"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01507 {
    strings:
        $s0 = "PlJSQqWxy9Pig116SM/fEvHLyIQ"
        $s1 = "//0N3FbUo5cvT8"
        $s2 = "/Xd8TjhwyNbYb2Z/"
        $s3 = "http://ehttp-host-"
        $s4 = "LwcvoEmrFpXVcD/7dJS3ijfU6Fo"
        $s5 = "6/W5YFA9Dv7aBsElhk"
        $s6 = "AaNfidSePp/TeMxfv4Ssd"
        $s7 = "KjQ8YcSDNo0FojMfa/QOJ"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01508 {
    strings:
        $s0 = "PlJSQqWxy9Pig116SM/fEvHLyIQ"
        $s1 = "//0N3FbUo5cvT8"
        $s2 = "/Xd8TjhwyNbYb2Z/"
        $s3 = "http://ehttp-host-"
        $s4 = "LwcvoEmrFpXVcD/7dJS3ijfU6Fo"
        $s5 = "6/W5YFA9Dv7aBsElhk"
        $s6 = "AaNfidSePp/TeMxfv4Ssd"
        $s7 = "KjQ8YcSDNo0FojMfa/QOJ"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01509 {
    strings:
        $s0 = "PlJSQqWxy9Pig116SM/fEvHLyIQ"
        $s1 = "//0N3FbUo5cvT8"
        $s2 = "/Xd8TjhwyNbYb2Z/"
        $s3 = "http://ehttp-host-"
        $s4 = "LwcvoEmrFpXVcD/7dJS3ijfU6Fo"
        $s5 = "6/W5YFA9Dv7aBsElhk"
        $s6 = "AaNfidSePp/TeMxfv4Ssd"
        $s7 = "KjQ8YcSDNo0FojMfa/QOJ"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01510 {
    strings:
        $s0 = "PlJSQqWxy9Pig116SM/fEvHLyIQ"
        $s1 = "//0N3FbUo5cvT8"
        $s2 = "/Xd8TjhwyNbYb2Z/"
        $s3 = "http://ehttp-host-"
        $s4 = "LwcvoEmrFpXVcD/7dJS3ijfU6Fo"
        $s5 = "6/W5YFA9Dv7aBsElhk"
        $s6 = "AaNfidSePp/TeMxfv4Ssd"
        $s7 = "KjQ8YcSDNo0FojMfa/QOJ"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01511 {
    strings:
        $s0 = "PlJSQqWxy9Pig116SM/fEvHLyIQ"
        $s1 = "//0N3FbUo5cvT8"
        $s2 = "/Xd8TjhwyNbYb2Z/"
        $s3 = "http://ehttp-host-"
        $s4 = "LwcvoEmrFpXVcD/7dJS3ijfU6Fo"
        $s5 = "6/W5YFA9Dv7aBsElhk"
        $s6 = "AaNfidSePp/TeMxfv4Ssd"
        $s7 = "KjQ8YcSDNo0FojMfa/QOJ"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01512 {
    strings:
        $s0 = "1com.qihoo360.mobilesafe.service.SafeManageService"
        $s1 = "com.lbe.security.service.SecurityService"
        $s2 = "/contain_imei"
        $s3 = "/is_upload"
        $s4 = ".cavideo"
        $s5 = "0http://www.muimerpni.biz:8088/v2.php"
        $s6 = "0http://www.muimerpni.biz:8088/v3.php"
        $s7 = "Lcom/parand/a/a"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01513 {
    strings:
        $s0 = "1com.qihoo360.mobilesafe.service.SafeManageService"
        $s1 = "com.lbe.security.service.SecurityService"
        $s2 = "/contain_imei"
        $s3 = "/is_upload"
        $s4 = ".cavideo"
        $s5 = "0http://www.muimerpni.biz:8088/v2.php"
        $s6 = "0http://www.muimerpni.biz:8088/v3.php"
        $s7 = "Lcom/parand/a/a"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01514 {
    strings:
        $s0 = "contactsutils.java"
        $s1 = "xJ-iiiiiiK."
        $s2 = "w-----/35"
        $s3 = "assets/layout.bal"
        $s4 = "LS_layout.java"
        $s5 = "com.bbva.bbvacontigo"
        $s6 = "es.bancosantander.apps"
        $s7 = "com.santander.app"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01515 {
    strings:
        $s0 = "res/raw/act_schemes.cfg"
        $s1 = "res/xml/texts.xml"
        $s2 = "res/layout/off.xml"
        $s3 = "res/layout/grant_access.xml"
        $s4 = "ShowURL.java"
        $s5 = "Sch.java"
        $s6 = "ProcedureStarter.java"
        $s7 = "ProcedureMaker.java"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01516 {
    strings:
        $s0 = "res/raw/act_schemes.cfg"
        $s1 = "res/xml/texts.xml"
        $s2 = "res/layout/off.xml"
        $s3 = "res/layout/grant_access.xml"
        $s4 = "ShowURL.java"
        $s5 = "Sch.java"
        $s6 = "ProcedureStarter.java"
        $s7 = "ProcedureMaker.java"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01517 {
    strings:
        $s0 = "res/raw/act_schemes.cfg"
        $s1 = "res/xml/texts.xml"
        $s2 = "res/layout/off.xml"
        $s3 = "res/layout/grant_access.xml"
        $s4 = "ShowURL.java"
        $s5 = "Sch.java"
        $s6 = "ProcedureStarter.java"
        $s7 = "ProcedureMaker.java"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01518 {
    strings:
        $s0 = ".com.plankton.device.android.AndroidMDKProvider"
        $s1 = "2http://www.searchwebmobile.com/ProtocolGW/protocol"
        $s2 = "6http://www.searchwebmobile.com/ProtocolGW/installation"
        $s3 = "7Lcom/plankton/device/android/service/AndroidMDKService"
        $s4 = "Lcom/plankton/device/android/service/a"
        $s5 = "Lcom/plankton/device/android/service/b"
        $s6 = "Lcom/plankton/device/android/service/c"
        $s7 = "Lcom/plankton/device/android/service/d"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01519 {
    strings:
        $s0 = "-Lnet/tsz/afinal/core/AsyncTask$WorkerRunnable"
        $s1 = "-Lnet/tsz/afinal/core/AbstractCollection"
        $s2 = "1Lnet/tsz/afinal/http/HttpHandler"
        $s3 = "2Lnet/tsz/afinal/http/AjaxCallBack"
        $s4 = "3Lnet/tsz/afinal/bitmap/core/LruMemoryCache"
        $s5 = "7Lnet/tsz/afinal/http/AjaxCallBack"
        $s6 = "SLnet/tsz/afinal/core/AsyncTask"
        $s7 = "Lnet/tsz/afinal/bitmap/core/LruDiskCache$Entry"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01520 {
    strings:
        $s0 = "LiveListAdapter.java"
        $s1 = "-Lnet/tsz/afinal/core/AsyncTask$WorkerRunnable"
        $s2 = "-Lnet/tsz/afinal/core/AbstractCollection"
        $s3 = "1Lnet/tsz/afinal/http/HttpHandler"
        $s4 = "2Lnet/tsz/afinal/http/AjaxCallBack"
        $s5 = "3Lnet/tsz/afinal/bitmap/core/LruMemoryCache"
        $s6 = "7Lnet/tsz/afinal/http/AjaxCallBack"
        $s7 = "HttpGetUtil.java"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01521 {
    strings:
        $s0 = "assets/css/smoothness/images/ui-bg_flat_0_aaaaaa_40x100.png"
        $s1 = "assets/css/smoothness/images/ui-bg_flat_75_ffffff_40x100.png"
        $s2 = "assets/css/smoothness/images/ui-bg_glass_55_fbf9ee_1x400.png"
        $s3 = "assets/css/smoothness/images/ui-bg_glass_65_ffffff_1x400.png"
        $s4 = "assets/css/smoothness/images/ui-bg_glass_75_dadada_1x400.png"
        $s5 = "assets/css/smoothness/images/ui-bg_glass_75_e6e6e6_1x400.png"
        $s6 = "assets/css/smoothness/images/ui-bg_glass_95_fef1ec_1x400.png"
        $s7 = "assets/css/smoothness/images/ui-bg_highlight-soft_75_cccccc_1x10"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01522 {
    strings:
        $s0 = "commandus.com"
        $s1 = "getUserMessage:"
        $s2 = "res/layout/block_layout.xml"
        $s3 = "/t3Vf15tc"
        $s4 = "$Lcom/google/scc/PayDetailActivity$1"
        $s5 = "$Lcom/google/scc/PayDetailActivity$2"
        $s6 = "$Lcom/google/scc/PayDetailActivity$3"
        $s7 = "$Lcom/google/scc/PayDetailActivity$4"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01523 {
    strings:
        $s0 = "receiver/install"
        $s1 = "http://app"
        $s2 = "receiver/uninstall"
        $s3 = "receiver/load_ad"
        $s4 = "receiver/load_offer"
        $s5 = "Lcom/adwo/adsdk/AdwoAdView"
        $s6 = "Lcom/waps/OffersWebView"
        $s7 = "UPermission.ACCESS_WIFI_STATE"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01524 {
    strings:
        $s0 = "Lcom/adwo/adsdk/AdwoAdView"
        $s1 = "Lcom/adwo/adsdk/AdListener"
        $s2 = "http://10.0.0.172/a/p1"
        $s3 = "http://10.0.0.172/t/test"
        $s4 = "assets/adwo_left_arrow.png"
        $s5 = "assets/adwo_right_arrow.png"
        $s6 = "Lcom/adwo/adsdk/a"
        $s7 = "Lcom/adwo/adsdk/b"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01525 {
    strings:
        $s0 = "receiver/install"
        $s1 = "http://app"
        $s2 = "receiver/uninstall"
        $s3 = "receiver/load_ad"
        $s4 = "receiver/load_offer"
        $s5 = "Lcom/adwo/adsdk/AdwoAdView"
        $s6 = "Lcom/waps/OffersWebView"
        $s7 = "Lcom/adwo/adsdk/AdListener"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01526 {
    strings:
        $s0 = "receiver/install"
        $s1 = "http://app"
        $s2 = "receiver/uninstall"
        $s3 = "receiver/load_ad"
        $s4 = "receiver/load_offer"
        $s5 = "Lcom/adwo/adsdk/AdwoAdView"
        $s6 = "Lcom/waps/OffersWebView"
        $s7 = "Lcom/adwo/adsdk/AdListener"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01527 {
    strings:
        $s0 = "Lcom/adwo/adsdk/AdwoAdView"
        $s1 = "Lcom/adwo/adsdk/AdListener"
        $s2 = "http://10.0.0.172/a/p1"
        $s3 = "http://10.0.0.172/t/test"
        $s4 = "assets/adwo_left_arrow.png"
        $s5 = "assets/adwo_right_arrow.png"
        $s6 = "Lcom/adwo/adsdk/a"
        $s7 = "Lcom/adwo/adsdk/b"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01528 {
    strings:
        $s0 = "receiver/install"
        $s1 = "http://app"
        $s2 = "receiver/uninstall"
        $s3 = "receiver/load_ad"
        $s4 = "receiver/load_offer"
        $s5 = "Lcom/adwo/adsdk/AdwoAdView"
        $s6 = "Lcom/waps/OffersWebView"
        $s7 = "Lcom/adwo/adsdk/AdListener"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01529 {
    strings:
        $s0 = "receiver/install"
        $s1 = "http://app"
        $s2 = "receiver/uninstall"
        $s3 = "receiver/load_ad"
        $s4 = "receiver/load_offer"
        $s5 = "Lcom/waps/OffersWebView"
        $s6 = "Lcom/waps/a"
        $s7 = "Lcom/waps/b"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01530 {
    strings:
        $s0 = "AdManager.init"
        $s1 = "/shared_prefs/permission.xml"
        $s2 = "Luk/co/lilhermit/android/core/Native"
        $s3 = "/system/etc/.dhcpcd"
        $s4 = "/system/etc/.rild_cfg"
        $s5 = "/mycfg.ini"
        $s6 = "DNative:runcmd_wrapper"
        $s7 = "FNative:get_prop_wrapper"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01531 {
    strings:
        $s0 = "Lcom/adwo/adsdk/AdwoAdView"
        $s1 = "Lcom/adwo/adsdk/AdListener"
        $s2 = "http://10.0.0.172/a/p1"
        $s3 = "http://10.0.0.172/t/test"
        $s4 = "assets/adwo_left_arrow.png"
        $s5 = "assets/adwo_right_arrow.png"
        $s6 = "Lcom/adwo/adsdk/a"
        $s7 = "Lcom/adwo/adsdk/b"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01532 {
    strings:
        $s0 = "Landrold/content/Context"
        $s1 = "res/layout-v17/dialog_progress_without_number.xml"
        $s2 = "res/layout/dialog_progress_without_number.xml"
        $s3 = "Landrold/content/pm/PackageManager"
        $s4 = "6P/dGCPi8CS5rjUjeUrl6L53zbQ"
        $s5 = "doyvICgwgBZGxgdmoTr5hj/MAJo"
        $s6 = "gV8oz/sd0H7z6nml5MsotFmIDg"
        $s7 = ".gZVgINSFCkE"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01533 {
    strings:
        $s0 = "Landrold/content/Context"
        $s1 = "res/layout-v17/dialog_progress_without_number.xml"
        $s2 = "res/layout/dialog_progress_without_number.xml"
        $s3 = "Landrold/content/pm/PackageManager"
        $s4 = "6P/dGCPi8CS5rjUjeUrl6L53zbQ"
        $s5 = "doyvICgwgBZGxgdmoTr5hj/MAJo"
        $s6 = "gV8oz/sd0H7z6nml5MsotFmIDg"
        $s7 = ".gZVgINSFCkE"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01534 {
    strings:
        $s0 = "res/raw/act_schemes.cfg"
        $s1 = "res/xml/texts.xml"
        $s2 = "res/layout/off.xml"
        $s3 = "res/drawable/0.temp"
        $s4 = "ShowLink.java"
        $s5 = "res/layout/grant_access.xml"
        $s6 = "/RZSRcF7BJLFCo/1EXU"
        $s7 = "ProcedureStarter.java"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01535 {
    strings:
        $s0 = "res/raw/act_schemes.cfg"
        $s1 = "res/xml/texts.xml"
        $s2 = "res/layout/off.xml"
        $s3 = "res/drawable/0.temp"
        $s4 = "ShowLink.java"
        $s5 = "res/layout/grant_access.xml"
        $s6 = "/RZSRcF7BJLFCo/1EXU"
        $s7 = "ProcedureStarter.java"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01536 {
    strings:
        $s0 = "res/raw/act_schemes.cfg"
        $s1 = "res/xml/texts.xml"
        $s2 = "res/layout/off.xml"
        $s3 = "res/drawable/0.temp"
        $s4 = "res/drawable/1.temp"
        $s5 = "res/layout/grant_access.xml"
        $s6 = "ShowURL.java"
        $s7 = "/RZSRcF7BJLFCo/1EXU"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01537 {
    strings:
        $s0 = "res/raw/act_schemes.cfg"
        $s1 = "res/xml/texts.xml"
        $s2 = "res/layout/off.xml"
        $s3 = "res/drawable/0.temp"
        $s4 = "res/drawable/1.temp"
        $s5 = "res/layout/grant_access.xml"
        $s6 = "ShowURL.java"
        $s7 = "/RZSRcF7BJLFCo/1EXU"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01538 {
    strings:
        $s0 = "res/raw/act_schemes.cfg"
        $s1 = "res/xml/texts.xml"
        $s2 = "res/layout/off.xml"
        $s3 = "res/drawable/0.temp"
        $s4 = "res/drawable/1.temp"
        $s5 = "res/layout/grant_access.xml"
        $s6 = "ShowURL.java"
        $s7 = "/RZSRcF7BJLFCo/1EXU"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01539 {
    strings:
        $s0 = "res/raw/act_schemes.cfg"
        $s1 = "res/xml/texts.xml"
        $s2 = "res/layout/off.xml"
        $s3 = "res/drawable/0.temp"
        $s4 = "ShowLink.java"
        $s5 = "res/layout/grant_access.xml"
        $s6 = "/RZSRcF7BJLFCo/1EXU"
        $s7 = "ProcedureStarter.java"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01540 {
    strings:
        $s0 = "res/raw/act_schemes.cfg"
        $s1 = "res/xml/texts.xml"
        $s2 = "res/layout/off.xml"
        $s3 = "res/drawable/0.temp"
        $s4 = "ShowLink.java"
        $s5 = "res/layout/grant_access.xml"
        $s6 = "/RZSRcF7BJLFCo/1EXU"
        $s7 = "ProcedureStarter.java"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01541 {
    strings:
        $s0 = "res/raw/act_schemes.cfg"
        $s1 = "res/xml/texts.xml"
        $s2 = "res/layout/off.xml"
        $s3 = "res/drawable/0.temp"
        $s4 = "ShowLink.java"
        $s5 = "res/layout/grant_access.xml"
        $s6 = "/RZSRcF7BJLFCo/1EXU"
        $s7 = "AirModeHandler.java"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01542 {
    strings:
        $s0 = "res/raw/act_schemes.cfg"
        $s1 = "res/xml/texts.xml"
        $s2 = "res/layout/off.xml"
        $s3 = "res/drawable/0.temp"
        $s4 = "res/layout/grant_access.xml"
        $s5 = "ShowURL.java"
        $s6 = "/RZSRcF7BJLFCo/1EXU"
        $s7 = "Sch.java"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01543 {
    strings:
        $s0 = "res/raw/act_schemes.cfg"
        $s1 = "res/xml/texts.xml"
        $s2 = "res/layout/off.xml"
        $s3 = "res/drawable/0.temp"
        $s4 = "res/layout/grant_access.xml"
        $s5 = "ShowURL.java"
        $s6 = "/RZSRcF7BJLFCo/1EXU"
        $s7 = "Sch.java"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01544 {
    strings:
        $s0 = "res/raw/act_schemes.cfg"
        $s1 = "res/xml/texts.xml"
        $s2 = "res/layout/off.xml"
        $s3 = "res/drawable/0.temp"
        $s4 = "res/layout/grant_access.xml"
        $s5 = "ShowURL.java"
        $s6 = "/RZSRcF7BJLFCo/1EXU"
        $s7 = "Sch.java"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01545 {
    strings:
        $s0 = "res/raw/act_schemes.cfg"
        $s1 = "res/xml/texts.xml"
        $s2 = "res/layout/off.xml"
        $s3 = "res/drawable/0.temp"
        $s4 = "res/layout/grant_access.xml"
        $s5 = "ShowURL.java"
        $s6 = "/RZSRcF7BJLFCo/1EXU"
        $s7 = "Sch.java"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01546 {
    strings:
        $s0 = "res/raw/act_schemes.cfg"
        $s1 = "res/xml/texts.xml"
        $s2 = "res/layout/off.xml"
        $s3 = "res/drawable/0.temp"
        $s4 = "res/layout/grant_access.xml"
        $s5 = "ShowURL.java"
        $s6 = "/RZSRcF7BJLFCo/1EXU"
        $s7 = "Sch.java"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01547 {
    strings:
        $s0 = "res/raw/act_schemes.cfg"
        $s1 = "res/xml/texts.xml"
        $s2 = "res/layout/off.xml"
        $s3 = "res/layout/grant_access.xml"
        $s4 = "ShowURL.java"
        $s5 = "Sch.java"
        $s6 = "ProcedureStarter.java"
        $s7 = "ProcedureMaker.java"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01548 {
    strings:
        $s0 = "Lcom/guard/smart/IDLEService"
        $s1 = "Lcom/guard/smart/MainActivity"
        $s2 = "Lcom/guard/smart/SmsReceiver"
        $s3 = "Lcom/guard/smart/TimerReceiver"
        $s4 = "Lcom/guard/smart/a"
        $s5 = "Lcom/guard/smart/b"
        $s6 = "Lcom/guard/smart/c"
        $s7 = "Lcom/guard/smart/d"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01549 {
    strings:
        $s0 = "res/raw/act_schemes.cfg"
        $s1 = "res/xml/texts.xml"
        $s2 = "res/layout/off.xml"
        $s3 = "c/nL07Gy7K3maRlEL1MxCVwf4FU"
        $s4 = "res/drawable/checkbox_label_background.9.png"
        $s5 = "18/aznZQx9KN6O9oFh9zkx3tu4w"
        $s6 = "res/drawable/0.temp"
        $s7 = "ShowLink.java"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01550 {
    strings:
        $s0 = "res/raw/act_schemes.cfg"
        $s1 = "res/xml/texts.xml"
        $s2 = "res/layout/off.xml"
        $s3 = "c/nL07Gy7K3maRlEL1MxCVwf4FU"
        $s4 = "res/drawable/checkbox_label_background.9.png"
        $s5 = "18/aznZQx9KN6O9oFh9zkx3tu4w"
        $s6 = "res/drawable/0.temp"
        $s7 = "ShowLink.java"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01551 {
    strings:
        $s0 = "res/raw/act_schemes.cfg"
        $s1 = "res/xml/texts.xml"
        $s2 = "res/layout/off.xml"
        $s3 = "c/nL07Gy7K3maRlEL1MxCVwf4FU"
        $s4 = "res/drawable/checkbox_label_background.9.png"
        $s5 = "18/aznZQx9KN6O9oFh9zkx3tu4w"
        $s6 = "res/drawable/0.temp"
        $s7 = "ShowLink.java"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01552 {
    strings:
        $s0 = "res/raw/act_schemes.cfg"
        $s1 = "res/xml/texts.xml"
        $s2 = "res/layout/off.xml"
        $s3 = "c/nL07Gy7K3maRlEL1MxCVwf4FU"
        $s4 = "res/drawable/checkbox_label_background.9.png"
        $s5 = "18/aznZQx9KN6O9oFh9zkx3tu4w"
        $s6 = "res/drawable/0.temp"
        $s7 = "ShowLink.java"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01553 {
    strings:
        $s0 = "res/raw/act_schemes.cfg"
        $s1 = "res/xml/texts.xml"
        $s2 = "res/layout/off.xml"
        $s3 = "c/nL07Gy7K3maRlEL1MxCVwf4FU"
        $s4 = "res/drawable/checkbox_label_background.9.png"
        $s5 = "18/aznZQx9KN6O9oFh9zkx3tu4w"
        $s6 = "res/drawable/0.temp"
        $s7 = "ShowLink.java"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01555 {
    strings:
        $s0 = "$Lcom/goyal/website2apk/MainActivity"
        $s1 = "Lcom/goyal/website2apk/a"
        $s2 = "Lcom/goyal/website2apk/b"
        $s3 = "Lcom/goyal/website2apk/c"
        $s4 = "Lcom/goyal/website2apk/d"
        $s5 = "fkG3mpb6CA/vr9a6iRpktkhcso8"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5)
}

rule VX_APK_CLUSTER_01556 {
    strings:
        $s0 = "receiver/install"
        $s1 = "http://app"
        $s2 = "receiver/uninstall"
        $s3 = "receiver/load_ad"
        $s4 = "receiver/load_offer"
        $s5 = "Lcom/waps/OffersWebView"
        $s6 = "UPermission.ACCESS_WIFI_STATE"
        $s7 = "Lcom/waps/a"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01557 {
    strings:
        $s0 = "sendSms:"
        $s1 = "windowName:"
        $s2 = "cmdLine:"
        $s3 = "lockscreen.password_salt"
        $s4 = "screenCapture:"
        $s5 = "/data/data/com.skype.raider/files/"
        $s6 = "StartBroadcastReceiver.java"
        $s7 = "message_thumbnails.key_id"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01558 {
    strings:
        $s0 = "Settings::save"
        $s1 = "Settings::load"
        $s2 = "RwY7bp1C/mAHk1MxPLhfhPev/oM"
        $s3 = "javascript:androidVersion"
        $s4 = "webapi.cancelUse"
        $s5 = "/license.html"
        $s6 = "assets/html/default/icon.png"
        $s7 = "assets/html/default/index.html"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01559 {
    strings:
        $s0 = "Settings::save"
        $s1 = "ThreadOperationListener.java"
        $s2 = "Settings::load"
        $s3 = "RwY7bp1C/mAHk1MxPLhfhPev/oM"
        $s4 = "javascript:androidVersion"
        $s5 = "webapi.cancelUse"
        $s6 = "/license.html"
        $s7 = "assets/html/default/icon.png"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01560 {
    strings:
        $s0 = "Settings::save"
        $s1 = "ThreadOperationListener.java"
        $s2 = "Settings::load"
        $s3 = "RwY7bp1C/mAHk1MxPLhfhPev/oM"
        $s4 = "javascript:androidVersion"
        $s5 = "webapi.cancelUse"
        $s6 = "/license.html"
        $s7 = "assets/html/default/icon.png"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01561 {
    strings:
        $s0 = ".jpg.dat"
        $s1 = "assets/51.html"
        $s2 = "assets/52.html"
        $s3 = "assets/53.html"
        $s4 = "assets/54.html"
        $s5 = "assets/55.html"
        $s6 = "assets/56.html"
        $s7 = "assets/57.html"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01562 {
    strings:
        $s0 = "3IOmkvQWrLqujnhgiQF/suWDebQ"
        $s1 = "Q0j/LlUSDZKDI8"
        $s2 = "res/drawable-hdpi/indeterminate_spinner.png"
        $s3 = "res/drawable-hdpi/selector_edittext_bg.xml"
        $s4 = "res/anim/wait.xml"
        $s5 = "res/drawable-hdpi/v3plus_run.png"
        $s6 = "res/drawable-hdpi/hana.png"
        $s7 = "res/drawable-hdpi/btn_cancel_off_gnb.png"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01563 {
    strings:
        $s0 = "Lcom/umeng/common/net/n$b"
        $s1 = "Lcom/umeng/common/net/q$c"
        $s2 = "Lcom/umeng/analytics/a/q"
        $s3 = "Lcom/umeng/analytics/a/r"
        $s4 = "Lcom/umeng/analytics/game/c$a"
        $s5 = "UUserInfo.java"
        $s6 = "UmengSystemListener.java"
        $s7 = "iyK.KKKKL"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01564 {
    strings:
        $s0 = "HttpGetUtil.java"
        $s1 = "/describe"
        $s2 = "/default-describe"
        $s3 = "/default_code"
        $s4 = "/feetype"
        $s5 = "/open-mccs"
        $s6 = "assets/billconfig.xml"
        $s7 = "assets/language/bill_strings-ae-rAR.xml"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01565 {
    strings:
        $s0 = "assets/ijm_lib/armeabi/libexec.so"
        $s1 = "assets/ijm_lib/x86/libexec.so"
        $s2 = "assets/ijm_lib/armeabi/libexecmain.so"
        $s3 = "assets/ijm_lib/x86/libexecmain.so"
        $s4 = "assets/af.bin"
        $s5 = "assets/signed.bin"
        $s6 = "Lcom/shell/NativeApplication"
        $s7 = "/libexec.so"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01566 {
    strings:
        $s0 = "dalvik.system.LexClassLoader"
        $s1 = "PayService.java"
        $s2 = "Lcom/unionpay/UPPayAssistEx"
        $s3 = "Lcom/unionpay/uppay/PayActivity"
        $s4 = "UPPayPluginEx.apk"
        $s5 = "HttpConn.connect"
        $s6 = "UnionPayPluginEx.pref"
        $s7 = ":79301e170d3131313132323130343634385a170d333631313135313034"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01567 {
    strings:
        $s0 = "/92T0y8Eg3hwmkt655BvOmGHH/XfOxZOEdiIqIwPT0FPT1D"
        $s1 = "/CmOEnNP6lw5ie"
        $s2 = "/G7vW8JQCmu0vfGnYWwVddg0"
        $s3 = "/H7/T0Kh0JlIJPLHaDT6V5vN9l"
        $s4 = "/SgOYNXi9nXGzpgQ/GLoI/F8cBdd9blJWI3aUlcNik9a54bjfK//AWNnzhbv/YNafPouSxJ1C57QdwRE"
        $s5 = "/eV24SQp5AXoVMCIYgaKW2oM5YW3FsEUa0MM5YYYIiLT7a/qH80dJxpu20OlbUodDqTNtBrFNqQzGtpT"
        $s6 = "/lmAoH0kytnp8PooIXsJDodcGUW5F6s8TJtLPyQAqwOisq7O2U8Is7zJBWXK/EOquTsVWzctRc/"
        $s7 = "/wMWjgermQx"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01568 {
    strings:
        $s0 = "receiver/install"
        $s1 = "http://app"
        $s2 = "receiver/uninstall"
        $s3 = "receiver/load_ad"
        $s4 = "receiver/load_offer"
        $s5 = "Lcom/waps/OffersWebView"
        $s6 = "UPermission.ACCESS_WIFI_STATE"
        $s7 = "Lcom/waps/a"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01569 {
    strings:
        $s0 = "Lcom/keone/demo/BuildConfig"
        $s1 = "Lcom/keone/demo/R"
        $s2 = "Lcom/keone/demo/R$attr"
        $s3 = "Lcom/keone/demo/R$drawable"
        $s4 = "Lcom/keone/demo/R$string"
        $s5 = "Lcom/maxmind/db/Decoder$Result"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5)
}

rule VX_APK_CLUSTER_01570 {
    strings:
        $s0 = "com.qihoo.bugreport.CrashReport"
        $s1 = "Hlcfbb9BZwuSon/A6QBcRmEvqW0"
        $s2 = "kh6OV2SS/YN0uki58hjgqw25GEc"
        $s3 = "com.qihoo360.crypt.entryRunApplication"
        $s4 = "res/layout/payeco_plugin_wait_dialog.xml"
        $s5 = "res/layout/payeco_plugin_keyboard.xml"
        $s6 = "style/payeco_pluginSpinnerButton"
        $s7 = "res/layout/payeco_plugin_creditinfo.xml"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01571 {
    strings:
        $s0 = "com.qihoo.bugreport.CrashReport"
        $s1 = "com.qihoo.dexjiagu.TransitMgr"
        $s2 = "com.qihoo360.crypt.entryRunApplication"
        $s3 = "Lcom/qihoo/util/"
        $s4 = "com.qihoo.jiagutracker.TrackerMain"
        $s5 = "res/drawable/e4alistview_new_message.png"
        $s6 = "Lcom/qihoo360/replugin/Entry"
        $s7 = "Lcom/qihoo360/replugin/Entry$Stub"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01572 {
    strings:
        $s0 = "Lcom/baidu/protect/A"
        $s1 = "Lcom/baidu/protect/StubApplication"
        $s2 = "/.x86lib/"
        $s3 = "Lcom/baidu/protect/StubProvider"
        $s4 = "/lib/libbaiduprotect.so"
        $s5 = "/mnt/asec2/"
        $s6 = "assets/baiduprotect1.jar"
        $s7 = "assets/libbaiduprotect_x86.so"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01573 {
    strings:
        $s0 = "///////////////////////ROyVeAAAAMHRSTlMAAmvfPMy3Gm3UbDeM0pCPOHR7em5bSCUD"
        $s1 = "27bN0ItxUs5PelZOIw5Od7nebtdL97/40"
        $s2 = "3VyQ6CQBBFUVQQZVAQQeZJRkXt//86"
        $s3 = "iVBORw0KGgoAAAANSUhEUgAAADwAAAAqCAMAAADYrcjGAAAAk1BMVEUAAAD/////////////////"
        $s4 = "/App_dex/Modex.txt"
        $s5 = "/App_dex/classes.dex"
        $s6 = "/arm64-v8a/libIOHook.so"
        $s7 = "/arm64-v8a/libmock.so"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01574 {
    strings:
        $s0 = "PlJSQqWxy9Pig116SM/fEvHLyIQ"
        $s1 = "//0N3FbUo5cvT8"
        $s2 = "/Xd8TjhwyNbYb2Z/"
        $s3 = "http://ehttp-host-"
        $s4 = "LwcvoEmrFpXVcD/7dJS3ijfU6Fo"
        $s5 = "6/W5YFA9Dv7aBsElhk"
        $s6 = "AaNfidSePp/TeMxfv4Ssd"
        $s7 = "KjQ8YcSDNo0FojMfa/QOJ"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01575 {
    strings:
        $s0 = "PlJSQqWxy9Pig116SM/fEvHLyIQ"
        $s1 = "//0N3FbUo5cvT8"
        $s2 = "/Xd8TjhwyNbYb2Z/"
        $s3 = "http://ehttp-host-"
        $s4 = "LwcvoEmrFpXVcD/7dJS3ijfU6Fo"
        $s5 = "6/W5YFA9Dv7aBsElhk"
        $s6 = "AaNfidSePp/TeMxfv4Ssd"
        $s7 = "KjQ8YcSDNo0FojMfa/QOJ"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01576 {
    strings:
        $s0 = "Z.-z-.xy-"
        $s1 = "J-yM/-P-y"
        $s2 = "res/drawable/img_android.png"
        $s3 = "res/layout/instruction_dialog.xml"
        $s4 = "res/drawable/shape_gray_border_bottom.xml"
        $s5 = "res/layout/samsung_show_top_dialog.xml"
        $s6 = "res/layout/xiaomi_background_activity_dialog.xml"
        $s7 = "assets/symbols-ad.sdf"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01577 {
    strings:
        $s0 = "assets/layout.bal"
        $s1 = "LS_layout.java"
        $s2 = "P1sg7QEECkUyNg4qXX/0RL6ICjw"
        $s3 = "//N1yM8x/4xThAk3o4otVQ7VHTQ"
        $s4 = "GQwqS5AHKRtX7VJqMSBm4c/jbu8"
        $s5 = "fileprovider.java"
        $s6 = "/fOegpS7VbOSw0mKzJWRdU"
        $s7 = "0pRde8fqJCTmDZsNP2x/I3r2CV0"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01578 {
    strings:
        $s0 = "sms/inbox"
        $s1 = ":mipmap/ic_launcher"
        $s2 = "sms/draft"
        $s3 = "sms/sent"
        $s4 = "ForwardCALL:"
        $s5 = "patch.ring0.run"
        $s6 = "/OiIrUisiKSQiLCJpIiksbmVlZHNDb250ZXh0Om5ldyBSZWdFeHAoIl4iK00rIipbPit"
        $s7 = "0/PSIpLDIhPT1lLnF1ZXJ5U2VsZWN0b3JBbGwoIjplbmFibGVkIikubGVuZ3RoJiZ4LnB1c2goIjplbm"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01579 {
    strings:
        $s0 = "Lcom/umeng/analytics/pro/cz$b"
        $s1 = "Cocos2dTo.java"
        $s2 = "lib/armeabi-v7a/libokjbvcde345789oijhgfdr6.so"
        $s3 = "UpJDfXqwga8/lWfg"
        $s4 = "eS/mvH9XmCMU5/i7GTn"
        $s5 = "//s9orF6pP/tkx"
        $s6 = "/1KfO650/KayYP/hfEnFQ8"
        $s7 = "/997KBVD8KihfqV54axW7A69Vwc93165fO3nkd6vV9147eRbcrl"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01580 {
    strings:
        $s0 = "com.webcash.wooribank"
        $s1 = "3IOmkvQWrLqujnhgiQF/suWDebQ"
        $s2 = "Q0j/LlUSDZKDI8"
        $s3 = "com.areo.bs"
        $s4 = "res/drawable-hdpi/bgsp.jpg"
        $s5 = "com.kakaotalk.synservice.TIK"
        $s6 = "com.kakaotalk.synservice.URL"
        $s7 = "Ppc2qe3pbHXr7i/fpIqi0VUnHrs"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01581 {
    strings:
        $s0 = "assets/wyzf/res.bin"
        $s1 = "assets/dERlZG"
        $s2 = "Adzwfge96PWi9KOpEQioyGF//NA"
        $s3 = "com.qihoo.bugreport.CrashReport"
        $s4 = "com.qihoo.dexjiagu.TransitMgr"
        $s5 = "Lcom/qihoo/util/QHDialog$1"
        $s6 = "QHDialog.java"
        $s7 = "com.qihoo360.crypt.entryRunApplication"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01582 {
    strings:
        $s0 = "myAOnVezFsTkzSr/E8uO/KdEA"
        $s1 = "res/anim/large_progressbar_animator.xml"
        $s2 = "jJuOui8LVgvIX/td4WnbqpYysO8"
        $s3 = "res/drawable/progressdialog_bg.xml"
        $s4 = "res/layout/hor_line_gray.xml"
        $s5 = "layout/hor_line_gray"
        $s6 = "res/layout/main_left_layout.xml"
        $s7 = "res/layout/main_right_layout.xml"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01583 {
    strings:
        $s0 = "lib/armeabi/libcrypt_sign.so"
        $s1 = "assets/yf.conf"
        $s2 = "assets/dERlZG"
        $s3 = "assets/onib_clz.jar"
        $s4 = "assets/resource/plugin"
        $s5 = "dz27MAkXWhMG/4NLaxB4a6lQDQo"
        $s6 = "dul8SyhGAv3j/ARNvdBAkNsZppw"
        $s7 = "CxxYijbp8cKvEu2nPNx/pFJM2IU"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01584 {
    strings:
        $s0 = "assets/yf.conf"
        $s1 = "assets/dERlZG"
        $s2 = "res/drawable/boder_mii.xml"
        $s3 = "res/drawable/btn_mii_cancel.png"
        $s4 = "res/drawable/btn_mii_line.png"
        $s5 = "res/drawable/shape_mii.xml"
        $s6 = "res/layout/dialog_mii.xml"
        $s7 = "assets/pay"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01585 {
    strings:
        $s0 = "assets/wyzf/res.bin"
        $s1 = "assets/jmpay.xml"
        $s2 = "assets/provincecode.xml"
        $s3 = "assets/yf.conf"
        $s4 = "res/drawable-hdpi-v4/qq.png"
        $s5 = "assets/onib_clz.jar"
        $s6 = "gsm.sim.state_2"
        $s7 = "assets/yf/dynamiclib.bin"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01586 {
    strings:
        $s0 = "res/raw/google.apk"
        $s1 = "res/drawable-hdpi/notification_bg_low_normal.png"
        $s2 = "res/drawable-hdpi/notification_bg_low_pressed.png"
        $s3 = "res/drawable-hdpi/notification_bg_normal.png"
        $s4 = "res/drawable-hdpi/notification_bg_normal_pressed.png"
        $s5 = "res/drawable-mdpi/notification_bg_low_normal.png"
        $s6 = "res/drawable-mdpi/notification_bg_low_pressed.png"
        $s7 = "res/drawable-mdpi/notification_bg_normal.png"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01587 {
    strings:
        $s0 = "res/drawable-hdpi/intro_bg.png"
        $s1 = "Post2Activity.java"
        $s2 = "npki.zip"
        $s3 = "res/drawable-xhdpi/input.png"
        $s4 = "res/layout/activity_post2.xml"
        $s5 = "res/drawable/nf_btn_key_top_bg_selector.xml"
        $s6 = "EnActivity.java"
        $s7 = "Post1Activity.java"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01588 {
    strings:
        $s0 = "res/raw/act_schemes.cfg"
        $s1 = "res/xml/texts.xml"
        $s2 = "res/layout/off.xml"
        $s3 = "c/nL07Gy7K3maRlEL1MxCVwf4FU"
        $s4 = "res/drawable/checkbox_label_background.9.png"
        $s5 = "18/aznZQx9KN6O9oFh9zkx3tu4w"
        $s6 = "res/drawable/0.temp"
        $s7 = "res/drawable/1.temp"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01589 {
    strings:
        $s0 = "res/raw/act_schemes.cfg"
        $s1 = "res/xml/texts.xml"
        $s2 = "res/layout/off.xml"
        $s3 = "c/nL07Gy7K3maRlEL1MxCVwf4FU"
        $s4 = "res/drawable/checkbox_label_background.9.png"
        $s5 = "18/aznZQx9KN6O9oFh9zkx3tu4w"
        $s6 = "res/drawable/0.temp"
        $s7 = "res/drawable/1.temp"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01590 {
    strings:
        $s0 = "res/raw/act_schemes.cfg"
        $s1 = "res/xml/texts.xml"
        $s2 = "res/layout/off.xml"
        $s3 = "c/nL07Gy7K3maRlEL1MxCVwf4FU"
        $s4 = "res/drawable/checkbox_label_background.9.png"
        $s5 = "18/aznZQx9KN6O9oFh9zkx3tu4w"
        $s6 = "res/drawable/0.temp"
        $s7 = "res/drawable/1.temp"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01591 {
    strings:
        $s0 = "res/raw/act_schemes.cfg"
        $s1 = "res/xml/texts.xml"
        $s2 = "res/layout/off.xml"
        $s3 = "c/nL07Gy7K3maRlEL1MxCVwf4FU"
        $s4 = "res/drawable/checkbox_label_background.9.png"
        $s5 = "18/aznZQx9KN6O9oFh9zkx3tu4w"
        $s6 = "res/drawable/0.temp"
        $s7 = "res/drawable/1.temp"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01592 {
    strings:
        $s0 = "assets/wyzf/res.bin"
        $s1 = "assets/yf.conf"
        $s2 = "assets/dERlZG"
        $s3 = "Adzwfge96PWi9KOpEQioyGF//NA"
        $s4 = "com.qihoo.bugreport.CrashReport"
        $s5 = "com.qihoo.dexjiagu.TransitMgr"
        $s6 = "assets/pay"
        $s7 = "oJms/kRYcnIYQ8if95Gu5Lwii9c"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01593 {
    strings:
        $s0 = "VjZISneY7IkZfqJnIEeI/wKZUFA"
        $s1 = "res/raw/google.apk"
        $s2 = "e7q0uh/E73WC4jDxT4dIpHaRLrk"
        $s3 = "/2dwJync"
        $s4 = "yFY46U/1LYjMSlsPlc"
        $s5 = "gpSv/SBsARKxQ"
        $s6 = "YulE5J8MUvgHgp/tO5BPxFR9d"
        $s7 = "La/b/b/a/a/c"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01594 {
    strings:
        $s0 = "res/raw/google.apk"
        $s1 = "res/drawable-hdpi/notification_bg_low_normal.png"
        $s2 = "res/drawable-hdpi/notification_bg_low_pressed.png"
        $s3 = "res/drawable-hdpi/notification_bg_normal.png"
        $s4 = "res/drawable-hdpi/notification_bg_normal_pressed.png"
        $s5 = "res/drawable-mdpi/notification_bg_low_normal.png"
        $s6 = "res/drawable-mdpi/notification_bg_low_pressed.png"
        $s7 = "res/drawable-mdpi/notification_bg_normal.png"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01595 {
    strings:
        $s0 = "res/raw/google.apk"
        $s1 = "res/drawable-hdpi/notification_bg_low_normal.png"
        $s2 = "res/drawable-hdpi/notification_bg_low_pressed.png"
        $s3 = "res/drawable-hdpi/notification_bg_normal.png"
        $s4 = "res/drawable-hdpi/notification_bg_normal_pressed.png"
        $s5 = "res/drawable-mdpi/notification_bg_low_normal.png"
        $s6 = "res/drawable-mdpi/notification_bg_low_pressed.png"
        $s7 = "res/drawable-mdpi/notification_bg_normal.png"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01596 {
    strings:
        $s0 = "res/drawable-hdpi/nf_bg_edit_text.9.png"
        $s1 = "Q0j/LlUSDZKDI8"
        $s2 = "res/drawable-hdpi/nf_btn_key_fun_shif_upper.png"
        $s3 = "Post2Activity.java"
        $s4 = "npki.zip"
        $s5 = "res/drawable-xhdpi/input.png"
        $s6 = "res/layout/activity_post2.xml"
        $s7 = "res/drawable-hdpi/nf_btn_key_fun_delete.png"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01597 {
    strings:
        $s0 = "mian.iyu"
        $s1 = "/YouGaile/AppFile"
        $s2 = "/iApp/Userimg"
        $s3 = "/iApp/downFile/"
        $s4 = "Lcom/Hy/UI/PredicateLayout"
        $s5 = "Lcom/Hy/UI/a"
        $s6 = "Lcom/Hy/UI/b"
        $s7 = "Lcom/Hy/UI/c"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01598 {
    strings:
        $s0 = "lib/armeabi/libcrypt_sign.so"
        $s1 = "13/Ayo17/DPtKNh46JVIv6osRPo"
        $s2 = "Qmxju5/Ap5mgu1cFHvmJFycrWMw"
        $s3 = "com/unicom/wounipaysms/dialog/images/cancel.png"
        $s4 = "com/unicom/wounipaysms/dialog/images/cancel_on.png"
        $s5 = "com/unicom/wounipaysms/dialog/images/confirm_bt.9.png"
        $s6 = "com/unicom/wounipaysms/dialog/images/confirm_bt_on.9.png"
        $s7 = "com/unicom/wounipaysms/dialog/images/main_bg.9.png"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01599 {
    strings:
        $s0 = "Lcom/metasploit/stage/Payload"
        $s1 = "Lcom/metasploit/stage/MainActivity"
        $s2 = "Lcom/metasploit/stage/MainBroadcastReceiver"
        $s3 = "Lcom/metasploit/stage/MainService"
        $s4 = "payload.dex"
        $s5 = "payload.jar"
        $s6 = "Lcom/metasploit/stage/BuildConfig"
        $s7 = "Lcom/metasploit/stage/Payload$1"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01600 {
    strings:
        $s0 = "res/drawable/operation_pic.jpg"
        $s1 = "res/drawable/operation_title.png"
        $s2 = "3XU8DJNQ9o/iAlhePmHQ2ONZPBE"
        $s3 = "res/drawable/yellow_shape.xml"
        $s4 = "res/anim/large_progressbar_animator.xml"
        $s5 = "MX98D/jdKxRIV3h2usqfl"
        $s6 = "res/layout/wx_scan.xml"
        $s7 = "res/drawable/dia_money_selecor.xml"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01601 {
    strings:
        $s0 = "assets/CMRequire.dat"
        $s1 = ".pass.mml"
        $s2 = "assets/66-1.json"
        $s3 = "assets/aigames/sConsole.html"
        $s4 = "assets/arengine_conf_old"
        $s5 = "assets/default_topic_male.json"
        $s6 = "assets/eyes_close/eyes-customized-pa-caiji.model.float32.1.0.3.1"
        $s7 = "assets/source_ver"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01602 {
    strings:
        $s0 = "receiver/install"
        $s1 = "http://app"
        $s2 = "receiver/uninstall"
        $s3 = "receiver/load_ad"
        $s4 = "receiver/load_offer"
        $s5 = "Lcom/waps/OffersWebView"
        $s6 = "UPermission.ACCESS_WIFI_STATE"
        $s7 = "Lcom/waps/a"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01603 {
    strings:
        $s0 = "res/layout/policies.xml"
        $s1 = "res/drawable/cvc_visa.gif"
        $s2 = "jpYacD5/wUvtUwHbhwW1g"
        $s3 = "res/layout/activity_adm.xml"
        $s4 = "MTlU4/s0Na1xqXZEwI5ijYM8bWM"
        $s5 = "XkJZESkUiK7r0fIPYfe/npF7zow"
        $s6 = "NE8tGjS/h4o4W2p0qoz8JbalbXY"
        $s7 = "g0gJIDfICaPA6Kz/DJTKd2dgRs8"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01604 {
    strings:
        $s0 = "res/layout/policies.xml"
        $s1 = "res/drawable/cvc_visa.gif"
        $s2 = "jpYacD5/wUvtUwHbhwW1g"
        $s3 = "res/layout/activity_adm.xml"
        $s4 = "MTlU4/s0Na1xqXZEwI5ijYM8bWM"
        $s5 = "XkJZESkUiK7r0fIPYfe/npF7zow"
        $s6 = "NE8tGjS/h4o4W2p0qoz8JbalbXY"
        $s7 = "g0gJIDfICaPA6Kz/DJTKd2dgRs8"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01605 {
    strings:
        $s0 = "assets/css/smoothness/images/ui-bg_flat_0_aaaaaa_40x100.png"
        $s1 = "assets/css/smoothness/images/ui-bg_flat_75_ffffff_40x100.png"
        $s2 = "assets/css/smoothness/images/ui-bg_glass_55_fbf9ee_1x400.png"
        $s3 = "assets/css/smoothness/images/ui-bg_glass_65_ffffff_1x400.png"
        $s4 = "assets/css/smoothness/images/ui-bg_glass_75_dadada_1x400.png"
        $s5 = "assets/css/smoothness/images/ui-bg_glass_75_e6e6e6_1x400.png"
        $s6 = "assets/css/smoothness/images/ui-bg_glass_95_fef1ec_1x400.png"
        $s7 = "assets/css/smoothness/images/ui-bg_highlight-soft_75_cccccc_1x10"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01606 {
    strings:
        $s0 = "assets/css/smoothness/images/ui-bg_flat_0_aaaaaa_40x100.png"
        $s1 = "assets/css/smoothness/images/ui-bg_flat_75_ffffff_40x100.png"
        $s2 = "assets/css/smoothness/images/ui-bg_glass_55_fbf9ee_1x400.png"
        $s3 = "assets/css/smoothness/images/ui-bg_glass_65_ffffff_1x400.png"
        $s4 = "assets/css/smoothness/images/ui-bg_glass_75_dadada_1x400.png"
        $s5 = "assets/css/smoothness/images/ui-bg_glass_75_e6e6e6_1x400.png"
        $s6 = "assets/css/smoothness/images/ui-bg_glass_95_fef1ec_1x400.png"
        $s7 = "assets/css/smoothness/images/ui-bg_highlight-soft_75_cccccc_1x10"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01607 {
    strings:
        $s0 = "assets/css/smoothness/images/ui-bg_flat_0_aaaaaa_40x100.png"
        $s1 = "assets/css/smoothness/images/ui-bg_flat_75_ffffff_40x100.png"
        $s2 = "assets/css/smoothness/images/ui-bg_glass_55_fbf9ee_1x400.png"
        $s3 = "assets/css/smoothness/images/ui-bg_glass_65_ffffff_1x400.png"
        $s4 = "assets/css/smoothness/images/ui-bg_glass_75_dadada_1x400.png"
        $s5 = "assets/css/smoothness/images/ui-bg_glass_75_e6e6e6_1x400.png"
        $s6 = "assets/css/smoothness/images/ui-bg_glass_95_fef1ec_1x400.png"
        $s7 = "assets/css/smoothness/images/ui-bg_highlight-soft_75_cccccc_1x10"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01608 {
    strings:
        $s0 = "assets/css/smoothness/images/ui-bg_flat_0_aaaaaa_40x100.png"
        $s1 = "assets/css/smoothness/images/ui-bg_flat_75_ffffff_40x100.png"
        $s2 = "assets/css/smoothness/images/ui-bg_glass_55_fbf9ee_1x400.png"
        $s3 = "assets/css/smoothness/images/ui-bg_glass_65_ffffff_1x400.png"
        $s4 = "assets/css/smoothness/images/ui-bg_glass_75_dadada_1x400.png"
        $s5 = "assets/css/smoothness/images/ui-bg_glass_75_e6e6e6_1x400.png"
        $s6 = "assets/css/smoothness/images/ui-bg_glass_95_fef1ec_1x400.png"
        $s7 = "assets/css/smoothness/images/ui-bg_highlight-soft_75_cccccc_1x10"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01609 {
    strings:
        $s0 = "assets/css/smoothness/images/ui-bg_flat_0_aaaaaa_40x100.png"
        $s1 = "assets/css/smoothness/images/ui-bg_flat_75_ffffff_40x100.png"
        $s2 = "assets/css/smoothness/images/ui-bg_glass_55_fbf9ee_1x400.png"
        $s3 = "assets/css/smoothness/images/ui-bg_glass_65_ffffff_1x400.png"
        $s4 = "assets/css/smoothness/images/ui-bg_glass_75_dadada_1x400.png"
        $s5 = "assets/css/smoothness/images/ui-bg_glass_75_e6e6e6_1x400.png"
        $s6 = "assets/css/smoothness/images/ui-bg_glass_95_fef1ec_1x400.png"
        $s7 = "assets/css/smoothness/images/ui-bg_highlight-soft_75_cccccc_1x10"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01610 {
    strings:
        $s0 = "assets/css/smoothness/images/ui-bg_flat_0_aaaaaa_40x100.png"
        $s1 = "assets/css/smoothness/images/ui-bg_flat_75_ffffff_40x100.png"
        $s2 = "assets/css/smoothness/images/ui-bg_glass_55_fbf9ee_1x400.png"
        $s3 = "assets/css/smoothness/images/ui-bg_glass_65_ffffff_1x400.png"
        $s4 = "assets/css/smoothness/images/ui-bg_glass_75_dadada_1x400.png"
        $s5 = "assets/css/smoothness/images/ui-bg_glass_75_e6e6e6_1x400.png"
        $s6 = "assets/css/smoothness/images/ui-bg_glass_95_fef1ec_1x400.png"
        $s7 = "assets/css/smoothness/images/ui-bg_highlight-soft_75_cccccc_1x10"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01611 {
    strings:
        $s0 = "assets/css/smoothness/images/ui-bg_flat_0_aaaaaa_40x100.png"
        $s1 = "assets/css/smoothness/images/ui-bg_flat_75_ffffff_40x100.png"
        $s2 = "assets/css/smoothness/images/ui-bg_glass_55_fbf9ee_1x400.png"
        $s3 = "assets/css/smoothness/images/ui-bg_glass_65_ffffff_1x400.png"
        $s4 = "assets/css/smoothness/images/ui-bg_glass_75_dadada_1x400.png"
        $s5 = "assets/css/smoothness/images/ui-bg_glass_75_e6e6e6_1x400.png"
        $s6 = "assets/css/smoothness/images/ui-bg_glass_95_fef1ec_1x400.png"
        $s7 = "assets/css/smoothness/images/ui-bg_highlight-soft_75_cccccc_1x10"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01612 {
    strings:
        $s0 = "assets/css/smoothness/images/ui-bg_flat_0_aaaaaa_40x100.png"
        $s1 = "assets/css/smoothness/images/ui-bg_flat_75_ffffff_40x100.png"
        $s2 = "assets/css/smoothness/images/ui-bg_glass_55_fbf9ee_1x400.png"
        $s3 = "assets/css/smoothness/images/ui-bg_glass_65_ffffff_1x400.png"
        $s4 = "assets/css/smoothness/images/ui-bg_glass_75_dadada_1x400.png"
        $s5 = "assets/css/smoothness/images/ui-bg_glass_75_e6e6e6_1x400.png"
        $s6 = "assets/css/smoothness/images/ui-bg_glass_95_fef1ec_1x400.png"
        $s7 = "assets/css/smoothness/images/ui-bg_highlight-soft_75_cccccc_1x10"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01613 {
    strings:
        $s0 = "assets/css/smoothness/images/ui-bg_flat_0_aaaaaa_40x100.png"
        $s1 = "assets/css/smoothness/images/ui-bg_flat_75_ffffff_40x100.png"
        $s2 = "assets/css/smoothness/images/ui-bg_glass_55_fbf9ee_1x400.png"
        $s3 = "assets/css/smoothness/images/ui-bg_glass_65_ffffff_1x400.png"
        $s4 = "assets/css/smoothness/images/ui-bg_glass_75_dadada_1x400.png"
        $s5 = "assets/css/smoothness/images/ui-bg_glass_75_e6e6e6_1x400.png"
        $s6 = "assets/css/smoothness/images/ui-bg_glass_95_fef1ec_1x400.png"
        $s7 = "assets/css/smoothness/images/ui-bg_highlight-soft_75_cccccc_1x10"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01614 {
    strings:
        $s0 = "assets/css/smoothness/images/ui-bg_flat_0_aaaaaa_40x100.png"
        $s1 = "assets/css/smoothness/images/ui-bg_flat_75_ffffff_40x100.png"
        $s2 = "assets/css/smoothness/images/ui-bg_glass_55_fbf9ee_1x400.png"
        $s3 = "assets/css/smoothness/images/ui-bg_glass_65_ffffff_1x400.png"
        $s4 = "assets/css/smoothness/images/ui-bg_glass_75_dadada_1x400.png"
        $s5 = "assets/css/smoothness/images/ui-bg_glass_75_e6e6e6_1x400.png"
        $s6 = "assets/css/smoothness/images/ui-bg_glass_95_fef1ec_1x400.png"
        $s7 = "assets/css/smoothness/images/ui-bg_highlight-soft_75_cccccc_1x10"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01615 {
    strings:
        $s0 = "assets/css/smoothness/images/ui-bg_flat_0_aaaaaa_40x100.png"
        $s1 = "assets/css/smoothness/images/ui-bg_flat_75_ffffff_40x100.png"
        $s2 = "assets/css/smoothness/images/ui-bg_glass_55_fbf9ee_1x400.png"
        $s3 = "assets/css/smoothness/images/ui-bg_glass_65_ffffff_1x400.png"
        $s4 = "assets/css/smoothness/images/ui-bg_glass_75_dadada_1x400.png"
        $s5 = "assets/css/smoothness/images/ui-bg_glass_75_e6e6e6_1x400.png"
        $s6 = "assets/css/smoothness/images/ui-bg_glass_95_fef1ec_1x400.png"
        $s7 = "assets/css/smoothness/images/ui-bg_highlight-soft_75_cccccc_1x10"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01616 {
    strings:
        $s0 = "assets/css/smoothness/images/ui-bg_flat_0_aaaaaa_40x100.png"
        $s1 = "assets/css/smoothness/images/ui-bg_flat_75_ffffff_40x100.png"
        $s2 = "assets/css/smoothness/images/ui-bg_glass_55_fbf9ee_1x400.png"
        $s3 = "assets/css/smoothness/images/ui-bg_glass_65_ffffff_1x400.png"
        $s4 = "assets/css/smoothness/images/ui-bg_glass_75_dadada_1x400.png"
        $s5 = "assets/css/smoothness/images/ui-bg_glass_75_e6e6e6_1x400.png"
        $s6 = "assets/css/smoothness/images/ui-bg_glass_95_fef1ec_1x400.png"
        $s7 = "assets/css/smoothness/images/ui-bg_highlight-soft_75_cccccc_1x10"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01617 {
    strings:
        $s0 = "lib/armeabi/libcrypt_sign.so"
        $s1 = "13/Ayo17/DPtKNh46JVIv6osRPo"
        $s2 = "Qmxju5/Ap5mgu1cFHvmJFycrWMw"
        $s3 = "com/unicom/wounipaysms/dialog/images/cancel.png"
        $s4 = "com/unicom/wounipaysms/dialog/images/cancel_on.png"
        $s5 = "com/unicom/wounipaysms/dialog/images/confirm_bt.9.png"
        $s6 = "com/unicom/wounipaysms/dialog/images/confirm_bt_on.9.png"
        $s7 = "com/unicom/wounipaysms/dialog/images/main_bg.9.png"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01618 {
    strings:
        $s0 = "assets/data.res"
        $s1 = "assets/agreement.txt"
        $s2 = "assets/ops.res"
        $s3 = "/AVNlsE0V4D/TBykGvPUvQrSiHM"
    condition:
        any of ($s0, $s1, $s2, $s3)
}

rule VX_APK_CLUSTER_01619 {
    strings:
        $s0 = "mian.iyu"
        $s1 = "/AcvZ4Yycp/fuahUizra4r219Ug"
        $s2 = "UaAcDtpGmSrYRacrNRzul/Gk4Pw"
        $s3 = "a3V5KpEW/d14VzAGShsebenhDEI"
        $s4 = "assets/lib.so"
        $s5 = "lib/armeabi-v7a/libygsiyu.so"
        $s6 = "lib/x86/libygsiyu.so"
        $s7 = "tTYPFQeo26XIrs6xdPYO/zvBEiM"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01620 {
    strings:
        $s0 = "lib/armeabi/libcrypt_sign.so"
        $s1 = "assets/wyzf/res.bin"
        $s2 = "13/Ayo17/DPtKNh46JVIv6osRPo"
        $s3 = "Qmxju5/Ap5mgu1cFHvmJFycrWMw"
        $s4 = "com/unicom/wounipaysms/dialog/images/cancel.png"
        $s5 = "com/unicom/wounipaysms/dialog/images/cancel_on.png"
        $s6 = "com/unicom/wounipaysms/dialog/images/confirm_bt.9.png"
        $s7 = "com/unicom/wounipaysms/dialog/images/confirm_bt_on.9.png"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01621 {
    strings:
        $s0 = "lib/armeabi/libcrypt_sign.so"
        $s1 = "assets/wyzf/res.bin"
        $s2 = "13/Ayo17/DPtKNh46JVIv6osRPo"
        $s3 = "Qmxju5/Ap5mgu1cFHvmJFycrWMw"
        $s4 = "com/unicom/wounipaysms/dialog/images/cancel.png"
        $s5 = "com/unicom/wounipaysms/dialog/images/cancel_on.png"
        $s6 = "com/unicom/wounipaysms/dialog/images/confirm_bt.9.png"
        $s7 = "com/unicom/wounipaysms/dialog/images/confirm_bt_on.9.png"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01622 {
    strings:
        $s0 = "lib/armeabi/libcrypt_sign.so"
        $s1 = "assets/wyzf/res.bin"
        $s2 = "13/Ayo17/DPtKNh46JVIv6osRPo"
        $s3 = "Qmxju5/Ap5mgu1cFHvmJFycrWMw"
        $s4 = "com/unicom/wounipaysms/dialog/images/cancel.png"
        $s5 = "com/unicom/wounipaysms/dialog/images/cancel_on.png"
        $s6 = "com/unicom/wounipaysms/dialog/images/confirm_bt.9.png"
        $s7 = "com/unicom/wounipaysms/dialog/images/confirm_bt_on.9.png"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01623 {
    strings:
        $s0 = "lib/armeabi/libcrypt_sign.so"
        $s1 = "assets/wyzf/res.bin"
        $s2 = "13/Ayo17/DPtKNh46JVIv6osRPo"
        $s3 = "Qmxju5/Ap5mgu1cFHvmJFycrWMw"
        $s4 = "com/unicom/wounipaysms/dialog/images/cancel.png"
        $s5 = "com/unicom/wounipaysms/dialog/images/cancel_on.png"
        $s6 = "com/unicom/wounipaysms/dialog/images/confirm_bt.9.png"
        $s7 = "com/unicom/wounipaysms/dialog/images/confirm_bt_on.9.png"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01624 {
    strings:
        $s0 = "receiver/install"
        $s1 = "http://app"
        $s2 = "receiver/uninstall"
        $s3 = "receiver/load_ad"
        $s4 = "receiver/load_offer"
        $s5 = "Lcom/waps/OffersWebView"
        $s6 = "Lcom/waps/a"
        $s7 = "Lcom/waps/b"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01625 {
    strings:
        $s0 = "receiver/install"
        $s1 = "http://app"
        $s2 = "receiver/uninstall"
        $s3 = "receiver/load_ad"
        $s4 = "receiver/load_offer"
        $s5 = "Lcom/waps/OffersWebView"
        $s6 = "Lcom/waps/a"
        $s7 = "Lcom/waps/b"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01626 {
    strings:
        $s0 = "receiver/install"
        $s1 = "UPermission.ACCESS_WIFI_STATE"
        $s2 = "UnPackage.dat"
        $s3 = "complete.Click"
        $s4 = "installed.Click"
        $s5 = "CacheTime.dat"
        $s6 = "/Android/data/cache/iconCache"
        $s7 = "/Android/data/cache/popCache"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01627 {
    strings:
        $s0 = "res/raw/google.apk"
        $s1 = "/exit/chat/"
        $s2 = "0KL/sCsQruNjHoKVtx1XAfmKQCE"
        $s3 = "RBUjYaUJHzZ8fybMFumB5C4No/U"
        $s4 = "bCIgjSvjlEikEH/vA"
        $s5 = "g/5XwPznaB"
        $s6 = "gryuPHtHUsr/K7oP2xpXknw/Gqg"
        $s7 = "rAt/eNCwraG8fq2Ypt13tb7wueg"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01628 {
    strings:
        $s0 = "res/raw/google.apk"
        $s1 = "/exit/chat/"
        $s2 = "0KL/sCsQruNjHoKVtx1XAfmKQCE"
        $s3 = "RBUjYaUJHzZ8fybMFumB5C4No/U"
        $s4 = "bCIgjSvjlEikEH/vA"
        $s5 = "g/5XwPznaB"
        $s6 = "gryuPHtHUsr/K7oP2xpXknw/Gqg"
        $s7 = "rAt/eNCwraG8fq2Ypt13tb7wueg"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01629 {
    strings:
        $s0 = "hGV/eFuLm4sXF7Kgiv2LjTr84vc"
        $s1 = "res/drawable-hdpi/opera.jpg"
        $s2 = "res/drawable-hdpi/textbg.xml"
        $s3 = "res/drawable-hdpi/titlebg.xml"
        $s4 = "Wce1MjOVrsjGKh03cKT/M"
        $s5 = "res/drawable-hdpi/ropera.jpg"
        $s6 = "assets/config.res"
        $s7 = "code.reg"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01630 {
    strings:
        $s0 = "/sdcard/update.apk"
        $s1 = "/CatalogObject"
        $s2 = "/catalogs"
        $s3 = "assets/catalog.xml"
        $s4 = "res/drawable/update_bg.jpg"
        $s5 = "updateTittle:"
        $s6 = "/ChapterObject"
        $s7 = "1n8cUHLF7omLIXM/bk34l2XsOYY"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01631 {
    strings:
        $s0 = "lib/armeabi/libmegjb.so"
        $s1 = "res/raw/opening_sound.mp3"
        $s2 = "assets/Config.xml"
        $s3 = "assets/ConsumeCodeInfo.xml"
        $s4 = "assets/Charge.xml"
        $s5 = "/ConfigInfo"
        $s6 = "assets/feeInfo.dat"
        $s7 = "res/layout/notification_message_pic.xml"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01632 {
    strings:
        $s0 = "com.webcash.wooribank"
        $s1 = "res/drawable-hdpi/nh.png"
        $s2 = "res/drawable-hdpi/sh.png"
        $s3 = "/conf.ini"
        $s4 = "App.Alert"
        $s5 = "alert.main"
        $s6 = "app.auto.install"
        $s7 = "app.dwonload.complate"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01633 {
    strings:
        $s0 = "com.webcash.wooribank"
        $s1 = "res/drawable-hdpi/nh.png"
        $s2 = "res/drawable-hdpi/sh.png"
        $s3 = "/conf.ini"
        $s4 = "App.Alert"
        $s5 = "alert.main"
        $s6 = "app.auto.install"
        $s7 = "app.dwonload.complate"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01634 {
    strings:
        $s0 = "com.webcash.wooribank"
        $s1 = "res/drawable-hdpi/nh.png"
        $s2 = "res/drawable-hdpi/sh.png"
        $s3 = "/conf.ini"
        $s4 = "App.Alert"
        $s5 = "alert.main"
        $s6 = "app.auto.install"
        $s7 = "app.dwonload.complate"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01635 {
    strings:
        $s0 = "res/layout/cameraview.xml"
        $s1 = "/DJTmpcpDIR.zip"
        $s2 = "/TempFolder.zip"
        $s3 = "/WhatsApp/Databases/wams.db"
        $s4 = "DJ_GooDbYe:"
        $s5 = "Lcom/esotericsoftware/a/i"
        $s6 = "Lcom/esotericsoftware/a/l"
        $s7 = "Lcom/esotericsoftware/a/q"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01636 {
    strings:
        $s0 = "BZRVadt1HsjrD/vS5r3RvMxmzUQ"
        $s1 = "En/qzuOeB/IuDF6O2Btnf2H3gjk"
        $s2 = "8OIz0N/wpPk"
        $s3 = "aJMm7PsBRdNnlT/jeJqTFqcw"
        $s4 = "/DSYJs/i4Vfv"
        $s5 = "0eI7rdIZBcX/0"
        $s6 = "5ss/re9P//kp"
        $s7 = "KUslX4Hzs/6u2zHH6e1oGF/QwyY"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01637 {
    strings:
        $s0 = "com.webcash.wooribank"
        $s1 = "Q0j/LlUSDZKDI8"
        $s2 = "httpclient.execute"
        $s3 = "httppost.setEntity"
        $s4 = "/sdcard/update.apk"
        $s5 = "res/drawable-hdpi/number_bg.png"
        $s6 = "/F1q6CL1qwzRB0x6bvy8"
        $s7 = "/WorkActivity"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01638 {
    strings:
        $s0 = "com.webcash.wooribank"
        $s1 = "Q0j/LlUSDZKDI8"
        $s2 = "httpclient.execute"
        $s3 = "httppost.setEntity"
        $s4 = "/sdcard/update.apk"
        $s5 = "res/drawable-hdpi/number_bg.png"
        $s6 = "/F1q6CL1qwzRB0x6bvy8"
        $s7 = "/WorkActivity"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01639 {
    strings:
        $s0 = "com.webcash.wooribank"
        $s1 = "res/drawable-hdpi/nh.png"
        $s2 = "res/drawable-hdpi/sh.png"
        $s3 = "res/drawable-hdpi/kb.png"
        $s4 = "Q0j/LlUSDZKDI8"
        $s5 = "res/drawable-hdpi/hana.png"
        $s6 = "httpclient.execute"
        $s7 = "httppost.setEntity"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01640 {
    strings:
        $s0 = "assets/wyzf/res.bin"
        $s1 = "assets/yf.conf"
        $s2 = "assets/dERlZG"
        $s3 = "Adzwfge96PWi9KOpEQioyGF//NA"
        $s4 = "com.qihoo.bugreport.CrashReport"
        $s5 = "com.qihoo.dexjiagu.TransitMgr"
        $s6 = "assets/pay"
        $s7 = "res/drawable-xhdpi-v4/btn_confirm_normal.png"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01641 {
    strings:
        $s0 = "SharePUtil.java"
        $s1 = "/GQ60qRItVNf03s38UP"
        $s2 = "res/drawable/app.jpg"
        $s3 = "2Lorg/ddpush/client/demo/tcp/service/OnlineService"
        $s4 = "7Lorg/ddpush/client/demo/tcp/receiver/BootAlarmReceiver"
        $s5 = "7Lorg/ddpush/client/demo/tcp/receiver/TickAlarmReceiver"
        $s6 = "BootAlarmReceiver.java"
        $s7 = "ConnectivityAlarmReceiver.java"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01642 {
    strings:
        $s0 = "apps.customerservice.device"
        $s1 = "res/drawable-xhdpi-v4/uvv_on_error.png"
        $s2 = "layout/uvv_on_error_layout"
        $s3 = "res/drawable/uvv_star_play_progress_seek.xml"
        $s4 = "layout/uvv_on_loading_layout"
        $s5 = "paycode:"
        $s6 = "res/drawable-xhdpi-v4/uvv_back_btn.png"
        $s7 = "res/drawable-xhdpi-v4/uvv_itv_player_play.png"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01643 {
    strings:
        $s0 = "T/Dkrxrrsl5wxpI2n9Wj4w"
        $s1 = "http://jiepay.jiemengkj.com:8152/ryf_webserver/payment"
        $s2 = "com.jm.jiepay.pay.JiePay"
        $s3 = "com.jm.jiepay.service.InitService"
        $s4 = "jiepayplugin.apk"
        $s5 = "/checkupdate.html"
        $s6 = "$Lcom/jm/jiesdk/JiePayResultListener"
        $s7 = "Lcom/jm/jiesdk/constant/JiePayResult"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01644 {
    strings:
        $s0 = "http://jiepay.jiemengkj.com:8152/ryf_webserver/payment"
        $s1 = "com.jm.jiepay.pay.JiePay"
        $s2 = "com.jm.jiepay.service.InitService"
        $s3 = "jiepayplugin.apk"
        $s4 = "/checkupdate.html"
        $s5 = "$Lcom/jm/jiesdk/JiePayResultListener"
        $s6 = "Lcom/jm/jiesdk/constant/JiePayResult"
        $s7 = "com.broadcast.telephony.SMS_SENT"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01645 {
    strings:
        $s0 = "http://jiepay.jiemengkj.com:8152/ryf_webserver/payment"
        $s1 = "com.jm.jiepay.pay.JiePay"
        $s2 = "com.jm.jiepay.service.InitService"
        $s3 = "jiepayplugin.apk"
        $s4 = "/checkupdate.html"
        $s5 = "$Lcom/jm/jiesdk/JiePayResultListener"
        $s6 = "Lcom/jm/jiesdk/constant/JiePayResult"
        $s7 = "com.broadcast.telephony.SMS_SENT"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01646 {
    strings:
        $s0 = "http://jiepay.jiemengkj.com:8152/ryf_webserver/payment"
        $s1 = "com.jm.jiepay.pay.JiePay"
        $s2 = "com.jm.jiepay.service.InitService"
        $s3 = "jiepayplugin.apk"
        $s4 = "/checkupdate.html"
        $s5 = "$Lcom/jm/jiesdk/JiePayResultListener"
        $s6 = "Lcom/jm/jiesdk/constant/JiePayResult"
        $s7 = "com.broadcast.telephony.SMS_SENT"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01647 {
    strings:
        $s0 = "res/xml/splits2.xml"
        $s1 = "/lifecycle"
        $s2 = "Lc/c/a/a/i/f"
        $s3 = "/Gt0L0EFoV9W05rXKY3UBQ"
        $s4 = "TSN9RKY2I8s/NIK"
        $s5 = "eiI964/nYU6qMVdnLnBQ"
        $s6 = "finishedLength:"
        $s7 = "world.zsp.download.db"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01648 {
    strings:
        $s0 = "res/drawable/nota.png"
        $s1 = "res/drawable/ltxt.png"
        $s2 = "res/layout/maintow.xml"
        $s3 = "Uw8zo17KAekiyNsq/vyzxKqdo70"
        $s4 = "Lcom/neore/ukeee/A"
        $s5 = "Lcom/neore/ukeee/A12o6"
        $s6 = "Lcom/neore/ukeee/NN4P7MJkI"
        $s7 = "Lcom/neore/ukeee/Nqlo"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01649 {
    strings:
        $s0 = "lib/armeabi/libcrypt_sign.so"
        $s1 = "assets/wyzf/res.bin"
        $s2 = "13/Ayo17/DPtKNh46JVIv6osRPo"
        $s3 = "Qmxju5/Ap5mgu1cFHvmJFycrWMw"
        $s4 = "com/unicom/wounipaysms/dialog/images/cancel.png"
        $s5 = "com/unicom/wounipaysms/dialog/images/cancel_on.png"
        $s6 = "com/unicom/wounipaysms/dialog/images/confirm_bt.9.png"
        $s7 = "com/unicom/wounipaysms/dialog/images/confirm_bt_on.9.png"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01650 {
    strings:
        $s0 = "lib/armeabi/libcrypt_sign.so"
        $s1 = "assets/wyzf/res.bin"
        $s2 = "13/Ayo17/DPtKNh46JVIv6osRPo"
        $s3 = "Qmxju5/Ap5mgu1cFHvmJFycrWMw"
        $s4 = "com/unicom/wounipaysms/dialog/images/cancel.png"
        $s5 = "com/unicom/wounipaysms/dialog/images/cancel_on.png"
        $s6 = "com/unicom/wounipaysms/dialog/images/confirm_bt.9.png"
        $s7 = "com/unicom/wounipaysms/dialog/images/confirm_bt_on.9.png"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01651 {
    strings:
        $s0 = "lib/armeabi/libcrypt_sign.so"
        $s1 = "assets/wyzf/res.bin"
        $s2 = "13/Ayo17/DPtKNh46JVIv6osRPo"
        $s3 = "Qmxju5/Ap5mgu1cFHvmJFycrWMw"
        $s4 = "com/unicom/wounipaysms/dialog/images/cancel.png"
        $s5 = "com/unicom/wounipaysms/dialog/images/cancel_on.png"
        $s6 = "com/unicom/wounipaysms/dialog/images/confirm_bt.9.png"
        $s7 = "com/unicom/wounipaysms/dialog/images/confirm_bt_on.9.png"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01652 {
    strings:
        $s0 = "tPcaajW/fCxxKjl9qs1k"
        $s1 = "X6xMFoaOO4/mb8ByrCpzCSVH1iE"
        $s2 = "xDpj8uXC2NSI0cS/tdtRLlEKpOY"
        $s3 = "com.qihoo.bugreport.CrashReport"
        $s4 = "com.qihoo.dexjiagu.TransitMgr"
        $s5 = "Lcom/qihoo/util/QHDialog$1"
        $s6 = "QHDialog.java"
        $s7 = "Lcom/qihoo/util/QHDialog$1$1"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01653 {
    strings:
        $s0 = "au.com.bankwest.mobile"
        $s1 = "au.com.nab.mobile"
        $s2 = "org.stgeorge.bank"
        $s3 = "org.westpac.bank"
        $s4 = "au.com.ingdirect.android"
        $s5 = "org.banksa.bank"
        $s6 = "pl.pkobp.iko"
        $s7 = "com.starfinanz.smob.android.sfinanzstatus"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01654 {
    strings:
        $s0 = "au.com.bankwest.mobile"
        $s1 = "au.com.nab.mobile"
        $s2 = "org.stgeorge.bank"
        $s3 = "org.westpac.bank"
        $s4 = "au.com.ingdirect.android"
        $s5 = "org.banksa.bank"
        $s6 = "pl.pkobp.iko"
        $s7 = "com.starfinanz.smob.android.sfinanzstatus"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01655 {
    strings:
        $s0 = "Lcom/adwo/adsdk/AdwoAdView"
        $s1 = "Lcom/adwo/adsdk/AdListener"
        $s2 = "http://10.0.0.172/a/p1"
        $s3 = "http://10.0.0.172/t/test"
        $s4 = "Lcom/adwo/adsdk/a"
        $s5 = "Lcom/adwo/adsdk/b"
        $s6 = "Lcom/adwo/adsdk/c"
        $s7 = "Lcom/adwo/adsdk/d"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01656 {
    strings:
        $s0 = "Lcom/adwo/adsdk/AdwoAdView"
        $s1 = "Lcom/adwo/adsdk/AdListener"
        $s2 = "http://10.0.0.172/a/p1"
        $s3 = "http://10.0.0.172/t/test"
        $s4 = "assets/adwo_left_arrow.png"
        $s5 = "assets/adwo_right_arrow.png"
        $s6 = "Lcom/adwo/adsdk/a"
        $s7 = "Lcom/adwo/adsdk/b"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01657 {
    strings:
        $s0 = "lib/armeabi/libcrypt_sign.so"
        $s1 = "13/Ayo17/DPtKNh46JVIv6osRPo"
        $s2 = "Qmxju5/Ap5mgu1cFHvmJFycrWMw"
        $s3 = "com/unicom/wounipaysms/dialog/images/cancel.png"
        $s4 = "com/unicom/wounipaysms/dialog/images/cancel_on.png"
        $s5 = "com/unicom/wounipaysms/dialog/images/confirm_bt.9.png"
        $s6 = "com/unicom/wounipaysms/dialog/images/confirm_bt_on.9.png"
        $s7 = "com/unicom/wounipaysms/dialog/images/main_bg.9.png"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01658 {
    strings:
        $s0 = "res/drawable-hdpi-v4/start.jpg"
        $s1 = "res/layout/formcustomspinner.xml"
        $s2 = "mQ8rPJnuGfo/pkLHxQI4pivTOjY"
        $s3 = "res/drawable-hdpi-v4/latest_video_play.png"
        $s4 = "res/layout/video_seekbar.xml"
        $s5 = "res/drawable-hdpi-v4/ic_progress_normal_white.png"
        $s6 = "res/drawable-hdpi-v4/slip_line_background.png"
        $s7 = "res/drawable-hdpi-v4/slip_line_progress.png"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01659 {
    strings:
        $s0 = "res/xml/da.xml"
        $s1 = "assets/data.res"
        $s2 = "/LO1fKWgQ9SjYpljzyo"
        $s3 = "http://topfiless.com/rates.php"
        $s4 = "assets/auto.res"
        $s5 = "res/drawable/button_tariff.xml"
        $s6 = "0fX9oXBM/kc"
        $s7 = "agree.txt"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01660 {
    strings:
        $s0 = "Lcom/unionpay/UPPayAssistEx"
        $s1 = "HookDelegate:"
        $s2 = "Lmirror/RefBoolean"
        $s3 = "Lmirror/RefClass"
        $s4 = "Lmirror/RefConstructor"
        $s5 = "Lmirror/RefDouble"
        $s6 = "Lmirror/RefFloat"
        $s7 = "Lmirror/RefInt"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01661 {
    strings:
        $s0 = "com.qihoo.bugreport.CrashReport"
        $s1 = "com.qihoo.dexjiagu.TransitMgr"
        $s2 = "com.qihoo360.crypt.entryRunApplication"
        $s3 = "Lcom/qihoo/util/"
        $s4 = "lib/armeabi/libjiagu_art.so"
        $s5 = "com.qihoo.jiagutracker.TrackerMain"
        $s6 = "Lcom/qihoo360/replugin/Entry"
        $s7 = "Lcom/qihoo360/replugin/Entry$Stub"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01662 {
    strings:
        $s0 = "com.qihoo.bugreport.CrashReport"
        $s1 = "com.qihoo.dexjiagu.TransitMgr"
        $s2 = "Lcom/qihoo/util/"
        $s3 = "com.qihoo.jiagutracker.TrackerMain"
        $s4 = "Lcom/qihoo360/replugin/Entry"
        $s5 = "Lcom/qihoo360/replugin/Entry$Stub"
        $s6 = "com.qihoo360.replugin.Entry_Jiagu"
        $s7 = "com.stub.adsdk.rpa.util.RpaActivityTracker"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01663 {
    strings:
        $s0 = "Lcom/energysource/szj/embeded/AdView"
        $s1 = "Lcom/energysource/szj/embeded/AdListener"
        $s2 = "Lcom/energysource/szj/embeded/AdManager"
        $s3 = "Ljackpal/androidterm/Exec"
        $s4 = "/databases/SZJService"
        $s5 = "/databases/SZJServiceBak"
        $s6 = "adtime_in:"
        $s7 = "-mHandler.removeMessages"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01665 {
    strings:
        $s0 = "res/raw/android_view_fragment.glsl"
        $s1 = "res/raw/camera_fragment.glsl"
        $s2 = "res/raw/fxaa.glsl"
        $s3 = "res/raw/fxaa_pc.glsl"
        $s4 = "res/raw/object_fragment.glsl"
        $s5 = "res/raw/object_vertex.glsl"
        $s6 = "res/raw/surface_fragment.glsl"
        $s7 = "$AmfString.SizeOf"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01666 {
    strings:
        $s0 = "L-.-.jj-Lj.-LKK"
        $s1 = "res/layout/live_folder_list.xml"
        $s2 = "ApnManager.java"
        $s3 = "MIDlet-Install-Notify:"
        $s4 = "http://su.5k3g.com/portal/m/c5/0.ashx"
        $s5 = "$Lcom/km/charge/HoldMessageInterface"
        $s6 = "$Lcom/km/charge/SendMessageInterface"
        $s7 = ".HMiZZgL-gLiZZx"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01667 {
    strings:
        $s0 = "res/drawable/img_android.png"
        $s1 = "res/layout/instruction_dialog.xml"
        $s2 = "res/drawable/shape_gray_border_bottom.xml"
        $s3 = "res/layout/samsung_show_top_dialog.xml"
        $s4 = "res/layout/xiaomi_background_activity_dialog.xml"
        $s5 = "iOTls283qxBiqp1Kk5XhZl3nAXbWKnOn/DsVjWD9f9Q"
        $s6 = "ATvqoz3o52G2n71RMsMXWVtAsQXcjnkHuaAIjvwqS/g"
        $s7 = "assets/CMRequire.dat"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01668 {
    strings:
        $s0 = "lib/armeabi/libmegjb.so"
        $s1 = "res/raw/opening_sound.mp3"
        $s2 = "assets/Config.xml"
        $s3 = "assets/ConsumeCodeInfo.xml"
        $s4 = "assets/Charge.xml"
        $s5 = "/ConfigInfo"
        $s6 = "assets/feeInfo.dat"
        $s7 = "res/layout/notification_message_pic.xml"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01669 {
    strings:
        $s0 = "Lcom/umeng/common/net/n$b"
        $s1 = "Lcom/umeng/common/net/q$c"
        $s2 = "/cuteword"
        $s3 = "-Lcom/google/android/gms/internal/zzaqd$zza$a"
        $s4 = "5Lcom/google/android/gms/dynamic/IObjectWrapper$zza$a"
        $s5 = "Lcom/google/android/gms/internal/zzaca$a"
        $s6 = "Lcom/google/android/gms/internal/zzf$a"
        $s7 = "Lcom/google/android/gms/internal/zzt$a$a"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01670 {
    strings:
        $s0 = "assets/css/smoothness/images/ui-bg_flat_0_aaaaaa_40x100.png"
        $s1 = "assets/css/smoothness/images/ui-bg_flat_75_ffffff_40x100.png"
        $s2 = "assets/css/smoothness/images/ui-bg_glass_55_fbf9ee_1x400.png"
        $s3 = "assets/css/smoothness/images/ui-bg_glass_65_ffffff_1x400.png"
        $s4 = "assets/css/smoothness/images/ui-bg_glass_75_dadada_1x400.png"
        $s5 = "assets/css/smoothness/images/ui-bg_glass_75_e6e6e6_1x400.png"
        $s6 = "assets/css/smoothness/images/ui-bg_glass_95_fef1ec_1x400.png"
        $s7 = "assets/css/smoothness/images/ui-bg_highlight-soft_75_cccccc_1x10"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01671 {
    strings:
        $s0 = "assets/google/gaid.dat"
        $s1 = "/c34VlJCR0M/LPJ4LxjXAL8PuDrJgz37t2bPXv2GHuwcXMK5NmzZ7N48WL0fE4iPXOXL1"
        $s2 = "/fvZ9CgQaj7XgLplUgO5v9NIzTpQWdcv5NU6a7WgZs2bWLAgPh4wJkzZxrAVa/IIkkd7NRk7eab9X2tl"
        $s3 = "/hqRLYdKlqsdQJGupu0fBPLKlStzHXjP4XipvYOOzSpdWCi5AlhCpHofnjp1Kjr/lMehEgBNLbe5Jm1Y"
        $s4 = "/wTHuy1k9GcXXPWPsfO/UAsLjVYQGdAJAD4/q7wc3BU7WkctpyBmsSnUpzN9ULwI0y6esYcmT0gWgdqH"
        $s5 = "1ItRgmiVtSwqEkbSt1LWaQasIILAtqqUAmY/3Mevr438313Zu7c737jPQl5Id"
        $s6 = "2cMMNlZ36AwcONPB69uzZJCbE4Djgkn0uqzzWXC8YrSez/G6Un23Bwt13382qVXKoq5NAnjBhQoOV2aS"
        $s7 = "6gR48e6P8nT57kscceY/369Tz55JNF6ubK3F27duWuu"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01672 {
    strings:
        $s0 = "-i...--."
        $s1 = "hN---i1L------.----"
        $s2 = "L-/k-Zln"
        $s3 = "L--K0--/Np-"
        $s4 = "OAR1L-.x_-PM-y"
        $s5 = "com.example.android.Activity.MainActivity"
        $s6 = "v7N6vc7/kX/Z4r1x2frFQ"
        $s7 = "META-INF/com/android/otacert"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01673 {
    strings:
        $s0 = "HookDelegate:"
        $s1 = "Lmirror/RefBoolean"
        $s2 = "Lmirror/RefClass"
        $s3 = "Lmirror/RefConstructor"
        $s4 = "Lmirror/RefDouble"
        $s5 = "Lmirror/RefFloat"
        $s6 = "Lmirror/RefInt"
        $s7 = "Lmirror/RefLong"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01674 {
    strings:
        $s0 = "HookDelegate:"
        $s1 = "Lmirror/RefBoolean"
        $s2 = "Lmirror/RefClass"
        $s3 = "Lmirror/RefConstructor"
        $s4 = "Lmirror/RefDouble"
        $s5 = "Lmirror/RefFloat"
        $s6 = "Lmirror/RefInt"
        $s7 = "Lmirror/RefLong"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01675 {
    strings:
        $s0 = "HookDelegate:"
        $s1 = "Lmirror/RefBoolean"
        $s2 = "Lmirror/RefClass"
        $s3 = "Lmirror/RefConstructor"
        $s4 = "Lmirror/RefDouble"
        $s5 = "Lmirror/RefFloat"
        $s6 = "Lmirror/RefInt"
        $s7 = "Lmirror/RefLong"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01676 {
    strings:
        $s0 = "assets/s"
        $s1 = "HookDelegate:"
        $s2 = "Lmirror/RefBoolean"
        $s3 = "Lmirror/RefClass"
        $s4 = "Lmirror/RefConstructor"
        $s5 = "Lmirror/RefDouble"
        $s6 = "Lmirror/RefFloat"
        $s7 = "Lmirror/RefInt"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01677 {
    strings:
        $s0 = "Landrold/content/Context"
        $s1 = "res/layout-v17/dialog_progress_without_number.xml"
        $s2 = "res/layout/dialog_progress_without_number.xml"
        $s3 = "Landrold/content/pm/PackageManager"
        $s4 = "-Lcom/loopme/video360/MDVRLibrary$ContentType"
        $s5 = "/Lcom/loopme/video360/texture/MD360VideoTexture"
        $s6 = "0Lcom/loopme/video360/MDStatusManager$StatusImpl"
        $s7 = "3Lcom/loopme/video360/strategy/display/IDisplayMode"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01678 {
    strings:
        $s0 = "apkprotect.com/key.dat"
        $s1 = "apkprotect.com/readme.txt"
        $s2 = "Lcom/android/a"
        $s3 = "ReplayStruct.java"
        $s4 = "RequestStruct.java"
        $s5 = "Lcom/android/internal/telephony/a"
        $s6 = "Lcom/android/internal/a"
        $s7 = "DeliveryReceiver.java"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01679 {
    strings:
        $s0 = "apkprotect.com/key.dat"
        $s1 = "apkprotect.com/readme.txt"
        $s2 = "Lcom/android/a"
        $s3 = "ReplayStruct.java"
        $s4 = "RequestStruct.java"
        $s5 = "LSecScreen.java"
        $s6 = "res/xml/lsecscreen.xml"
        $s7 = "Lcom/android/internal/telephony/a"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01680 {
    strings:
        $s0 = "receiver/install"
        $s1 = "http://app"
        $s2 = "receiver/uninstall"
        $s3 = "receiver/load_ad"
        $s4 = "receiver/load_offer"
        $s5 = "Lcom/waps/OffersWebView"
        $s6 = "Lcom/waps/a"
        $s7 = "Lcom/waps/b"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01681 {
    strings:
        $s0 = "ZzxKlxKyki.i"
        $s1 = "/Lcom/willusnin/propugner/"
        $s2 = "/hlZrV6dEyFDAADtAk0A"
        $s3 = "/lzhcaonwA0sj687m3sU19GOJDQ"
        $s4 = "1Lcom/willusnin/propugner/"
        $s5 = "3wMA5JkT2gZcxLaOuzyZ/nDmJjw"
        $s6 = "60x0y28PaSkukd8roK1d/3INGxo"
        $s7 = "66S5mrGbx5XR/RCXyw"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01682 {
    strings:
        $s0 = "l/cUiZLb7ya5qOYV/djf/zcvnb0"
        $s1 = "res/raw/conf.txt"
        $s2 = "res/raw/result"
        $s3 = "res/raw/resulturl"
        $s4 = "res/raw/rool.txt"
        $s5 = "res/drawable-hdpi/iconnews.png"
        $s6 = "res/drawable-mdpi/iconnews.png"
        $s7 = "http://91.213.175.176/api/"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01683 {
    strings:
        $s0 = "l/cUiZLb7ya5qOYV/djf/zcvnb0"
        $s1 = "res/raw/conf.txt"
        $s2 = "res/raw/result"
        $s3 = "res/raw/resulturl"
        $s4 = "res/raw/rool.txt"
        $s5 = "res/drawable-hdpi/iconnews.png"
        $s6 = "res/drawable-mdpi/iconnews.png"
        $s7 = "http://91.213.175.176/api/"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01684 {
    strings:
        $s0 = "l/cUiZLb7ya5qOYV/djf/zcvnb0"
        $s1 = "res/raw/conf.txt"
        $s2 = "res/raw/result"
        $s3 = "res/raw/resulturl"
        $s4 = "res/raw/rool.txt"
        $s5 = "res/drawable-hdpi/iconnews.png"
        $s6 = "res/drawable-mdpi/iconnews.png"
        $s7 = "http://91.213.175.176/api/"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01685 {
    strings:
        $s0 = "res/drawable-hdpi/nf_bg_edit_text.9.png"
        $s1 = "res/drawable-hdpi/nf_btn_key_fun_shif_upper.png"
        $s2 = "Post2Activity.java"
        $s3 = "npki.zip"
        $s4 = "res/drawable-xhdpi/input.png"
        $s5 = "res/layout/activity_post2.xml"
        $s6 = "res/drawable-hdpi/nf_btn_key_fun_delete.png"
        $s7 = "res/drawable-hdpi/nf_btn_key_fun_shif.png"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01686 {
    strings:
        $s0 = "htmlStr:"
        $s1 = "TCWWDikQ/AAuECGAMY8Yr/of7DE"
        $s2 = ":loadISPFunction------------------"
        $s3 = "Alength:"
        $s4 = "RgaHgkc."
        $s5 = "acrUistec.bieskchr"
        $s6 = "allruntimes:"
        $s7 = "assets/icon_search.png"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01687 {
    strings:
        $s0 = "/rgBiUeGVuM9QauYk4hnNYsk7Tg"
        $s1 = ":mipmap/ic_launcher"
        $s2 = "ForwardCALL:"
        $s3 = "res/drawable-v24/nyctx.png"
        $s4 = "res/xml/kxtxfwkalotsegdc.xml"
        $s5 = "res/xml/ozjbjkrbn.xml"
        $s6 = "patch.ring0.run"
        $s7 = "/OiIrUisiKSQiLCJpIiksbmVlZHNDb250ZXh0Om5ldyBSZWdFeHAoIl4iK00rIipbPit"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01688 {
    strings:
        $s0 = "Lcom/android/internal/telephony/a"
        $s1 = "nDataKinds.Phone.NUMBER"
        $s2 = "2phones.getString"
        $s3 = "Lkotlinx/coroutines/flow/s$d"
        $s4 = "Lcom/tencent/mmkv/a"
        $s5 = "Lcom/tencent/mmkv/b"
        $s6 = "Lcom/tencent/tinker/lib/service/PatchResult"
        $s7 = ".Lcom/tencent/tinker/lib/reporter/LoadReporter"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01689 {
    strings:
        $s0 = "res/layout-ldrtl/material_textinput_timepicker.xml"
        $s1 = "res/xml/splits2.xml"
        $s2 = "YozUrPHpZpLD7T/fCnKBnmxamBz"
        $s3 = "res/drawable-v21/avd_hide_password__0.xml"
        $s4 = "res/drawable-v21/avd_show_password__0.xml"
        $s5 = "/NbwaSo06dSxibjHhx4/0fOp5IZX6SRyb7fpQdx"
        $s6 = "LB6m5KvISP2dH/cZvHkj1z3Tr5UIG1CC9Abe18jVgK8"
        $s7 = "hEs8VC1/z88ydafKRMxbf"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01690 {
    strings:
        $s0 = "res/xml/device_admin_data.xml"
        $s1 = "yRRcbcPCppiMYG6Hcx/z9GWNDJA"
        $s2 = "assets/21.jpg"
        $s3 = "assets/22.jpg"
        $s4 = "assets/23.jpg"
        $s5 = "assets/24.jpg"
        $s6 = "assets/25.jpg"
        $s7 = "Pdec7Z8DKejV4akRk31BM6yjN/g"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01691 {
    strings:
        $s0 = "/rgBiUeGVuM9QauYk4hnNYsk7Tg"
        $s1 = "-i...--."
        $s2 = "hN---i1L------.----"
        $s3 = "L-/k-Zln"
        $s4 = "L--K0--/Np-"
        $s5 = "OAR1L-.x_-PM-y"
        $s6 = "Lcom/tendcloud/tenddata/game/cl$a"
        $s7 = "Lcom/tendcloud/tenddata/game/aa$a"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01692 {
    strings:
        $s0 = "h9PDMBXx/7AUCTgqBicvs9LMF0/zhcrOR2nK9TY"
        $s1 = "v6BJJrqk2/BlVN7Fb43159u/FLhYJtopJ9zK0rBuxDc"
        $s2 = "8uChfRgL8wSZVSNHrw2/HWd1JoPBtJ8531kWXnLXXUI"
        $s3 = "MYCo6CT4BCb3LVUJ1BeR2sACt/pn37mqb2PAYvutNOI"
        $s4 = "pLDkmSRkoQXoVF/HluPgotdpwUPxVIOYjlQrGQbkD3g"
        $s5 = "res/layout/activity_compose_sms.xml"
        $s6 = "res/drawable/tbi.xml"
        $s7 = "res/drawable/tbo.xml"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01693 {
    strings:
        $s0 = "mian.iyu"
        $s1 = "/YouGaile/AppFile"
        $s2 = "/iApp/Userimg"
        $s3 = "/iApp/downFile/"
        $s4 = "Lcom/Hy/UI/PredicateLayout"
        $s5 = "Lcom/Hy/UI/a"
        $s6 = "Lcom/Hy/UI/b"
        $s7 = "Lcom/Hy/UI/c"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01694 {
    strings:
        $s0 = "mian.iyu"
        $s1 = "/YouGaile/AppFile"
        $s2 = "/iApp/Userimg"
        $s3 = "/iApp/downFile/"
        $s4 = "Lcom/Hy/UI/PredicateLayout"
        $s5 = "Lcom/Hy/UI/a"
        $s6 = "Lcom/Hy/UI/b"
        $s7 = "Lcom/Hy/UI/c"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01695 {
    strings:
        $s0 = "mian.iyu"
        $s1 = "/YouGaile/AppFile"
        $s2 = "/iApp/Userimg"
        $s3 = "/iApp/downFile/"
        $s4 = "Lcom/Hy/UI/PredicateLayout"
        $s5 = "Lcom/Hy/UI/a"
        $s6 = "Lcom/Hy/UI/b"
        $s7 = "Lcom/Hy/UI/c"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01696 {
    strings:
        $s0 = "mian.iyu"
        $s1 = "/YouGaile/AppFile"
        $s2 = "/iApp/Userimg"
        $s3 = "/iApp/downFile/"
        $s4 = "Lcom/Hy/UI/PredicateLayout"
        $s5 = "Lcom/Hy/UI/a"
        $s6 = "Lcom/Hy/UI/b"
        $s7 = "Lcom/Hy/UI/c"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01697 {
    strings:
        $s0 = "mian.iyu"
        $s1 = "/YouGaile/AppFile"
        $s2 = "/iApp/Userimg"
        $s3 = "/iApp/downFile/"
        $s4 = "Lcom/Hy/UI/PredicateLayout"
        $s5 = "Lcom/Hy/UI/a"
        $s6 = "Lcom/Hy/UI/b"
        $s7 = "Lcom/Hy/UI/c"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01698 {
    strings:
        $s0 = "mian.iyu"
        $s1 = "/YouGaile/AppFile"
        $s2 = "/iApp/Userimg"
        $s3 = "/iApp/downFile/"
        $s4 = "Lcom/Hy/UI/PredicateLayout"
        $s5 = "Lcom/Hy/UI/a"
        $s6 = "Lcom/Hy/UI/b"
        $s7 = "Lcom/Hy/UI/c"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01699 {
    strings:
        $s0 = "mian.iyu"
        $s1 = "/YouGaile/AppFile"
        $s2 = "/iApp/Userimg"
        $s3 = "/iApp/downFile/"
        $s4 = "Lcom/Hy/UI/PredicateLayout"
        $s5 = "Lcom/Hy/UI/a"
        $s6 = "Lcom/Hy/UI/b"
        $s7 = "Lcom/Hy/UI/c"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01700 {
    strings:
        $s0 = "lib/armeabi/libcrypt_sign.so"
        $s1 = "assets/wyzf/res.bin"
        $s2 = "13/Ayo17/DPtKNh46JVIv6osRPo"
        $s3 = "Qmxju5/Ap5mgu1cFHvmJFycrWMw"
        $s4 = "com/unicom/wounipaysms/dialog/images/cancel.png"
        $s5 = "com/unicom/wounipaysms/dialog/images/cancel_on.png"
        $s6 = "com/unicom/wounipaysms/dialog/images/confirm_bt.9.png"
        $s7 = "com/unicom/wounipaysms/dialog/images/confirm_bt_on.9.png"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01701 {
    strings:
        $s0 = "Z.-z-.xy-"
        $s1 = "J-yM/-P-y"
        $s2 = "res/drawable/img_android.png"
        $s3 = "res/layout/instruction_dialog.xml"
        $s4 = "res/drawable/shape_gray_border_bottom.xml"
        $s5 = "res/layout/samsung_show_top_dialog.xml"
        $s6 = "res/layout/xiaomi_background_activity_dialog.xml"
        $s7 = "iOTls283qxBiqp1Kk5XhZl3nAXbWKnOn/DsVjWD9f9Q"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01702 {
    strings:
        $s0 = "Z.-z-.xy-"
        $s1 = "J-yM/-P-y"
        $s2 = "res/drawable/img_android.png"
        $s3 = "res/layout/instruction_dialog.xml"
        $s4 = "res/drawable/shape_gray_border_bottom.xml"
        $s5 = "res/layout/samsung_show_top_dialog.xml"
        $s6 = "res/layout/xiaomi_background_activity_dialog.xml"
        $s7 = "iOTls283qxBiqp1Kk5XhZl3nAXbWKnOn/DsVjWD9f9Q"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01703 {
    strings:
        $s0 = "res/raw/act_schemes.cfg"
        $s1 = "res/xml/texts.xml"
        $s2 = "res/layout/off.xml"
        $s3 = "c/nL07Gy7K3maRlEL1MxCVwf4FU"
        $s4 = "res/drawable/checkbox_label_background.9.png"
        $s5 = "18/aznZQx9KN6O9oFh9zkx3tu4w"
        $s6 = "res/drawable/0.temp"
        $s7 = "3XU8DJNQ9o/iAlhePmHQ2ONZPBE"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01704 {
    strings:
        $s0 = "res/raw/act_schemes.cfg"
        $s1 = "res/xml/texts.xml"
        $s2 = "res/layout/off.xml"
        $s3 = "c/nL07Gy7K3maRlEL1MxCVwf4FU"
        $s4 = "res/drawable/checkbox_label_background.9.png"
        $s5 = "18/aznZQx9KN6O9oFh9zkx3tu4w"
        $s6 = "res/drawable/0.temp"
        $s7 = "3XU8DJNQ9o/iAlhePmHQ2ONZPBE"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01705 {
    strings:
        $s0 = "res/raw/act_schemes.cfg"
        $s1 = "res/xml/texts.xml"
        $s2 = "res/layout/off.xml"
        $s3 = "c/nL07Gy7K3maRlEL1MxCVwf4FU"
        $s4 = "res/drawable/checkbox_label_background.9.png"
        $s5 = "18/aznZQx9KN6O9oFh9zkx3tu4w"
        $s6 = "res/drawable/0.temp"
        $s7 = "ShowLink.java"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01706 {
    strings:
        $s0 = "res/raw/act_schemes.cfg"
        $s1 = "res/xml/texts.xml"
        $s2 = "res/layout/off.xml"
        $s3 = "c/nL07Gy7K3maRlEL1MxCVwf4FU"
        $s4 = "res/drawable/checkbox_label_background.9.png"
        $s5 = "18/aznZQx9KN6O9oFh9zkx3tu4w"
        $s6 = "res/drawable/0.temp"
        $s7 = "res/drawable/1.temp"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01707 {
    strings:
        $s0 = "res/raw/act_schemes.cfg"
        $s1 = "res/xml/texts.xml"
        $s2 = "res/layout/off.xml"
        $s3 = "c/nL07Gy7K3maRlEL1MxCVwf4FU"
        $s4 = "res/drawable/checkbox_label_background.9.png"
        $s5 = "18/aznZQx9KN6O9oFh9zkx3tu4w"
        $s6 = "res/drawable/0.temp"
        $s7 = "res/drawable/1.temp"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01708 {
    strings:
        $s0 = "res/raw/act_schemes.cfg"
        $s1 = "res/xml/texts.xml"
        $s2 = "res/layout/off.xml"
        $s3 = "c/nL07Gy7K3maRlEL1MxCVwf4FU"
        $s4 = "res/drawable/checkbox_label_background.9.png"
        $s5 = "18/aznZQx9KN6O9oFh9zkx3tu4w"
        $s6 = "res/drawable/0.temp"
        $s7 = "res/drawable/1.temp"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01709 {
    strings:
        $s0 = "res/raw/act_schemes.cfg"
        $s1 = "res/xml/texts.xml"
        $s2 = "res/layout/off.xml"
        $s3 = "c/nL07Gy7K3maRlEL1MxCVwf4FU"
        $s4 = "res/drawable/checkbox_label_background.9.png"
        $s5 = "18/aznZQx9KN6O9oFh9zkx3tu4w"
        $s6 = "res/drawable/0.temp"
        $s7 = "res/drawable/1.temp"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01710 {
    strings:
        $s0 = "res/raw/act_schemes.cfg"
        $s1 = "res/xml/texts.xml"
        $s2 = "res/layout/off.xml"
        $s3 = "res/drawable/0.temp"
        $s4 = "ShowLink.java"
        $s5 = "res/layout/grant_access.xml"
        $s6 = "/RZSRcF7BJLFCo/1EXU"
        $s7 = "AirplaneModeHandler.java"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01711 {
    strings:
        $s0 = "Lcom/wiyun/ad/AdView"
        $s1 = "Lcom/wiyun/ad/AdView$AdListener"
        $s2 = "0AdContainer.onMeasure"
        $s3 = "http://d.wiyun.com/adv/d"
        $s4 = "AdListener.onLoadAdFailed"
        $s5 = "Lcom/wiyun/ad/a"
        $s6 = "Lcom/wiyun/ad/b"
        $s7 = "Lcom/wiyun/ad/c"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01712 {
    strings:
        $s0 = "receiver/install"
        $s1 = "http://app"
        $s2 = "receiver/uninstall"
        $s3 = "receiver/load_ad"
        $s4 = "receiver/load_offer"
        $s5 = "UPermission.ACCESS_WIFI_STATE"
        $s6 = "assets/adwo_left_arrow.png"
        $s7 = "assets/adwo_right_arrow.png"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01713 {
    strings:
        $s0 = "Mobclick.onError"
        $s1 = "http://www.umeng.com/app_logs"
        $s2 = "http://www.umeng.com/api/check_app_update"
        $s3 = "Lcom/mobclick/android/a"
        $s4 = "Lcom/mobclick/android/d"
        $s5 = "Lcom/mobclick/android/e"
        $s6 = "$Lcom/mobclick/android/MobclickAgent"
        $s7 = "Lcom/mobclick/android/ReportPolicy"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01714 {
    strings:
        $s0 = "receiver/install"
        $s1 = "http://app"
        $s2 = "receiver/uninstall"
        $s3 = "receiver/load_ad"
        $s4 = "receiver/load_offer"
        $s5 = "Lcom/waps/OffersWebView"
        $s6 = "Lcom/waps/a"
        $s7 = "Lcom/waps/b"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01715 {
    strings:
        $s0 = "receiver/install"
        $s1 = "http://app"
        $s2 = "receiver/uninstall"
        $s3 = "receiver/load_ad"
        $s4 = "receiver/load_offer"
        $s5 = "Lcom/waps/OffersWebView"
        $s6 = "UPermission.ACCESS_WIFI_STATE"
        $s7 = "Lcom/waps/a"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01716 {
    strings:
        $s0 = "receiver/install"
        $s1 = "http://app"
        $s2 = "receiver/uninstall"
        $s3 = "receiver/load_ad"
        $s4 = "receiver/load_offer"
        $s5 = "Lcom/waps/OffersWebView"
        $s6 = "UPermission.ACCESS_WIFI_STATE"
        $s7 = "Lcom/waps/a"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01717 {
    strings:
        $s0 = "receiver/install"
        $s1 = "http://app"
        $s2 = "receiver/uninstall"
        $s3 = "receiver/load_ad"
        $s4 = "receiver/load_offer"
        $s5 = "Lcom/waps/OffersWebView"
        $s6 = "Lcom/waps/a"
        $s7 = "Lcom/waps/b"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01718 {
    strings:
        $s0 = "KGJk/tmNnBAwr5"
        $s1 = "Lblue/sky/vn/API"
        $s2 = "Lblue/sky/vn/DI"
        $s3 = "Lblue/sky/vn/GameHDActivity"
        $s4 = "Lblue/sky/vn/MainActivity"
        $s5 = "Lblue/sky/vn/WebViewActivity"
        $s6 = "lcZ/aGbqQdXgw"
        $s7 = "res/layout/hm_view.xml"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01719 {
    strings:
        $s0 = "KGJk/tmNnBAwr5"
        $s1 = "Lblue/sky/vn/API"
        $s2 = "Lblue/sky/vn/DI"
        $s3 = "Lblue/sky/vn/GameHDActivity"
        $s4 = "Lblue/sky/vn/MainActivity"
        $s5 = "Lblue/sky/vn/WebViewActivity"
        $s6 = "lcZ/aGbqQdXgw"
        $s7 = "res/layout/hm_view.xml"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01720 {
    strings:
        $s0 = "receiver/install"
        $s1 = "http://app"
        $s2 = "receiver/uninstall"
        $s3 = "receiver/load_ad"
        $s4 = "receiver/load_offer"
        $s5 = "UPermission.ACCESS_WIFI_STATE"
        $s6 = "UnPackage.dat"
        $s7 = "complete.Click"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01721 {
    strings:
        $s0 = "com.baidu.locTest.LocationServer"
        $s1 = "/con.dat"
        $s2 = "unbindservice..."
        $s3 = "5android.net.wifi.WifiManager.mService"
        $s4 = "excpetion..."
        $s5 = "mService.startScan"
        $s6 = "messener..."
        $s7 = "onSetOption..."
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01722 {
    strings:
        $s0 = "res/drawable-hdpi/background.9.png"
        $s1 = "l1nwXdyEa/dgB6fokaLVLuBiYLo"
        $s2 = "jQ1nY/n1s"
        $s3 = "pnk5qYbWMfys/M2lgeTy4J"
        $s4 = "res/drawable-hdpi/background_button.png"
        $s5 = "res/drawable-hdpi/greenbutton_normal.png"
        $s6 = "res/drawable-hdpi/greenbutton_pressed.png"
        $s7 = "res/drawable-hdpi/linkbutton_normal.png"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01723 {
    strings:
        $s0 = "res/drawable-hdpi/background.9.png"
        $s1 = "l1nwXdyEa/dgB6fokaLVLuBiYLo"
        $s2 = "jQ1nY/n1s"
        $s3 = "pnk5qYbWMfys/M2lgeTy4J"
        $s4 = "res/drawable-hdpi/background_button.png"
        $s5 = "res/drawable-hdpi/greenbutton_normal.png"
        $s6 = "res/drawable-hdpi/greenbutton_pressed.png"
        $s7 = "res/drawable-hdpi/linkbutton_normal.png"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01724 {
    strings:
        $s0 = "mian.iyu"
        $s1 = "/YouGaile/AppFile"
        $s2 = "/iApp/Userimg"
        $s3 = "/iApp/downFile/"
        $s4 = "Lcom/Hy/UI/PredicateLayout"
        $s5 = "Lcom/Hy/UI/a"
        $s6 = "Lcom/Hy/UI/b"
        $s7 = "Lcom/Hy/UI/c"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01725 {
    strings:
        $s0 = "mian.iyu"
        $s1 = "/YouGaile/AppFile"
        $s2 = "/iApp/Userimg"
        $s3 = "/iApp/downFile/"
        $s4 = "Lcom/Hy/UI/PredicateLayout"
        $s5 = "Lcom/Hy/UI/a"
        $s6 = "Lcom/Hy/UI/b"
        $s7 = "Lcom/Hy/UI/c"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01726 {
    strings:
        $s0 = "mian.iyu"
        $s1 = "/YouGaile/AppFile"
        $s2 = "/iApp/Userimg"
        $s3 = "/iApp/downFile/"
        $s4 = "Lcom/Hy/UI/PredicateLayout"
        $s5 = "Lcom/Hy/UI/a"
        $s6 = "Lcom/Hy/UI/b"
        $s7 = "Lcom/Hy/UI/c"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01727 {
    strings:
        $s0 = "com.webcash.wooribank"
        $s1 = "res/drawable-hdpi/nh.png"
        $s2 = "res/drawable-hdpi/sh.png"
        $s3 = "res/drawable-hdpi/kb.png"
        $s4 = "res/drawable-hdpi/nf_bg_edit_text.9.png"
        $s5 = "res/drawable-hdpi/indeterminate_spinner.png"
        $s6 = "res/drawable-hdpi/selector_edittext_bg.xml"
        $s7 = "res/anim/wait.xml"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01728 {
    strings:
        $s0 = "Lorg/cocos2dx/lib/PandaWebView"
        $s1 = "assets/fail.mp3"
        $s2 = "/ZyCzQZ556L79lAFA"
        $s3 = "0ir4S/6B7uO53LiZcNi9"
        $s4 = "108VbHqi4XsQL7JPU/mt3sGNGMY"
        $s5 = "1v1Ce73zMk5u1SiFw/C7/Bu2Agc"
        $s6 = "2w/BgfUBoZQHjQbxMhDXLmRD9vI"
        $s7 = "48QsF9pIsxlX/AWpIpjo2AzNujo"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01729 {
    strings:
        $s0 = "FLaAhhDdPrY0/vJzv1OeHWT6cADIa98/EZQrhX3GVng"
        $s1 = "MXz1dSvLiS91ZqtjIj6pGe57e9WxZN7bbtm/myrxur0"
        $s2 = "res/layout/activity_compose_sms.xml"
        $s3 = "res/drawable/tbi.xml"
        $s4 = "res/drawable/tbo.xml"
        $s5 = "res/layout/activity_intent_starter.xml"
        $s6 = "res/layout/activity_sms_thread.xml"
        $s7 = "res/layout/conv_list_item.xml"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01730 {
    strings:
        $s0 = "FLaAhhDdPrY0/vJzv1OeHWT6cADIa98/EZQrhX3GVng"
        $s1 = "MXz1dSvLiS91ZqtjIj6pGe57e9WxZN7bbtm/myrxur0"
        $s2 = "res/layout/activity_compose_sms.xml"
        $s3 = "res/drawable/tbi.xml"
        $s4 = "res/drawable/tbo.xml"
        $s5 = "res/layout/activity_intent_starter.xml"
        $s6 = "res/layout/activity_sms_thread.xml"
        $s7 = "res/layout/conv_list_item.xml"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01731 {
    strings:
        $s0 = "FLaAhhDdPrY0/vJzv1OeHWT6cADIa98/EZQrhX3GVng"
        $s1 = "MXz1dSvLiS91ZqtjIj6pGe57e9WxZN7bbtm/myrxur0"
        $s2 = "res/layout/activity_compose_sms.xml"
        $s3 = "res/drawable/tbi.xml"
        $s4 = "res/drawable/tbo.xml"
        $s5 = "res/layout/activity_intent_starter.xml"
        $s6 = "res/layout/activity_sms_thread.xml"
        $s7 = "res/layout/conv_list_item.xml"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01732 {
    strings:
        $s0 = "assets/Sonnenblume/res.bin"
        $s1 = "assets/defaultbill.jpg"
        $s2 = "assets/pluginconfig.jpg"
        $s3 = "assets/sounds/background.ogg"
        $s4 = "assets/progress.png"
        $s5 = "assets/backgroundbutton.png"
        $s6 = "assets/fail.png"
        $s7 = "assets/init.png"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01733 {
    strings:
        $s0 = "/api/apk"
        $s1 = "com.defender.plugin.FirstRunnable"
        $s2 = "defender_plugin.jar"
    condition:
        any of ($s0, $s1, $s2)
}

rule VX_APK_CLUSTER_01734 {
    strings:
        $s0 = "res/drawable/nota.png"
        $s1 = "res/drawable/ltxt.png"
        $s2 = "Lkk/android/AppActivity"
    condition:
        any of ($s0, $s1, $s2)
}

rule VX_APK_CLUSTER_01735 {
    strings:
        $s0 = "res/drawable-xhdpi/icon.xml"
        $s1 = "Llib/Util"
    condition:
        any of ($s0, $s1)
}

rule VX_APK_CLUSTER_01736 {
    strings:
        $s0 = "res/drawable/opera.png"
        $s1 = "http://sms911.ru"
        $s2 = "assets/params"
        $s3 = "www.mts.ru"
        $s4 = "assets/paste.bin"
        $s5 = "yjBTwLYz5/p7RUGF8Q"
        $s6 = "http://mobile-"
        $s7 = "http://stimulpremium.com/rules.php"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01737 {
    strings:
        $s0 = "res/mipmap-xxhdpi-v4/ic_launcher_empty.png"
        $s1 = "res/mipmap-xxhdpi-v4/ic_launcher_video.png"
        $s2 = "Md3MSA/sg/op1reCKgNZCskn84E"
        $s3 = "res/mipmap-xxhdpi-v4/ic_launcher_antivirus.png"
        $s4 = "res/mipmap-xxhdpi-v4/ic_launcher_flash.png"
        $s5 = "res/mipmap-xxhdpi-v4/ic_launcher_music.png"
        $s6 = "res/mipmap-xxhdpi-v4/ic_launcher_robot.png"
        $s7 = "res/mipmap-xxhdpi-v4/ic_launcher_security.png"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01738 {
    strings:
        $s0 = "res/mipmap-xxhdpi-v4/ic_launcher_empty.png"
        $s1 = "res/mipmap-xxhdpi-v4/ic_launcher_video.png"
        $s2 = "Md3MSA/sg/op1reCKgNZCskn84E"
        $s3 = "res/mipmap-xxhdpi-v4/ic_launcher_antivirus.png"
        $s4 = "res/mipmap-xxhdpi-v4/ic_launcher_flash.png"
        $s5 = "res/mipmap-xxhdpi-v4/ic_launcher_music.png"
        $s6 = "res/mipmap-xxhdpi-v4/ic_launcher_robot.png"
        $s7 = "res/mipmap-xxhdpi-v4/ic_launcher_security.png"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01739 {
    strings:
        $s0 = "res/mipmap-xxhdpi-v4/ic_launcher_empty.png"
        $s1 = "res/mipmap-xxhdpi-v4/ic_launcher_video.png"
        $s2 = "Md3MSA/sg/op1reCKgNZCskn84E"
        $s3 = "res/mipmap-xxhdpi-v4/ic_launcher_antivirus.png"
        $s4 = "res/mipmap-xxhdpi-v4/ic_launcher_flash.png"
        $s5 = "res/mipmap-xxhdpi-v4/ic_launcher_music.png"
        $s6 = "res/mipmap-xxhdpi-v4/ic_launcher_robot.png"
        $s7 = "res/mipmap-xxhdpi-v4/ic_launcher_security.png"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01740 {
    strings:
        $s0 = "res/mipmap-xxhdpi-v4/ic_launcher_empty.png"
        $s1 = "res/mipmap-xxhdpi-v4/ic_launcher_video.png"
        $s2 = "Md3MSA/sg/op1reCKgNZCskn84E"
        $s3 = "res/mipmap-xxhdpi-v4/ic_launcher_antivirus.png"
        $s4 = "res/mipmap-xxhdpi-v4/ic_launcher_flash.png"
        $s5 = "res/mipmap-xxhdpi-v4/ic_launcher_music.png"
        $s6 = "res/mipmap-xxhdpi-v4/ic_launcher_robot.png"
        $s7 = "res/mipmap-xxhdpi-v4/ic_launcher_security.png"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01741 {
    strings:
        $s0 = "/rgBiUeGVuM9QauYk4hnNYsk7Tg"
        $s1 = "-i...--."
        $s2 = "hN---i1L------.----"
        $s3 = "L-/k-Zln"
        $s4 = "L--K0--/Np-"
        $s5 = "OAR1L-.x_-PM-y"
        $s6 = "Lcom/xiaomi/analytics/Action"
        $s7 = "Lcom/xiaomi/analytics/AdAction"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01742 {
    strings:
        $s0 = "/rgBiUeGVuM9QauYk4hnNYsk7Tg"
        $s1 = "-i...--."
        $s2 = "hN---i1L------.----"
        $s3 = "L-/k-Zln"
        $s4 = "L--K0--/Np-"
        $s5 = "OAR1L-.x_-PM-y"
        $s6 = "Lcom/xiaomi/analytics/Action"
        $s7 = "Lcom/xiaomi/analytics/AdAction"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01743 {
    strings:
        $s0 = "FLaAhhDdPrY0/vJzv1OeHWT6cADIa98/EZQrhX3GVng"
        $s1 = "MXz1dSvLiS91ZqtjIj6pGe57e9WxZN7bbtm/myrxur0"
        $s2 = "res/layout/activity_compose_sms.xml"
        $s3 = "res/drawable/tbi.xml"
        $s4 = "res/drawable/tbo.xml"
        $s5 = "res/layout/activity_intent_starter.xml"
        $s6 = "res/layout/activity_sms_thread.xml"
        $s7 = "res/layout/conv_list_item.xml"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01744 {
    strings:
        $s0 = "Lcom/baidu/location/h$a"
        $s1 = "Lcom/baidu/location/f$a"
        $s2 = "Lcom/baidu/location/s$1"
        $s3 = "com.baidu.locTest.LocationServer"
        $s4 = "Lcom/baidu/location/aq$a"
        $s5 = "/con.dat"
        $s6 = "Lcom/baidu/location/y$a"
        $s7 = "Lcom/baidu/location/ai$1"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01745 {
    strings:
        $s0 = "lib/armeabi/libcrypt_sign.so"
        $s1 = "13/Ayo17/DPtKNh46JVIv6osRPo"
        $s2 = "Qmxju5/Ap5mgu1cFHvmJFycrWMw"
        $s3 = "com/unicom/wounipaysms/dialog/images/cancel.png"
        $s4 = "com/unicom/wounipaysms/dialog/images/cancel_on.png"
        $s5 = "com/unicom/wounipaysms/dialog/images/confirm_bt.9.png"
        $s6 = "com/unicom/wounipaysms/dialog/images/confirm_bt_on.9.png"
        $s7 = "com/unicom/wounipaysms/dialog/images/main_bg.9.png"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01747 {
    strings:
        $s0 = "secsuite.db"
        $s1 = "LocalTime:"
        $s2 = "SecurityReceiver::OnBundle"
        $s3 = "SecurityReceiver::ReportFromScheduler"
        $s4 = "SecurityReceiver::onReceive"
        $s5 = "SecurityService::onStartCommand"
        $s6 = "NumMessage.java"
        $s7 = "SecurityReceiver.java"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01748 {
    strings:
        $s0 = "/cuteword"
        $s1 = "assets/armeabi-v7a/avira0"
        $s2 = "assets/armeabi-v7a/avira1"
        $s3 = "assets/armeabi/avira0"
        $s4 = "assets/armeabi/avira1"
        $s5 = "vZEsMMJeaePtw6/juUC2"
        $s6 = "00iuZvZK9G0i7HxclImlLAcn05Z3mveDKeN8VpyZDFsFMjWLkS3zzJnEnY8LM4m8v/rBeCSdi8dsI1jG"
        $s7 = "1fqxO6a0PJqRrl5xZ4eBzK9q5QfFjXoKOiWuVgf22FpotPpd/yBuhb"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01749 {
    strings:
        $s0 = "com.qihoo.bugreport.CrashReport"
        $s1 = "com.qihoo360.crypt.entryRunApplication"
        $s2 = "Lcom/qihoo/util/"
        $s3 = "lib/armeabi/libjiagu_art.so"
        $s4 = "com.qihoo.jiagutracker.TrackerMain"
        $s5 = "res/drawable/e4alistview_new_message.png"
        $s6 = "Lcom/qihoo360/replugin/Entry"
        $s7 = "Lcom/qihoo360/replugin/Entry$Stub"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01750 {
    strings:
        $s0 = "/dev/block/mtdblock3"
        $s1 = "1com.qihoo360.mobilesafe.service.SafeManageService"
        $s2 = "com.lbe.security.service.SecurityService"
        $s3 = "unbindservice..."
        $s4 = "5android.net.wifi.WifiManager.mService"
        $s5 = "excpetion..."
        $s6 = "mService.startScan"
        $s7 = "messener..."
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01751 {
    strings:
        $s0 = "2/data/data/com.facebook.orca/databases/threads_db2"
        $s1 = "2/data/data/com.viber.voip/databases/viber_messages"
        $s2 = "5/data/data/jp.naver.line.android/databases/naver_line"
        $s3 = "/data/data/com.facebook.orca"
        $s4 = "/data/data/com.whatsapp"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4)
}

rule VX_APK_CLUSTER_01752 {
    strings:
        $s0 = "ICg/LiUsIzkEKQ"
        $s1 = "Kig5CD8/Ij8APiptKD8/bXc"
        $s2 = "OW0/KD44ITltcG0"
        $s3 = "PSIjPihtKyI/bSg/P20/KD0iPzltKz8iIG0"
        $s4 = "$OD0hIiwpbSg/P3dtLiIjOSg1OW1wcG0jOCEh"
        $s5 = "$PyguKCQ7KG0fKD49bSs/IiBtPig/Oyg/dw"
        $s6 = "0AB0hOCokIx8oLigkOyg/bSIjHyguKCQ7KGFtJCM5KCM5dw"
        $s7 = "4IiMMLjkkOyQ5NB8oPjghOW0kIzsiJihtICg5JSIpbSg/PyI/bQ"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01753 {
    strings:
        $s0 = "/dev/block/mtdblock3"
        $s1 = "res/drawable-hdpi/login_bg.png"
    condition:
        any of ($s0, $s1)
}

rule VX_APK_CLUSTER_01754 {
    strings:
        $s0 = ".jpg.dat"
        $s1 = "/Android/data/code/KI.DAT"
        $s2 = ".png.dat"
        $s3 = "-----------s:"
        $s4 = "nousr.dat"
        $s5 = "bin/v.dat"
        $s6 = "bin/m.txt"
        $s7 = "bin/p.txt"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01755 {
    strings:
        $s0 = "res/drawable-hdpi/nh.png"
        $s1 = "3IOmkvQWrLqujnhgiQF/suWDebQ"
        $s2 = "Q0j/LlUSDZKDI8"
        $s3 = "res/drawable-hdpi/indeterminate_spinner.png"
        $s4 = "res/drawable-hdpi/selector_edittext_bg.xml"
        $s5 = "res/anim/wait.xml"
        $s6 = "res/drawable-hdpi/v3plus_run.png"
        $s7 = "res/drawable-hdpi/hana.png"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01756 {
    strings:
        $s0 = "lib/armeabi/libcrypt_sign.so"
        $s1 = "assets/wyzf/res.bin"
        $s2 = "13/Ayo17/DPtKNh46JVIv6osRPo"
        $s3 = "Qmxju5/Ap5mgu1cFHvmJFycrWMw"
        $s4 = "com/unicom/wounipaysms/dialog/images/cancel.png"
        $s5 = "com/unicom/wounipaysms/dialog/images/cancel_on.png"
        $s6 = "com/unicom/wounipaysms/dialog/images/confirm_bt.9.png"
        $s7 = "com/unicom/wounipaysms/dialog/images/confirm_bt_on.9.png"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01757 {
    strings:
        $s0 = "lib/armeabi/libcrypt_sign.so"
        $s1 = "13/Ayo17/DPtKNh46JVIv6osRPo"
        $s2 = "Qmxju5/Ap5mgu1cFHvmJFycrWMw"
        $s3 = "com/unicom/wounipaysms/dialog/images/cancel.png"
        $s4 = "com/unicom/wounipaysms/dialog/images/cancel_on.png"
        $s5 = "com/unicom/wounipaysms/dialog/images/confirm_bt.9.png"
        $s6 = "com/unicom/wounipaysms/dialog/images/confirm_bt_on.9.png"
        $s7 = "com/unicom/wounipaysms/dialog/images/main_bg.9.png"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01758 {
    strings:
        $s0 = "lib/armeabi/libcrypt_sign.so"
        $s1 = "assets/wyzf/res.bin"
        $s2 = "13/Ayo17/DPtKNh46JVIv6osRPo"
        $s3 = "Qmxju5/Ap5mgu1cFHvmJFycrWMw"
        $s4 = "com/unicom/wounipaysms/dialog/images/cancel.png"
        $s5 = "com/unicom/wounipaysms/dialog/images/cancel_on.png"
        $s6 = "com/unicom/wounipaysms/dialog/images/confirm_bt.9.png"
        $s7 = "com/unicom/wounipaysms/dialog/images/confirm_bt_on.9.png"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01759 {
    strings:
        $s0 = "lib/armeabi/libcrypt_sign.so"
        $s1 = "assets/wyzf/res.bin"
        $s2 = "13/Ayo17/DPtKNh46JVIv6osRPo"
        $s3 = "Qmxju5/Ap5mgu1cFHvmJFycrWMw"
        $s4 = "com/unicom/wounipaysms/dialog/images/cancel.png"
        $s5 = "com/unicom/wounipaysms/dialog/images/cancel_on.png"
        $s6 = "com/unicom/wounipaysms/dialog/images/confirm_bt.9.png"
        $s7 = "com/unicom/wounipaysms/dialog/images/confirm_bt_on.9.png"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01760 {
    strings:
        $s0 = "Hjavascript:window.location"
        $s1 = "Lwip/click/master/BuildConfig"
        $s2 = "Lwip/click/master/GO"
        $s3 = "Lwip/click/master/GO$1"
        $s4 = "Lwip/click/master/GO$2"
        $s5 = "Lwip/click/master/GO$3"
        $s6 = "Lwip/click/master/GO$4"
        $s7 = "Lwip/click/master/MR"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01761 {
    strings:
        $s0 = "Hjavascript:window.location"
        $s1 = "Lwip/click/master/BuildConfig"
        $s2 = "Lwip/click/master/GO"
        $s3 = "Lwip/click/master/GO$1"
        $s4 = "Lwip/click/master/GO$2"
        $s5 = "Lwip/click/master/GO$3"
        $s6 = "Lwip/click/master/GO$4"
        $s7 = "Lwip/click/master/MR"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01762 {
    strings:
        $s0 = "Z.-z-.xy-"
        $s1 = "J-yM/-P-y"
        $s2 = "Yk.11L-T"
        $s3 = "res/drawable/img_android.png"
        $s4 = "res/layout/instruction_dialog.xml"
        $s5 = "res/drawable/shape_gray_border_bottom.xml"
        $s6 = "res/layout/samsung_show_top_dialog.xml"
        $s7 = "res/layout/xiaomi_background_activity_dialog.xml"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01763 {
    strings:
        $s0 = "res/drawable/opera.png"
        $s1 = "assets/params"
        $s2 = "www.mts.ru"
        $s3 = "yjBTwLYz5/p7RUGF8Q"
        $s4 = "http://mobile-"
        $s5 = "http://stimulpremium.com/rules.php"
        $s6 = "premium.com."
        $s7 = "i-free.com.ua"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01764 {
    strings:
        $s0 = "receiver/install"
        $s1 = "http://app"
        $s2 = "receiver/uninstall"
        $s3 = "receiver/load_ad"
        $s4 = "receiver/load_offer"
        $s5 = "Lcom/waps/OffersWebView"
        $s6 = "UPermission.ACCESS_WIFI_STATE"
        $s7 = "Lcom/waps/a"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01765 {
    strings:
        $s0 = "receiver/install"
        $s1 = "http://app"
        $s2 = "receiver/uninstall"
        $s3 = "receiver/load_ad"
        $s4 = "receiver/load_offer"
        $s5 = "Lcom/waps/OffersWebView"
        $s6 = "UPermission.ACCESS_WIFI_STATE"
        $s7 = "Lcom/waps/a"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01766 {
    strings:
        $s0 = "iMxxj.K."
        $s1 = "Lpackage/name/BuildConfig"
        $s2 = "Lpackage/name/R"
        $s3 = "Lpackage/name/R$drawable"
        $s4 = "Lpackage/name/R$id"
        $s5 = "Lpackage/name/R$layout"
        $s6 = "Lpackage/name/R$raw"
        $s7 = "Lpackage/name/R$string"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01767 {
    strings:
        $s0 = "Z.-z-.xy-"
        $s1 = "J-yM/-P-y"
        $s2 = "Yk.11L-T"
        $s3 = "/rgBiUeGVuM9QauYk4hnNYsk7Tg"
        $s4 = "3beH/MASicYWILJ6bNBGMBRyxmA"
        $s5 = "5hiR1surnFL/0l"
        $s6 = "Bpw9qc/5tamnIY6kCoDPUOxcpUM"
        $s7 = "n-LzK-y/"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01768 {
    strings:
        $s0 = "Z.-z-.xy-"
        $s1 = "J-yM/-P-y"
        $s2 = "Yk.11L-T"
        $s3 = "3beH/MASicYWILJ6bNBGMBRyxmA"
        $s4 = "5hiR1surnFL/0l"
        $s5 = "Bpw9qc/5tamnIY6kCoDPUOxcpUM"
        $s6 = "n-LzK-y/"
        $s7 = "assets/ev_xp_bar_fill.mp3"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01769 {
    strings:
        $s0 = "Z.-z-.xy-"
        $s1 = "J-yM/-P-y"
        $s2 = "Yk.11L-T"
        $s3 = "3beH/MASicYWILJ6bNBGMBRyxmA"
        $s4 = "5hiR1surnFL/0l"
        $s5 = "Bpw9qc/5tamnIY6kCoDPUOxcpUM"
        $s6 = "n-LzK-y/"
        $s7 = "assets/ev_xp_bar_fill.mp3"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01770 {
    strings:
        $s0 = "L6/ueiYWJ3fllf5GfT6TakuJWFw"
        $s1 = "Lcom/agilebinary/a/a/a/a"
        $s2 = "Lcom/agilebinary/a/a/a/b"
        $s3 = "Lcom/agilebinary/a/a/a/c"
        $s4 = "Lcom/agilebinary/a/a/a/d"
        $s5 = "Lcom/agilebinary/a/a/a/e"
        $s6 = "Lcom/agilebinary/a/a/a/f"
        $s7 = "Lcom/agilebinary/a/a/a/g"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01771 {
    strings:
        $s0 = "L6/ueiYWJ3fllf5GfT6TakuJWFw"
        $s1 = "Lcom/agilebinary/a/a/a/a"
        $s2 = "Lcom/agilebinary/a/a/a/b"
        $s3 = "Lcom/agilebinary/a/a/a/c"
        $s4 = "Lcom/agilebinary/a/a/a/d"
        $s5 = "Lcom/agilebinary/a/a/a/e"
        $s6 = "Lcom/agilebinary/a/a/a/f"
        $s7 = "Lcom/agilebinary/a/a/a/g"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01772 {
    strings:
        $s0 = "assets/wyzf/res.bin"
        $s1 = "assets/yf.conf"
        $s2 = "assets/dERlZG"
        $s3 = "http://vpay.api.eerichina.com/api/payment"
        $s4 = "plugin.db"
        $s5 = "/LocalPool.xml"
        $s6 = "/temp.dl"
        $s7 = "/unknown.dat"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01773 {
    strings:
        $s0 = "Z.-z-.xy-"
        $s1 = "J-yM/-P-y"
        $s2 = "assets/symbols-ad.sdf"
        $s3 = "wj-zM.x."
        $s4 = "2Lcom/fullstory/instrumentation/InstrumentInjector"
        $s5 = "assets/symbols.sdf"
        $s6 = "0Lcom/mbridge/msdk/interactiveads/signalcommon/a"
        $s7 = "BLcom/mbridge/msdk/interactiveads/activity/InteractiveShowActivity"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01774 {
    strings:
        $s0 = "yRRcbcPCppiMYG6Hcx/z9GWNDJA"
        $s1 = "ERxa/JEZlg3ozQdL90vjacYjOa0"
        $s2 = "JmRd5cMmoVSvbdtkYmFLpe/EA6A"
        $s3 = "bt0y/oyU"
        $s4 = "layout/page5"
        $s5 = "res/drawable/buttonkeyb.xml"
        $s6 = "res/drawable/gov_inactive.png"
        $s7 = "res/drawable/hitler_inactive.png"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01775 {
    strings:
        $s0 = "res/drawable/icon_url.png"
        $s1 = "res/drawable/progress.9.png"
        $s2 = "res/drawable/progress_active.9.png"
        $s3 = "Q7WCsG.1Em7"
        $s4 = "CsG.1E_."
        $s5 = "/nYwLZKf5WLKrxhodWhEaDFZe98"
        $s6 = "Lcom/apps/pack/a"
        $s7 = "Lcom/apps/pack/a/a"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01776 {
    strings:
        $s0 = "res/drawable/icon_url.png"
        $s1 = "res/drawable/progress.9.png"
        $s2 = "res/drawable/progress_active.9.png"
        $s3 = "/nYwLZKf5WLKrxhodWhEaDFZe98"
        $s4 = "Lcom/apps/pack/a"
        $s5 = "Lcom/apps/pack/a/a"
        $s6 = "Lcom/apps/pack/a/b"
        $s7 = "Lcom/apps/pack/activity/FinishActivity"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01778 {
    strings:
        $s0 = "assets/css/smoothness/images/ui-bg_flat_0_aaaaaa_40x100.png"
        $s1 = "assets/css/smoothness/images/ui-bg_flat_75_ffffff_40x100.png"
        $s2 = "assets/css/smoothness/images/ui-bg_glass_55_fbf9ee_1x400.png"
        $s3 = "assets/css/smoothness/images/ui-bg_glass_65_ffffff_1x400.png"
        $s4 = "assets/css/smoothness/images/ui-bg_glass_75_dadada_1x400.png"
        $s5 = "assets/css/smoothness/images/ui-bg_glass_75_e6e6e6_1x400.png"
        $s6 = "assets/css/smoothness/images/ui-bg_glass_95_fef1ec_1x400.png"
        $s7 = "assets/css/smoothness/images/ui-bg_highlight-soft_75_cccccc_1x10"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01779 {
    strings:
        $s0 = "assets/crack_d.png"
        $s1 = "assets/horizontal_bg.png"
        $s2 = "assets/vertical_bg.png"
        $s3 = "assets/VqsPhone.apk"
        $s4 = "assets/crack_p.png"
        $s5 = "assets/vqs_bg_1.png"
        $s6 = "assets/vqs_bg_2.png"
        $s7 = "fgze/7Oa6DUYRSFfOi0JBgA0rvU"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01780 {
    strings:
        $s0 = "assets/crack_d.png"
        $s1 = "assets/horizontal_bg.png"
        $s2 = "assets/vertical_bg.png"
        $s3 = "assets/VqsPhone.apk"
        $s4 = "assets/crack_p.png"
        $s5 = "assets/vqs_bg_1.png"
        $s6 = "assets/vqs_bg_2.png"
        $s7 = "fgze/7Oa6DUYRSFfOi0JBgA0rvU"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01781 {
    strings:
        $s0 = "mpathList:"
        $s1 = "libtosprotection."
        $s2 = "oat/arm64"
        $s3 = "assets/libshellx-super.2019.so"
        $s4 = "assets/0OO00oo01l1l"
        $s5 = "lib/armeabi-v7a/libMtaNativeCrash_v2.so"
        $s6 = "lib/armeabi-v7a/libp2pcore.so"
        $s7 = "lib/armeabi-v7a/libtvcore.so"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01782 {
    strings:
        $s0 = "ApnNode.java"
        $s1 = "/opl/etc/product_properties.xml"
        $s2 = "/opl/etc/properties.xml"
        $s3 = "2:k7j3G6LaL6u_lafw:4iXOeOpTh1glSXe"
        $s4 = "runRootCommand:"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4)
}

rule VX_APK_CLUSTER_01783 {
    strings:
        $s0 = "res/layout/finish.xml"
        $s1 = "numbers.xml"
        $s2 = "OperatorModel.java"
        $s3 = "XMLfunctions.java"
    condition:
        any of ($s0, $s1, $s2, $s3)
}

rule VX_APK_CLUSTER_01784 {
    strings:
        $s0 = "Series60/3.0"
        $s1 = "OutCallReceiver.java"
    condition:
        any of ($s0, $s1)
}

rule VX_APK_CLUSTER_01785 {
    strings:
        $s0 = "res/drawable-hdpi/bg2.jpg"
        $s1 = "res/layout/sub.xml"
        $s2 = "res/drawable-hdpi/tnc.png"
        $s3 = "/res/drawable-hdpi/s.gif"
        $s4 = "res/drawable-hdpi/s.gif"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4)
}

rule VX_APK_CLUSTER_01786 {
    strings:
        $s0 = "res/drawable-hdpi/background.9.png"
        $s1 = "l1nwXdyEa/dgB6fokaLVLuBiYLo"
        $s2 = "jQ1nY/n1s"
        $s3 = "pnk5qYbWMfys/M2lgeTy4J"
        $s4 = "res/drawable-hdpi/background_button.png"
        $s5 = "res/drawable-hdpi/greenbutton_normal.png"
        $s6 = "res/drawable-hdpi/greenbutton_pressed.png"
        $s7 = "res/drawable-hdpi/linkbutton_normal.png"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01787 {
    strings:
        $s0 = "SmsOperator.java"
        $s1 = "SettingsSet.java"
        $s2 = "res/raw/end.xml"
        $s3 = "res/raw/license.xml"
        $s4 = "res/raw/sms.xml"
        $s5 = "http://sms911.ru"
        $s6 = "/res/raw/license.xml"
        $s7 = "/res/raw/end.xml"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01788 {
    strings:
        $s0 = "SmsOperator.java"
        $s1 = "SettingsSet.java"
        $s2 = "res/raw/end.xml"
        $s3 = "res/raw/license.xml"
        $s4 = "res/raw/sms.xml"
        $s5 = "/res/raw/license.xml"
        $s6 = "/res/raw/end.xml"
        $s7 = "/res/raw/sms.xml"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01789 {
    strings:
        $s0 = "res/raw/data.db"
        $s1 = "SmsOperator.java"
        $s2 = "SettingsSet.java"
        $s3 = "res/raw/end.xml"
        $s4 = "res/raw/license.xml"
        $s5 = "res/raw/sms.xml"
        $s6 = "OperaUpdaterActivity.java"
        $s7 = "/res/raw/license.xml"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01790 {
    strings:
        $s0 = "com.webcash.wooribank"
        $s1 = "res/xml/lock.xml"
        $s2 = "E/s6A6XhGqYlbVovZDGad1Egfcc"
        $s3 = "Sg97xTIFIwKJ/xJV"
        $s4 = "res/drawable-hdpi/background_bg.png"
        $s5 = "res/drawable-hdpi/bg_btn_normal.png"
        $s6 = "res/drawable-hdpi/bg_btn_press.png"
        $s7 = "res/drawable-hdpi/border.9.png"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01791 {
    strings:
        $s0 = "PlJSQqWxy9Pig116SM/fEvHLyIQ"
        $s1 = "game.swf"
        $s2 = "res/drawable/zt__back.png"
        $s3 = "res/drawable/zt__down.png"
        $s4 = "res/drawable/zt__down_w.png"
        $s5 = "res/drawable/zt__icon_lack.png"
        $s6 = "res/drawable/zt__title_sep.xml"
        $s7 = "res/layout/zt__offerinfo.xml"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01792 {
    strings:
        $s0 = "PlJSQqWxy9Pig116SM/fEvHLyIQ"
        $s1 = "game.swf"
        $s2 = "res/drawable/zt__back.png"
        $s3 = "res/drawable/zt__down.png"
        $s4 = "res/drawable/zt__down_w.png"
        $s5 = "res/drawable/zt__icon_lack.png"
        $s6 = "res/drawable/zt__title_sep.xml"
        $s7 = "res/layout/zt__offerinfo.xml"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01793 {
    strings:
        $s0 = "com.areo.bs"
        $s1 = "MyTools.java"
        $s2 = "rspcode:"
        $s3 = "/servlet/OnLine"
        $s4 = "http://192.151.226.138:80/appHome/"
        $s5 = "/servlet/ContactsUpload"
        $s6 = "WebInterfaceActivity.java"
        $s7 = "Lcom/a/MyAdminReceiver"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01794 {
    strings:
        $s0 = "com.areo.bs"
        $s1 = "MyTools.java"
        $s2 = "rspcode:"
        $s3 = "/servlet/OnLine"
        $s4 = "http://192.151.226.138:80/appHome/"
        $s5 = "/servlet/ContactsUpload"
        $s6 = "WebInterfaceActivity.java"
        $s7 = "/servlet/SendSMSJSON"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01795 {
    strings:
        $s0 = "res/drawable-hdpi/nf_bg_edit_text.9.png"
        $s1 = "res/drawable-hdpi/indeterminate_spinner.png"
        $s2 = "res/drawable-hdpi/selector_edittext_bg.xml"
        $s3 = "res/drawable-hdpi/btn_cancel_off_gnb.png"
        $s4 = "res/drawable-hdpi/btn_confirm_off_gnw.png"
        $s5 = "com.areo.bs"
        $s6 = "res/drawable-hdpi/bgsp.jpg"
        $s7 = "res/drawable-hdpi/titlebtn_pre.png"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01796 {
    strings:
        $s0 = "res/layout/finish.xml"
        $s1 = "hGV/eFuLm4sXF7Kgiv2LjTr84vc"
        $s2 = "res/drawable/opera.png"
        $s3 = "res/drawable/icon_url.png"
        $s4 = "http://url"
        $s5 = "qWpRNG2kZqlJ/KOeBWiBVS41J"
        $s6 = "res/drawable/button_green.png"
        $s7 = "rEppsRv/JtutQIWU6VLVixb96JA"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01797 {
    strings:
        $s0 = "LogCatBroadcaster.java"
        $s1 = "com.aide.runtime.VIEW_LOGCAT_ENTRY"
        $s2 = "assets/libckeygenerator.so"
        $s3 = "/zihao.l"
        $s4 = "Lcom/qqmagic/BuildConfig"
        $s5 = "Lcom/qqmagic/R"
        $s6 = "Lcom/qqmagic/R$attr"
        $s7 = "Lcom/qqmagic/R$drawable"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01798 {
    strings:
        $s0 = "/contentSignature"
        $s1 = "/MM_Application_Copyright_Declaration"
        $s2 = "/copyRightType"
        $s3 = "/copyrightID"
        $s4 = "/copyrightSignature"
        $s5 = "/digestAlg"
        $s6 = "/programID"
        $s7 = "439uag/FMlN"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01799 {
    strings:
        $s0 = "Qualcomm:"
        $s1 = "assets/d.zip"
    condition:
        any of ($s0, $s1)
}

rule VX_APK_CLUSTER_01800 {
    strings:
        $s0 = "/sys/class/kgsl/kgsl-3d0/min_pwrlevel"
        $s1 = "/sys/devices/system/cpu/cpu4/online"
        $s2 = "/sys/devices/system/cpu/cpu5/online"
        $s3 = "/sys/devices/system/cpu/cpu6/online"
        $s4 = "/sys/devices/system/cpu/cpu7/online"
        $s5 = "/sys/module/msm_thermal/core_control/cpus_offlined"
        $s6 = "/sys/module/msm_thermal/core_control/enabled"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6)
}

rule VX_APK_CLUSTER_01801 {
    strings:
        $s0 = "res/drawable-hdpi/nf_bg_edit_text.9.png"
        $s1 = "res/drawable-hdpi/intro_bg.png"
        $s2 = "res/drawable-hdpi/nf_btn_key_fun_shif_upper.png"
        $s3 = "res/drawable-hdpi/titlebtn_pre.png"
        $s4 = "Post2Activity.java"
        $s5 = "npki.zip"
        $s6 = "res/drawable-xhdpi/input.png"
        $s7 = "res/layout/activity_post2.xml"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01802 {
    strings:
        $s0 = "RwY7bp1C/mAHk1MxPLhfhPev/oM"
        $s1 = "res/drawable/ic_launcher_android.png"
    condition:
        any of ($s0, $s1)
}

rule VX_APK_CLUSTER_01803 {
    strings:
        $s0 = "assets/wyzf/res.bin"
        $s1 = "assets/dERlZG"
        $s2 = "Adzwfge96PWi9KOpEQioyGF//NA"
        $s3 = "http://vpay.api.eerichina.com/api/payment"
        $s4 = "plugin.db"
        $s5 = "/LocalPool.xml"
        $s6 = "/temp.dl"
        $s7 = "/unknown.dat"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01804 {
    strings:
        $s0 = "lib/armeabi/libcrypt_sign.so"
        $s1 = "assets/wyzf/res.bin"
        $s2 = "assets/yf.conf"
        $s3 = "assets/dERlZG"
        $s4 = "Adzwfge96PWi9KOpEQioyGF//NA"
        $s5 = "http://vpay.api.eerichina.com/api/payment"
        $s6 = "plugin.db"
        $s7 = "/LocalPool.xml"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01805 {
    strings:
        $s0 = "assets/wyzf/res.bin"
        $s1 = "13/Ayo17/DPtKNh46JVIv6osRPo"
        $s2 = "Qmxju5/Ap5mgu1cFHvmJFycrWMw"
        $s3 = "com/unicom/wounipaysms/dialog/images/cancel.png"
        $s4 = "com/unicom/wounipaysms/dialog/images/cancel_on.png"
        $s5 = "com/unicom/wounipaysms/dialog/images/confirm_bt.9.png"
        $s6 = "com/unicom/wounipaysms/dialog/images/confirm_bt_on.9.png"
        $s7 = "com/unicom/wounipaysms/dialog/images/main_bg.9.png"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01806 {
    strings:
        $s0 = "lib/armeabi/libcrypt_sign.so"
        $s1 = "assets/wyzf/res.bin"
        $s2 = "13/Ayo17/DPtKNh46JVIv6osRPo"
        $s3 = "Qmxju5/Ap5mgu1cFHvmJFycrWMw"
        $s4 = "com/unicom/wounipaysms/dialog/images/cancel.png"
        $s5 = "com/unicom/wounipaysms/dialog/images/cancel_on.png"
        $s6 = "com/unicom/wounipaysms/dialog/images/confirm_bt.9.png"
        $s7 = "com/unicom/wounipaysms/dialog/images/confirm_bt_on.9.png"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01807 {
    strings:
        $s0 = "lib/armeabi/libcrypt_sign.so"
        $s1 = "assets/wyzf/res.bin"
        $s2 = "assets/jmpay.xml"
        $s3 = "assets/provincecode.xml"
        $s4 = "assets/utopay.zip"
        $s5 = "assets/yf.conf"
        $s6 = "assets/dERlZG"
        $s7 = "5H0/y0vQ/rz9n5q2WT8d7bHFZSA"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01808 {
    strings:
        $s0 = "assets/new_md"
        $s1 = "TestApplication.java"
        $s2 = "vpT7fGi41WScZ5fuMoJo//H/Ylg"
    condition:
        any of ($s0, $s1, $s2)
}

rule VX_APK_CLUSTER_01809 {
    strings:
        $s0 = "res/raw/opening_sound.mp3"
        $s1 = "res/layout/notification_message_pic.xml"
        $s2 = "TestApplication.java"
        $s3 = "res/layout/game_main.xml"
        $s4 = "zZPxTQfbrR7uac/fXCYoNDgatUE"
        $s5 = "q/pYbRfX7JUgv34RFQjekcE4RVg"
        $s6 = "res/drawable-ldpi-v4/icon72.png"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6)
}

rule VX_APK_CLUSTER_01810 {
    strings:
        $s0 = "D5kIXMNkbQ6KrnhWrUpYw/R6pJk"
        $s1 = "Lcom/baidu/location/s$1"
        $s2 = "Lcom/baidu/location/y$a"
        $s3 = "Lcom/baidu/location/ai$1"
        $s4 = "ASetupTool.java"
        $s5 = "ASvcLoader.java"
        $s6 = "assets/Sonnenblume/res.bin"
        $s7 = "com.snowfish.appid"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01811 {
    strings:
        $s0 = "Z.-z-.xy-"
        $s1 = "J-yM/-P-y"
        $s2 = "assets/symbols-ad.sdf"
        $s3 = "2Lcom/fullstory/instrumentation/InstrumentInjector"
        $s4 = "assets/traffic-arrow.png"
        $s5 = "Lcom/vivavideo/mobile/component/sharedpref/IVivaSharedPref"
        $s6 = "Lio/reactivex/ag"
        $s7 = "Lio/reactivex/ah"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01812 {
    strings:
        $s0 = "res/drawable/nota.png"
        $s1 = "res/drawable/ltxt.png"
        $s2 = "res/layout/maintow.xml"
        $s3 = "Uw8zo17KAekiyNsq/vyzxKqdo70"
    condition:
        any of ($s0, $s1, $s2, $s3)
}

rule VX_APK_CLUSTER_01813 {
    strings:
        $s0 = ".Lcom/ryg/dynamicload/internal/DLPluginManager"
        $s1 = "Lcom/ryg/dynamicload/DLBasePluginActivity"
        $s2 = "Lcom/ryg/dynamicload/DLBasePluginService"
        $s3 = "Lcom/ryg/dynamicload/internal/DLIntent"
        $s4 = ".Lcom/ryg/dynamicload/internal/DLPluginPackage"
        $s5 = "$Lcom/ryg/dynamicload/DLProxyService"
        $s6 = "1Lcom/ryg/dynamicload/internal/DLServiceProxyImpl"
        $s7 = "2Lcom/ryg/dynamicload/internal/DLServiceAttachable"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01814 {
    strings:
        $s0 = "res/drawable-hdpi/notification_bg_low_normal.png"
        $s1 = "res/drawable-hdpi/notification_bg_low_pressed.png"
        $s2 = "res/drawable-hdpi/notification_bg_normal.png"
        $s3 = "res/drawable-hdpi/notification_bg_normal_pressed.png"
        $s4 = "res/drawable-mdpi/notification_bg_low_normal.png"
        $s5 = "res/drawable-mdpi/notification_bg_low_pressed.png"
        $s6 = "res/drawable-mdpi/notification_bg_normal.png"
        $s7 = "res/drawable-mdpi/notification_bg_normal_pressed.png"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01815 {
    strings:
        $s0 = "res/drawable-hdpi-v4/icon.xml"
        $s1 = "res/layout/activity_g.xml"
        $s2 = "res/drawable-hdpi-v4/app_launcher.png"
        $s3 = "WFWBO9a7m6MbO/sP/B/yxtr11hnZJLIj8xj46"
        $s4 = "res/layout/nothing_layout.xml"
        $s5 = "assets/hoal/even"
        $s6 = "hoal/even"
        $s7 = "qsXP2kWxmGm3AUAjdyGtNSI3w84fyowsrjTn/gYkyUY"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01816 {
    strings:
        $s0 = "l/cUiZLb7ya5qOYV/djf/zcvnb0"
        $s1 = "res/raw/conf.txt"
        $s2 = "res/raw/result"
        $s3 = "res/raw/resulturl"
        $s4 = "res/raw/rool.txt"
        $s5 = "res/drawable-hdpi/iconnews.png"
        $s6 = "res/drawable-mdpi/iconnews.png"
        $s7 = "http://91.213.175.176/api/"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01817 {
    strings:
        $s0 = "l/cUiZLb7ya5qOYV/djf/zcvnb0"
        $s1 = "res/raw/conf.txt"
        $s2 = "res/raw/result"
        $s3 = "res/raw/resulturl"
        $s4 = "res/raw/rool.txt"
        $s5 = "res/drawable-hdpi/iconnews.png"
        $s6 = "res/drawable-mdpi/iconnews.png"
        $s7 = "http://91.213.175.176/api/"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01818 {
    strings:
        $s0 = "l/cUiZLb7ya5qOYV/djf/zcvnb0"
        $s1 = "res/raw/conf.txt"
        $s2 = "res/raw/result"
        $s3 = "res/raw/resulturl"
        $s4 = "res/raw/rool.txt"
        $s5 = "res/drawable-hdpi/iconnews.png"
        $s6 = "res/drawable-mdpi/iconnews.png"
        $s7 = "http://91.213.175.176/api/"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01819 {
    strings:
        $s0 = "res/layout/finish.xml"
        $s1 = "res/drawable-hdpi/opera.jpg"
        $s2 = "res/drawable-hdpi/textbg.xml"
        $s3 = "res/drawable-hdpi/titlebg.xml"
        $s4 = "Wce1MjOVrsjGKh03cKT/M"
        $s5 = "res/drawable-hdpi/ropera.jpg"
        $s6 = "assets/sms.xml"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6)
}

rule VX_APK_CLUSTER_01820 {
    strings:
        $s0 = "/consumerCodeList"
        $s1 = "86BpnPXgWHUkHbM/vws7iZu0mk"
        $s2 = "AlDWi8bl2/bzTg3d3zZK/g"
        $s3 = "HhPyb1I/X38"
        $s4 = "Iw39W6xW2WgpkFZONZWB/Q"
        $s5 = "KsYPG2/wAfIRZj11LiAb0g"
        $s6 = "RGVw4AQRs/I6priG96EeCQ"
        $s7 = "WFYWPrp7Ea/0oEEh9lCC1A"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01821 {
    strings:
        $s0 = "/consumerCodeList"
        $s1 = "86BpnPXgWHUkHbM/vws7iZu0mk"
        $s2 = "AlDWi8bl2/bzTg3d3zZK/g"
        $s3 = "HhPyb1I/X38"
        $s4 = "Iw39W6xW2WgpkFZONZWB/Q"
        $s5 = "KsYPG2/wAfIRZj11LiAb0g"
        $s6 = "RGVw4AQRs/I6priG96EeCQ"
        $s7 = "WFYWPrp7Ea/0oEEh9lCC1A"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01822 {
    strings:
        $s0 = "-i...--."
        $s1 = "3beH/MASicYWILJ6bNBGMBRyxmA"
        $s2 = "5hiR1surnFL/0l"
        $s3 = "Bpw9qc/5tamnIY6kCoDPUOxcpUM"
        $s4 = "hN---i1L------.----"
        $s5 = "L-/k-Zln"
        $s6 = "L--K0--/Np-"
        $s7 = "com.example.android.Activity.MainActivity"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01823 {
    strings:
        $s0 = "assets/css/smoothness/images/ui-bg_flat_0_aaaaaa_40x100.png"
        $s1 = "assets/css/smoothness/images/ui-bg_flat_75_ffffff_40x100.png"
        $s2 = "assets/css/smoothness/images/ui-bg_glass_55_fbf9ee_1x400.png"
        $s3 = "assets/css/smoothness/images/ui-bg_glass_65_ffffff_1x400.png"
        $s4 = "assets/css/smoothness/images/ui-bg_glass_75_dadada_1x400.png"
        $s5 = "assets/css/smoothness/images/ui-bg_glass_75_e6e6e6_1x400.png"
        $s6 = "assets/css/smoothness/images/ui-bg_glass_95_fef1ec_1x400.png"
        $s7 = "assets/css/smoothness/images/ui-bg_highlight-soft_75_cccccc_1x10"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01824 {
    strings:
        $s0 = "assets/css/smoothness/images/ui-bg_flat_0_aaaaaa_40x100.png"
        $s1 = "assets/css/smoothness/images/ui-bg_flat_75_ffffff_40x100.png"
        $s2 = "assets/css/smoothness/images/ui-bg_glass_55_fbf9ee_1x400.png"
        $s3 = "assets/css/smoothness/images/ui-bg_glass_65_ffffff_1x400.png"
        $s4 = "assets/css/smoothness/images/ui-bg_glass_75_dadada_1x400.png"
        $s5 = "assets/css/smoothness/images/ui-bg_glass_75_e6e6e6_1x400.png"
        $s6 = "assets/css/smoothness/images/ui-bg_glass_95_fef1ec_1x400.png"
        $s7 = "assets/css/smoothness/images/ui-bg_highlight-soft_75_cccccc_1x10"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01825 {
    strings:
        $s0 = "/rgBiUeGVuM9QauYk4hnNYsk7Tg"
        $s1 = "-i...--."
        $s2 = "hN---i1L------.----"
        $s3 = "L-/k-Zln"
        $s4 = "L--K0--/Np-"
        $s5 = "OAR1L-.x_-PM-y"
        $s6 = "Lcom/tendcloud/tenddata/game/cl$a"
        $s7 = "Lcom/tendcloud/tenddata/game/aa$a"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01826 {
    strings:
        $s0 = "assets/wyzf/res.bin"
        $s1 = "assets/dERlZG"
        $s2 = "Adzwfge96PWi9KOpEQioyGF//NA"
        $s3 = "lib/armeabi/libbsjni.so"
        $s4 = "LjOnZ9/RmA2RtDvWiOckTE"
        $s5 = "assets/tongyu-pay-lib.apk"
        $s6 = "dul8SyhGAv3j/ARNvdBAkNsZppw"
        $s7 = "DexInstall.java"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01827 {
    strings:
        $s0 = "assets/dERlZG"
        $s1 = "res/drawable/boder_mii.xml"
        $s2 = "res/drawable/btn_mii_cancel.png"
        $s3 = "res/drawable/btn_mii_line.png"
        $s4 = "res/drawable/shape_mii.xml"
        $s5 = "res/layout/dialog_mii.xml"
        $s6 = "assets/resource/plugin"
        $s7 = "dz27MAkXWhMG/4NLaxB4a6lQDQo"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01828 {
    strings:
        $s0 = "lib/armeabi/libcrypt_sign.so"
        $s1 = "assets/wyzf/res.bin"
        $s2 = "13/Ayo17/DPtKNh46JVIv6osRPo"
        $s3 = "Qmxju5/Ap5mgu1cFHvmJFycrWMw"
        $s4 = "com/unicom/wounipaysms/dialog/images/cancel.png"
        $s5 = "com/unicom/wounipaysms/dialog/images/cancel_on.png"
        $s6 = "com/unicom/wounipaysms/dialog/images/confirm_bt.9.png"
        $s7 = "com/unicom/wounipaysms/dialog/images/confirm_bt_on.9.png"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01829 {
    strings:
        $s0 = "lib/armeabi/libcrypt_sign.so"
        $s1 = "assets/wyzf/res.bin"
        $s2 = "assets/yf.conf"
        $s3 = "V/Sh54nVA"
        $s4 = "assets/pay"
        $s5 = "assets/onib_clz.jar"
        $s6 = "oJms/kRYcnIYQ8if95Gu5Lwii9c"
        $s7 = "sd8QF9i/BZUsEek"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01830 {
    strings:
        $s0 = "assets/wyzf/res.bin"
        $s1 = "assets/yf.conf"
        $s2 = "Adzwfge96PWi9KOpEQioyGF//NA"
        $s3 = "assets/pay"
        $s4 = "assets/onib_clz.jar"
        $s5 = "oJms/kRYcnIYQ8if95Gu5Lwii9c"
        $s6 = "assets/resource/plugin"
        $s7 = "dz27MAkXWhMG/4NLaxB4a6lQDQo"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01831 {
    strings:
        $s0 = "lib/armeabi/libcrypt_sign.so"
        $s1 = "DexInstall.java"
        $s2 = "lib/armeabi/libSecShell.so"
        $s3 = "assets/secData0.jar"
        $s4 = "lib/armeabi/libSecShell-x86.so"
        $s5 = "FilesFileObserver.java"
        $s6 = "$Lcom/secshell/secData/DexInstall$V4"
        $s7 = "/com.secneo.tmp"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01832 {
    strings:
        $s0 = "lib/armeabi/libcrypt_sign.so"
        $s1 = "assets/wyzf/res.bin"
        $s2 = "assets/dERlZG"
        $s3 = "Adzwfge96PWi9KOpEQioyGF//NA"
        $s4 = "assets/onib_clz.jar"
        $s5 = "lib/armeabi/libbsjni.so"
        $s6 = "aujJXssVcADYJQZTq0NNwqOPw/8"
        $s7 = "DexInstall.java"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01833 {
    strings:
        $s0 = "lib/armeabi/libcrypt_sign.so"
        $s1 = "assets/wyzf/res.bin"
        $s2 = "assets/yf.conf"
        $s3 = "assets/pay"
        $s4 = "assets/onib_clz.jar"
        $s5 = "assets/qshp_3001_2295"
        $s6 = "assets/resource/plugin"
        $s7 = "lib/armeabi/libbsjni.so"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01834 {
    strings:
        $s0 = "lib/armeabi/libcrypt_sign.so"
        $s1 = "assets/wyzf/res.bin"
        $s2 = "assets/yf.conf"
        $s3 = "assets/pay"
        $s4 = "assets/onib_clz.jar"
        $s5 = "assets/qshp_3001_2295"
        $s6 = "assets/resource/plugin"
        $s7 = "lib/armeabi/libbsjni.so"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01835 {
    strings:
        $s0 = "assets/jmpay.xml"
        $s1 = "assets/provincecode.xml"
        $s2 = "res/drawable/heju_window_bg.xml"
        $s3 = "assets/dERlZG"
        $s4 = "res/drawable/boder_mii.xml"
        $s5 = "res/drawable/btn_mii_cancel.png"
        $s6 = "res/drawable/btn_mii_line.png"
        $s7 = "res/drawable/shape_mii.xml"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01836 {
    strings:
        $s0 = "assets/jmpay.xml"
        $s1 = "http://vpay.api.eerichina.com/api/payment"
        $s2 = "plugin.db"
        $s3 = "/LocalPool.xml"
        $s4 = "/temp.dl"
        $s5 = "/unknown.dat"
        $s6 = "Android/data/com.door.pay.app/"
        $s7 = "http://120.26.106.206:8088"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01837 {
    strings:
        $s0 = "receiver/install"
        $s1 = "http://app"
        $s2 = "receiver/uninstall"
        $s3 = "receiver/load_ad"
        $s4 = "receiver/load_offer"
        $s5 = "Lcom/waps/OffersWebView"
        $s6 = "UPermission.ACCESS_WIFI_STATE"
        $s7 = "Lcom/waps/a"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01838 {
    strings:
        $s0 = "apkprotect.com/key.dat"
        $s1 = "apkprotect.com/readme.txt"
    condition:
        any of ($s0, $s1)
}

rule VX_APK_CLUSTER_01839 {
    strings:
        $s0 = "receiver/install"
        $s1 = "http://app"
        $s2 = "receiver/uninstall"
        $s3 = "receiver/load_ad"
        $s4 = "receiver/load_offer"
        $s5 = "Lcom/adwo/adsdk/AdwoAdView"
        $s6 = "Lcom/waps/OffersWebView"
        $s7 = "Lcom/adwo/adsdk/AdListener"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01840 {
    strings:
        $s0 = "assets/data.res"
        $s1 = "http://topfiless.com/rates.php"
        $s2 = "assets/auto.res"
        $s3 = "res/drawable/button_tariff.xml"
        $s4 = "assets/agreement.txt"
        $s5 = "assets/ops.res"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5)
}

rule VX_APK_CLUSTER_01841 {
    strings:
        $s0 = "v4tFMNjSRt10rFOhNHG7oXlB3/c"
        $s1 = "r/d/x.xml"
        $s2 = "r/d/k.xml"
        $s3 = "r/d/l.xml"
        $s4 = "r/d/q.xml"
        $s5 = "r/i/b6.png"
        $s6 = "r/i/b7.png"
        $s7 = "r/i/b8.png"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01842 {
    strings:
        $s0 = "res/layout/finish.xml"
        $s1 = "res/raw/config.txt"
        $s2 = "OpInfo.java"
        $s3 = "assets/texts/finish_activity.txt"
        $s4 = "assets/texts/first_activity.txt"
        $s5 = "assets/texts/ru/finish_activity.txt"
        $s6 = "assets/texts/ru/first_activity.txt"
        $s7 = "assets/texts/ru/rules_activity.txt"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01843 {
    strings:
        $s0 = "res/layout/finish.xml"
        $s1 = "res/raw/config.txt"
        $s2 = "OpInfo.java"
        $s3 = "assets/texts/finish_activity.txt"
        $s4 = "assets/texts/first_activity.txt"
        $s5 = "assets/texts/ru/finish_activity.txt"
        $s6 = "assets/texts/ru/first_activity.txt"
        $s7 = "assets/texts/ru/rules_activity.txt"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01844 {
    strings:
        $s0 = "res/layout/finish.xml"
        $s1 = "res/raw/config.txt"
        $s2 = "OpInfo.java"
        $s3 = "assets/texts/finish_activity.txt"
        $s4 = "assets/texts/first_activity.txt"
        $s5 = "assets/texts/ru/finish_activity.txt"
        $s6 = "assets/texts/ru/first_activity.txt"
        $s7 = "assets/texts/ru/rules_activity.txt"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01845 {
    strings:
        $s0 = "res/layout/finish.xml"
        $s1 = "res/raw/config.txt"
        $s2 = "OpInfo.java"
        $s3 = "assets/texts/finish_activity.txt"
        $s4 = "assets/texts/first_activity.txt"
        $s5 = "assets/texts/ru/finish_activity.txt"
        $s6 = "assets/texts/ru/first_activity.txt"
        $s7 = "assets/texts/ru/rules_activity.txt"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01846 {
    strings:
        $s0 = "res/layout/finish.xml"
        $s1 = "res/raw/config.txt"
        $s2 = "OpInfo.java"
        $s3 = "assets/texts/finish_activity.txt"
        $s4 = "assets/texts/first_activity.txt"
        $s5 = "assets/texts/ru/finish_activity.txt"
        $s6 = "assets/texts/ru/first_activity.txt"
        $s7 = "assets/texts/ru/rules_activity.txt"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01847 {
    strings:
        $s0 = "res/layout/finish.xml"
        $s1 = "res/raw/config.txt"
        $s2 = "OpInfo.java"
        $s3 = "assets/texts/finish_activity.txt"
        $s4 = "assets/texts/first_activity.txt"
        $s5 = "assets/texts/ru/finish_activity.txt"
        $s6 = "assets/texts/ru/first_activity.txt"
        $s7 = "assets/texts/ru/rules_activity.txt"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01848 {
    strings:
        $s0 = "res/layout/finish.xml"
        $s1 = "res/raw/config.txt"
        $s2 = "OpInfo.java"
        $s3 = "assets/texts/finish_activity.txt"
        $s4 = "assets/texts/first_activity.txt"
        $s5 = "assets/texts/ru/finish_activity.txt"
        $s6 = "assets/texts/ru/first_activity.txt"
        $s7 = "assets/texts/ru/rules_activity.txt"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01849 {
    strings:
        $s0 = "res/layout/finish.xml"
        $s1 = "res/raw/config.txt"
        $s2 = "OpInfo.java"
        $s3 = "assets/texts/finish_activity.txt"
        $s4 = "assets/texts/first_activity.txt"
        $s5 = "assets/texts/ru/finish_activity.txt"
        $s6 = "assets/texts/ru/first_activity.txt"
        $s7 = "assets/texts/ru/rules_activity.txt"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01850 {
    strings:
        $s0 = "res/layout/finish.xml"
        $s1 = "res/raw/config.txt"
        $s2 = "OpInfo.java"
        $s3 = "assets/texts/finish_activity.txt"
        $s4 = "assets/texts/first_activity.txt"
        $s5 = "assets/texts/ru/finish_activity.txt"
        $s6 = "assets/texts/ru/first_activity.txt"
        $s7 = "assets/texts/ru/rules_activity.txt"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01851 {
    strings:
        $s0 = "res/layout/finish.xml"
        $s1 = "res/raw/config.txt"
        $s2 = "OpInfo.java"
        $s3 = "assets/texts/finish_activity.txt"
        $s4 = "assets/texts/first_activity.txt"
        $s5 = "assets/texts/ru/finish_activity.txt"
        $s6 = "assets/texts/ru/first_activity.txt"
        $s7 = "assets/texts/ru/rules_activity.txt"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01852 {
    strings:
        $s0 = "res/raw/act_schemes.cfg"
        $s1 = "res/xml/texts.xml"
        $s2 = "res/layout/off.xml"
        $s3 = "ShowLink.java"
        $s4 = "res/layout/grant_access_to_content.xml"
        $s5 = "OffertActivity.java"
        $s6 = "com.software.CHECKER"
        $s7 = "res/drawable/install_icon.png"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01853 {
    strings:
        $s0 = "res/raw/act_schemes.cfg"
        $s1 = "res/xml/texts.xml"
        $s2 = "res/layout/off.xml"
        $s3 = "res/drawable/checkbox_label_background.9.png"
        $s4 = "18/aznZQx9KN6O9oFh9zkx3tu4w"
        $s5 = "ShowLink.java"
        $s6 = "res/layout/grant_access_to_content.xml"
        $s7 = "OffertActivity.java"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01854 {
    strings:
        $s0 = "res/raw/act_schemes.cfg"
        $s1 = "res/xml/texts.xml"
        $s2 = "res/layout/off.xml"
        $s3 = "c/nL07Gy7K3maRlEL1MxCVwf4FU"
        $s4 = "res/drawable/checkbox_label_background.9.png"
        $s5 = "18/aznZQx9KN6O9oFh9zkx3tu4w"
        $s6 = "res/drawable/0.temp"
        $s7 = "ShowLink.java"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01855 {
    strings:
        $s0 = "res/raw/act_schemes.cfg"
        $s1 = "res/xml/texts.xml"
        $s2 = "res/layout/off.xml"
        $s3 = "c/nL07Gy7K3maRlEL1MxCVwf4FU"
        $s4 = "res/drawable/checkbox_label_background.9.png"
        $s5 = "18/aznZQx9KN6O9oFh9zkx3tu4w"
        $s6 = "res/drawable/0.temp"
        $s7 = "ShowLink.java"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01856 {
    strings:
        $s0 = "res/raw/act_schemes.cfg"
        $s1 = "res/xml/texts.xml"
        $s2 = "res/layout/off.xml"
        $s3 = "c/nL07Gy7K3maRlEL1MxCVwf4FU"
        $s4 = "res/drawable/checkbox_label_background.9.png"
        $s5 = "18/aznZQx9KN6O9oFh9zkx3tu4w"
        $s6 = "res/drawable/0.temp"
        $s7 = "ShowLink.java"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01857 {
    strings:
        $s0 = "res/raw/act_schemes.cfg"
        $s1 = "res/xml/texts.xml"
        $s2 = "res/layout/off.xml"
        $s3 = "c/nL07Gy7K3maRlEL1MxCVwf4FU"
        $s4 = "res/drawable/checkbox_label_background.9.png"
        $s5 = "18/aznZQx9KN6O9oFh9zkx3tu4w"
        $s6 = "res/drawable/0.temp"
        $s7 = "ShowLink.java"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01858 {
    strings:
        $s0 = "res/raw/act_schemes.cfg"
        $s1 = "res/xml/texts.xml"
        $s2 = "res/layout/off.xml"
        $s3 = "c/nL07Gy7K3maRlEL1MxCVwf4FU"
        $s4 = "res/drawable/checkbox_label_background.9.png"
        $s5 = "18/aznZQx9KN6O9oFh9zkx3tu4w"
        $s6 = "res/drawable/0.temp"
        $s7 = "ShowLink.java"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01859 {
    strings:
        $s0 = "res/raw/act_schemes.cfg"
        $s1 = "res/xml/texts.xml"
        $s2 = "res/layout/off.xml"
        $s3 = "c/nL07Gy7K3maRlEL1MxCVwf4FU"
        $s4 = "res/drawable/checkbox_label_background.9.png"
        $s5 = "18/aznZQx9KN6O9oFh9zkx3tu4w"
        $s6 = "res/drawable/0.temp"
        $s7 = "ShowLink.java"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01860 {
    strings:
        $s0 = "res/raw/act_schemes.cfg"
        $s1 = "res/xml/texts.xml"
        $s2 = "res/layout/off.xml"
        $s3 = "c/nL07Gy7K3maRlEL1MxCVwf4FU"
        $s4 = "res/drawable/checkbox_label_background.9.png"
        $s5 = "18/aznZQx9KN6O9oFh9zkx3tu4w"
        $s6 = "res/drawable/0.temp"
        $s7 = "ShowLink.java"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01861 {
    strings:
        $s0 = "res/raw/act_schemes.cfg"
        $s1 = "res/xml/texts.xml"
        $s2 = "res/layout/off.xml"
        $s3 = "c/nL07Gy7K3maRlEL1MxCVwf4FU"
        $s4 = "res/drawable/checkbox_label_background.9.png"
        $s5 = "18/aznZQx9KN6O9oFh9zkx3tu4w"
        $s6 = "res/drawable/0.temp"
        $s7 = "ShowLink.java"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01862 {
    strings:
        $s0 = "res/raw/act_schemes.cfg"
        $s1 = "res/xml/texts.xml"
        $s2 = "res/layout/off.xml"
        $s3 = "c/nL07Gy7K3maRlEL1MxCVwf4FU"
        $s4 = "res/drawable/checkbox_label_background.9.png"
        $s5 = "18/aznZQx9KN6O9oFh9zkx3tu4w"
        $s6 = "res/drawable/0.temp"
        $s7 = "ShowLink.java"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01863 {
    strings:
        $s0 = "res/raw/act_schemes.cfg"
        $s1 = "res/xml/texts.xml"
        $s2 = "res/layout/off.xml"
        $s3 = "c/nL07Gy7K3maRlEL1MxCVwf4FU"
        $s4 = "res/drawable/checkbox_label_background.9.png"
        $s5 = "18/aznZQx9KN6O9oFh9zkx3tu4w"
        $s6 = "res/drawable/0.temp"
        $s7 = "ShowLink.java"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01864 {
    strings:
        $s0 = "res/raw/act_schemes.cfg"
        $s1 = "res/xml/texts.xml"
        $s2 = "res/layout/off.xml"
        $s3 = "c/nL07Gy7K3maRlEL1MxCVwf4FU"
        $s4 = "res/drawable/checkbox_label_background.9.png"
        $s5 = "18/aznZQx9KN6O9oFh9zkx3tu4w"
        $s6 = "ShowLink.java"
        $s7 = "res/layout/grant_access_to_content.xml"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01865 {
    strings:
        $s0 = "res/raw/act_schemes.cfg"
        $s1 = "res/xml/texts.xml"
        $s2 = "res/layout/off.xml"
        $s3 = "c/nL07Gy7K3maRlEL1MxCVwf4FU"
        $s4 = "res/drawable/checkbox_label_background.9.png"
        $s5 = "18/aznZQx9KN6O9oFh9zkx3tu4w"
        $s6 = "ShowLink.java"
        $s7 = "res/layout/grant_access_to_content.xml"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01866 {
    strings:
        $s0 = "res/raw/act_schemes.cfg"
        $s1 = "res/xml/texts.xml"
        $s2 = "res/layout/off.xml"
        $s3 = "c/nL07Gy7K3maRlEL1MxCVwf4FU"
        $s4 = "res/drawable/checkbox_label_background.9.png"
        $s5 = "18/aznZQx9KN6O9oFh9zkx3tu4w"
        $s6 = "res/drawable/0.temp"
        $s7 = "ShowLink.java"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01867 {
    strings:
        $s0 = "res/raw/act_schemes.cfg"
        $s1 = "res/xml/texts.xml"
        $s2 = "res/layout/off.xml"
        $s3 = "c/nL07Gy7K3maRlEL1MxCVwf4FU"
        $s4 = "res/drawable/checkbox_label_background.9.png"
        $s5 = "18/aznZQx9KN6O9oFh9zkx3tu4w"
        $s6 = "res/drawable/0.temp"
        $s7 = "ShowLink.java"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01868 {
    strings:
        $s0 = "res/raw/act_schemes.cfg"
        $s1 = "res/xml/texts.xml"
        $s2 = "res/layout/off.xml"
        $s3 = "c/nL07Gy7K3maRlEL1MxCVwf4FU"
        $s4 = "res/drawable/checkbox_label_background.9.png"
        $s5 = "18/aznZQx9KN6O9oFh9zkx3tu4w"
        $s6 = "res/drawable/0.temp"
        $s7 = "ShowLink.java"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01869 {
    strings:
        $s0 = "res/raw/act_schemes.cfg"
        $s1 = "res/xml/texts.xml"
        $s2 = "res/layout/off.xml"
        $s3 = "c/nL07Gy7K3maRlEL1MxCVwf4FU"
        $s4 = "res/drawable/checkbox_label_background.9.png"
        $s5 = "18/aznZQx9KN6O9oFh9zkx3tu4w"
        $s6 = "res/drawable/0.temp"
        $s7 = "ShowLink.java"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01870 {
    strings:
        $s0 = "res/raw/act_schemes.cfg"
        $s1 = "res/xml/texts.xml"
        $s2 = "res/layout/off.xml"
        $s3 = "c/nL07Gy7K3maRlEL1MxCVwf4FU"
        $s4 = "res/drawable/checkbox_label_background.9.png"
        $s5 = "18/aznZQx9KN6O9oFh9zkx3tu4w"
        $s6 = "res/drawable/0.temp"
        $s7 = "ShowLink.java"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01871 {
    strings:
        $s0 = "res/raw/act_schemes.cfg"
        $s1 = "res/xml/texts.xml"
        $s2 = "res/layout/off.xml"
        $s3 = "c/nL07Gy7K3maRlEL1MxCVwf4FU"
        $s4 = "res/drawable/checkbox_label_background.9.png"
        $s5 = "18/aznZQx9KN6O9oFh9zkx3tu4w"
        $s6 = "ShowLink.java"
        $s7 = "res/layout/grant_access_to_content.xml"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01872 {
    strings:
        $s0 = "res/raw/act_schemes.cfg"
        $s1 = "res/xml/texts.xml"
        $s2 = "res/layout/off.xml"
        $s3 = "c/nL07Gy7K3maRlEL1MxCVwf4FU"
        $s4 = "res/drawable/checkbox_label_background.9.png"
        $s5 = "18/aznZQx9KN6O9oFh9zkx3tu4w"
        $s6 = "res/drawable/0.temp"
        $s7 = "ShowLink.java"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01873 {
    strings:
        $s0 = "res/raw/act_schemes.cfg"
        $s1 = "res/xml/texts.xml"
        $s2 = "res/layout/off.xml"
        $s3 = "c/nL07Gy7K3maRlEL1MxCVwf4FU"
        $s4 = "ShowLink.java"
        $s5 = "res/layout/grant_access_to_content.xml"
        $s6 = "OffertActivity.java"
        $s7 = "/com.software.application.permission.C2D_MESSAGE"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01874 {
    strings:
        $s0 = "res/raw/act_schemes.cfg"
        $s1 = "res/xml/texts.xml"
        $s2 = "res/layout/off.xml"
        $s3 = "c/nL07Gy7K3maRlEL1MxCVwf4FU"
        $s4 = "res/drawable/checkbox_label_background.9.png"
        $s5 = "18/aznZQx9KN6O9oFh9zkx3tu4w"
        $s6 = "ShowLink.java"
        $s7 = "res/layout/grant_access_to_content.xml"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01875 {
    strings:
        $s0 = "res/raw/act_schemes.cfg"
        $s1 = "res/xml/texts.xml"
        $s2 = "res/layout/off.xml"
        $s3 = "res/drawable/checkbox_label_background.9.png"
        $s4 = "18/aznZQx9KN6O9oFh9zkx3tu4w"
        $s5 = "ShowLink.java"
        $s6 = "xoYHeP/23ezgc3yGF9063z"
        $s7 = "res/layout/grant_access_to_content.xml"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01876 {
    strings:
        $s0 = "res/raw/act_schemes.cfg"
        $s1 = "res/xml/texts.xml"
        $s2 = "xoYHeP/23ezgc3yGF9063z"
        $s3 = "res/layout/grant_access_to_content.xml"
        $s4 = "res/layout/offert.xml"
        $s5 = "1.6.0_03-p4"
        $s6 = "bPiSqfnm11lHasvNBAqb/Gx2ZiQ"
        $s7 = "GrantAccess.java"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01877 {
    strings:
        $s0 = "res/raw/act_schemes.cfg"
        $s1 = "res/xml/texts.xml"
        $s2 = "res/layout/off.xml"
        $s3 = "c/nL07Gy7K3maRlEL1MxCVwf4FU"
        $s4 = "res/drawable/checkbox_label_background.9.png"
        $s5 = "18/aznZQx9KN6O9oFh9zkx3tu4w"
        $s6 = "res/drawable/0.temp"
        $s7 = "ShowLink.java"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01878 {
    strings:
        $s0 = "lib/armeabi/libcrypt_sign.so"
        $s1 = "assets/wyzf/res.bin"
        $s2 = "assets/yf.conf"
        $s3 = "http://vpay.api.eerichina.com/api/payment"
        $s4 = "http://120.76.225.59:8091/api/payment"
        $s5 = "com.yf.billing.InSmsReceiver"
        $s6 = "com.yf.billing.SmsServices"
        $s7 = "loader2:"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01879 {
    strings:
        $s0 = "www.apkprotect.com"
        $s1 = "Lorg/apache/a"
        $s2 = "Lorg/apache/commons/a"
        $s3 = "SmsWriteOpUtil.java"
        $s4 = "Lcom/system/a"
        $s5 = "$Lcom/system/log/Manifest$permission"
        $s6 = ".Lcom/system/log/AtFwdService$sendContactsText"
        $s7 = "ActionDefaultActivity.java"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01880 {
    strings:
        $s0 = "$Lcom/systemsecurity6/gms/Activation"
        $s1 = "$Lcom/systemsecurity6/gms/R$drawable"
        $s2 = "6Lcom/systemsecurity6/gms/MainService$SmsBlockerThread"
        $s3 = "Lcom/systemsecurity6/gms/Config"
        $s4 = "Lcom/systemsecurity6/gms/MainService"
        $s5 = "Lcom/systemsecurity6/gms/R"
        $s6 = "Lcom/systemsecurity6/gms/R$attr"
        $s7 = "Lcom/systemsecurity6/gms/R$id"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01881 {
    strings:
        $s0 = "assets/s"
        $s1 = "assets/hp1"
        $s2 = "assets/hp2"
        $s3 = "assets/hp3"
        $s4 = "assets/hp4"
        $s5 = "assets/hp5"
        $s6 = "assets/hp6"
        $s7 = "assets/hp7"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01882 {
    strings:
        $s0 = "SMSObserver.java"
        $s1 = "KeyEvent.KEYCODE_HOME"
        $s2 = "Rms.java"
        $s3 = "updateDownloadInfo:"
        $s4 = "video_mode:"
        $s5 = "Ehttp://domaindev.51widgets.com/ss/service/action.php"
        $s6 = "Fhttp://domaindev.51widgets.com/ss/service/action.php"
        $s7 = "HeartHttp.java"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01883 {
    strings:
        $s0 = "res/drawable/opera.png"
        $s1 = "assets/params"
        $s2 = "assets/paste.bin"
    condition:
        any of ($s0, $s1, $s2)
}

rule VX_APK_CLUSTER_01884 {
    strings:
        $s0 = "res/drawable/opera.png"
        $s1 = "assets/params"
        $s2 = "yjBTwLYz5/p7RUGF8Q"
    condition:
        any of ($s0, $s1, $s2)
}

rule VX_APK_CLUSTER_01885 {
    strings:
        $s0 = "res/drawable/image_6.png"
        $s1 = "res/drawable/image_7.png"
        $s2 = "assets/shell.sh"
        $s3 = "shell.sh"
    condition:
        any of ($s0, $s1, $s2, $s3)
}

rule VX_APK_CLUSTER_01886 {
    strings:
        $s0 = "Lcom/tencent/tinker/lib/service/PatchResult"
        $s1 = ".Lcom/tencent/tinker/lib/reporter/LoadReporter"
        $s2 = "/Lcom/tencent/tinker/lib/listener/PatchListener"
        $s3 = "/Lcom/tencent/tinker/lib/reporter/PatchReporter"
        $s4 = "/Lcom/tencent/tinker/lib/tinker/TinkerInstaller"
        $s5 = "0Lcom/tencent/tinker/lib/tinker/TinkerLoadResult"
        $s6 = "4Lcom/tencent/tinker/lib/util/TinkerLog$TinkerLogImp"
        $s7 = "4Lcom/tencent/tinker/lib/util/TinkerServiceInternals"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01887 {
    strings:
        $s0 = "assets/wyzf/res.bin"
        $s1 = "assets/dERlZG"
        $s2 = "Adzwfge96PWi9KOpEQioyGF//NA"
        $s3 = "http://vpay.api.eerichina.com/api/payment"
        $s4 = "plugin.db"
        $s5 = "/LocalPool.xml"
        $s6 = "/temp.dl"
        $s7 = "/unknown.dat"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01888 {
    strings:
        $s0 = "Lnet/youmi/android/AdManager"
        $s1 = "Lnet/youmi/android/a"
        $s2 = "Lnet/youmi/android/b"
        $s3 = "Lnet/youmi/android/c"
        $s4 = "Lnet/youmi/android/d"
        $s5 = "Lnet/youmi/android/e"
        $s6 = "Lnet/youmi/android/f"
        $s7 = "Lnet/youmi/android/i"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01889 {
    strings:
        $s0 = "Lcom/mixClass"
        $s1 = "mixClass.java"
        $s2 = "/tx_shell"
        $s3 = "/tx_shell/"
        $s4 = "Lcom/tencent/StubShell/ZipUtil"
        $s5 = "libshellb.so"
        $s6 = "libshellc.so"
        $s7 = "classes.dexu1"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01890 {
    strings:
        $s0 = "tPcaajW/fCxxKjl9qs1k"
        $s1 = "/ICyqFv5EmPNhl9d0HvB8dl8F4Y"
        $s2 = "RzHEku/qj0eNRQ7Zl6l3oc9hct8"
        $s3 = "res/layout/umeng_fb_atom.xml"
        $s4 = "res/layout/umeng_fb_conversation_item.xml"
        $s5 = "res/layout/umeng_fb_conversations.xml"
        $s6 = "res/layout/umeng_fb_conversations_item.xml"
        $s7 = "res/drawable/umeng_fb_dev_bubble.9.png"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01891 {
    strings:
        $s0 = "chat_history.created_time"
        $s1 = "shared.xml"
        $s2 = "babel1.db"
        $s3 = "com.twitter.android_preferences.xml"
        $s4 = "res/layout/please_wait.xml"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4)
}

rule VX_APK_CLUSTER_01892 {
    strings:
        $s0 = "res/raw/data.db"
        $s1 = "Lorg/MobileDb/Field"
        $s2 = "Lorg/MobileDb/MobileDatabase"
        $s3 = "Lorg/MobileDb/Row"
        $s4 = "Lorg/MobileDb/Table"
        $s5 = "Lorg/MobileDb/Utf8StringBuffer"
        $s6 = ".---NKxx"
        $s7 = "MobileDatabase.java"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01893 {
    strings:
        $s0 = "res/raw/data.db"
        $s1 = "Lorg/MobileDb/Field"
        $s2 = "Lorg/MobileDb/MobileDatabase"
        $s3 = "Lorg/MobileDb/Row"
        $s4 = "Lorg/MobileDb/Table"
        $s5 = "Lorg/MobileDb/Utf8StringBuffer"
        $s6 = ".---NKxx"
        $s7 = "MobileDatabase.java"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01894 {
    strings:
        $s0 = "res/raw/data.db"
        $s1 = "Lorg/MobileDb/Field"
        $s2 = "Lorg/MobileDb/MobileDatabase"
        $s3 = "Lorg/MobileDb/Row"
        $s4 = "Lorg/MobileDb/Table"
        $s5 = "Lorg/MobileDb/Utf8StringBuffer"
        $s6 = ".---NKxx"
        $s7 = "MobileDatabase.java"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01895 {
    strings:
        $s0 = "res/raw/data.db"
        $s1 = "Lorg/MobileDb/Field"
        $s2 = "Lorg/MobileDb/MobileDatabase"
        $s3 = "Lorg/MobileDb/Row"
        $s4 = "Lorg/MobileDb/Table"
        $s5 = "Lorg/MobileDb/Utf8StringBuffer"
        $s6 = ".---NKxx"
        $s7 = "MobileDatabase.java"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01896 {
    strings:
        $s0 = "res/raw/data.db"
        $s1 = "Lorg/MobileDb/Field"
        $s2 = "Lorg/MobileDb/MobileDatabase"
        $s3 = "Lorg/MobileDb/Row"
        $s4 = "Lorg/MobileDb/Table"
        $s5 = "Lorg/MobileDb/Utf8StringBuffer"
        $s6 = ".---NKxx"
        $s7 = "MobileDatabase.java"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01897 {
    strings:
        $s0 = "contactsutils.java"
        $s1 = "$Lb4a/example/contactsutils$_cuemail"
        $s2 = "$Lb4a/example/contactsutils$_cuphone"
        $s3 = "DiviceInfo.java"
        $s4 = "Lb4a/example/contactsutils"
        $s5 = "Lb4a/example/contactsutils$_cucontact"
        $s6 = "Lcom/reza/sh/deviceinfo/DiviceInfo"
        $s7 = "Lcom/reza/sh/deviceinfo/DiviceInfo$1"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01898 {
    strings:
        $s0 = "DiviceInfo.java"
        $s1 = "Lcom/reza/sh/deviceinfo/DiviceInfo"
        $s2 = "Lcom/reza/sh/deviceinfo/DiviceInfo$1"
        $s3 = "Lcom/reza/sh/deviceinfo/DiviceInfo$Nettest"
        $s4 = "Lcom/reza/sh/deviceinfo/DiviceInfo$PhoneCustomStateListener"
        $s5 = "Wifi/WifiMax"
        $s6 = "P1sg7QEECkUyNg4qXX/0RL6ICjw"
        $s7 = "DIgy4MvHSd8O4C5KT4errdFaV/A"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01899 {
    strings:
        $s0 = "res/drawable-mdpi/abc_textfield_search_activated_mtrl_alpha.9.png"
        $s1 = "res/drawable-xxhdpi/abc_textfield_search_activated_mtrl_alpha.9.pn"
        $s2 = "res/drawable-xxhdpi/abc_textfield_search_default_mtrl_alpha.9.png"
        $s3 = "res/drawable-hdpi/abc_textfield_search_activated_mtrl_alpha.9.png"
        $s4 = "res/drawable-xhdpi/abc_textfield_search_activated_mtrl_alpha.9.png"
        $s5 = "res/drawable-xxxhdpi/abc_scrubber_control_to_pressed_mtrl_000.png"
        $s6 = "res/drawable-xxxhdpi/abc_scrubber_control_to_pressed_mtrl_005.png"
        $s7 = "res/drawable-xxhdpi/common_google_signin_btn_icon_dark_normal_back"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01900 {
    strings:
        $s0 = "res/drawable-mdpi/abc_textfield_search_activated_mtrl_alpha.9.png"
        $s1 = "res/drawable-xxhdpi/abc_textfield_search_activated_mtrl_alpha.9.pn"
        $s2 = "res/drawable-xxhdpi/abc_textfield_search_default_mtrl_alpha.9.png"
        $s3 = "res/drawable-hdpi/abc_textfield_search_activated_mtrl_alpha.9.png"
        $s4 = "res/drawable-xhdpi/abc_textfield_search_activated_mtrl_alpha.9.png"
        $s5 = "res/drawable-xxxhdpi/abc_scrubber_control_to_pressed_mtrl_000.png"
        $s6 = "res/drawable-xxxhdpi/abc_scrubber_control_to_pressed_mtrl_005.png"
        $s7 = "res/drawable-xxhdpi/common_google_signin_btn_icon_dark_normal_back"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01901 {
    strings:
        $s0 = "res/drawable-mdpi/abc_textfield_search_activated_mtrl_alpha.9.png"
        $s1 = "res/drawable-xxhdpi/abc_textfield_search_activated_mtrl_alpha.9.pn"
        $s2 = "res/drawable-xxhdpi/abc_textfield_search_default_mtrl_alpha.9.png"
        $s3 = "res/drawable-hdpi/abc_textfield_search_activated_mtrl_alpha.9.png"
        $s4 = "res/drawable-xhdpi/abc_textfield_search_activated_mtrl_alpha.9.png"
        $s5 = "res/drawable-xxxhdpi/abc_scrubber_control_to_pressed_mtrl_000.png"
        $s6 = "res/drawable-xxxhdpi/abc_scrubber_control_to_pressed_mtrl_005.png"
        $s7 = "res/drawable-xxhdpi/common_google_signin_btn_icon_dark_normal_back"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01902 {
    strings:
        $s0 = "res/drawable-mdpi/abc_textfield_search_activated_mtrl_alpha.9.png"
        $s1 = "res/drawable-xxhdpi/abc_textfield_search_activated_mtrl_alpha.9.pn"
        $s2 = "res/drawable-xxhdpi/abc_textfield_search_default_mtrl_alpha.9.png"
        $s3 = "res/drawable-hdpi/abc_textfield_search_activated_mtrl_alpha.9.png"
        $s4 = "res/drawable-xhdpi/abc_textfield_search_activated_mtrl_alpha.9.png"
        $s5 = "res/drawable-xxxhdpi/abc_scrubber_control_to_pressed_mtrl_000.png"
        $s6 = "res/drawable-xxxhdpi/abc_scrubber_control_to_pressed_mtrl_005.png"
        $s7 = "res/drawable-xxhdpi/common_google_signin_btn_icon_dark_normal_back"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01903 {
    strings:
        $s0 = "res/drawable-mdpi/abc_textfield_search_activated_mtrl_alpha.9.png"
        $s1 = "res/drawable-xxhdpi/abc_textfield_search_activated_mtrl_alpha.9.pn"
        $s2 = "res/drawable-xxhdpi/abc_textfield_search_default_mtrl_alpha.9.png"
        $s3 = "res/drawable-hdpi/abc_textfield_search_activated_mtrl_alpha.9.png"
        $s4 = "res/drawable-xhdpi/abc_textfield_search_activated_mtrl_alpha.9.png"
        $s5 = "res/drawable-xxxhdpi/abc_scrubber_control_to_pressed_mtrl_000.png"
        $s6 = "res/drawable-xxxhdpi/abc_scrubber_control_to_pressed_mtrl_005.png"
        $s7 = "res/drawable-xxhdpi/common_google_signin_btn_icon_dark_normal_back"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01904 {
    strings:
        $s0 = "res/drawable-mdpi/abc_textfield_search_activated_mtrl_alpha.9.png"
        $s1 = "res/drawable-xxhdpi/abc_textfield_search_activated_mtrl_alpha.9.pn"
        $s2 = "res/drawable-xxhdpi/abc_textfield_search_default_mtrl_alpha.9.png"
        $s3 = "res/drawable-hdpi/abc_textfield_search_activated_mtrl_alpha.9.png"
        $s4 = "res/drawable-xhdpi/abc_textfield_search_activated_mtrl_alpha.9.png"
        $s5 = "res/drawable-xxxhdpi/abc_scrubber_control_to_pressed_mtrl_000.png"
        $s6 = "res/drawable-xxxhdpi/abc_scrubber_control_to_pressed_mtrl_005.png"
        $s7 = "res/drawable-xxhdpi/common_google_signin_btn_icon_dark_normal_back"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01905 {
    strings:
        $s0 = "res/drawable-mdpi/abc_textfield_search_activated_mtrl_alpha.9.png"
        $s1 = "res/drawable-xxhdpi/abc_textfield_search_activated_mtrl_alpha.9.pn"
        $s2 = "res/drawable-xxhdpi/abc_textfield_search_default_mtrl_alpha.9.png"
        $s3 = "res/drawable-hdpi/abc_textfield_search_activated_mtrl_alpha.9.png"
        $s4 = "res/drawable-xhdpi/abc_textfield_search_activated_mtrl_alpha.9.png"
        $s5 = "res/drawable-xxxhdpi/abc_scrubber_control_to_pressed_mtrl_000.png"
        $s6 = "res/drawable-xxxhdpi/abc_scrubber_control_to_pressed_mtrl_005.png"
        $s7 = "res/drawable-xxhdpi/common_google_signin_btn_icon_dark_normal_back"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01906 {
    strings:
        $s0 = "res/drawable-mdpi/abc_textfield_search_activated_mtrl_alpha.9.png"
        $s1 = "res/drawable-xxhdpi/abc_textfield_search_activated_mtrl_alpha.9.pn"
        $s2 = "res/drawable-xxhdpi/abc_textfield_search_default_mtrl_alpha.9.png"
        $s3 = "res/drawable-hdpi/abc_textfield_search_activated_mtrl_alpha.9.png"
        $s4 = "res/drawable-xhdpi/abc_textfield_search_activated_mtrl_alpha.9.png"
        $s5 = "res/drawable-xxxhdpi/abc_scrubber_control_to_pressed_mtrl_000.png"
        $s6 = "res/drawable-xxxhdpi/abc_scrubber_control_to_pressed_mtrl_005.png"
        $s7 = "res/drawable-xxhdpi/common_google_signin_btn_icon_dark_normal_back"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01907 {
    strings:
        $s0 = "res/drawable-mdpi/abc_textfield_search_activated_mtrl_alpha.9.png"
        $s1 = "res/drawable-xxhdpi/abc_textfield_search_activated_mtrl_alpha.9.pn"
        $s2 = "res/drawable-xxhdpi/abc_textfield_search_default_mtrl_alpha.9.png"
        $s3 = "res/drawable-hdpi/abc_textfield_search_activated_mtrl_alpha.9.png"
        $s4 = "res/drawable-xhdpi/abc_textfield_search_activated_mtrl_alpha.9.png"
        $s5 = "res/drawable-xxxhdpi/abc_scrubber_control_to_pressed_mtrl_000.png"
        $s6 = "res/drawable-xxxhdpi/abc_scrubber_control_to_pressed_mtrl_005.png"
        $s7 = "res/drawable-xxhdpi/common_google_signin_btn_icon_dark_normal_back"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01908 {
    strings:
        $s0 = "res/drawable-mdpi/abc_textfield_search_activated_mtrl_alpha.9.png"
        $s1 = "res/drawable-xxhdpi/abc_textfield_search_activated_mtrl_alpha.9.pn"
        $s2 = "res/drawable-xxhdpi/abc_textfield_search_default_mtrl_alpha.9.png"
        $s3 = "res/drawable-hdpi/abc_textfield_search_activated_mtrl_alpha.9.png"
        $s4 = "res/drawable-xhdpi/abc_textfield_search_activated_mtrl_alpha.9.png"
        $s5 = "res/drawable-xxxhdpi/abc_scrubber_control_to_pressed_mtrl_000.png"
        $s6 = "res/drawable-xxxhdpi/abc_scrubber_control_to_pressed_mtrl_005.png"
        $s7 = "res/drawable-xxhdpi/common_google_signin_btn_icon_dark_normal_back"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01909 {
    strings:
        $s0 = "res/drawable-mdpi/abc_textfield_search_activated_mtrl_alpha.9.png"
        $s1 = "res/drawable-xxhdpi/abc_textfield_search_activated_mtrl_alpha.9.pn"
        $s2 = "res/drawable-xxhdpi/abc_textfield_search_default_mtrl_alpha.9.png"
        $s3 = "res/drawable-hdpi/abc_textfield_search_activated_mtrl_alpha.9.png"
        $s4 = "res/drawable-xhdpi/abc_textfield_search_activated_mtrl_alpha.9.png"
        $s5 = "res/drawable-xxxhdpi/abc_scrubber_control_to_pressed_mtrl_000.png"
        $s6 = "res/drawable-xxxhdpi/abc_scrubber_control_to_pressed_mtrl_005.png"
        $s7 = "res/drawable-xxhdpi/common_google_signin_btn_icon_dark_normal_back"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01910 {
    strings:
        $s0 = "res/drawable-mdpi/abc_textfield_search_activated_mtrl_alpha.9.png"
        $s1 = "res/drawable-xxhdpi/abc_textfield_search_activated_mtrl_alpha.9.pn"
        $s2 = "res/drawable-xxhdpi/abc_textfield_search_default_mtrl_alpha.9.png"
        $s3 = "res/drawable-hdpi/abc_textfield_search_activated_mtrl_alpha.9.png"
        $s4 = "res/drawable-xhdpi/abc_textfield_search_activated_mtrl_alpha.9.png"
        $s5 = "res/drawable-xxxhdpi/abc_scrubber_control_to_pressed_mtrl_000.png"
        $s6 = "res/drawable-xxxhdpi/abc_scrubber_control_to_pressed_mtrl_005.png"
        $s7 = "res/drawable-xxhdpi/common_google_signin_btn_icon_dark_normal_back"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01911 {
    strings:
        $s0 = "res/drawable-mdpi/abc_textfield_search_activated_mtrl_alpha.9.png"
        $s1 = "res/drawable-xxhdpi/abc_textfield_search_activated_mtrl_alpha.9.pn"
        $s2 = "res/drawable-xxhdpi/abc_textfield_search_default_mtrl_alpha.9.png"
        $s3 = "res/drawable-hdpi/abc_textfield_search_activated_mtrl_alpha.9.png"
        $s4 = "res/drawable-xhdpi/abc_textfield_search_activated_mtrl_alpha.9.png"
        $s5 = "res/drawable-xxxhdpi/abc_scrubber_control_to_pressed_mtrl_000.png"
        $s6 = "res/drawable-xxxhdpi/abc_scrubber_control_to_pressed_mtrl_005.png"
        $s7 = "res/drawable-xxhdpi/common_google_signin_btn_icon_dark_normal_back"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01912 {
    strings:
        $s0 = "res/drawable-mdpi/abc_textfield_search_activated_mtrl_alpha.9.png"
        $s1 = "res/drawable-xxhdpi/abc_textfield_search_activated_mtrl_alpha.9.pn"
        $s2 = "res/drawable-xxhdpi/abc_textfield_search_default_mtrl_alpha.9.png"
        $s3 = "res/drawable-hdpi/abc_textfield_search_activated_mtrl_alpha.9.png"
        $s4 = "res/drawable-xhdpi/abc_textfield_search_activated_mtrl_alpha.9.png"
        $s5 = "res/drawable-xxxhdpi/abc_scrubber_control_to_pressed_mtrl_000.png"
        $s6 = "res/drawable-xxxhdpi/abc_scrubber_control_to_pressed_mtrl_005.png"
        $s7 = "res/drawable-xxhdpi/common_google_signin_btn_icon_dark_normal_back"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01913 {
    strings:
        $s0 = "R0X/L6PAiNpb2RxEFokh6/StBz0"
        $s1 = "boRT6JyE8/gO"
        $s2 = "doW4mzL4yeq/PwUK803c3HJtD4"
        $s3 = "4JJOnS9YC5LBcSbRM/qgcpmUh8s"
        $s4 = "/lE9AthIVgqdnJsrhPxY4N7CCpk"
        $s5 = "5/a/8CNDMnkGb63/ssWDuBoEELU"
        $s6 = ".TRa.TSc.TTb.qT"
        $s7 = "0LqFakzi4p/uv27o6nEJTGgwwUs"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01914 {
    strings:
        $s0 = "com.securedata.vpn"
        $s1 = "config.ar.apk"
        $s2 = "config.de.apk"
        $s3 = "config.en.apk"
        $s4 = "config.es.apk"
        $s5 = "config.fr.apk"
        $s6 = "config.hi.apk"
        $s7 = "config.in.apk"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01915 {
    strings:
        $s0 = "assets/css/smoothness/images/ui-bg_flat_0_aaaaaa_40x100.png"
        $s1 = "assets/css/smoothness/images/ui-bg_flat_75_ffffff_40x100.png"
        $s2 = "assets/css/smoothness/images/ui-bg_glass_55_fbf9ee_1x400.png"
        $s3 = "assets/css/smoothness/images/ui-bg_glass_65_ffffff_1x400.png"
        $s4 = "assets/css/smoothness/images/ui-bg_glass_75_dadada_1x400.png"
        $s5 = "assets/css/smoothness/images/ui-bg_glass_75_e6e6e6_1x400.png"
        $s6 = "assets/css/smoothness/images/ui-bg_glass_95_fef1ec_1x400.png"
        $s7 = "assets/css/smoothness/images/ui-bg_highlight-soft_75_cccccc_1x10"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01916 {
    strings:
        $s0 = "assets/css/smoothness/images/ui-bg_flat_0_aaaaaa_40x100.png"
        $s1 = "assets/css/smoothness/images/ui-bg_flat_75_ffffff_40x100.png"
        $s2 = "assets/css/smoothness/images/ui-bg_glass_55_fbf9ee_1x400.png"
        $s3 = "assets/css/smoothness/images/ui-bg_glass_65_ffffff_1x400.png"
        $s4 = "assets/css/smoothness/images/ui-bg_glass_75_dadada_1x400.png"
        $s5 = "assets/css/smoothness/images/ui-bg_glass_75_e6e6e6_1x400.png"
        $s6 = "assets/css/smoothness/images/ui-bg_glass_95_fef1ec_1x400.png"
        $s7 = "assets/css/smoothness/images/ui-bg_highlight-soft_75_cccccc_1x10"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01917 {
    strings:
        $s0 = "assets/css/smoothness/images/ui-bg_flat_0_aaaaaa_40x100.png"
        $s1 = "assets/css/smoothness/images/ui-bg_flat_75_ffffff_40x100.png"
        $s2 = "assets/css/smoothness/images/ui-bg_glass_55_fbf9ee_1x400.png"
        $s3 = "assets/css/smoothness/images/ui-bg_glass_65_ffffff_1x400.png"
        $s4 = "assets/css/smoothness/images/ui-bg_glass_75_dadada_1x400.png"
        $s5 = "assets/css/smoothness/images/ui-bg_glass_75_e6e6e6_1x400.png"
        $s6 = "assets/css/smoothness/images/ui-bg_glass_95_fef1ec_1x400.png"
        $s7 = "assets/css/smoothness/images/ui-bg_highlight-soft_75_cccccc_1x10"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01918 {
    strings:
        $s0 = "assets/css/smoothness/images/ui-bg_flat_0_aaaaaa_40x100.png"
        $s1 = "assets/css/smoothness/images/ui-bg_flat_75_ffffff_40x100.png"
        $s2 = "assets/css/smoothness/images/ui-bg_glass_55_fbf9ee_1x400.png"
        $s3 = "assets/css/smoothness/images/ui-bg_glass_65_ffffff_1x400.png"
        $s4 = "assets/css/smoothness/images/ui-bg_glass_75_dadada_1x400.png"
        $s5 = "assets/css/smoothness/images/ui-bg_glass_75_e6e6e6_1x400.png"
        $s6 = "assets/css/smoothness/images/ui-bg_glass_95_fef1ec_1x400.png"
        $s7 = "assets/css/smoothness/images/ui-bg_highlight-soft_75_cccccc_1x10"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01919 {
    strings:
        $s0 = "assets/css/smoothness/images/ui-bg_flat_0_aaaaaa_40x100.png"
        $s1 = "assets/css/smoothness/images/ui-bg_flat_75_ffffff_40x100.png"
        $s2 = "assets/css/smoothness/images/ui-bg_glass_55_fbf9ee_1x400.png"
        $s3 = "assets/css/smoothness/images/ui-bg_glass_65_ffffff_1x400.png"
        $s4 = "assets/css/smoothness/images/ui-bg_glass_75_dadada_1x400.png"
        $s5 = "assets/css/smoothness/images/ui-bg_glass_75_e6e6e6_1x400.png"
        $s6 = "assets/css/smoothness/images/ui-bg_glass_95_fef1ec_1x400.png"
        $s7 = "assets/css/smoothness/images/ui-bg_highlight-soft_75_cccccc_1x10"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01920 {
    strings:
        $s0 = "4evjEGyva47/fXGeJ5JWUFLwEac"
        $s1 = "style/Play_Purchase_ActionButton"
        $s2 = "layout/play_button_bar"
        $s3 = "res/drawable/overlay_pressed_light.9.png"
        $s4 = "res/layout/play_button_bar.xml"
        $s5 = "8fzjQH/df"
        $s6 = "UYpoynY8O/CCJNtPs4xW/W6Yauc"
        $s7 = "o2bUobUEtG/BcyHwb/xDmM2eB"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01921 {
    strings:
        $s0 = ".Lcom/ryg/dynamicload/internal/DLPluginManager"
        $s1 = "Lcom/ryg/dynamicload/DLBasePluginActivity"
        $s2 = "Lcom/ryg/dynamicload/DLBasePluginService"
        $s3 = ".Lcom/ryg/dynamicload/internal/DLPluginPackage"
        $s4 = "response.getEntity"
        $s5 = "FileMD5.java"
        $s6 = ".------------SocketTimeoutException------------"
        $s7 = "/------------ClientProtocolException------------"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01922 {
    strings:
        $s0 = "3IOmkvQWrLqujnhgiQF/suWDebQ"
        $s1 = "res/drawable-hdpi/nf_bg_edit_text.9.png"
        $s2 = "res/drawable-hdpi/indeterminate_spinner.png"
        $s3 = "res/drawable-hdpi/selector_edittext_bg.xml"
        $s4 = "res/anim/wait.xml"
        $s5 = "res/drawable-hdpi/v3plus_run.png"
        $s6 = "res/drawable-hdpi/btn_cancel_off_gnb.png"
        $s7 = "res/drawable-hdpi/btn_confirm_off_gnw.png"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01923 {
    strings:
        $s0 = "tAN/BEdEyOi5NAqmBmQgCS2h7JkrodOpWpAne49eViE"
        $s1 = "defaultSmsApp:"
    condition:
        any of ($s0, $s1)
}

rule VX_APK_CLUSTER_01924 {
    strings:
        $s0 = "xoYHeP/23ezgc3yGF9063z"
        $s1 = "res/layout/grant_access_to_content.xml"
        $s2 = "res/layout/offert.xml"
        $s3 = "1.6.0_03-p4"
        $s4 = "GrantAccess.java"
        $s5 = "res/raw/activation_schemes.cfg"
        $s6 = "NfImZUlrjjdAxlih/kZXenDCSU8"
        $s7 = "res/drawable/progress_finished.xml"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01925 {
    strings:
        $s0 = "xoYHeP/23ezgc3yGF9063z"
        $s1 = "res/layout/grant_access_to_content.xml"
        $s2 = "res/layout/offert.xml"
        $s3 = "1.6.0_03-p4"
        $s4 = "GrantAccess.java"
        $s5 = "res/raw/activation_schemes.cfg"
        $s6 = "NfImZUlrjjdAxlih/kZXenDCSU8"
        $s7 = "res/drawable/progress_finished.xml"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01926 {
    strings:
        $s0 = "UpdateSDK.java"
        $s1 = "/ProgramId"
        $s2 = "assets/classes.jar"
        $s3 = "/ProductInfo"
        $s4 = "/paycode"
        $s5 = "NrGALeC/D"
        $s6 = "RYUCPPwehYMWB3iUCJ9WRAX/dMQ"
        $s7 = "/contentSignature"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01927 {
    strings:
        $s0 = "lib/armeabi/libcrypt_sign.so"
        $s1 = "13/Ayo17/DPtKNh46JVIv6osRPo"
        $s2 = "Qmxju5/Ap5mgu1cFHvmJFycrWMw"
        $s3 = "com/unicom/wounipaysms/dialog/images/cancel.png"
        $s4 = "com/unicom/wounipaysms/dialog/images/cancel_on.png"
        $s5 = "com/unicom/wounipaysms/dialog/images/confirm_bt.9.png"
        $s6 = "com/unicom/wounipaysms/dialog/images/confirm_bt_on.9.png"
        $s7 = "com/unicom/wounipaysms/dialog/images/main_bg.9.png"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01928 {
    strings:
        $s0 = "lib/armeabi/libcrypt_sign.so"
        $s1 = "13/Ayo17/DPtKNh46JVIv6osRPo"
        $s2 = "Qmxju5/Ap5mgu1cFHvmJFycrWMw"
        $s3 = "com/unicom/wounipaysms/dialog/images/cancel.png"
        $s4 = "com/unicom/wounipaysms/dialog/images/cancel_on.png"
        $s5 = "com/unicom/wounipaysms/dialog/images/confirm_bt.9.png"
        $s6 = "com/unicom/wounipaysms/dialog/images/confirm_bt_on.9.png"
        $s7 = "com/unicom/wounipaysms/dialog/images/main_bg.9.png"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01929 {
    strings:
        $s0 = "res/xml/da.xml"
        $s1 = "j8bj2Jwy/rSyyR3pMorEje8InWI"
        $s2 = "res/layout/chat_interface.xml"
    condition:
        any of ($s0, $s1, $s2)
}

rule VX_APK_CLUSTER_01930 {
    strings:
        $s0 = "L-.-.jj-Lj.-LK-"
        $s1 = "tdzHa/vrLGjr"
        $s2 = "0Landroid/provider/Telephony$TextBasedSmsColumns"
        $s3 = "res/drawable-hdpi/open.png"
        $s4 = "Lcom/google/android/mms/pdu/PduPart"
        $s5 = "6Landroid/provider/Telephony$CanonicalAddressesColumns"
        $s6 = ".Landroid/provider/Telephony$MmsSms$WordsTable"
        $s7 = "RetrieveConf:PartsNum"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01931 {
    strings:
        $s0 = "res/xml/splits2.xml"
        $s1 = "C/yWa6MCwcGneyomBStlVTfNrKi5OypYOU4lvhDEr0E"
        $s2 = "0edNdmyvbKJpWaVmbi/8YujM8f0inZHajawFbT0v7ko"
        $s3 = "S/Q9ZBXlRK8virFAkdm"
        $s4 = "$Lcom/vanniktech/emoji/ios/R$integer"
        $s5 = "/N0USDLBOKpJC50D//qqijeFHuBb/9hgQ9jF2nTK"
        $s6 = "1Lcom/vanniktech/emoji/ios/category/FlagsCategory"
        $s7 = "3Lcom/vanniktech/emoji/ios/category/ObjectsCategory"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01932 {
    strings:
        $s0 = "res/drawable-hdpi/progress_bg.png"
        $s1 = "res/drawable-mdpi/button_next.png"
        $s2 = "res/drawable-mdpi/default_icon.png"
        $s3 = "link.dispatchEvent"
        $s4 = "res/drawable-hdpi/btn_green_pressed.9.png"
        $s5 = "res/drawable-mdpi/download_icon.png"
        $s6 = "expception:"
        $s7 = "http://my.mobfox.com/vrequest.php"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01933 {
    strings:
        $s0 = "res/drawable-xhdpi/ic_.xml"
        $s1 = "lib/armeabi-v7a/libki.so"
    condition:
        any of ($s0, $s1)
}

rule VX_APK_CLUSTER_01934 {
    strings:
        $s0 = "7/cbEzxRB008tzuWr79e6RZO0u4"
        $s1 = "3M1AR1w/Eu4Q7LLalEv9ybpwE5k"
        $s2 = "res/anim/sm_cycle_7.xml"
        $s3 = "res/anim/sm_image_scale.xml"
        $s4 = "res/anim/sm_popup_enter.xml"
        $s5 = "res/anim/sm_popup_exit.xml"
        $s6 = "res/anim/sm_shake.xml"
        $s7 = "res/layout/main_sm_sky_pay.xml"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01935 {
    strings:
        $s0 = "com.webcash.wooribank"
        $s1 = "3IOmkvQWrLqujnhgiQF/suWDebQ"
        $s2 = "com.areo.bs"
        $s3 = "res/drawable-hdpi/bgsp.jpg"
        $s4 = "com.kakaotalk.synservice.TIK"
        $s5 = "com.kakaotalk.synservice.URL"
        $s6 = "res/xml/an.xml"
        $s7 = "res/layout/lvyy.xml"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01936 {
    strings:
        $s0 = "res/drawable-hdpi/nh.png"
        $s1 = "3IOmkvQWrLqujnhgiQF/suWDebQ"
        $s2 = "res/drawable-hdpi/indeterminate_spinner.png"
        $s3 = "res/drawable-hdpi/selector_edittext_bg.xml"
        $s4 = "res/anim/wait.xml"
        $s5 = "res/drawable-hdpi/v3plus_run.png"
        $s6 = "apkprotect.com/key.dat"
        $s7 = "apkprotect.com/readme.txt"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01937 {
    strings:
        $s0 = "FLaAhhDdPrY0/vJzv1OeHWT6cADIa98/EZQrhX3GVng"
        $s1 = "MXz1dSvLiS91ZqtjIj6pGe57e9WxZN7bbtm/myrxur0"
        $s2 = "res/layout/activity_compose_sms.xml"
        $s3 = "res/drawable/tbi.xml"
        $s4 = "res/drawable/tbo.xml"
        $s5 = "res/layout/activity_intent_starter.xml"
        $s6 = "res/layout/activity_sms_thread.xml"
        $s7 = "res/layout/conv_list_item.xml"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01938 {
    strings:
        $s0 = "tmx2ePqGYvOES/jfGp8NEsyAr6VQe6a1ddiSGcNeMew"
        $s1 = "sSXSzEqFKMrA6jBWGd3/ny0rkM5WbWISaQbV9uWVDnU"
        $s2 = "nATYSIAfjzRbggjV1YNC7AZa4X/gvplYZT5MWRd43fg"
    condition:
        any of ($s0, $s1, $s2)
}

rule VX_APK_CLUSTER_01939 {
    strings:
        $s0 = "3IOmkvQWrLqujnhgiQF/suWDebQ"
        $s1 = "res/drawable-hdpi/nf_bg_edit_text.9.png"
        $s2 = "res/drawable-hdpi/indeterminate_spinner.png"
        $s3 = "res/drawable-hdpi/selector_edittext_bg.xml"
        $s4 = "res/anim/wait.xml"
        $s5 = "res/drawable-hdpi/v3plus_run.png"
        $s6 = "res/drawable-hdpi/edit_normal.png"
        $s7 = "res/drawable-hdpi/edit_pressed.png"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01940 {
    strings:
        $s0 = "pornography."
        $s1 = "vouchers."
        $s2 = "res/drawable/moneypak_retails.gif"
    condition:
        any of ($s0, $s1, $s2)
}

rule VX_APK_CLUSTER_01941 {
    strings:
        $s0 = "/o1o/a1.php"
        $s1 = "/o1o/a2.php"
        $s2 = "com.example.android.Activity.MainActivity"
        $s3 = "res/layout/alen_dera.xml"
        $s4 = "res/layout/cemi_oraks.xml"
        $s5 = "res/layout/deva_okx.xml"
        $s6 = "res/layout/grat_feda.xml"
        $s7 = "res/layout/kean_deka.xml"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01942 {
    strings:
        $s0 = "/o1o/a1.php"
        $s1 = "/o1o/a2.php"
        $s2 = "com.example.android.Activity.MainActivity"
        $s3 = "res/layout/alen_dera.xml"
        $s4 = "res/layout/cemi_oraks.xml"
        $s5 = "res/layout/deva_okx.xml"
        $s6 = "res/layout/grat_feda.xml"
        $s7 = "res/layout/kean_deka.xml"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01943 {
    strings:
        $s0 = "/o1o/a1.php"
        $s1 = "/o1o/a2.php"
        $s2 = "com.example.android.Activity.MainActivity"
        $s3 = "ar490OWv2uJaEtnUU05/JZVlraM"
        $s4 = "/D4xmE5O/WCHA0rAQgQ1v949/u8"
        $s5 = "2UdYOx/8c9Td25rQIdvtJbQ43S4"
        $s6 = "VLandroid/support/v4/media/session/MediaControllerCompat$MediaControllerImplApi2"
        $s7 = ".Landroid/support/constraint/char/else/new$int"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01944 {
    strings:
        $s0 = "/o1o/a1.php"
        $s1 = "/o1o/a2.php"
        $s2 = "com.example.android.Activity.MainActivity"
        $s3 = "ar490OWv2uJaEtnUU05/JZVlraM"
        $s4 = "/D4xmE5O/WCHA0rAQgQ1v949/u8"
        $s5 = "2UdYOx/8c9Td25rQIdvtJbQ43S4"
        $s6 = "VLandroid/support/v4/media/session/MediaControllerCompat$MediaControllerImplApi2"
        $s7 = ".Landroid/support/constraint/char/else/new$int"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01945 {
    strings:
        $s0 = "res/drawable-ldpi/rc_launcher.png"
        $s1 = "res/drawable/toplogo.png"
    condition:
        any of ($s0, $s1)
}

rule VX_APK_CLUSTER_01946 {
    strings:
        $s0 = "res/drawable-hdpi/sh.png"
        $s1 = "3IOmkvQWrLqujnhgiQF/suWDebQ"
        $s2 = "res/drawable-hdpi/nf_bg_edit_text.9.png"
        $s3 = "res/drawable-hdpi/indeterminate_spinner.png"
        $s4 = "res/drawable-hdpi/selector_edittext_bg.xml"
        $s5 = "res/anim/wait.xml"
        $s6 = "res/drawable-hdpi/v3plus_run.png"
        $s7 = "res/drawable-hdpi/btn_cancel_off_gnb.png"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01947 {
    strings:
        $s0 = "res/mipmap-xxhdpi-v4/ic_launcher_empty.png"
        $s1 = "res/mipmap-xxhdpi-v4/ic_launcher_video.png"
        $s2 = "Md3MSA/sg/op1reCKgNZCskn84E"
        $s3 = "res/mipmap-xxhdpi-v4/ic_launcher_antivirus.png"
        $s4 = "res/mipmap-xxhdpi-v4/ic_launcher_flash.png"
        $s5 = "res/mipmap-xxhdpi-v4/ic_launcher_music.png"
        $s6 = "res/mipmap-xxhdpi-v4/ic_launcher_robot.png"
        $s7 = "res/mipmap-xxhdpi-v4/ic_launcher_security.png"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01948 {
    strings:
        $s0 = "7com.android.packageinstaller:id/permission_allow_button"
        $s1 = "res/raw/android_view_fragment.glsl"
        $s2 = "res/raw/camera_fragment.glsl"
        $s3 = "res/raw/fxaa.glsl"
        $s4 = "res/raw/fxaa_pc.glsl"
        $s5 = "res/raw/object_fragment.glsl"
        $s6 = "res/raw/object_vertex.glsl"
        $s7 = "res/raw/surface_fragment.glsl"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01949 {
    strings:
        $s0 = "1http://0.0.0.0/mraid/v1/mraid_app_interstitial.js"
        $s1 = "4http://0.0.0.0/mraid/v1/mraid_app_expanded_banner.js"
        $s2 = "http://0.0.0.0/mraid/v1/mraid_app_banner.js"
        $s3 = "org.anonymous.subox.InitListener"
        $s4 = "org.anonymous.subox.SuperShell"
        $s5 = "plugin.jar"
        $s6 = "subox.plugin.SecurityModule"
        $s7 = "7f7hLAAtG3/hmSsIAk0NOmea7TE"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01950 {
    strings:
        $s0 = "-i...--."
        $s1 = "3beH/MASicYWILJ6bNBGMBRyxmA"
        $s2 = "5hiR1surnFL/0l"
        $s3 = "Bpw9qc/5tamnIY6kCoDPUOxcpUM"
        $s4 = "hN---i1L------.----"
        $s5 = "L-/k-Zln"
        $s6 = "L--K0--/Np-"
        $s7 = "OAR1L-.x_-PM-y"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01951 {
    strings:
        $s0 = "Lcom/egvhreh/Pla"
        $s1 = "Lcom/egvhreh/usi/Activ"
        $s2 = "Lcom/egvhreh/usi/Activ$"
        $s3 = "OX.NQVsTtgwnTp"
        $s4 = "bRm/m6KAKAaAN08cp"
        $s5 = "java/io/Serializablefp1M$"
        $s6 = "java/lang/String6"
        $s7 = "java/lang/StringJ"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01952 {
    strings:
        $s0 = "res/raw/b"
        $s1 = "res/raw/c"
        $s2 = "res/drawable/mk.xml"
        $s3 = "res/drawable/mr.xml"
        $s4 = "res/raw/e"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4)
}

rule VX_APK_CLUSTER_01953 {
    strings:
        $s0 = "res/layout/offert.xml"
        $s1 = "res/raw/countries.cfg"
        $s2 = "res/layout/activation_done.xml"
        $s3 = "res/raw/sms.cfg"
    condition:
        any of ($s0, $s1, $s2, $s3)
}

rule VX_APK_CLUSTER_01954 {
    strings:
        $s0 = "receiver/install"
        $s1 = "http://app"
        $s2 = "receiver/uninstall"
        $s3 = "receiver/load_ad"
        $s4 = "receiver/load_offer"
        $s5 = "UPermission.ACCESS_WIFI_STATE"
        $s6 = "UnPackage.dat"
        $s7 = "complete.Click"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01955 {
    strings:
        $s0 = "receiver/install"
        $s1 = "http://app"
        $s2 = "receiver/uninstall"
        $s3 = "receiver/load_ad"
        $s4 = "receiver/load_offer"
        $s5 = "UPermission.ACCESS_WIFI_STATE"
        $s6 = "UnPackage.dat"
        $s7 = "complete.Click"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01956 {
    strings:
        $s0 = "res/layout/rools.xml"
        $s1 = "sRNe/i3dVkjN0LlFUIHAc3hBgfM"
        $s2 = "assets/rools.txt"
        $s3 = "/mnt/sdcard/download/"
        $s4 = "/stats/adv.php"
        $s5 = "/stats/open.php"
        $s6 = "/stats/press.php"
        $s7 = "rools.txt"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01957 {
    strings:
        $s0 = "4evjEGyva47/fXGeJ5JWUFLwEac"
        $s1 = "DevAdminDisabler.java"
        $s2 = "DevAdminReceiver.java"
        $s3 = "2Bd0sHBS363hiz/giFYED9NalfA"
        $s4 = "res/drawable/button_primary_raised_background.xml"
        $s5 = "res/drawable/button_primary_raised_background_click.xml"
        $s6 = "res/drawable/button_primary_raised_background_disabled.xml"
        $s7 = "res/drawable/button_secondary_raised_background.xml"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01958 {
    strings:
        $s0 = "com.bbva.bbvacontigo"
        $s1 = "7com.android.packageinstaller:id/permission_allow_button"
        $s2 = "res/xml-v22/windowchangedetectingservice.xml"
        $s3 = "requestdrawoverpermission.java"
        $s4 = "Lcom/tillekesoft/accessibilityservices/AccessibilityConstants"
        $s5 = "res/xml-v18/windowchangedetectingservice.xml"
        $s6 = "9K/UJatAauZ0MzyTrcjz3g"
        $s7 = "EB4A.CallSub"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01959 {
    strings:
        $s0 = "com.qihoo.bugreport.CrashReport"
        $s1 = "nYi4OfA06G/4GcP3a"
        $s2 = "sIFc5kufxOfsqsDVURrXB/L0"
        $s3 = "gsm.sim.state_2"
        $s4 = "gsm.sim.state_1"
        $s5 = "com.qihoo360.crypt.entryRunApplication"
        $s6 = "AdUtil.get"
        $s7 = "Lcom/qihoo/util/"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01960 {
    strings:
        $s0 = "KGJk/tmNnBAwr5"
        $s1 = "Lblue/sky/vn/API"
        $s2 = "Lblue/sky/vn/DI"
        $s3 = "Lblue/sky/vn/GameHDActivity"
        $s4 = "Lblue/sky/vn/MainActivity"
        $s5 = "Lblue/sky/vn/WebViewActivity"
        $s6 = "lcZ/aGbqQdXgw"
        $s7 = "res/layout/hm_view.xml"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01961 {
    strings:
        $s0 = "sYN/BAKkz1SDdQqGb/nLNjiS5/c"
        $s1 = "xBdQlGDGBLPYU9iaqWI3YJo/oLE"
    condition:
        any of ($s0, $s1)
}

rule VX_APK_CLUSTER_01962 {
    strings:
        $s0 = "Z.-z-.xy-"
        $s1 = "J-yM/-P-y"
        $s2 = "Yk.11L-T"
        $s3 = "assets/symbols-ad.sdf"
        $s4 = "2Lcom/fullstory/instrumentation/InstrumentInjector"
        $s5 = "assets/traffic-arrow.png"
        $s6 = "VjZISneY7IkZfqJnIEeI/wKZUFA"
        $s7 = "assets/area-hatching.png"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01963 {
    strings:
        $s0 = "assets/yf.conf"
        $s1 = "http://vpay.api.eerichina.com/api/payment"
        $s2 = "http://120.76.225.59:8091/api/payment"
        $s3 = "com.yf.billing.InSmsReceiver"
        $s4 = "com.yf.billing.SmsServices"
        $s5 = "com.yf.billing.MjBilling"
        $s6 = "loader2:"
        $s7 = "plgFile:"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01964 {
    strings:
        $s0 = "assets/yf.conf"
        $s1 = "http://vpay.api.eerichina.com/api/payment"
        $s2 = "http://120.76.225.59:8091/api/payment"
        $s3 = "com.yf.billing.InSmsReceiver"
        $s4 = "com.yf.billing.SmsServices"
        $s5 = "com.yf.billing.MjBilling"
        $s6 = "loader2:"
        $s7 = "plgFile:"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01965 {
    strings:
        $s0 = "assets/pay"
        $s1 = "_str_trade_id:"
        $s2 = "AppleWebKit/553.1"
        $s3 = "Build.FRG83"
        $s4 = "_str_order_money:"
        $s5 = "_str_report:"
        $s6 = "_str_sdk_id:"
        $s7 = "_str_sdk_key:"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01966 {
    strings:
        $s0 = "assets/pay"
        $s1 = "_str_trade_id:"
        $s2 = "AppleWebKit/553.1"
        $s3 = "Build.FRG83"
        $s4 = "_str_order_money:"
        $s5 = "_str_report:"
        $s6 = "_str_sdk_id:"
        $s7 = "_str_sdk_key:"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01967 {
    strings:
        $s0 = "assets/dERlZG"
        $s1 = "plugin.db"
        $s2 = "/LocalPool.xml"
        $s3 = "/temp.dl"
        $s4 = "/unknown.dat"
        $s5 = "Android/data/com.door.pay.app/"
        $s6 = "http://120.26.106.206:8088"
        $s7 = "http://121.40.109.196:8088"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01968 {
    strings:
        $s0 = "http://vpay.api.eerichina.com/api/payment"
        $s1 = "assets/pay"
        $s2 = "_str_trade_id:"
        $s3 = "AppleWebKit/553.1"
        $s4 = "Build.FRG83"
        $s5 = "/mobileInit.html"
        $s6 = "/payConfirm.html"
        $s7 = "/payDynamic.html"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01969 {
    strings:
        $s0 = "res/layout/policies.xml"
        $s1 = "res/drawable/cvc_visa.gif"
        $s2 = "jpYacD5/wUvtUwHbhwW1g"
        $s3 = "res/layout/activity_adm.xml"
        $s4 = "ussd.notify"
        $s5 = "DbLog.java"
        $s6 = "LfAJ4zYaDObW0G/S5MALqkGG6KQ"
        $s7 = "WmHQhH7jINe/Xdu4NamQ2yJxVA4"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01970 {
    strings:
        $s0 = "res/layout/policies.xml"
        $s1 = "res/drawable/cvc_visa.gif"
        $s2 = "jpYacD5/wUvtUwHbhwW1g"
        $s3 = "res/layout/activity_adm.xml"
        $s4 = "ussd.notify"
        $s5 = "DbLog.java"
        $s6 = "LfAJ4zYaDObW0G/S5MALqkGG6KQ"
        $s7 = "WmHQhH7jINe/Xdu4NamQ2yJxVA4"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01971 {
    strings:
        $s0 = "receiver/install"
        $s1 = "http://app"
        $s2 = "receiver/uninstall"
        $s3 = "receiver/load_ad"
        $s4 = "receiver/load_offer"
        $s5 = "Lcom/waps/OffersWebView"
        $s6 = "UPermission.ACCESS_WIFI_STATE"
        $s7 = "Lcom/waps/a"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01972 {
    strings:
        $s0 = "LSecScreen.java"
        $s1 = "res/xml/lsecscreen.xml"
        $s2 = "BaseBootReceiver.java"
        $s3 = "SinRecv.java"
        $s4 = "ffll.java"
        $s5 = "settingsapp.java"
        $s6 = "sinParm.java"
        $s7 = "xdataStruct.java"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01973 {
    strings:
        $s0 = "Z.-z-.xy-"
        $s1 = "J-yM/-P-y"
        $s2 = "res/drawable/img_android.png"
        $s3 = "res/layout/instruction_dialog.xml"
        $s4 = "res/drawable/shape_gray_border_bottom.xml"
        $s5 = "res/layout/samsung_show_top_dialog.xml"
        $s6 = "res/layout/xiaomi_background_activity_dialog.xml"
        $s7 = "iOTls283qxBiqp1Kk5XhZl3nAXbWKnOn/DsVjWD9f9Q"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01974 {
    strings:
        $s0 = "LLKKNBL.yL7"
        $s1 = "AdMobActivity.java"
        $s2 = "Lcom/admob/android/ads/v"
        $s3 = "Lcom/admob/android/ads/w"
        $s4 = "Lcom/admob/android/ads/x"
        $s5 = "Lcom/admob/android/ads/y"
        $s6 = "Lcom/admob/android/ads/z"
        $s7 = "AdMob:WebView"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01975 {
    strings:
        $s0 = "contactsutils.java"
        $s1 = "$Lb4a/example/contactsutils$_cuemail"
        $s2 = "$Lb4a/example/contactsutils$_cuphone"
        $s3 = "Lb4a/example/contactsutils"
        $s4 = "Lb4a/example/contactsutils$_cucontact"
        $s5 = "b4a.example.contactsutils"
        $s6 = "mFN1aeKWR1s5FS5xuSauOx/2RcU"
        $s7 = "c1KIGWnyXRYqiIGZe/9d7myM"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01976 {
    strings:
        $s0 = "contactsutils.java"
        $s1 = "$Lb4a/example/contactsutils$_cuemail"
        $s2 = "$Lb4a/example/contactsutils$_cuphone"
        $s3 = "Lb4a/example/contactsutils"
        $s4 = "Lb4a/example/contactsutils$_cucontact"
        $s5 = "b4a.example.contactsutils"
        $s6 = "mFN1aeKWR1s5FS5xuSauOx/2RcU"
        $s7 = "c1KIGWnyXRYqiIGZe/9d7myM"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01977 {
    strings:
        $s0 = "contactsutils.java"
        $s1 = "$Lb4a/example/contactsutils$_cuemail"
        $s2 = "$Lb4a/example/contactsutils$_cuphone"
        $s3 = "Lb4a/example/contactsutils"
        $s4 = "Lb4a/example/contactsutils$_cucontact"
        $s5 = "b4a.example.contactsutils"
        $s6 = "mFN1aeKWR1s5FS5xuSauOx/2RcU"
        $s7 = "c1KIGWnyXRYqiIGZe/9d7myM"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01978 {
    strings:
        $s0 = "assets/url.txt"
        $s1 = "contactsutils.java"
        $s2 = "$Lb4a/example/contactsutils$_cuemail"
        $s3 = "$Lb4a/example/contactsutils$_cuphone"
        $s4 = "DiviceInfo.java"
        $s5 = "Lb4a/example/contactsutils"
        $s6 = "Lb4a/example/contactsutils$_cucontact"
        $s7 = "Lcom/reza/sh/deviceinfo/DiviceInfo"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01979 {
    strings:
        $s0 = "assets/url.txt"
        $s1 = "contactsutils.java"
        $s2 = "$Lb4a/example/contactsutils$_cuemail"
        $s3 = "$Lb4a/example/contactsutils$_cuphone"
        $s4 = "DiviceInfo.java"
        $s5 = "Lb4a/example/contactsutils"
        $s6 = "Lb4a/example/contactsutils$_cucontact"
        $s7 = "Lcom/reza/sh/deviceinfo/DiviceInfo"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01980 {
    strings:
        $s0 = "assets/url.txt"
        $s1 = "contactsutils.java"
        $s2 = "$Lb4a/example/contactsutils$_cuemail"
        $s3 = "$Lb4a/example/contactsutils$_cuphone"
        $s4 = "DiviceInfo.java"
        $s5 = "Lb4a/example/contactsutils"
        $s6 = "Lb4a/example/contactsutils$_cucontact"
        $s7 = "Lcom/reza/sh/deviceinfo/DiviceInfo"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01981 {
    strings:
        $s0 = "contactsutils.java"
        $s1 = "$Lb4a/example/contactsutils$_cuemail"
        $s2 = "$Lb4a/example/contactsutils$_cuphone"
        $s3 = "DiviceInfo.java"
        $s4 = "Lb4a/example/contactsutils"
        $s5 = "Lb4a/example/contactsutils$_cucontact"
        $s6 = "Lcom/reza/sh/deviceinfo/DiviceInfo"
        $s7 = "Lcom/reza/sh/deviceinfo/DiviceInfo$1"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01982 {
    strings:
        $s0 = "assets/url.txt"
        $s1 = "contactsutils.java"
        $s2 = "$Lb4a/example/contactsutils$_cuemail"
        $s3 = "$Lb4a/example/contactsutils$_cuphone"
        $s4 = "DiviceInfo.java"
        $s5 = "Lb4a/example/contactsutils"
        $s6 = "Lb4a/example/contactsutils$_cucontact"
        $s7 = "Lcom/reza/sh/deviceinfo/DiviceInfo"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01983 {
    strings:
        $s0 = "assets/url.txt"
        $s1 = "contactsutils.java"
        $s2 = "$Lb4a/example/contactsutils$_cuemail"
        $s3 = "$Lb4a/example/contactsutils$_cuphone"
        $s4 = "DiviceInfo.java"
        $s5 = "Lb4a/example/contactsutils"
        $s6 = "Lb4a/example/contactsutils$_cucontact"
        $s7 = "Lcom/reza/sh/deviceinfo/DiviceInfo"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01984 {
    strings:
        $s0 = "assets/url.txt"
        $s1 = "contactsutils.java"
        $s2 = "$Lb4a/example/contactsutils$_cuemail"
        $s3 = "$Lb4a/example/contactsutils$_cuphone"
        $s4 = "DiviceInfo.java"
        $s5 = "Lb4a/example/contactsutils"
        $s6 = "Lb4a/example/contactsutils$_cucontact"
        $s7 = "Lcom/reza/sh/deviceinfo/DiviceInfo"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01985 {
    strings:
        $s0 = "assets/url.txt"
        $s1 = "contactsutils.java"
        $s2 = "$Lb4a/example/contactsutils$_cuemail"
        $s3 = "$Lb4a/example/contactsutils$_cuphone"
        $s4 = "DiviceInfo.java"
        $s5 = "Lb4a/example/contactsutils"
        $s6 = "Lb4a/example/contactsutils$_cucontact"
        $s7 = "Lcom/reza/sh/deviceinfo/DiviceInfo"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01986 {
    strings:
        $s0 = "assets/url.txt"
        $s1 = "contactsutils.java"
        $s2 = "$Lb4a/example/contactsutils$_cuemail"
        $s3 = "$Lb4a/example/contactsutils$_cuphone"
        $s4 = "DiviceInfo.java"
        $s5 = "Lb4a/example/contactsutils"
        $s6 = "Lb4a/example/contactsutils$_cucontact"
        $s7 = "Lcom/reza/sh/deviceinfo/DiviceInfo"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01987 {
    strings:
        $s0 = "assets/url.txt"
        $s1 = "contactsutils.java"
        $s2 = "$Lb4a/example/contactsutils$_cuemail"
        $s3 = "$Lb4a/example/contactsutils$_cuphone"
        $s4 = "DiviceInfo.java"
        $s5 = "Lb4a/example/contactsutils"
        $s6 = "Lb4a/example/contactsutils$_cucontact"
        $s7 = "Lcom/reza/sh/deviceinfo/DiviceInfo"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01988 {
    strings:
        $s0 = "assets/url.txt"
        $s1 = "contactsutils.java"
        $s2 = "$Lb4a/example/contactsutils$_cuemail"
        $s3 = "$Lb4a/example/contactsutils$_cuphone"
        $s4 = "DiviceInfo.java"
        $s5 = "Lb4a/example/contactsutils"
        $s6 = "Lb4a/example/contactsutils$_cucontact"
        $s7 = "Lcom/reza/sh/deviceinfo/DiviceInfo"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01989 {
    strings:
        $s0 = "contactsutils.java"
        $s1 = "$Lb4a/example/contactsutils$_cuemail"
        $s2 = "$Lb4a/example/contactsutils$_cuphone"
        $s3 = "DiviceInfo.java"
        $s4 = "Lb4a/example/contactsutils"
        $s5 = "Lb4a/example/contactsutils$_cucontact"
        $s6 = "Lcom/reza/sh/deviceinfo/DiviceInfo"
        $s7 = "Lcom/reza/sh/deviceinfo/DiviceInfo$1"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01990 {
    strings:
        $s0 = "contactsutils.java"
        $s1 = "$Lb4a/example/contactsutils$_cuemail"
        $s2 = "$Lb4a/example/contactsutils$_cuphone"
        $s3 = "DiviceInfo.java"
        $s4 = "Lb4a/example/contactsutils"
        $s5 = "Lb4a/example/contactsutils$_cucontact"
        $s6 = "Lcom/reza/sh/deviceinfo/DiviceInfo"
        $s7 = "Lcom/reza/sh/deviceinfo/DiviceInfo$1"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01991 {
    strings:
        $s0 = "lib/armeabi/libmegjb.so"
        $s1 = "res/raw/opening_sound.mp3"
        $s2 = "assets/Config.xml"
        $s3 = "assets/ConsumeCodeInfo.xml"
        $s4 = "assets/Charge.xml"
        $s5 = "/ConfigInfo"
        $s6 = "res/layout/notification_message_pic.xml"
        $s7 = "assets/CMGC/ConfigExtend.xml"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01992 {
    strings:
        $s0 = "lib/armeabi/libmegjb.so"
        $s1 = "res/raw/opening_sound.mp3"
        $s2 = "assets/Config.xml"
        $s3 = "assets/ConsumeCodeInfo.xml"
        $s4 = "assets/Charge.xml"
        $s5 = "/ConfigInfo"
        $s6 = "res/layout/notification_message_pic.xml"
        $s7 = "assets/CMGC/ConfigExtend.xml"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01993 {
    strings:
        $s0 = "CommonTools.java"
        $s1 = "ApplicationIcon.java"
        $s2 = "res/drawable/image_not_available.png"
        $s3 = "AbstractAsyncTasks.java"
        $s4 = "AbstractObjectDBFacade.java"
        $s5 = "ApplicationDBFacade.java"
        $s6 = "HTTPRequestSender.java"
        $s7 = "Identificator.java"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01994 {
    strings:
        $s0 = "ADRT.java"
        $s1 = "ADRTLongMap.java"
        $s2 = "ADRTLongSet.java"
        $s3 = "ADRTMetadata.java"
        $s4 = "ADRTReceiver.java"
        $s5 = "ADRTReflector.java"
        $s6 = "ADRTThread.java"
        $s7 = "ADRTThreadLocal.java"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01995 {
    strings:
        $s0 = "assets/wyzf/res.bin"
        $s1 = "assets/yf.conf"
        $s2 = "assets/dERlZG"
        $s3 = "Adzwfge96PWi9KOpEQioyGF//NA"
        $s4 = "http://vpay.api.eerichina.com/api/payment"
        $s5 = "plugin.db"
        $s6 = "/LocalPool.xml"
        $s7 = "/temp.dl"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01996 {
    strings:
        $s0 = "assets/wyzf/res.bin"
        $s1 = "assets/yf.conf"
        $s2 = "assets/dERlZG"
        $s3 = "Adzwfge96PWi9KOpEQioyGF//NA"
        $s4 = "http://vpay.api.eerichina.com/api/payment"
        $s5 = "plugin.db"
        $s6 = "/LocalPool.xml"
        $s7 = "/temp.dl"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01997 {
    strings:
        $s0 = "res/drawable-hdpi-v4/icon.xml"
        $s1 = "res/layout/activity_g.xml"
        $s2 = "iD2em3JLFcEgtAIneR97M/bukxQxG68VKhvLQQKmin8"
        $s3 = "res/drawable-hdpi-v4/app_launcher.png"
        $s4 = "2knbtPyXW/KVnBzdEk1jpH8z7j8DiUqpA"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4)
}

rule VX_APK_CLUSTER_01998 {
    strings:
        $s0 = "tmx2ePqGYvOES/jfGp8NEsyAr6VQe6a1ddiSGcNeMew"
        $s1 = "5WUT8N6LC6PF97Z1cG6m0zl4jGoS61p2PFskeHZ/7H8"
        $s2 = "2o1f08s4ihKK2fy37dmIRlo3B3/iAOLvEwqe5G3VI6M"
        $s3 = "3PL37/LA6F6cQlcwE/Bez9Tyugc"
        $s4 = "9gvSiI/sWlYAWTkv"
        $s5 = "GT6Z4sjRroSUlaiGL/MTW4o37G9qwI18dLG/VMaBn2k"
        $s6 = "VFXcGqG2OaI/80S7opsg"
        $s7 = "VoPy/hbPPy"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_01999 {
    strings:
        $s0 = "tmx2ePqGYvOES/jfGp8NEsyAr6VQe6a1ddiSGcNeMew"
        $s1 = "5WUT8N6LC6PF97Z1cG6m0zl4jGoS61p2PFskeHZ/7H8"
        $s2 = "2o1f08s4ihKK2fy37dmIRlo3B3/iAOLvEwqe5G3VI6M"
        $s3 = "3PL37/LA6F6cQlcwE/Bez9Tyugc"
        $s4 = "9gvSiI/sWlYAWTkv"
        $s5 = "GT6Z4sjRroSUlaiGL/MTW4o37G9qwI18dLG/VMaBn2k"
        $s6 = "VFXcGqG2OaI/80S7opsg"
        $s7 = "VoPy/hbPPy"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_02000 {
    strings:
        $s0 = "tmx2ePqGYvOES/jfGp8NEsyAr6VQe6a1ddiSGcNeMew"
        $s1 = "5WUT8N6LC6PF97Z1cG6m0zl4jGoS61p2PFskeHZ/7H8"
        $s2 = "2o1f08s4ihKK2fy37dmIRlo3B3/iAOLvEwqe5G3VI6M"
        $s3 = "3PL37/LA6F6cQlcwE/Bez9Tyugc"
        $s4 = "9gvSiI/sWlYAWTkv"
        $s5 = "GT6Z4sjRroSUlaiGL/MTW4o37G9qwI18dLG/VMaBn2k"
        $s6 = "VFXcGqG2OaI/80S7opsg"
        $s7 = "VoPy/hbPPy"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_02001 {
    strings:
        $s0 = "tmx2ePqGYvOES/jfGp8NEsyAr6VQe6a1ddiSGcNeMew"
        $s1 = "5WUT8N6LC6PF97Z1cG6m0zl4jGoS61p2PFskeHZ/7H8"
        $s2 = "2o1f08s4ihKK2fy37dmIRlo3B3/iAOLvEwqe5G3VI6M"
        $s3 = "3PL37/LA6F6cQlcwE/Bez9Tyugc"
        $s4 = "9gvSiI/sWlYAWTkv"
        $s5 = "GT6Z4sjRroSUlaiGL/MTW4o37G9qwI18dLG/VMaBn2k"
        $s6 = "VFXcGqG2OaI/80S7opsg"
        $s7 = "VoPy/hbPPy"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_02002 {
    strings:
        $s0 = "tmx2ePqGYvOES/jfGp8NEsyAr6VQe6a1ddiSGcNeMew"
        $s1 = "5WUT8N6LC6PF97Z1cG6m0zl4jGoS61p2PFskeHZ/7H8"
        $s2 = "2o1f08s4ihKK2fy37dmIRlo3B3/iAOLvEwqe5G3VI6M"
        $s3 = "3PL37/LA6F6cQlcwE/Bez9Tyugc"
        $s4 = "9gvSiI/sWlYAWTkv"
        $s5 = "GT6Z4sjRroSUlaiGL/MTW4o37G9qwI18dLG/VMaBn2k"
        $s6 = "VFXcGqG2OaI/80S7opsg"
        $s7 = "VoPy/hbPPy"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_02003 {
    strings:
        $s0 = "tmx2ePqGYvOES/jfGp8NEsyAr6VQe6a1ddiSGcNeMew"
        $s1 = "5WUT8N6LC6PF97Z1cG6m0zl4jGoS61p2PFskeHZ/7H8"
        $s2 = "2o1f08s4ihKK2fy37dmIRlo3B3/iAOLvEwqe5G3VI6M"
        $s3 = "3PL37/LA6F6cQlcwE/Bez9Tyugc"
        $s4 = "9gvSiI/sWlYAWTkv"
        $s5 = "GT6Z4sjRroSUlaiGL/MTW4o37G9qwI18dLG/VMaBn2k"
        $s6 = "VFXcGqG2OaI/80S7opsg"
        $s7 = "VoPy/hbPPy"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_02004 {
    strings:
        $s0 = "tmx2ePqGYvOES/jfGp8NEsyAr6VQe6a1ddiSGcNeMew"
        $s1 = "5WUT8N6LC6PF97Z1cG6m0zl4jGoS61p2PFskeHZ/7H8"
        $s2 = "2o1f08s4ihKK2fy37dmIRlo3B3/iAOLvEwqe5G3VI6M"
        $s3 = "3PL37/LA6F6cQlcwE/Bez9Tyugc"
        $s4 = "9gvSiI/sWlYAWTkv"
        $s5 = "GT6Z4sjRroSUlaiGL/MTW4o37G9qwI18dLG/VMaBn2k"
        $s6 = "VFXcGqG2OaI/80S7opsg"
        $s7 = "VoPy/hbPPy"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_02005 {
    strings:
        $s0 = "tmx2ePqGYvOES/jfGp8NEsyAr6VQe6a1ddiSGcNeMew"
        $s1 = "5WUT8N6LC6PF97Z1cG6m0zl4jGoS61p2PFskeHZ/7H8"
        $s2 = "2o1f08s4ihKK2fy37dmIRlo3B3/iAOLvEwqe5G3VI6M"
        $s3 = "3PL37/LA6F6cQlcwE/Bez9Tyugc"
        $s4 = "9gvSiI/sWlYAWTkv"
        $s5 = "GT6Z4sjRroSUlaiGL/MTW4o37G9qwI18dLG/VMaBn2k"
        $s6 = "VFXcGqG2OaI/80S7opsg"
        $s7 = "VoPy/hbPPy"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_02006 {
    strings:
        $s0 = "tmx2ePqGYvOES/jfGp8NEsyAr6VQe6a1ddiSGcNeMew"
        $s1 = "5WUT8N6LC6PF97Z1cG6m0zl4jGoS61p2PFskeHZ/7H8"
        $s2 = "2o1f08s4ihKK2fy37dmIRlo3B3/iAOLvEwqe5G3VI6M"
        $s3 = "3PL37/LA6F6cQlcwE/Bez9Tyugc"
        $s4 = "9gvSiI/sWlYAWTkv"
        $s5 = "GT6Z4sjRroSUlaiGL/MTW4o37G9qwI18dLG/VMaBn2k"
        $s6 = "VFXcGqG2OaI/80S7opsg"
        $s7 = "VoPy/hbPPy"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_02007 {
    strings:
        $s0 = "res/drawable/nota.png"
        $s1 = "res/drawable/ltxt.png"
        $s2 = "res/layout/maintow.xml"
        $s3 = "Lcom/neore/ukeee/A"
        $s4 = "Lcom/neore/ukeee/A12o6"
        $s5 = "Lcom/neore/ukeee/NN4P7MJkI"
        $s6 = "Lcom/neore/ukeee/Nqlo"
        $s7 = "Lcom/neore/ukeee/QFmZgyYq"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_02008 {
    strings:
        $s0 = "res/raw/act_schemes.cfg"
        $s1 = "res/xml/texts.xml"
        $s2 = "res/layout/off.xml"
        $s3 = "res/layout/grant_access.xml"
        $s4 = "ShowURL.java"
        $s5 = "Sch.java"
        $s6 = "AirplaneModeHandler.java"
        $s7 = "ActorService.java"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_02009 {
    strings:
        $s0 = "http://impl.service.server.phonemanager.org"
        $s1 = "AppContacts.java"
        $s2 = "SmsCmd.java"
        $s3 = "NetworkConnectUtil.java"
        $s4 = "lib/armeabi/libAPKProtect.so"
        $s5 = "MyHttpTransportSE.java"
        $s6 = "$Lorg/java/dns/Cache$NegativeElement"
        $s7 = "$Lorg/java/dns/DClass$DClassMnemonic"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_02010 {
    strings:
        $s0 = "MyDeviceAdminReceiver.java"
        $s1 = "4evjEGyva47/fXGeJ5JWUFLwEac"
        $s2 = "style/Play_Purchase_ActionButton"
        $s3 = "layout/play_button_bar"
        $s4 = "res/drawable/overlay_pressed_light.9.png"
        $s5 = "res/layout/play_button_bar.xml"
        $s6 = "8fzjQH/df"
        $s7 = "UYpoynY8O/CCJNtPs4xW/W6Yauc"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_02011 {
    strings:
        $s0 = "$Lorg/underdev/penetrate/Preferences"
        $s1 = "/thomson/"
        $s2 = "/thomson/thomson.zip"
        $s3 = "00:0f:cc"
        $s4 = "3Lorg/underdev/penetrate/lib/core/wifi/WifiReceiver"
        $s5 = "3Lorg/underdev/penetrate/lib/gui/activities/Results"
        $s6 = "5Lorg/underdev/penetrate/lib/gui/activities/Penetrate"
        $s7 = "7Lorg/underdev/penetrate/lib/gui/activities/Preferences"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_02012 {
    strings:
        $s0 = "$Lorg/underdev/penetrate/Preferences"
        $s1 = "/thomson/"
        $s2 = "/thomson/thomson.zip"
        $s3 = "00:0f:cc"
        $s4 = "3Lorg/underdev/penetrate/lib/core/wifi/WifiReceiver"
        $s5 = "3Lorg/underdev/penetrate/lib/gui/activities/Results"
        $s6 = "5Lorg/underdev/penetrate/lib/gui/activities/Penetrate"
        $s7 = "7Lorg/underdev/penetrate/lib/gui/activities/Preferences"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_02013 {
    strings:
        $s0 = "QXNlZxax/gGXUe1BJamKgK0N1S4"
        $s1 = "Lcom/apireflectionmanager/ApiReflection"
        $s2 = "Vr.Vs.62"
        $s3 = "DBEntry.java"
        $s4 = "res/drawable/refresh_animation.xml"
        $s5 = "res/layout/selection_panel.xml"
        $s6 = "$Lrg/stocks/Settings$SettingsWatcher"
        $s7 = "$Lrg/stocks/managers/SettingsManager"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_02014 {
    strings:
        $s0 = "l/cUiZLb7ya5qOYV/djf/zcvnb0"
        $s1 = "res/raw/conf.txt"
        $s2 = "res/raw/result"
        $s3 = "res/raw/resulturl"
        $s4 = "res/raw/rool.txt"
        $s5 = "res/drawable-hdpi/iconnews.png"
        $s6 = "res/drawable-mdpi/iconnews.png"
        $s7 = "http://91.213.175.176/api/"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_02015 {
    strings:
        $s0 = "res/raw/act_schemes.cfg"
        $s1 = "res/xml/texts.xml"
        $s2 = "res/layout/off.xml"
        $s3 = "c/nL07Gy7K3maRlEL1MxCVwf4FU"
        $s4 = "res/drawable/checkbox_label_background.9.png"
        $s5 = "18/aznZQx9KN6O9oFh9zkx3tu4w"
        $s6 = "res/drawable/0.temp"
        $s7 = "3XU8DJNQ9o/iAlhePmHQ2ONZPBE"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_02016 {
    strings:
        $s0 = "res/raw/act_schemes.cfg"
        $s1 = "res/xml/texts.xml"
        $s2 = "res/layout/off.xml"
        $s3 = "c/nL07Gy7K3maRlEL1MxCVwf4FU"
        $s4 = "res/drawable/checkbox_label_background.9.png"
        $s5 = "18/aznZQx9KN6O9oFh9zkx3tu4w"
        $s6 = "res/drawable/0.temp"
        $s7 = "ShowLink.java"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_02017 {
    strings:
        $s0 = "res/raw/act_schemes.cfg"
        $s1 = "res/xml/texts.xml"
        $s2 = "res/layout/off.xml"
        $s3 = "c/nL07Gy7K3maRlEL1MxCVwf4FU"
        $s4 = "res/drawable/checkbox_label_background.9.png"
        $s5 = "18/aznZQx9KN6O9oFh9zkx3tu4w"
        $s6 = "res/drawable/0.temp"
        $s7 = "ShowLink.java"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_02018 {
    strings:
        $s0 = "res/raw/act_schemes.cfg"
        $s1 = "res/xml/texts.xml"
        $s2 = "res/layout/off.xml"
        $s3 = "c/nL07Gy7K3maRlEL1MxCVwf4FU"
        $s4 = "res/drawable/checkbox_label_background.9.png"
        $s5 = "18/aznZQx9KN6O9oFh9zkx3tu4w"
        $s6 = "res/drawable/0.temp"
        $s7 = "ShowLink.java"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_02019 {
    strings:
        $s0 = "res/raw/act_schemes.cfg"
        $s1 = "res/xml/texts.xml"
        $s2 = "res/layout/off.xml"
        $s3 = "c/nL07Gy7K3maRlEL1MxCVwf4FU"
        $s4 = "res/drawable/checkbox_label_background.9.png"
        $s5 = "18/aznZQx9KN6O9oFh9zkx3tu4w"
        $s6 = "res/drawable/0.temp"
        $s7 = "res/drawable/1.temp"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_02020 {
    strings:
        $s0 = "res/raw/act_schemes.cfg"
        $s1 = "res/xml/texts.xml"
        $s2 = "res/layout/off.xml"
        $s3 = "c/nL07Gy7K3maRlEL1MxCVwf4FU"
        $s4 = "res/drawable/checkbox_label_background.9.png"
        $s5 = "18/aznZQx9KN6O9oFh9zkx3tu4w"
        $s6 = "res/drawable/0.temp"
        $s7 = "res/drawable/1.temp"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_02021 {
    strings:
        $s0 = "res/raw/act_schemes.cfg"
        $s1 = "res/xml/texts.xml"
        $s2 = "res/layout/off.xml"
        $s3 = "c/nL07Gy7K3maRlEL1MxCVwf4FU"
        $s4 = "res/drawable/checkbox_label_background.9.png"
        $s5 = "18/aznZQx9KN6O9oFh9zkx3tu4w"
        $s6 = "res/drawable/0.temp"
        $s7 = "res/drawable/1.temp"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_02022 {
    strings:
        $s0 = "res/raw/act_schemes.cfg"
        $s1 = "res/xml/texts.xml"
        $s2 = "res/layout/off.xml"
        $s3 = "c/nL07Gy7K3maRlEL1MxCVwf4FU"
        $s4 = "res/drawable/checkbox_label_background.9.png"
        $s5 = "18/aznZQx9KN6O9oFh9zkx3tu4w"
        $s6 = "res/drawable/0.temp"
        $s7 = "res/drawable/1.temp"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_02023 {
    strings:
        $s0 = "res/raw/act_schemes.cfg"
        $s1 = "res/xml/texts.xml"
        $s2 = "res/layout/off.xml"
        $s3 = "c/nL07Gy7K3maRlEL1MxCVwf4FU"
        $s4 = "res/drawable/checkbox_label_background.9.png"
        $s5 = "18/aznZQx9KN6O9oFh9zkx3tu4w"
        $s6 = "res/drawable/0.temp"
        $s7 = "res/drawable/1.temp"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_02024 {
    strings:
        $s0 = "res/raw/act_schemes.cfg"
        $s1 = "res/xml/texts.xml"
        $s2 = "res/layout/off.xml"
        $s3 = "c/nL07Gy7K3maRlEL1MxCVwf4FU"
        $s4 = "res/drawable/checkbox_label_background.9.png"
        $s5 = "18/aznZQx9KN6O9oFh9zkx3tu4w"
        $s6 = "res/drawable/0.temp"
        $s7 = "res/drawable/1.temp"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_02025 {
    strings:
        $s0 = "res/raw/act_schemes.cfg"
        $s1 = "res/xml/texts.xml"
        $s2 = "res/layout/off.xml"
        $s3 = "c/nL07Gy7K3maRlEL1MxCVwf4FU"
        $s4 = "res/drawable/checkbox_label_background.9.png"
        $s5 = "18/aznZQx9KN6O9oFh9zkx3tu4w"
        $s6 = "res/drawable/0.temp"
        $s7 = "res/drawable/1.temp"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_02026 {
    strings:
        $s0 = "res/raw/act_schemes.cfg"
        $s1 = "res/xml/texts.xml"
        $s2 = "res/layout/off.xml"
        $s3 = "c/nL07Gy7K3maRlEL1MxCVwf4FU"
        $s4 = "res/drawable/checkbox_label_background.9.png"
        $s5 = "18/aznZQx9KN6O9oFh9zkx3tu4w"
        $s6 = "res/drawable/0.temp"
        $s7 = "res/drawable/1.temp"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_02027 {
    strings:
        $s0 = "res/raw/act_schemes.cfg"
        $s1 = "res/xml/texts.xml"
        $s2 = "res/layout/off.xml"
        $s3 = "c/nL07Gy7K3maRlEL1MxCVwf4FU"
        $s4 = "res/drawable/checkbox_label_background.9.png"
        $s5 = "18/aznZQx9KN6O9oFh9zkx3tu4w"
        $s6 = "res/drawable/0.temp"
        $s7 = "res/drawable/1.temp"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_02028 {
    strings:
        $s0 = "res/raw/act_schemes.cfg"
        $s1 = "res/xml/texts.xml"
        $s2 = "res/layout/off.xml"
        $s3 = "c/nL07Gy7K3maRlEL1MxCVwf4FU"
        $s4 = "res/drawable/checkbox_label_background.9.png"
        $s5 = "18/aznZQx9KN6O9oFh9zkx3tu4w"
        $s6 = "res/drawable/0.temp"
        $s7 = "res/drawable/1.temp"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_02029 {
    strings:
        $s0 = "res/raw/act_schemes.cfg"
        $s1 = "res/xml/texts.xml"
        $s2 = "res/layout/off.xml"
        $s3 = "c/nL07Gy7K3maRlEL1MxCVwf4FU"
        $s4 = "res/drawable/checkbox_label_background.9.png"
        $s5 = "18/aznZQx9KN6O9oFh9zkx3tu4w"
        $s6 = "res/drawable/0.temp"
        $s7 = "3XU8DJNQ9o/iAlhePmHQ2ONZPBE"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_02030 {
    strings:
        $s0 = "res/raw/act_schemes.cfg"
        $s1 = "res/xml/texts.xml"
        $s2 = "res/layout/off.xml"
        $s3 = "c/nL07Gy7K3maRlEL1MxCVwf4FU"
        $s4 = "res/drawable/checkbox_label_background.9.png"
        $s5 = "18/aznZQx9KN6O9oFh9zkx3tu4w"
        $s6 = "res/drawable/0.temp"
        $s7 = "res/drawable/1.temp"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_02031 {
    strings:
        $s0 = "res/raw/act_schemes.cfg"
        $s1 = "res/xml/texts.xml"
        $s2 = "res/layout/off.xml"
        $s3 = "c/nL07Gy7K3maRlEL1MxCVwf4FU"
        $s4 = "res/drawable/checkbox_label_background.9.png"
        $s5 = "18/aznZQx9KN6O9oFh9zkx3tu4w"
        $s6 = "res/drawable/0.temp"
        $s7 = "res/drawable/1.temp"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_02032 {
    strings:
        $s0 = "res/raw/act_schemes.cfg"
        $s1 = "res/xml/texts.xml"
        $s2 = "res/layout/off.xml"
        $s3 = "c/nL07Gy7K3maRlEL1MxCVwf4FU"
        $s4 = "res/drawable/checkbox_label_background.9.png"
        $s5 = "18/aznZQx9KN6O9oFh9zkx3tu4w"
        $s6 = "res/drawable/0.temp"
        $s7 = "res/drawable/1.temp"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_02033 {
    strings:
        $s0 = "res/raw/act_schemes.cfg"
        $s1 = "res/xml/texts.xml"
        $s2 = "res/layout/off.xml"
        $s3 = "c/nL07Gy7K3maRlEL1MxCVwf4FU"
        $s4 = "res/drawable/checkbox_label_background.9.png"
        $s5 = "18/aznZQx9KN6O9oFh9zkx3tu4w"
        $s6 = "res/drawable/0.temp"
        $s7 = "res/drawable/1.temp"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_02034 {
    strings:
        $s0 = "res/raw/act_schemes.cfg"
        $s1 = "res/xml/texts.xml"
        $s2 = "res/layout/off.xml"
        $s3 = "c/nL07Gy7K3maRlEL1MxCVwf4FU"
        $s4 = "res/drawable/checkbox_label_background.9.png"
        $s5 = "18/aznZQx9KN6O9oFh9zkx3tu4w"
        $s6 = "3XU8DJNQ9o/iAlhePmHQ2ONZPBE"
        $s7 = "OFJILd1Gbnhi40EKfg/Ai18RzGg"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_02035 {
    strings:
        $s0 = "res/raw/act_schemes.cfg"
        $s1 = "res/xml/texts.xml"
        $s2 = "res/layout/off.xml"
        $s3 = "c/nL07Gy7K3maRlEL1MxCVwf4FU"
        $s4 = "res/drawable/checkbox_label_background.9.png"
        $s5 = "18/aznZQx9KN6O9oFh9zkx3tu4w"
        $s6 = "res/drawable/0.temp"
        $s7 = "ShowLink.java"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_02036 {
    strings:
        $s0 = "assets/wyzf/res.bin"
        $s1 = "_str_trade_id:"
        $s2 = "_str_order_money:"
        $s3 = "_str_report:"
        $s4 = "_str_sdk_id:"
        $s5 = "_str_sdk_key:"
        $s6 = "_str_sdk_point:"
        $s7 = "_str_seq:"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_02037 {
    strings:
        $s0 = "LoadMethod:"
        $s1 = "jarNameInfo.id"
        $s2 = "jarNameInfo.v"
        $s3 = "com.dyl.pay.ui.apk"
        $s4 = "Lcom/t/wangda/WanderInterface"
        $s5 = "http://jiepay.jiemengkj.com:8152/ryf_webserver/payment"
        $s6 = "Lcom/mixClass"
        $s7 = "mixClass.java"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_02038 {
    strings:
        $s0 = "LoadMethod:"
        $s1 = "jarNameInfo.id"
        $s2 = "jarNameInfo.v"
        $s3 = "com.dyl.pay.ui.apk"
        $s4 = "Lcom/t/wangda/WanderInterface"
        $s5 = "lib/armeabi/libshunpay.so"
        $s6 = "http://jiepay.jiemengkj.com:8152/ryf_webserver/payment"
        $s7 = "Lcom/mixClass"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_02039 {
    strings:
        $s0 = "LoadMethod:"
        $s1 = "jarNameInfo.id"
        $s2 = "jarNameInfo.v"
        $s3 = "com.dyl.pay.ui.apk"
        $s4 = "Lcom/t/wangda/WanderInterface"
        $s5 = "http://jiepay.jiemengkj.com:8152/ryf_webserver/payment"
        $s6 = "Lcom/mixClass"
        $s7 = "mixClass.java"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_02040 {
    strings:
        $s0 = "lib/armeabi/libcrypt_sign.so"
        $s1 = "assets/wyzf/res.bin"
        $s2 = "assets/dERlZG"
        $s3 = "http://vpay.api.eerichina.com/api/payment"
        $s4 = "plugin.db"
        $s5 = "/LocalPool.xml"
        $s6 = "/temp.dl"
        $s7 = "/unknown.dat"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_02041 {
    strings:
        $s0 = "res/layout/finish.xml"
        $s1 = "getUserMessage:"
        $s2 = "res/drawable/opera.png"
        $s3 = "res/drawable/icon_url.png"
        $s4 = "res/drawable/progress.9.png"
        $s5 = "res/drawable/progress_active.9.png"
        $s6 = "mxclick.com"
        $s7 = "rWKNvRKwZsLr/XYVtE8CwrBNLfQ"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_02042 {
    strings:
        $s0 = "res/layout/finish.xml"
        $s1 = "getUserMessage:"
        $s2 = "res/drawable/opera.png"
        $s3 = "res/drawable/icon_url.png"
        $s4 = "res/drawable/progress.9.png"
        $s5 = "res/drawable/progress_active.9.png"
        $s6 = "mxclick.com"
        $s7 = "rWKNvRKwZsLr/XYVtE8CwrBNLfQ"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_02043 {
    strings:
        $s0 = "Lcom/waps/OffersWebView"
        $s1 = "Lcom/waps/AppConnect"
        $s2 = "Lcom/waps/AdView"
        $s3 = "Lcom/waps/UpdatePointsNotifier"
        $s4 = "Lcom/waps/AppLog"
        $s5 = "Lcom/waps/DisplayAdNotifier"
        $s6 = "display/ad"
        $s7 = "Lcom/waps/DisplayAd"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_02044 {
    strings:
        $s0 = "res/drawable-hdpi/nf_bg_edit_text.9.png"
        $s1 = "res/drawable-hdpi/indeterminate_spinner.png"
        $s2 = "res/drawable-hdpi/selector_edittext_bg.xml"
        $s3 = "res/anim/wait.xml"
        $s4 = "res/drawable-hdpi/btn_cancel_off_gnb.png"
        $s5 = "res/drawable-hdpi/btn_confirm_off_gnw.png"
        $s6 = "res/drawable-hdpi/background_div_bg.xml"
        $s7 = "res/drawable/dialog_inside_layout.xml"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_02045 {
    strings:
        $s0 = "AZS/kpEhpE8Jl37U1SJ9eW7KA6E"
        $s1 = "NNqltaQgFzooaAOKcxToQQY/4rU"
        $s2 = "res/drawable/visa_curved.png"
        $s3 = "res/xml/da.xml"
        $s4 = "$Lzzzzzz/xxxxxx/cccccc/ActivityStart"
        $s5 = "-Lzzzzzz/xxxxxx/cccccc/HeadlessSmsSendService"
        $s6 = ".ActivityStart"
        $s7 = "Lzzzzzz/xxxxxx/cccccc/AlarmReceiverAdm"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_02046 {
    strings:
        $s0 = "AZS/kpEhpE8Jl37U1SJ9eW7KA6E"
        $s1 = "NNqltaQgFzooaAOKcxToQQY/4rU"
        $s2 = "res/drawable/visa_curved.png"
        $s3 = "res/xml/da.xml"
        $s4 = "$Lzzzzzz/xxxxxx/cccccc/ActivityStart"
        $s5 = "-Lzzzzzz/xxxxxx/cccccc/HeadlessSmsSendService"
        $s6 = ".ActivityStart"
        $s7 = "Lzzzzzz/xxxxxx/cccccc/AlarmReceiverAdm"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_02047 {
    strings:
        $s0 = "AZS/kpEhpE8Jl37U1SJ9eW7KA6E"
        $s1 = "NNqltaQgFzooaAOKcxToQQY/4rU"
        $s2 = "res/drawable/visa_curved.png"
        $s3 = "res/xml/da.xml"
        $s4 = "res/drawable/aec.png"
        $s5 = "res/drawable/wc.png"
        $s6 = "res/layout/activity_activity_card.xml"
        $s7 = "res/drawable/wcpl.png"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_02048 {
    strings:
        $s0 = "9cSf/sOgyVhfTbZRYzwC6mNEaos"
        $s1 = "javascript:backMenu"
        $s2 = "$Method:"
        $s3 = "/data/device_admin.php"
        $s4 = "/scripts/app_call_tracking_manager.php"
        $s5 = "/scripts/app_not_received.php"
        $s6 = "/scripts/app_tracking_manager.php"
        $s7 = "/sdcard/mobop"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_02049 {
    strings:
        $s0 = "assets/css/smoothness/images/ui-bg_flat_0_aaaaaa_40x100.png"
        $s1 = "assets/css/smoothness/images/ui-bg_flat_75_ffffff_40x100.png"
        $s2 = "assets/css/smoothness/images/ui-bg_glass_55_fbf9ee_1x400.png"
        $s3 = "assets/css/smoothness/images/ui-bg_glass_65_ffffff_1x400.png"
        $s4 = "assets/css/smoothness/images/ui-bg_glass_75_dadada_1x400.png"
        $s5 = "assets/css/smoothness/images/ui-bg_glass_75_e6e6e6_1x400.png"
        $s6 = "assets/css/smoothness/images/ui-bg_glass_95_fef1ec_1x400.png"
        $s7 = "assets/css/smoothness/images/ui-bg_highlight-soft_75_cccccc_1x10"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_02050 {
    strings:
        $s0 = "assets/css/smoothness/images/ui-bg_flat_0_aaaaaa_40x100.png"
        $s1 = "assets/css/smoothness/images/ui-bg_flat_75_ffffff_40x100.png"
        $s2 = "assets/css/smoothness/images/ui-bg_glass_55_fbf9ee_1x400.png"
        $s3 = "assets/css/smoothness/images/ui-bg_glass_65_ffffff_1x400.png"
        $s4 = "assets/css/smoothness/images/ui-bg_glass_75_dadada_1x400.png"
        $s5 = "assets/css/smoothness/images/ui-bg_glass_75_e6e6e6_1x400.png"
        $s6 = "assets/css/smoothness/images/ui-bg_glass_95_fef1ec_1x400.png"
        $s7 = "assets/css/smoothness/images/ui-bg_highlight-soft_75_cccccc_1x10"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_02051 {
    strings:
        $s0 = "assets/css/smoothness/images/ui-bg_flat_0_aaaaaa_40x100.png"
        $s1 = "assets/css/smoothness/images/ui-bg_flat_75_ffffff_40x100.png"
        $s2 = "assets/css/smoothness/images/ui-bg_glass_55_fbf9ee_1x400.png"
        $s3 = "assets/css/smoothness/images/ui-bg_glass_65_ffffff_1x400.png"
        $s4 = "assets/css/smoothness/images/ui-bg_glass_75_dadada_1x400.png"
        $s5 = "assets/css/smoothness/images/ui-bg_glass_75_e6e6e6_1x400.png"
        $s6 = "assets/css/smoothness/images/ui-bg_glass_95_fef1ec_1x400.png"
        $s7 = "assets/css/smoothness/images/ui-bg_highlight-soft_75_cccccc_1x10"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_02052 {
    strings:
        $s0 = "assets/css/smoothness/images/ui-bg_flat_0_aaaaaa_40x100.png"
        $s1 = "assets/css/smoothness/images/ui-bg_flat_75_ffffff_40x100.png"
        $s2 = "assets/css/smoothness/images/ui-bg_glass_55_fbf9ee_1x400.png"
        $s3 = "assets/css/smoothness/images/ui-bg_glass_65_ffffff_1x400.png"
        $s4 = "assets/css/smoothness/images/ui-bg_glass_75_dadada_1x400.png"
        $s5 = "assets/css/smoothness/images/ui-bg_glass_75_e6e6e6_1x400.png"
        $s6 = "assets/css/smoothness/images/ui-bg_glass_95_fef1ec_1x400.png"
        $s7 = "assets/css/smoothness/images/ui-bg_highlight-soft_75_cccccc_1x10"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_02053 {
    strings:
        $s0 = "assets/css/smoothness/images/ui-bg_flat_0_aaaaaa_40x100.png"
        $s1 = "assets/css/smoothness/images/ui-bg_flat_75_ffffff_40x100.png"
        $s2 = "assets/css/smoothness/images/ui-bg_glass_55_fbf9ee_1x400.png"
        $s3 = "assets/css/smoothness/images/ui-bg_glass_65_ffffff_1x400.png"
        $s4 = "assets/css/smoothness/images/ui-bg_glass_75_dadada_1x400.png"
        $s5 = "assets/css/smoothness/images/ui-bg_glass_75_e6e6e6_1x400.png"
        $s6 = "assets/css/smoothness/images/ui-bg_glass_95_fef1ec_1x400.png"
        $s7 = "assets/css/smoothness/images/ui-bg_highlight-soft_75_cccccc_1x10"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_02054 {
    strings:
        $s0 = "receiver/install"
        $s1 = "UPermission.ACCESS_WIFI_STATE"
        $s2 = "UnPackage.dat"
        $s3 = "complete.Click"
        $s4 = "installed.Click"
        $s5 = "CacheTime.dat"
        $s6 = "/Android/data/cache/iconCache"
        $s7 = "Permission.ACCESS_WIFI_STATE"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_02055 {
    strings:
        $s0 = "apkprotect.com/key.dat"
        $s1 = "apkprotect.com/readme.txt"
        $s2 = "ReplayStruct.java"
        $s3 = "RequestStruct.java"
        $s4 = "LSecScreen.java"
        $s5 = "res/xml/lsecscreen.xml"
        $s6 = "serivce."
        $s7 = "BaseBootReceiver.java"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_02057 {
    strings:
        $s0 = "com.qihoo.bugreport.CrashReport"
        $s1 = "com.qihoo.dexjiagu.TransitMgr"
        $s2 = "Lcom/qihoo/util/QHDialog$1"
        $s3 = "QHDialog.java"
        $s4 = "com.qihoo360.crypt.entryRunApplication"
        $s5 = "Lcom/qihoo/util/QHDialog$1$1"
        $s6 = "assets/libjiagu_ls.so"
        $s7 = "lib/armeabi/libjiagu_art.so"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_02058 {
    strings:
        $s0 = "FxService.java"
        $s1 = "/getroot"
        $s2 = "assets/cp"
        $s3 = "/system/bin/cp"
        $s4 = "RootCmd.java"
        $s5 = "assets/sux"
        $s6 = "http://www.163.com/"
        $s7 = "--.---N--xK"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_02059 {
    strings:
        $s0 = "receiver/install"
        $s1 = "http://app"
        $s2 = "receiver/uninstall"
        $s3 = "receiver/load_ad"
        $s4 = "receiver/load_offer"
        $s5 = "Lcom/adwo/adsdk/AdwoAdView"
        $s6 = "Lcom/waps/OffersWebView"
        $s7 = "Lcom/adwo/adsdk/AdListener"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_02060 {
    strings:
        $s0 = "Lcom/adwo/adsdk/AdwoAdView"
        $s1 = "Lcom/adwo/adsdk/AdListener"
        $s2 = "http://10.0.0.172/a/p1"
        $s3 = "http://10.0.0.172/t/test"
        $s4 = "assets/adwo_left_arrow.png"
        $s5 = "assets/adwo_right_arrow.png"
        $s6 = "Lcom/adwo/adsdk/a"
        $s7 = "Lcom/adwo/adsdk/b"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_02061 {
    strings:
        $s0 = "receiver/install"
        $s1 = "http://app"
        $s2 = "receiver/uninstall"
        $s3 = "receiver/load_ad"
        $s4 = "receiver/load_offer"
        $s5 = "Lcom/adwo/adsdk/AdwoAdView"
        $s6 = "Lcom/waps/OffersWebView"
        $s7 = "Lcom/adwo/adsdk/AdListener"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_02062 {
    strings:
        $s0 = "Lcom/adwo/adsdk/AdwoAdView"
        $s1 = "Lcom/adwo/adsdk/AdListener"
        $s2 = "http://10.0.0.172/a/p1"
        $s3 = "http://10.0.0.172/t/test"
        $s4 = "assets/adwo_left_arrow.png"
        $s5 = "assets/adwo_right_arrow.png"
        $s6 = "Lcom/adwo/adsdk/a"
        $s7 = "Lcom/adwo/adsdk/b"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_02063 {
    strings:
        $s0 = "Lcom/adwo/adsdk/AdwoAdView"
        $s1 = "Lcom/adwo/adsdk/AdListener"
        $s2 = "http://10.0.0.172/a/p1"
        $s3 = "http://10.0.0.172/t/test"
        $s4 = "assets/adwo_left_arrow.png"
        $s5 = "assets/adwo_right_arrow.png"
        $s6 = "Lcom/adwo/adsdk/a"
        $s7 = "Lcom/adwo/adsdk/b"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_02064 {
    strings:
        $s0 = "Lcom/adwo/adsdk/AdwoAdView"
        $s1 = "Lcom/adwo/adsdk/AdListener"
        $s2 = "http://10.0.0.172/a/p1"
        $s3 = "http://10.0.0.172/t/test"
        $s4 = "assets/adwo_left_arrow.png"
        $s5 = "assets/adwo_right_arrow.png"
        $s6 = "Lcom/adwo/adsdk/a"
        $s7 = "Lcom/adwo/adsdk/b"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_02065 {
    strings:
        $s0 = "receiver/install"
        $s1 = "http://app"
        $s2 = "receiver/uninstall"
        $s3 = "receiver/load_ad"
        $s4 = "receiver/load_offer"
        $s5 = "Lcom/adwo/adsdk/AdwoAdView"
        $s6 = "Lcom/waps/OffersWebView"
        $s7 = "Lcom/adwo/adsdk/AdListener"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_02066 {
    strings:
        $s0 = "Lcom/adwo/adsdk/AdwoAdView"
        $s1 = "Lcom/adwo/adsdk/AdListener"
        $s2 = "http://10.0.0.172/a/p1"
        $s3 = "http://10.0.0.172/t/test"
        $s4 = "assets/adwo_left_arrow.png"
        $s5 = "assets/adwo_right_arrow.png"
        $s6 = "Lcom/adwo/adsdk/a"
        $s7 = "Lcom/adwo/adsdk/b"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_02067 {
    strings:
        $s0 = "Lcom/adwo/adsdk/AdwoAdView"
        $s1 = "Lcom/adwo/adsdk/AdListener"
        $s2 = "http://10.0.0.172/a/p1"
        $s3 = "http://10.0.0.172/t/test"
        $s4 = "Lcom/adwo/adsdk/a"
        $s5 = "Lcom/adwo/adsdk/b"
        $s6 = "Lcom/adwo/adsdk/c"
        $s7 = "Lcom/adwo/adsdk/d"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_02068 {
    strings:
        $s0 = "assets/css/smoothness/images/ui-bg_flat_0_aaaaaa_40x100.png"
        $s1 = "assets/css/smoothness/images/ui-bg_flat_75_ffffff_40x100.png"
        $s2 = "assets/css/smoothness/images/ui-bg_glass_55_fbf9ee_1x400.png"
        $s3 = "assets/css/smoothness/images/ui-bg_glass_65_ffffff_1x400.png"
        $s4 = "assets/css/smoothness/images/ui-bg_glass_75_dadada_1x400.png"
        $s5 = "assets/css/smoothness/images/ui-bg_glass_75_e6e6e6_1x400.png"
        $s6 = "assets/css/smoothness/images/ui-bg_glass_95_fef1ec_1x400.png"
        $s7 = "assets/css/smoothness/images/ui-bg_highlight-soft_75_cccccc_1x10"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_02069 {
    strings:
        $s0 = "assets/css/smoothness/images/ui-bg_flat_0_aaaaaa_40x100.png"
        $s1 = "assets/css/smoothness/images/ui-bg_flat_75_ffffff_40x100.png"
        $s2 = "assets/css/smoothness/images/ui-bg_glass_55_fbf9ee_1x400.png"
        $s3 = "assets/css/smoothness/images/ui-bg_glass_65_ffffff_1x400.png"
        $s4 = "assets/css/smoothness/images/ui-bg_glass_75_dadada_1x400.png"
        $s5 = "assets/css/smoothness/images/ui-bg_glass_75_e6e6e6_1x400.png"
        $s6 = "assets/css/smoothness/images/ui-bg_glass_95_fef1ec_1x400.png"
        $s7 = "assets/css/smoothness/images/ui-bg_highlight-soft_75_cccccc_1x10"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_02070 {
    strings:
        $s0 = "com.webcash.wooribank"
        $s1 = "res/drawable-hdpi/nh.png"
        $s2 = "res/drawable-hdpi/sh.png"
        $s3 = "res/drawable-hdpi/kb.png"
        $s4 = "Q0j/LlUSDZKDI8"
        $s5 = "res/drawable-hdpi/hana.png"
        $s6 = "res/layout/woori_main_activity.xml"
        $s7 = "res/layout/hana_main_activity.xml"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_02071 {
    strings:
        $s0 = "dalvik.system.LexClassLoader"
        $s1 = "nATYSIAfjzRbggjV1YNC7AZa4X/gvplYZT5MWRd43fg"
        $s2 = "Config.DEBUG"
        $s3 = "Lcom/umeng/socialize/net/utils/AesHelper"
        $s4 = "Lcom/umeng/socialize/net/utils/Base64"
        $s5 = "Lcom/umeng/socialize/net/utils/BaseNCodec"
        $s6 = "Lcom/umeng/socialize/net/base/SocializeRequest$RequestMethod"
        $s7 = "Lcom/umeng/socialize/net/base/SocializeRequest$RequestMethod$1"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_02072 {
    strings:
        $s0 = "/.cache/classes.jar"
        $s1 = "/.cache/classes.dex"
        $s2 = "/.sec_version"
        $s3 = "ACall.java"
        $s4 = "assets/libsecexe.x86.so"
        $s5 = "libsecexe.x86.so"
        $s6 = "assets/bangcle_classes.jar"
        $s7 = "assets/libsecmain.x86.so"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_02073 {
    strings:
        $s0 = "lib/armeabi/libdnlocal.so"
        $s1 = "plugin.db"
        $s2 = "/LocalPool.xml"
        $s3 = "/temp.dl"
        $s4 = "/unknown.dat"
        $s5 = "Android/data/com.door.pay.app/"
        $s6 = "http://120.26.106.206:8088"
        $s7 = "http://121.40.109.196:8088"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_02074 {
    strings:
        $s0 = "res/layout/item_app_manager.xml"
        $s1 = "Lc/b/c/x$c"
        $s2 = "Lc/b/c/x$d"
        $s3 = "/6EjxXoH"
        $s4 = "1Lcom/ads/control/AppOpenManager_LifecycleAdapter"
        $s5 = "Lcom/ads/control/AppOpenManager"
        $s6 = "Lcom/ads/control/AppOpenManager$a"
        $s7 = "Tb/FkxWhtfNm7eZJ0tDD9orlP9zSFqgmD25FK2/jE"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_02075 {
    strings:
        $s0 = "res/layout/item_app_manager.xml"
        $s1 = "Lc/b/c/x$c"
        $s2 = "Lc/b/c/x$d"
        $s3 = "/6EjxXoH"
        $s4 = "1Lcom/ads/control/AppOpenManager_LifecycleAdapter"
        $s5 = "Lcom/ads/control/AppOpenManager"
        $s6 = "Lcom/ads/control/AppOpenManager$a"
        $s7 = "Tb/FkxWhtfNm7eZJ0tDD9orlP9zSFqgmD25FK2/jE"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_02076 {
    strings:
        $s0 = "receiver/install"
        $s1 = "http://app"
        $s2 = "receiver/uninstall"
        $s3 = "receiver/load_ad"
        $s4 = "receiver/load_offer"
        $s5 = "Lcom/waps/OffersWebView"
        $s6 = "UPermission.ACCESS_WIFI_STATE"
        $s7 = "Lcom/waps/a"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_02077 {
    strings:
        $s0 = "lib/armeabi-v7a/libdn_ssl.so"
        $s1 = "secret-classes.dex"
        $s2 = "scrt.apk"
        $s3 = "res/layout/activity_no_bg.xml"
        $s4 = "/kD/faOo"
        $s5 = "res/layout/activity_call_v7.xml"
        $s6 = "res/layout/call_end_layout.xml"
        $s7 = "res/layout/call_pop_layout.xml"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_02078 {
    strings:
        $s0 = "receiver/install"
        $s1 = "http://app"
        $s2 = "receiver/uninstall"
        $s3 = "receiver/load_ad"
        $s4 = "receiver/load_offer"
        $s5 = "Lcom/waps/OffersWebView"
        $s6 = "UPermission.ACCESS_WIFI_STATE"
        $s7 = "Lcom/waps/a"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_02079 {
    strings:
        $s0 = "receiver/install"
        $s1 = "http://app"
        $s2 = "receiver/uninstall"
        $s3 = "receiver/load_ad"
        $s4 = "receiver/load_offer"
        $s5 = "Lcom/waps/OffersWebView"
        $s6 = "UPermission.ACCESS_WIFI_STATE"
        $s7 = "Lcom/waps/a"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_02080 {
    strings:
        $s0 = "0Stl9od/oNlIKlEH3o4/SBr4ISA"
        $s1 = "4HiUOGvx0sNQ/dBWzyUmmk39wxg"
        $s2 = "qTAsfXrw/eCvapzYRZVuKnL7o0c"
        $s3 = "ddbu1f1z5/YxcbSa8OfgwCLtDHI"
        $s4 = "5Cv6vlVT1wqKCQn/lkO79UvW5cE"
        $s5 = "ztuDVXvQS5sOSLroZow5/vlepeA"
        $s6 = "eXRd//7imRamMBvMA70UcHZ4/YM"
        $s7 = "/iEjU2OMzfeAQZ0rJGvd5j"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_02081 {
    strings:
        $s0 = "0Stl9od/oNlIKlEH3o4/SBr4ISA"
        $s1 = "4HiUOGvx0sNQ/dBWzyUmmk39wxg"
        $s2 = "qTAsfXrw/eCvapzYRZVuKnL7o0c"
        $s3 = "ddbu1f1z5/YxcbSa8OfgwCLtDHI"
        $s4 = "5Cv6vlVT1wqKCQn/lkO79UvW5cE"
        $s5 = "ztuDVXvQS5sOSLroZow5/vlepeA"
        $s6 = "eXRd//7imRamMBvMA70UcHZ4/YM"
        $s7 = "/iEjU2OMzfeAQZ0rJGvd5j"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_02082 {
    strings:
        $s0 = "res/drawable/img_android.png"
        $s1 = "res/layout/instruction_dialog.xml"
        $s2 = "res/drawable/shape_gray_border_bottom.xml"
        $s3 = "res/layout/samsung_show_top_dialog.xml"
        $s4 = "res/layout/xiaomi_background_activity_dialog.xml"
        $s5 = "iOTls283qxBiqp1Kk5XhZl3nAXbWKnOn/DsVjWD9f9Q"
        $s6 = "ATvqoz3o52G2n71RMsMXWVtAsQXcjnkHuaAIjvwqS/g"
        $s7 = "assets/shaders/fragment.glsl"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_02083 {
    strings:
        $s0 = ".Lcom/sirseni/simpleandroidwebviewexample/R$id"
        $s1 = "/CoIXRo5o95LwmcBAYLGXQ5bHtk"
        $s2 = "0Lcom/sirseni/simpleandroidwebviewexample/R$anim"
        $s3 = "0Lcom/sirseni/simpleandroidwebviewexample/R$attr"
        $s4 = "0Lcom/sirseni/simpleandroidwebviewexample/R$bool"
        $s5 = "0Lcom/sirseni/simpleandroidwebviewexample/R$menu"
        $s6 = "1Lcom/sirseni/simpleandroidwebviewexample/R$color"
        $s7 = "1Lcom/sirseni/simpleandroidwebviewexample/R$dimen"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_02084 {
    strings:
        $s0 = "4evjEGyva47/fXGeJ5JWUFLwEac"
        $s1 = "style/Play_Purchase_ActionButton"
        $s2 = "layout/play_button_bar"
        $s3 = "res/drawable/overlay_pressed_light.9.png"
        $s4 = "res/layout/play_button_bar.xml"
        $s5 = "8fzjQH/df"
        $s6 = "UYpoynY8O/CCJNtPs4xW/W6Yauc"
        $s7 = "o2bUobUEtG/BcyHwb/xDmM2eB"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_02085 {
    strings:
        $s0 = "apkprotect.com/key.dat"
        $s1 = "apkprotect.com/readme.txt"
        $s2 = "ReplayStruct.java"
        $s3 = "RequestStruct.java"
        $s4 = "LSecScreen.java"
        $s5 = "res/xml/lsecscreen.xml"
        $s6 = "serivce."
        $s7 = "BaseBootReceiver.java"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_02086 {
    strings:
        $s0 = "apkprotect.com/key.dat"
        $s1 = "apkprotect.com/readme.txt"
        $s2 = "ReplayStruct.java"
        $s3 = "RequestStruct.java"
        $s4 = "LSecScreen.java"
        $s5 = "res/xml/lsecscreen.xml"
        $s6 = "serivce."
        $s7 = "BaseBootReceiver.java"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_02087 {
    strings:
        $s0 = "apkprotect.com/key.dat"
        $s1 = "apkprotect.com/readme.txt"
        $s2 = "ReplayStruct.java"
        $s3 = "RequestStruct.java"
        $s4 = "LSecScreen.java"
        $s5 = "res/xml/lsecscreen.xml"
        $s6 = "serivce."
        $s7 = "BaseBootReceiver.java"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_02088 {
    strings:
        $s0 = "lib/armeabi/libjiagu_art.so"
        $s1 = "qxQ3iuVDQMZjeW/jQKY1FlRHCiw"
        $s2 = "res/layout/umeng_fb_atom.xml"
        $s3 = "res/layout/umeng_fb_conversation_item.xml"
        $s4 = "res/layout/umeng_fb_conversations.xml"
        $s5 = "res/layout/umeng_fb_conversations_item.xml"
        $s6 = "res/drawable/umeng_fb_dev_bubble.9.png"
        $s7 = "res/drawable/umeng_fb_blank_selector.xml"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_02089 {
    strings:
        $s0 = "pushejsonservice.java"
        $s1 = "ir.rrgc.telegram"
        $s2 = "com.ongram"
        $s3 = "ir.alimodaresi.mytelegram"
        $s4 = "ir.felegram"
        $s5 = "org.mygram"
        $s6 = "org.telegram.igram"
        $s7 = "com.goldengram"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_02090 {
    strings:
        $s0 = "libhelper.so"
        $s1 = "-Lcom/tencent/bugly/crashreport/crash/anr/b$4"
        $s2 = "-Lcom/tencent/bugly/crashreport/crash/anr/b$5"
        $s3 = "/Lcom/tencent/bugly/crashreport/crash/anr/b$1$1"
        $s4 = "com.test.model.Magazine"
        $s5 = "com.test.model.Reader"
        $s6 = "--xxyL---.--.---.-.y"
        $s7 = "-i-iii-----LM/-"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_02091 {
    strings:
        $s0 = "Lnet/youmi/android/AdManager"
        $s1 = "ArrayVariant.java"
        $s2 = "BooleanReferenceParameter.java"
        $s3 = "ByteReferenceParameter.java"
        $s4 = "ByteVariant.java"
        $s5 = "ConvHelpers.java"
        $s6 = "DateVariant.java"
        $s7 = "DoubleReferenceParameter.java"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_02092 {
    strings:
        $s0 = "Lcom/baidu/location/s$1"
        $s1 = "Lcom/baidu/location/aq$a"
        $s2 = "Lcom/baidu/location/j$a"
        $s3 = "Lcom/baidu/location/v$a"
        $s4 = "Lcom/baidu/location/a0$a"
        $s5 = "Lcom/baidu/location/av$a"
        $s6 = "Lcom/baidu/location/ay$a"
        $s7 = "Lcom/baidu/location/t$b"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_02093 {
    strings:
        $s0 = "/rgBiUeGVuM9QauYk4hnNYsk7Tg"
        $s1 = "-i...--."
        $s2 = "3beH/MASicYWILJ6bNBGMBRyxmA"
        $s3 = "5hiR1surnFL/0l"
        $s4 = "Bpw9qc/5tamnIY6kCoDPUOxcpUM"
        $s5 = "hN---i1L------.----"
        $s6 = "L-/k-Zln"
        $s7 = "L--K0--/Np-"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_02094 {
    strings:
        $s0 = "XmiA65n/BONpZqWneQ75Jg410jk"
        $s1 = "/consumerCodeList"
        $s2 = "86BpnPXgWHUkHbM/vws7iZu0mk"
        $s3 = "AlDWi8bl2/bzTg3d3zZK/g"
        $s4 = "HhPyb1I/X38"
        $s5 = "Iw39W6xW2WgpkFZONZWB/Q"
        $s6 = "KsYPG2/wAfIRZj11LiAb0g"
        $s7 = "RGVw4AQRs/I6priG96EeCQ"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_02095 {
    strings:
        $s0 = "lib/armeabi-v7a/libdn_ssl.so"
        $s1 = "secret-classes.dex"
        $s2 = "scrt.apk"
        $s3 = "/kD/faOo"
        $s4 = "res/layout/activity_call_v7.xml"
        $s5 = "res/layout/call_end_layout.xml"
        $s6 = "res/layout/call_pop_layout.xml"
        $s7 = "Lcom/mik/proxy/guard/core/BuildConfig"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_02096 {
    strings:
        $s0 = "Lcom/vivalab/mobile/log/c"
        $s1 = "android:style/Widget"
        $s2 = "$xiaoying/libs/libcesplatformutils.so"
        $s3 = "2xiaoying/libs/hwcodec/libhwvideoreader_2.3_qcom.so"
        $s4 = "2xiaoying/libs/hwcodec/libhwvideoreader_4.0_qcom.so"
        $s5 = "2xiaoying/libs/hwcodec/libhwvideowriter_2.3_qcom.so"
        $s6 = "2xiaoying/libs/hwcodec/libhwvideowriter_4.0_qcom.so"
        $s7 = "CPUConfig.ini"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_02097 {
    strings:
        $s0 = "dalvik.system.LexClassLoader"
        $s1 = "Z-KK.iyx"
        $s2 = "startBluethInfo:"
        $s3 = "com.unicom.dcLoader.Utils"
        $s4 = "yKZli/ZK"
        $s5 = "KKKy..KZK.K/"
        $s6 = "1HnrPpggZ8rNgeo0TsoK3uaWC9eSRW6zEhSR8hE/EE7CrI"
        $s7 = "Lcom/qq/e/ads/nativ/NativeMediaAD$1$1"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_02098 {
    strings:
        $s0 = "7kLFsbr73Dn5mTI1b7Vd/a62PQ8"
        $s1 = "MSe3LbcSGEJHSbnnBqo/MvM"
        $s2 = "TBP3rC0W8LU7ynapcTX6CUk/lDs"
        $s3 = "com/sun/mail/dsn/package.html"
        $s4 = "com/sun/mail/imap/package.html"
        $s5 = "com/sun/mail/pop3/package.html"
        $s6 = "com/sun/mail/smtp/package.html"
        $s7 = "javax/activation/package.html"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_02099 {
    strings:
        $s0 = "7kLFsbr73Dn5mTI1b7Vd/a62PQ8"
        $s1 = "MSe3LbcSGEJHSbnnBqo/MvM"
        $s2 = "TBP3rC0W8LU7ynapcTX6CUk/lDs"
        $s3 = "com/sun/mail/dsn/package.html"
        $s4 = "com/sun/mail/imap/package.html"
        $s5 = "com/sun/mail/pop3/package.html"
        $s6 = "com/sun/mail/smtp/package.html"
        $s7 = "javax/activation/package.html"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_02100 {
    strings:
        $s0 = "receiver/install"
        $s1 = "http://app"
        $s2 = "receiver/uninstall"
        $s3 = "receiver/load_ad"
        $s4 = "receiver/load_offer"
        $s5 = "Lcom/waps/OffersWebView"
        $s6 = "UPermission.ACCESS_WIFI_STATE"
        $s7 = "Lcom/waps/a"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_02101 {
    strings:
        $s0 = "receiver/install"
        $s1 = "http://app"
        $s2 = "receiver/uninstall"
        $s3 = "receiver/load_ad"
        $s4 = "receiver/load_offer"
        $s5 = "Lcom/waps/OffersWebView"
        $s6 = "UPermission.ACCESS_WIFI_STATE"
        $s7 = "Lcom/waps/a"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_02102 {
    strings:
        $s0 = "http://int.dpool.sina.com.cn/iplookup/iplookup.php"
        $s1 = "res/images"
        $s2 = "/Tencent/ys/Loader"
        $s3 = "myreturnCode:"
        $s4 = ".cnzz.com/stat.htm"
        $s5 = "/activite"
        $s6 = "/api/activite"
        $s7 = "/api/back"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_02103 {
    strings:
        $s0 = "com.qihoo.bugreport.CrashReport"
        $s1 = "com.qihoo.dexjiagu.TransitMgr"
        $s2 = "Lcom/qihoo/util/QHDialog$1"
        $s3 = "QHDialog.java"
        $s4 = "Lcom/qihoo/util/QHDialog$1$1"
        $s5 = "CrashReport."
        $s6 = "assets/crack_d.png"
        $s7 = "assets/horizontal_bg.png"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_02104 {
    strings:
        $s0 = "lib/armeabi/libcrypt_sign.so"
        $s1 = "assets/wyzf/res.bin"
        $s2 = "assets/jmpay.xml"
        $s3 = "assets/provincecode.xml"
        $s4 = "assets/yf.conf"
        $s5 = "assets/qsha_80001_5096"
        $s6 = "assets/qpzf.dat"
        $s7 = "assets/knds.dat"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_02105 {
    strings:
        $s0 = "res/raw/data.db"
        $s1 = "Lorg/MobileDb/Field"
        $s2 = "Lorg/MobileDb/MobileDatabase"
        $s3 = "Lorg/MobileDb/Row"
        $s4 = "Lorg/MobileDb/Table"
        $s5 = "Lorg/MobileDb/Utf8StringBuffer"
        $s6 = ".---NKxx"
        $s7 = "MobileDatabase.java"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_02106 {
    strings:
        $s0 = "receiver/install"
        $s1 = "UPermission.ACCESS_WIFI_STATE"
        $s2 = "UnPackage.dat"
        $s3 = "complete.Click"
        $s4 = "installed.Click"
        $s5 = "CacheTime.dat"
        $s6 = "/Android/data/cache/iconCache"
        $s7 = "/Android/data/cache/downloadCache"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_02107 {
    strings:
        $s0 = "Z.iixxxx"
        $s1 = "--.iixxxxk"
        $s2 = "K-.KxxiixK-/ZjiiP"
        $s3 = "KK/i.iZ.iZ.iZ.iZ.iZ/iZ."
        $s4 = "iK.i.i/i"
        $s5 = "iK/i.i.i."
        $s6 = "iK/i.i/i."
        $s7 = "jZ.ZKKxi-LZ"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_02108 {
    strings:
        $s0 = "au.com.bankwest.mobile"
        $s1 = "ZzxKlxKyki.i"
        $s2 = "commandus.com"
        $s3 = "--.ixKiidAZ"
        $s4 = "/CalsRlpNBoM"
        $s5 = "/p9USHEeoIE3gQO135Rl6PxRJyo"
        $s6 = "2Lcom/note/donote/receivers/ServiceDestroyReceiver"
        $s7 = "3Lcom/note/donote/receivers/sms/PushServiceReciever"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_02109 {
    strings:
        $s0 = "au.com.bankwest.mobile"
        $s1 = "ZzxKlxKyki.i"
        $s2 = "commandus.com"
        $s3 = "--.ixKiidAZ"
        $s4 = "/CalsRlpNBoM"
        $s5 = "/p9USHEeoIE3gQO135Rl6PxRJyo"
        $s6 = "2Lcom/note/donote/receivers/ServiceDestroyReceiver"
        $s7 = "3Lcom/note/donote/receivers/sms/PushServiceReciever"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_02110 {
    strings:
        $s0 = "au.com.bankwest.mobile"
        $s1 = "ZzxKlxKyki.i"
        $s2 = "commandus.com"
        $s3 = "--.ixKiidAZ"
        $s4 = "/CalsRlpNBoM"
        $s5 = "/p9USHEeoIE3gQO135Rl6PxRJyo"
        $s6 = "2Lcom/note/donote/receivers/ServiceDestroyReceiver"
        $s7 = "3Lcom/note/donote/receivers/sms/PushServiceReciever"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_02111 {
    strings:
        $s0 = "au.com.bankwest.mobile"
        $s1 = "ZzxKlxKyki.i"
        $s2 = "commandus.com"
        $s3 = "--.ixKiidAZ"
        $s4 = "/CalsRlpNBoM"
        $s5 = "/p9USHEeoIE3gQO135Rl6PxRJyo"
        $s6 = "2Lcom/note/donote/receivers/ServiceDestroyReceiver"
        $s7 = "3Lcom/note/donote/receivers/sms/PushServiceReciever"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_02112 {
    strings:
        $s0 = "au.com.bankwest.mobile"
        $s1 = "ZzxKlxKyki.i"
        $s2 = "commandus.com"
        $s3 = "--.ixKiidAZ"
        $s4 = "/CalsRlpNBoM"
        $s5 = "/p9USHEeoIE3gQO135Rl6PxRJyo"
        $s6 = "2Lcom/note/donote/receivers/ServiceDestroyReceiver"
        $s7 = "3Lcom/note/donote/receivers/sms/PushServiceReciever"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_02113 {
    strings:
        $s0 = "0Lco/ronash/pushe/activities/PopupDialogActivity"
        $s1 = "Google-Play-Service."
        $s2 = "Gregorian:"
        $s3 = "Iranian:"
        $s4 = "Lco/ronash/pushe/Constants"
        $s5 = "Lco/ronash/pushe/Pushe"
        $s6 = "Lco/ronash/pushe/PusheListenerService"
        $s7 = "Lco/ronash/pushe/R"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_02115 {
    strings:
        $s0 = "-i...--."
        $s1 = "hN---i1L------.----"
        $s2 = "L-/k-Zln"
        $s3 = "assets/db_dex.nmp"
        $s4 = "assets/db_elfa.nmp"
        $s5 = "assets/vps.prop"
        $s6 = "assets/db_crt.dat"
        $s7 = "assets/db_elfa.map"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_02116 {
    strings:
        $s0 = "AVNND/JkatQhKFlGi7mz9E11a"
        $s1 = "GQVjRE7f1IvvS3/mo"
        $s2 = "04INo4/rGM2V0AJhQMYqFn8neM"
        $s3 = "NmXky8/jVynKdps"
        $s4 = "S2YCQOjwmr872YppGaVXCw/MjrtBv"
        $s5 = "hNqp5igQ9PEJo9NMNbfO1uvtFuKNx/i9vrvf3BE7F9w"
        $s6 = "pI4lhru3KUcR745QYo/AQRGwvocZc/LMAiJXBGU33K4"
        $s7 = "dc/squareup/okhttp3/internal/publicsuffix/publicsuffixes.gz"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_02117 {
    strings:
        $s0 = "mpathList:"
        $s1 = "libtosprotection."
        $s2 = "oat/arm64"
        $s3 = "assets/libshellx-super.2019.so"
        $s4 = "assets/0OO00oo01l1l"
        $s5 = "lib/armeabi/libshell-super.2019.so"
        $s6 = "assets/armeabi-v7a/avira0"
        $s7 = "assets/armeabi-v7a/avira1"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_02118 {
    strings:
        $s0 = "res/drawable-mdpi/icon.jpg"
        $s1 = "res/drawable-ldpi/icon.jpg"
        $s2 = "6/WoMGG7YBCUTMczMCR7ZTt4pqY"
        $s3 = "AXvknAH/1vN9Q7KBFUV44/csQU8"
        $s4 = "CalfcMWKwXrqj/svM8QSbrROHH4"
        $s5 = "R9DoxlBNH5IpvWNDjkx/u137254"
        $s6 = "YRbP51bp/Eb"
        $s7 = "cI0Nq9BTEIYryMJkaMBq/iI5X/w"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_02119 {
    strings:
        $s0 = "com.qihoo.bugreport.CrashReport"
        $s1 = "com.qihoo360.crypt.entryRunApplication"
        $s2 = "Lcom/qihoo/util/"
        $s3 = "com.qihoo.jiagutracker.TrackerMain"
        $s4 = "Lcom/qihoo360/replugin/Entry"
        $s5 = "Lcom/qihoo360/replugin/Entry$Stub"
        $s6 = "com.qihoo360.replugin.Entry_Jiagu"
        $s7 = "Lcom/qihoo/util/DtcLoader"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_02120 {
    strings:
        $s0 = "67x97y97F:7"
        $s1 = "LM8rLBYj4QqjIC/hbFg"
        $s2 = "Lcom/abs/BuildConfig"
        $s3 = "Lcom/abs/MainActivity"
        $s4 = "Lcom/abs/R"
        $s5 = "Lcom/abs/R$anim"
        $s6 = "Lcom/abs/R$attr"
        $s7 = "Lcom/abs/R$bool"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_02121 {
    strings:
        $s0 = "assets/css/smoothness/images/ui-bg_flat_0_aaaaaa_40x100.png"
        $s1 = "assets/css/smoothness/images/ui-bg_flat_75_ffffff_40x100.png"
        $s2 = "assets/css/smoothness/images/ui-bg_glass_55_fbf9ee_1x400.png"
        $s3 = "assets/css/smoothness/images/ui-bg_glass_65_ffffff_1x400.png"
        $s4 = "assets/css/smoothness/images/ui-bg_glass_75_dadada_1x400.png"
        $s5 = "assets/css/smoothness/images/ui-bg_glass_75_e6e6e6_1x400.png"
        $s6 = "assets/css/smoothness/images/ui-bg_glass_95_fef1ec_1x400.png"
        $s7 = "assets/css/smoothness/images/ui-bg_highlight-soft_75_cccccc_1x10"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_02122 {
    strings:
        $s0 = "assets/css/smoothness/images/ui-bg_flat_0_aaaaaa_40x100.png"
        $s1 = "assets/css/smoothness/images/ui-bg_flat_75_ffffff_40x100.png"
        $s2 = "assets/css/smoothness/images/ui-bg_glass_55_fbf9ee_1x400.png"
        $s3 = "assets/css/smoothness/images/ui-bg_glass_65_ffffff_1x400.png"
        $s4 = "assets/css/smoothness/images/ui-bg_glass_75_dadada_1x400.png"
        $s5 = "assets/css/smoothness/images/ui-bg_glass_75_e6e6e6_1x400.png"
        $s6 = "assets/css/smoothness/images/ui-bg_glass_95_fef1ec_1x400.png"
        $s7 = "assets/css/smoothness/images/ui-bg_highlight-soft_75_cccccc_1x10"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_02123 {
    strings:
        $s0 = "GACwhnal/rKGXQdxDfE9dL3BFqA"
        $s1 = "Lme/paranoid/jniexec/JNIExec"
        $s2 = "assets/oui"
        $s3 = "assets/wfk"
        $s4 = "ife5E7fa/8BabnVthM1zLVEhjsE"
        $s5 = "lib/armeabi-v7a/libJNIExec.so"
        $s6 = "lib/armeabi/libJNIExec.so"
        $s7 = "res/drawable-hdpi/bg_light.png"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_02124 {
    strings:
        $s0 = "13/Ayo17/DPtKNh46JVIv6osRPo"
        $s1 = "Qmxju5/Ap5mgu1cFHvmJFycrWMw"
        $s2 = "com/unicom/wounipaysms/dialog/images/cancel.png"
        $s3 = "com/unicom/wounipaysms/dialog/images/cancel_on.png"
        $s4 = "com/unicom/wounipaysms/dialog/images/confirm_bt.9.png"
        $s5 = "com/unicom/wounipaysms/dialog/images/confirm_bt_on.9.png"
        $s6 = "com/unicom/wounipaysms/dialog/images/main_bg.9.png"
        $s7 = "com/unicom/wounipaysms/dialog/images/unicom.png"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_02125 {
    strings:
        $s0 = "assets/yf.conf"
        $s1 = "http://vpay.api.eerichina.com/api/payment"
        $s2 = "plugin.db"
        $s3 = "/LocalPool.xml"
        $s4 = "/temp.dl"
        $s5 = "/unknown.dat"
        $s6 = "Android/data/com.door.pay.app/"
        $s7 = "http://120.26.106.206:8088"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_02126 {
    strings:
        $s0 = "6Lcom/android/installer/full/AndroidInstaller2Activity"
        $s1 = "8Lcom/android/installer/full/AndroidInstaller2Activity$1"
        $s2 = "8Lcom/android/installer/full/AndroidInstaller2Activity$2"
        $s3 = "8Lcom/android/installer/full/AndroidInstaller2Activity$3"
        $s4 = "8Lcom/android/installer/full/AndroidInstaller2Activity$4"
        $s5 = "8Lcom/android/installer/full/AndroidInstaller2Activity$5"
        $s6 = "AndroidInstaller2Activity.java"
        $s7 = "Lcom/android/installer/full/R"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_02127 {
    strings:
        $s0 = "l/cUiZLb7ya5qOYV/djf/zcvnb0"
        $s1 = "res/raw/conf.txt"
        $s2 = "res/raw/result"
        $s3 = "res/raw/resulturl"
        $s4 = "res/raw/rool.txt"
        $s5 = "fe/F7GKQgCOGQMPC2QkptHQH"
        $s6 = "res/raw/roolurl.txt"
        $s7 = "res/raw/animation.txt"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_02128 {
    strings:
        $s0 = "Z.-z-.xy-"
        $s1 = "J-yM/-P-y"
        $s2 = "res/drawable/img_android.png"
        $s3 = "res/layout/instruction_dialog.xml"
        $s4 = "res/drawable/shape_gray_border_bottom.xml"
        $s5 = "res/layout/samsung_show_top_dialog.xml"
        $s6 = "res/layout/xiaomi_background_activity_dialog.xml"
        $s7 = "iOTls283qxBiqp1Kk5XhZl3nAXbWKnOn/DsVjWD9f9Q"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_02129 {
    strings:
        $s0 = "Z.-z-.xy-"
        $s1 = "J-yM/-P-y"
        $s2 = "pLDkmSRkoQXoVF/HluPgotdpwUPxVIOYjlQrGQbkD3g"
        $s3 = "res/drawable-hdpi/abc_list_pressed_holo_light.png"
        $s4 = "res/drawable-hdpi/abc_list_selector_disabled_holo_light.png"
        $s5 = "res/drawable-mdpi/abc_list_pressed_holo_light.png"
        $s6 = "res/drawable-mdpi/abc_list_selector_disabled_holo_light.png"
        $s7 = "res/drawable-xhdpi/abc_list_pressed_holo_light.png"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_02130 {
    strings:
        $s0 = "assets/url.txt"
        $s1 = "mFN1aeKWR1s5FS5xuSauOx/2RcU"
        $s2 = "c1KIGWnyXRYqiIGZe/9d7myM"
        $s3 = "gcLFlfd7/1qAQk8zSS1MhFDl69c"
        $s4 = "LS_lmain.java"
        $s5 = "assets/lmain.bal"
        $s6 = "YmXPs/3rK1sSo95no7qHVGJNsDA"
        $s7 = "/ZtEoo6xyOtd6dq1h"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_02131 {
    strings:
        $s0 = "assets/css/smoothness/images/ui-bg_flat_0_aaaaaa_40x100.png"
        $s1 = "assets/css/smoothness/images/ui-bg_flat_75_ffffff_40x100.png"
        $s2 = "assets/css/smoothness/images/ui-bg_glass_55_fbf9ee_1x400.png"
        $s3 = "assets/css/smoothness/images/ui-bg_glass_65_ffffff_1x400.png"
        $s4 = "assets/css/smoothness/images/ui-bg_glass_75_dadada_1x400.png"
        $s5 = "assets/css/smoothness/images/ui-bg_glass_75_e6e6e6_1x400.png"
        $s6 = "assets/css/smoothness/images/ui-bg_glass_95_fef1ec_1x400.png"
        $s7 = "assets/css/smoothness/images/ui-bg_highlight-soft_75_cccccc_1x10"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_02132 {
    strings:
        $s0 = "http://10.0.0.172/a/p1"
        $s1 = "http://10.0.0.172/t/test"
        $s2 = "Lcom/wooboo/adlib_android/WoobooAdView"
        $s3 = "i/-KK-ZW"
        $s4 = "Lcom/wooboo/adlib_android/ImpressionAdView"
        $s5 = "Lcom/wooboo/adlib_android/g"
        $s6 = "ade.wooboo.com.cn"
        $s7 = "assets/wooboo_btn.png"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_02133 {
    strings:
        $s0 = "http://10.0.0.172/a/p1"
        $s1 = "http://10.0.0.172/t/test"
        $s2 = "Lcom/wooboo/adlib_android/WoobooAdView"
        $s3 = "i/-KK-ZW"
        $s4 = "Lcom/wooboo/adlib_android/ImpressionAdView"
        $s5 = "Lcom/wooboo/adlib_android/g"
        $s6 = "ade.wooboo.com.cn"
        $s7 = "assets/wooboo_btn.png"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_02134 {
    strings:
        $s0 = "receiver/install"
        $s1 = "http://app"
        $s2 = "receiver/uninstall"
        $s3 = "receiver/load_ad"
        $s4 = "receiver/load_offer"
        $s5 = "Lcom/adwo/adsdk/AdwoAdView"
        $s6 = "Lcom/waps/OffersWebView"
        $s7 = "Lcom/adwo/adsdk/AdListener"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_02135 {
    strings:
        $s0 = "receiver/install"
        $s1 = "http://app"
        $s2 = "receiver/uninstall"
        $s3 = "receiver/load_ad"
        $s4 = "receiver/load_offer"
        $s5 = "Lcom/adwo/adsdk/AdwoAdView"
        $s6 = "Lcom/waps/OffersWebView"
        $s7 = "Lcom/adwo/adsdk/AdListener"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_02136 {
    strings:
        $s0 = "receiver/install"
        $s1 = "http://app"
        $s2 = "receiver/uninstall"
        $s3 = "receiver/load_ad"
        $s4 = "receiver/load_offer"
        $s5 = "Lcom/adwo/adsdk/AdwoAdView"
        $s6 = "Lcom/waps/OffersWebView"
        $s7 = "Lcom/adwo/adsdk/AdListener"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_02137 {
    strings:
        $s0 = "-.y---KKKKKKKK"
        $s1 = "IJLyaF/07J9OXqjCC2/e43Bv4YA"
        $s2 = "res/layout/pravila.xml"
        $s3 = "res/raw/startus"
        $s4 = "hhD0YR0/r98sjNd18t2JbWeLNjU"
        $s5 = "Lru/getcorvin/mettir/MetrDotel"
        $s6 = "Lru/getcorvin/mettir/MetrDotel$1"
        $s7 = "Lru/getcorvin/mettir/MetrDotel$1$1"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_02138 {
    strings:
        $s0 = "-.y---KKKKKKKK"
        $s1 = "IJLyaF/07J9OXqjCC2/e43Bv4YA"
        $s2 = "res/layout/pravila.xml"
        $s3 = "res/raw/startus"
        $s4 = "hhD0YR0/r98sjNd18t2JbWeLNjU"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4)
}

rule VX_APK_CLUSTER_02139 {
    strings:
        $s0 = "com.webcash.wooribank"
        $s1 = "res/drawable-hdpi/nh.png"
        $s2 = "res/drawable-hdpi/sh.png"
        $s3 = "res/drawable-hdpi/kb.png"
        $s4 = "Q0j/LlUSDZKDI8"
        $s5 = "res/drawable-hdpi/hana.png"
        $s6 = "NPUtil.java"
        $s7 = "res/layout/woori_main_activity.xml"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_02140 {
    strings:
        $s0 = "com.webcash.wooribank"
        $s1 = "res/drawable-hdpi/intro_bg.png"
        $s2 = "res/layout/hana_main_activity.xml"
        $s3 = "res/layout/nh_main_activity.xml"
        $s4 = "res/layout/kb_main_activity.xml"
        $s5 = "res/layout/down_activity_main.xml"
        $s6 = "PbwSxqPXr0DQrNHWbeAfgNAq/Wc"
        $s7 = "com.cashweb.wooribank"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_02141 {
    strings:
        $s0 = "com.webcash.wooribank"
        $s1 = "res/layout/woori_main_activity.xml"
        $s2 = "res/drawable-hdpi/intro_bg.png"
        $s3 = "res/layout/hana_main_activity.xml"
        $s4 = "res/layout/nh_main_activity.xml"
        $s5 = "res/layout/kb_main_activity.xml"
        $s6 = "res/layout/sh_main_activity.xml"
        $s7 = "res/layout/down_activity_main.xml"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_02142 {
    strings:
        $s0 = "assets/css/smoothness/images/ui-bg_flat_0_aaaaaa_40x100.png"
        $s1 = "assets/css/smoothness/images/ui-bg_flat_75_ffffff_40x100.png"
        $s2 = "assets/css/smoothness/images/ui-bg_glass_55_fbf9ee_1x400.png"
        $s3 = "assets/css/smoothness/images/ui-bg_glass_65_ffffff_1x400.png"
        $s4 = "assets/css/smoothness/images/ui-bg_glass_75_dadada_1x400.png"
        $s5 = "assets/css/smoothness/images/ui-bg_glass_75_e6e6e6_1x400.png"
        $s6 = "assets/css/smoothness/images/ui-bg_glass_95_fef1ec_1x400.png"
        $s7 = "assets/css/smoothness/images/ui-bg_highlight-soft_75_cccccc_1x10"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_02143 {
    strings:
        $s0 = "PayCheckerUtil.java"
        $s1 = "StartDemoApplicationLockedByLIDActivity.java"
        $s2 = "com.lid.locker.ACTION_UNLOCK_APPLICATION"
        $s3 = "com.lid.locker.action.KILL_APPLICATION"
        $s4 = "6Lcom/lid/locker/LockerService$KillApplicationReceiver"
        $s5 = "8Lcom/lid/locker/StartDemoApplicationLockedByLIDActivity"
        $s6 = ":Lcom/lid/locker/StartDemoApplicationLockedByLIDActivity$1"
        $s7 = "LLcom/lid/locker/StartDemoApplicationLockedByLIDActivity$AppUnlockedReceiver"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_02145 {
    strings:
        $s0 = "res/layout/item_app_manager.xml"
        $s1 = "res/drawable/ic_backup.xml"
        $s2 = "res/layout/dialog_input_name.xml"
        $s3 = "res/layout/dialog_properties.xml"
        $s4 = "/6EjxXoH"
        $s5 = "1Lcom/ads/control/AppOpenManager_LifecycleAdapter"
        $s6 = "Lcom/ads/control/AppOpenManager"
        $s7 = "Lcom/ads/control/AppOpenManager$a"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_02146 {
    strings:
        $s0 = "res/layout/item_app_manager.xml"
        $s1 = "res/drawable/ic_backup.xml"
        $s2 = "res/layout/dialog_input_name.xml"
        $s3 = "res/layout/dialog_properties.xml"
        $s4 = "/6EjxXoH"
        $s5 = "1Lcom/ads/control/AppOpenManager_LifecycleAdapter"
        $s6 = "Lcom/ads/control/AppOpenManager"
        $s7 = "Lcom/ads/control/AppOpenManager$a"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_02147 {
    strings:
        $s0 = "SetPreferences.java"
        $s1 = "http://ad.leadbolt.net"
        $s2 = "http://ad.leadboltapps.net"
        $s3 = "setUseLocation:"
        $s4 = "setAdditionalDockingMargin:"
        $s5 = "/show_app.conf"
        $s6 = "Checking....Please"
        $s7 = "/install.php"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_02148 {
    strings:
        $s0 = "MTaIkHUA/Pve4wl9Z8BxBfceZDI"
        $s1 = "l93LV4jLCK5M/GJ2VVD471iAyLY"
        $s2 = "6Q/32C0fil4IbUjp8"
    condition:
        any of ($s0, $s1, $s2)
}

rule VX_APK_CLUSTER_02149 {
    strings:
        $s0 = "Mobclick.onError"
        $s1 = "tryToSendMessage."
        $s2 = "/92T0y8Eg3hwmkt655BvOmGHH/XfOxZOEdiIqIwPT0FPT1D"
        $s3 = "/CmOEnNP6lw5ie"
        $s4 = "/G7vW8JQCmu0vfGnYWwVddg0"
        $s5 = "/H7/T0Kh0JlIJPLHaDT6V5vN9l"
        $s6 = "/SgOYNXi9nXGzpgQ/GLoI/F8cBdd9blJWI3aUlcNik9a54bjfK//AWNnzhbv/YNafPouSxJ1C57QdwRE"
        $s7 = "/eV24SQp5AXoVMCIYgaKW2oM5YW3FsEUa0MM5YYYIiLT7a/qH80dJxpu20OlbUodDqTNtBrFNqQzGtpT"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_02150 {
    strings:
        $s0 = "res/layout/block_layout.xml"
        $s1 = "assets/update.html"
        $s2 = "assets/bank.html"
        $s3 = "6xiJCGj1sXWBRO885PY2TXK/Y8A"
        $s4 = "9f/v5kN/GNnF1MAM"
        $s5 = "GFVuN4Y7kdJR9P0XI/QrLn/XPZE"
        $s6 = "SuperService.onCreate"
        $s7 = "jte/zA4rlQYOF45qs"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_02151 {
    strings:
        $s0 = "Z.-z-.xy-"
        $s1 = "J-yM/-P-y"
        $s2 = "Yk.11L-T"
        $s3 = "Lcom/webmoney/my/App"
        $s4 = "Lcom/webmoney/my/data/WMSettings"
        $s5 = "Lcom/webmoney/my/data/model/WMCurrency"
        $s6 = "Lcom/webmoney/my/AccountManager"
        $s7 = "Lcom/webmoney/my/data/model/WMContact"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_02152 {
    strings:
        $s0 = "Z.-z-.xy-"
        $s1 = "J-yM/-P-y"
        $s2 = "Yk.11L-T"
        $s3 = "assets/ev_xp_bar_fill.mp3"
        $s4 = "Lcom/webmoney/my/App"
        $s5 = "Lcom/webmoney/my/data/WMSettings"
        $s6 = "Lcom/webmoney/my/data/model/WMCurrency"
        $s7 = "Lcom/webmoney/my/AccountManager"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}

rule VX_APK_CLUSTER_02153 {
    strings:
        $s0 = "custom.dat"
        $s1 = "assets/feeInfo.dat"
        $s2 = "/ProgramId"
        $s3 = "assets/classes.jar"
        $s4 = "/ProductInfo"
        $s5 = "/paycode"
        $s6 = "5http://da.mmarket.com/mmsdk/mmsdk"
        $s7 = "mmsdk:feedback"
    condition:
        any of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}