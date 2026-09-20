# Keep VPN service and receivers reachable from the manifest / system.
-keep class com.sinkhole.adblock.vpn.SinkholeVpnService { *; }
-keep class com.sinkhole.adblock.notification.NotificationActionReceiver { *; }
-keep class com.sinkhole.adblock.boot.BootReceiver { *; }
