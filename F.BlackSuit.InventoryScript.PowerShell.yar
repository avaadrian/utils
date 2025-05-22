rule F_BlackSuit_InventoryScript_PowerShell
{
    meta:
        description = "Detects a custom PowerShell script used for enumerating live hosts, disk info, and installed software across a network, as documented in BlackSuit ransomware tooling."
        author = "Andriu Viorel"
        reference = "BlackSuit Ransomware – Inventory Script Analysis"
        date = "2025-05-21"
        malware_family = "BlackSuit"

   strings:
       // AV keywords
       $av_list_1 = "Defence"
       $av_list_2 = "Defender"
       $av_list_3 = "Endpoint"
       $av_list_4 = "AV"
       $av_list_5 = "AntiVirus"
       $av_list_6 = "BitDefender"
       $av_list_7 = "Kaspersky"
       $av_list_8 = "Norton"
       $av_list_9 = "Avast"
       $av_list_10 = "WebRoo"
       $av_list_11 = "AVG"
       $av_list_12 = "ESET"
       $av_list_13 = "Malware"
       $av_list_14 = "Sophos"
       $av_list_15 = "Trend"
       $av_list_16 = "Symantec Endpoint Protection"
       $av_list_17 = "Security"
       // Backup keywords
       $backup_list_1 = "Veeam"
       $backup_list_2 = "Backup"
       $backup_list_3 = "Recovery"
       $backup_list_4 = "Synology"
       $backup_list_5 = "C2"
       $backup_list_6 = "Cloud"
       $backup_list_7 = "Dropbox"
       $backup_list_8 = "Acronis"
       $backup_list_9 = "Cobian"
       $backup_list_10 = "EaseUS"
       $backup_list_11 = "Paragon"
       $backup_list_12 = "IDrive"

       // Additional match indicators
       $msg_diskinfo = "Grubbing Disk.info complete"
       $archive_cmd = "& '.\\7z.exe' a"
   condition:
       (any of ($av_list*) or any of ($backup_list*)) and
       ($msg_diskinfo and $archive_cmd)
}