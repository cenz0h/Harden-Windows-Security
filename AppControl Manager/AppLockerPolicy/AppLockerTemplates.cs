// MIT License
//
// Copyright (c) 2023-Present - Violet Hansen - (aka HotCakeX on GitHub) - Email Address: spynetgirl@outlook.com
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// See here for more information: https://github.com/HotCakeX/Harden-Windows-Security/blob/main/LICENSE
//

using System;
using System.Collections.Generic;

namespace AppControlManager.AppLockerPolicy;

/// <summary>
/// A curated "quick rule" template: a well-known app/binary described by robust path conditions,
/// ready to be turned into an Allow or Deny rule with a chosen identity scope.
/// </summary>
internal sealed class AppLockerTemplate
{
	internal required string Id { get; init; }
	internal required string DisplayName { get; init; }
	internal required string Category { get; init; }
	internal required RuleCollectionType Collection { get; init; }

	/// <summary>AppLocker path patterns (any-match) that identify the binary. Uses AppLocker macros.</summary>
	internal required string[] Paths { get; init; }

	internal string Description { get; init; } = string.Empty;
}

/// <summary>
/// The built-in template catalog. Kept as plain data so both the editor UI and any future
/// consumers can share it.
/// </summary>
internal static class AppLockerTemplates
{
	internal const string ScriptHostsCategory = "Windows script hosts & LOLBins";
	internal const string TorrentCategory = "Torrent clients";
	internal const string RemoteAccessCategory = "Remote-access tools";

	/// <summary>
	/// Windows built-in interpreters / living-off-the-land binaries. All are EXE-collection path
	/// rules covering both System32 and the 32-bit SysWOW64 location where applicable.
	/// </summary>
	internal static readonly IReadOnlyList<AppLockerTemplate> All =
	[
		new() { Id = "cmd", DisplayName = "Command Prompt (cmd.exe)", Category = ScriptHostsCategory, Collection = RuleCollectionType.Exe,
			Paths = [@"%SYSTEM32%\cmd.exe", @"%WINDIR%\SysWOW64\cmd.exe"],
			Description = "Windows Command Processor." },

		new() { Id = "powershell", DisplayName = "Windows PowerShell (powershell.exe)", Category = ScriptHostsCategory, Collection = RuleCollectionType.Exe,
			Paths = [@"%SYSTEM32%\WindowsPowerShell\v1.0\powershell.exe", @"%WINDIR%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe"],
			Description = "Windows PowerShell 5.1 host." },

		new() { Id = "powershell_ise", DisplayName = "PowerShell ISE (powershell_ise.exe)", Category = ScriptHostsCategory, Collection = RuleCollectionType.Exe,
			Paths = [@"%SYSTEM32%\WindowsPowerShell\v1.0\powershell_ise.exe", @"%WINDIR%\SysWOW64\WindowsPowerShell\v1.0\powershell_ise.exe"],
			Description = "PowerShell Integrated Scripting Environment." },

		new() { Id = "pwsh", DisplayName = "PowerShell 7 (pwsh.exe)", Category = ScriptHostsCategory, Collection = RuleCollectionType.Exe,
			Paths = [@"%PROGRAMFILES%\PowerShell\*\pwsh.exe"],
			Description = "PowerShell 7+ (cross-platform) host, installed under Program Files." },

		new() { Id = "wscript", DisplayName = "Windows Script Host (wscript.exe)", Category = ScriptHostsCategory, Collection = RuleCollectionType.Exe,
			Paths = [@"%SYSTEM32%\wscript.exe", @"%WINDIR%\SysWOW64\wscript.exe"],
			Description = "GUI Windows Script Host (VBScript/JScript)." },

		new() { Id = "cscript", DisplayName = "Console Script Host (cscript.exe)", Category = ScriptHostsCategory, Collection = RuleCollectionType.Exe,
			Paths = [@"%SYSTEM32%\cscript.exe", @"%WINDIR%\SysWOW64\cscript.exe"],
			Description = "Console Windows Script Host (VBScript/JScript)." },

		new() { Id = "mshta", DisplayName = "HTML Application host (mshta.exe)", Category = ScriptHostsCategory, Collection = RuleCollectionType.Exe,
			Paths = [@"%SYSTEM32%\mshta.exe", @"%WINDIR%\SysWOW64\mshta.exe"],
			Description = "Microsoft HTML Application host - a common script/malware launcher." },

		new() { Id = "regsvr32", DisplayName = "regsvr32.exe", Category = ScriptHostsCategory, Collection = RuleCollectionType.Exe,
			Paths = [@"%SYSTEM32%\regsvr32.exe", @"%WINDIR%\SysWOW64\regsvr32.exe"],
			Description = "Registers DLLs; a well-known LOLBin for proxy execution." },

		new() { Id = "rundll32", DisplayName = "rundll32.exe", Category = ScriptHostsCategory, Collection = RuleCollectionType.Exe,
			Paths = [@"%SYSTEM32%\rundll32.exe", @"%WINDIR%\SysWOW64\rundll32.exe"],
			Description = "Runs DLL entry points; a common LOLBin." },

		new() { Id = "certutil", DisplayName = "certutil.exe", Category = ScriptHostsCategory, Collection = RuleCollectionType.Exe,
			Paths = [@"%SYSTEM32%\certutil.exe", @"%WINDIR%\SysWOW64\certutil.exe"],
			Description = "Certificate utility; abused for download/decoding." },

		new() { Id = "bitsadmin", DisplayName = "bitsadmin.exe", Category = ScriptHostsCategory, Collection = RuleCollectionType.Exe,
			Paths = [@"%SYSTEM32%\bitsadmin.exe", @"%WINDIR%\SysWOW64\bitsadmin.exe"],
			Description = "BITS admin tool; abused for downloads/persistence." },

		new() { Id = "wmic", DisplayName = "wmic.exe", Category = ScriptHostsCategory, Collection = RuleCollectionType.Exe,
			Paths = [@"%SYSTEM32%\wbem\wmic.exe", @"%WINDIR%\SysWOW64\wbem\wmic.exe"],
			Description = "WMI command-line tool; a LOLBin for execution." },

		new() { Id = "reg", DisplayName = "reg.exe", Category = ScriptHostsCategory, Collection = RuleCollectionType.Exe,
			Paths = [@"%SYSTEM32%\reg.exe", @"%WINDIR%\SysWOW64\reg.exe"],
			Description = "Registry command-line editor." },

		// -------- Torrent clients (filename path rules; match the executable anywhere) --------
		new() { Id = "qbittorrent", DisplayName = "qBittorrent", Category = TorrentCategory, Collection = RuleCollectionType.Exe,
			Paths = [@"*\qbittorrent.exe"], Description = "qBittorrent client (qbittorrent.exe)." },

		new() { Id = "utorrent", DisplayName = "uTorrent", Category = TorrentCategory, Collection = RuleCollectionType.Exe,
			Paths = [@"*\utorrent.exe", @"*\uTorrentie.exe"], Description = "uTorrent client (utorrent.exe)." },

		new() { Id = "bittorrent", DisplayName = "BitTorrent", Category = TorrentCategory, Collection = RuleCollectionType.Exe,
			Paths = [@"*\bittorrent.exe"], Description = "BitTorrent client (bittorrent.exe)." },

		new() { Id = "transmission", DisplayName = "Transmission", Category = TorrentCategory, Collection = RuleCollectionType.Exe,
			Paths = [@"*\transmission-qt.exe", @"*\transmission-daemon.exe"], Description = "Transmission client (transmission-qt.exe)." },

		new() { Id = "deluge", DisplayName = "Deluge", Category = TorrentCategory, Collection = RuleCollectionType.Exe,
			Paths = [@"*\deluge.exe", @"*\deluged.exe", @"*\deluge-console.exe"], Description = "Deluge client (deluge.exe)." },

		new() { Id = "vuze", DisplayName = "Vuze / Azureus", Category = TorrentCategory, Collection = RuleCollectionType.Exe,
			Paths = [@"*\Vuze.exe", @"*\Azureus.exe"], Description = "Vuze (formerly Azureus) client." },

		new() { Id = "tixati", DisplayName = "Tixati", Category = TorrentCategory, Collection = RuleCollectionType.Exe,
			Paths = [@"*\tixati.exe"], Description = "Tixati client (tixati.exe)." },

		// -------- Remote-access tools (filename path rules) --------
		new() { Id = "teamviewer", DisplayName = "TeamViewer", Category = RemoteAccessCategory, Collection = RuleCollectionType.Exe,
			Paths = [@"*\TeamViewer.exe", @"*\TeamViewer_Service.exe"], Description = "TeamViewer remote access." },

		new() { Id = "anydesk", DisplayName = "AnyDesk", Category = RemoteAccessCategory, Collection = RuleCollectionType.Exe,
			Paths = [@"*\AnyDesk.exe"], Description = "AnyDesk remote access (AnyDesk.exe)." },

		new() { Id = "rustdesk", DisplayName = "RustDesk", Category = RemoteAccessCategory, Collection = RuleCollectionType.Exe,
			Paths = [@"*\rustdesk.exe"], Description = "RustDesk remote access (rustdesk.exe)." },

		new() { Id = "chromeremote", DisplayName = "Chrome Remote Desktop", Category = RemoteAccessCategory, Collection = RuleCollectionType.Exe,
			Paths = [@"*\remoting_host.exe"], Description = "Chrome Remote Desktop host (remoting_host.exe)." },

		new() { Id = "ultravnc", DisplayName = "UltraVNC", Category = RemoteAccessCategory, Collection = RuleCollectionType.Exe,
			Paths = [@"*\winvnc.exe", @"*\vncviewer.exe"], Description = "UltraVNC server/viewer." },

		new() { Id = "tightvnc", DisplayName = "TightVNC", Category = RemoteAccessCategory, Collection = RuleCollectionType.Exe,
			Paths = [@"*\tvnserver.exe", @"*\tvnviewer.exe"], Description = "TightVNC server/viewer." },

		new() { Id = "realvnc", DisplayName = "RealVNC", Category = RemoteAccessCategory, Collection = RuleCollectionType.Exe,
			Paths = [@"*\vncserver.exe", @"*\winvnc4.exe", @"*\vncviewer.exe"], Description = "RealVNC server/viewer." },

		new() { Id = "logmein", DisplayName = "LogMeIn", Category = RemoteAccessCategory, Collection = RuleCollectionType.Exe,
			Paths = [@"*\LogMeIn.exe", @"*\LMIGuardianSvc.exe"], Description = "LogMeIn remote access." },

		new() { Id = "splashtop", DisplayName = "Splashtop", Category = RemoteAccessCategory, Collection = RuleCollectionType.Exe,
			Paths = [@"*\Splashtop*.exe", @"*\SRService.exe"], Description = "Splashtop remote access." },

		new() { Id = "screenconnect", DisplayName = "ConnectWise Control (ScreenConnect)", Category = RemoteAccessCategory, Collection = RuleCollectionType.Exe,
			Paths = [@"*\ScreenConnect.WindowsClient.exe", @"*\ScreenConnect.ClientService.exe"], Description = "ConnectWise Control / ScreenConnect client." },

		new() { Id = "ammyy", DisplayName = "Ammyy Admin", Category = RemoteAccessCategory, Collection = RuleCollectionType.Exe,
			Paths = [@"*\AA_v3.exe"], Description = "Ammyy Admin - frequently abused RAT (AA_v3.exe)." },

		new() { Id = "remoteutilities", DisplayName = "Remote Utilities", Category = RemoteAccessCategory, Collection = RuleCollectionType.Exe,
			Paths = [@"*\rutserv.exe", @"*\rfusclient.exe"], Description = "Remote Utilities host/client." },

		new() { Id = "dwservice", DisplayName = "DWService", Category = RemoteAccessCategory, Collection = RuleCollectionType.Exe,
			Paths = [@"*\dwagent.exe"], Description = "DWService agent (dwagent.exe)." },
	];

	/// <summary>
	/// Builds one rule per path in the template. AppLocker permits only a SINGLE condition per rule,
	/// so a template that lists e.g. both the System32 and SysWOW64 locations yields two rules.
	/// Each Id is a new lower-case GUID (AppLocker's convention).
	/// </summary>
	internal static IEnumerable<FilePathRule> CreateRules(AppLockerTemplate template, RuleActionType action, string userOrGroupSid, string scopeLabel)
	{
		foreach (string path in template.Paths)
		{
			yield return new FilePathRule
			{
				Id = Guid.NewGuid().ToString(),
				Name = $"{template.DisplayName} [{action} - {scopeLabel}]",
				Description = template.Description,
				UserOrGroupSid = userOrGroupSid,
				Action = action,
				Conditions = { new FilePathCondition { Path = path } }
			};
		}
	}
}
