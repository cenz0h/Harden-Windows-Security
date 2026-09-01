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

using System.Collections.Generic;
using System.Security.Principal;

namespace AppControlManager.ViewModels;

/// <summary>
/// A well-known security identifier and its friendly meaning, for the editor's SID legend.
/// </summary>
internal sealed class SidInfo(string sid, string name, string description)
{
	internal string Sid => sid;
	internal string Name => name;
	internal string Description => description;
}

/// <summary>
/// Common built-in SIDs shown in the AppLocker editor's "SID legend" so users don't have to
/// memorise them. The list is intentionally the groups most useful for AppLocker scoping.
/// </summary>
internal static class WellKnownSids
{
	internal static readonly IReadOnlyList<SidInfo> CommonGroups =
	[
		new("S-1-1-0", "Everyone", "All users. AppLocker rules for everyone use this."),
		new("S-1-5-11", "Authenticated Users", "Any user who signed in with credentials (excludes anonymous/guest)."),
		new("S-1-5-32-544", "Administrators", "BUILTIN\\Administrators. Use with a scoped Allow to permit admins only."),
		new("S-1-5-32-545", "Users", "BUILTIN\\Users - standard (non-admin) users. Note: admins are members too."),
		new("S-1-5-32-546", "Guests", "BUILTIN\\Guests."),
		new("S-1-5-32-555", "Remote Desktop Users", "BUILTIN\\Remote Desktop Users."),
		new("S-1-5-32-547", "Power Users", "BUILTIN\\Power Users (legacy)."),
		new("S-1-5-18", "Local System", "The SYSTEM account (services)."),
		new("S-1-5-19", "Local Service", "The LOCAL SERVICE account."),
		new("S-1-5-20", "Network Service", "The NETWORK SERVICE account."),
		new("S-1-5-4", "Interactive", "Users logged on interactively (local console/RDP)."),
		new("S-1-5-6", "Service", "Accounts logged on as a service."),
		new("S-1-5-113", "Local account", "Any local (non-domain) account."),
		new("S-1-5-114", "Local account and member of Administrators", "A local account that is also in the Administrators group.")
	];

	/// <summary>
	/// Resolves a SID string to a friendly name: first from the well-known table above, then via
	/// the OS (<see cref="SecurityIdentifier"/> translation, which also handles domain SIDs when
	/// reachable). Returns a short status string when the SID is empty/invalid/unresolvable.
	/// </summary>
	internal static string Resolve(string? sid)
	{
		if (string.IsNullOrWhiteSpace(sid))
		{
			return string.Empty;
		}

		string trimmed = sid.Trim();

		foreach (SidInfo known in CommonGroups)
		{
			if (string.Equals(known.Sid, trimmed, System.StringComparison.OrdinalIgnoreCase))
			{
				return known.Name;
			}
		}

		try
		{
			SecurityIdentifier identifier = new(trimmed);
			try
			{
				NTAccount account = (NTAccount)identifier.Translate(typeof(NTAccount));
				return account.Value;
			}
			catch
			{
				// Valid SID format, but not resolvable on this machine (e.g. offline domain).
				return Atlas.GetStr("AppLockerSidUnresolved");
			}
		}
		catch
		{
			return Atlas.GetStr("AppLockerSidInvalid");
		}
	}
}
