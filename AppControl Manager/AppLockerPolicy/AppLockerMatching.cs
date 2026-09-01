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
/// Stateless matching helpers shared by the AppLocker rule evaluator: extension→collection
/// mapping, path/macro/wildcard matching, version-range checks and publisher-string parsing.
/// </summary>
internal static class AppLockerMatching
{
	// Extension → rule collection. AppLocker's fixed extension sets for each collection.
	private static readonly Dictionary<string, RuleCollectionType> ExtensionMap = new(StringComparer.OrdinalIgnoreCase)
	{
		{ ".exe", RuleCollectionType.Exe },
		{ ".com", RuleCollectionType.Exe },
		{ ".dll", RuleCollectionType.Dll },
		{ ".ocx", RuleCollectionType.Dll },
		{ ".msi", RuleCollectionType.Msi },
		{ ".msp", RuleCollectionType.Msi },
		{ ".mst", RuleCollectionType.Msi },
		{ ".ps1", RuleCollectionType.Script },
		{ ".bat", RuleCollectionType.Script },
		{ ".cmd", RuleCollectionType.Script },
		{ ".vbs", RuleCollectionType.Script },
		{ ".js", RuleCollectionType.Script },
		{ ".appx", RuleCollectionType.Appx },
		{ ".msix", RuleCollectionType.Appx }
	};

	/// <summary>
	/// Returns the AppLocker rule collection an extension belongs to, or null if AppLocker
	/// does not govern that file type.
	/// </summary>
	internal static RuleCollectionType? CollectionForExtension(string extensionWithDot)
	{
		return ExtensionMap.TryGetValue(extensionWithDot, out RuleCollectionType type) ? type : null;
	}

	#region Path matching

	/// <summary>
	/// Determines whether a concrete file path is matched by an AppLocker path pattern,
	/// expanding AppLocker macros and honoring '*' / '?' wildcards (case-insensitive).
	/// </summary>
	internal static bool PathMatches(string filePath, string pattern)
	{
		if (string.IsNullOrEmpty(pattern))
		{
			return false;
		}

		foreach (string expanded in ExpandMacros(pattern))
		{
			// A pattern that names a directory (ends with '\') should match everything under it.
			string effective = expanded.EndsWith('\\') ? expanded + "*" : expanded;

			if (Glob(filePath, effective))
			{
				return true;
			}
		}

		return false;
	}

	/// <summary>
	/// Expands AppLocker path macros to concrete prefixes. A single macro can expand to more
	/// than one concrete path (e.g. %PROGRAMFILES% covers both 64-bit and 32-bit locations).
	/// Media macros (%REMOVABLE%, %HOT%) cannot be resolved for a local scan and are dropped.
	/// </summary>
	private static IEnumerable<string> ExpandMacros(string pattern)
	{
		string windir = Environment.GetEnvironmentVariable("windir") ?? @"C:\Windows";
		string osDrive = System.IO.Path.GetPathRoot(windir)?.TrimEnd('\\') ?? "C:";
		string pf = Environment.GetEnvironmentVariable("ProgramFiles") ?? @"C:\Program Files";
		string pfx86 = Environment.GetEnvironmentVariable("ProgramFiles(x86)") ?? @"C:\Program Files (x86)";

		string upper = pattern;

		if (Contains(upper, "%REMOVABLE%") || Contains(upper, "%HOT%"))
		{
			// Unresolvable during a local filesystem scan.
			yield break;
		}

		if (Contains(upper, "%PROGRAMFILES%"))
		{
			yield return ReplaceCI(upper, "%PROGRAMFILES%", pf);
			yield return ReplaceCI(upper, "%PROGRAMFILES%", pfx86);
			yield break;
		}

		string result = upper;
		result = ReplaceCI(result, "%SYSTEM32%", windir + @"\System32");
		result = ReplaceCI(result, "%WINDIR%", windir);
		result = ReplaceCI(result, "%OSDRIVE%", osDrive);
		yield return result;
	}

	private static bool Contains(string s, string token) =>
		s.Contains(token, StringComparison.OrdinalIgnoreCase);

	private static string ReplaceCI(string input, string token, string replacement) =>
		input.Replace(token, replacement, StringComparison.OrdinalIgnoreCase);

	/// <summary>
	/// Case-insensitive glob: '*' matches any run of characters (including path separators),
	/// '?' matches exactly one character.
	/// </summary>
	private static bool Glob(string text, string pattern)
	{
		int t = 0, p = 0, star = -1, mark = 0;

		while (t < text.Length)
		{
			if (p < pattern.Length && (pattern[p] == '?' ||
				char.ToUpperInvariant(pattern[p]) == char.ToUpperInvariant(text[t])))
			{
				t++;
				p++;
			}
			else if (p < pattern.Length && pattern[p] == '*')
			{
				star = p++;
				mark = t;
			}
			else if (star != -1)
			{
				p = star + 1;
				t = ++mark;
			}
			else
			{
				return false;
			}
		}

		while (p < pattern.Length && pattern[p] == '*')
		{
			p++;
		}

		return p == pattern.Length;
	}

	#endregion

	#region Version range

	/// <summary>
	/// Checks whether a file version falls within an AppLocker BinaryVersionRange
	/// (inclusive). "*" means unbounded on that end.
	/// </summary>
	internal static bool VersionInRange(Version? fileVersion, string lowSection, string highSection)
	{
		bool lowWild = string.IsNullOrEmpty(lowSection) || lowSection == "*";
		bool highWild = string.IsNullOrEmpty(highSection) || highSection == "*";

		if (fileVersion is null)
		{
			// Only an entirely-unbounded range applies to a file that has no version resource.
			return lowWild && highWild;
		}

		if (!lowWild && Version.TryParse(lowSection, out Version? low) && fileVersion < low)
		{
			return false;
		}

		if (!highWild && Version.TryParse(highSection, out Version? high) && fileVersion > high)
		{
			return false;
		}

		return true;
	}

	#endregion

	#region Publisher parsing

	/// <summary>
	/// Extracts the Organization (O=) value from an AppLocker publisher-name string, upper-cased,
	/// or empty if none is present. Best-effort parse (values containing commas are uncommon).
	/// </summary>
	internal static string ExtractOrganization(string publisherName)
	{
		if (string.IsNullOrEmpty(publisherName))
		{
			return string.Empty;
		}

		foreach (string raw in publisherName.Split(','))
		{
			string token = raw.Trim();
			if (token.StartsWith("O=", StringComparison.OrdinalIgnoreCase))
			{
				return token[2..].Trim().ToUpperInvariant();
			}
		}

		return string.Empty;
	}

	#endregion
}
