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
using System.Runtime.InteropServices;
using AppControlManager.SiPolicy;
using CommonCore.IntelGathering;

namespace AppControlManager.SimulationMethods;

/// <summary>
/// The non-signer half of Deny evaluation for the simulation: Deny rules based on a hash, a file path,
/// or file attributes (FileName / InternalName / FileDescription / ProductName plus a version range).
///
/// Deny signers are handled separately by <see cref="Arbitrator.Compare"/> with
/// <c>evaluateDeniedSigners: true</c>, because matching a signer needs the full certificate logic.
/// </summary>
internal sealed class DenyRuleSet
{
	/// <summary>Authenticode hashes from Deny rules.</summary>
	internal HashSet<string> Hashes { get; } = new(StringComparer.OrdinalIgnoreCase);

	/// <summary>File paths from Deny rules.</summary>
	internal HashSet<string> FilePaths { get; } = new(StringComparer.OrdinalIgnoreCase);

	/// <summary>Deny rules that match on version-resource attributes.</summary>
	internal List<Deny> AttributeRules { get; } = [];

	/// <summary>True when the policy contains any Deny rule this evaluator can act on.</summary>
	internal bool HasAny => Hashes.Count > 0 || FilePaths.Count > 0 || AttributeRules.Count > 0;
}

internal static class DenyRuleEvaluator
{
	/// <summary>
	/// Pulls every Deny rule out of the policy and buckets it by how it has to be matched.
	/// </summary>
	internal static DenyRuleSet Extract(SiPolicy.SiPolicy policyObj)
	{
		DenyRuleSet result = new();

		if (policyObj.FileRules is null)
			return result;

		foreach (object item in CollectionsMarshal.AsSpan(policyObj.FileRules))
		{
			if (item is not Deny denyRule)
				continue;

			// A Deny rule carrying a hash.
			if (!denyRule.Hash.IsEmpty)
			{
				_ = result.Hashes.Add(Convert.ToHexString(denyRule.Hash.Span));
				continue;
			}

			// A Deny rule carrying a file path.
			if (!string.IsNullOrWhiteSpace(denyRule.FilePath))
			{
				_ = result.FilePaths.Add(denyRule.FilePath);
				continue;
			}

			// Otherwise it matches on version-resource attributes. Ignore an all-wildcard rule, which
			// would deny everything and is never what an authored rule means here.
			if (HasAnyAttribute(denyRule))
				result.AttributeRules.Add(denyRule);
		}

		return result;
	}

	private static bool HasAnyAttribute(Deny rule) =>
		!string.IsNullOrWhiteSpace(rule.FileName) ||
		!string.IsNullOrWhiteSpace(rule.InternalName) ||
		!string.IsNullOrWhiteSpace(rule.FileDescription) ||
		!string.IsNullOrWhiteSpace(rule.ProductName);

	/// <summary>
	/// Checks a file against the Deny rules. Returns null when nothing denies it.
	/// </summary>
	/// <param name="denyRules">The extracted rules.</param>
	/// <param name="fullPath">Full path of the file being tested.</param>
	/// <param name="sha256">Authenticode SHA256 of the file.</param>
	/// <param name="sha1">Authenticode SHA1 of the file.</param>
	/// <param name="fileInfo">Version-resource attributes of the file, when they could be read.</param>
	internal static (SimulationOutputSource Source, string Reason)? Evaluate(
		DenyRuleSet denyRules,
		string fullPath,
		string? sha256,
		string? sha1,
		ExFileInfo? fileInfo)
	{
		// Hash deny
		if (denyRules.Hashes.Count > 0)
		{
			if ((sha256 is not null && denyRules.Hashes.Contains(sha256)) ||
				(sha1 is not null && denyRules.Hashes.Contains(sha1)))
			{
				return (SimulationOutputSource.DeniedByHash, "Blocked by a Deny hash rule");
			}
		}

		// File path deny
		if (denyRules.FilePaths.Count > 0 && denyRules.FilePaths.Contains(fullPath))
		{
			return (SimulationOutputSource.DeniedByFilePath, "Blocked by a Deny file path rule");
		}

		// Attribute deny
		foreach (Deny rule in CollectionsMarshal.AsSpan(denyRules.AttributeRules))
		{
			if (Matches(rule, fileInfo))
			{
				string label = !string.IsNullOrWhiteSpace(rule.FriendlyName) ? rule.FriendlyName : rule.ID;
				return (SimulationOutputSource.DeniedByFileAttribute, $"Blocked by Deny rule '{label}'");
			}
		}

		return null;
	}

	/// <summary>
	/// A file matches an attribute Deny rule when every attribute the rule specifies matches the file
	/// AND the file's version falls inside the rule's version range.
	///
	/// The rule's FileName attribute is compared against the file's Original File Name, which is what
	/// App Control matches on - deliberately NOT the name on disk, since renaming a file must not change
	/// whether a rule applies.
	/// </summary>
	private static bool Matches(Deny rule, ExFileInfo? fileInfo)
	{
		if (fileInfo is null)
			return false;

		bool anyAttributeCompared = false;

		if (!string.IsNullOrWhiteSpace(rule.FileName))
		{
			if (!EqualsOrdinalIgnoreCase(rule.FileName, fileInfo.OriginalFileName)) return false;
			anyAttributeCompared = true;
		}

		if (!string.IsNullOrWhiteSpace(rule.InternalName))
		{
			if (!EqualsOrdinalIgnoreCase(rule.InternalName, fileInfo.InternalName)) return false;
			anyAttributeCompared = true;
		}

		if (!string.IsNullOrWhiteSpace(rule.FileDescription))
		{
			if (!EqualsOrdinalIgnoreCase(rule.FileDescription, fileInfo.FileDescription)) return false;
			anyAttributeCompared = true;
		}

		if (!string.IsNullOrWhiteSpace(rule.ProductName))
		{
			if (!EqualsOrdinalIgnoreCase(rule.ProductName, fileInfo.ProductName)) return false;
			anyAttributeCompared = true;
		}

		// Never let a rule with nothing to compare deny everything.
		if (!anyAttributeCompared)
			return false;

		return VersionInRange(rule.MinimumFileVersion, rule.MaximumFileVersion, fileInfo.Version);
	}

	private static bool EqualsOrdinalIgnoreCase(string? ruleValue, string? fileValue) =>
		!string.IsNullOrWhiteSpace(fileValue) && string.Equals(ruleValue, fileValue, StringComparison.OrdinalIgnoreCase);

	/// <summary>
	/// Applies the rule's version bounds. An absent bound is open ended; an unreadable file version is
	/// treated as in-range so a rule isn't silently skipped for a file with no version resource.
	/// </summary>
	private static bool VersionInRange(string? minimum, string? maximum, Version? fileVersion)
	{
		if (string.IsNullOrWhiteSpace(minimum) && string.IsNullOrWhiteSpace(maximum))
			return true;

		if (fileVersion is null)
			return true;

		if (!string.IsNullOrWhiteSpace(minimum) && Version.TryParse(minimum, out Version? min) && fileVersion < min)
			return false;

		if (!string.IsNullOrWhiteSpace(maximum) && Version.TryParse(maximum, out Version? max) && fileVersion > max)
			return false;

		return true;
	}
}
