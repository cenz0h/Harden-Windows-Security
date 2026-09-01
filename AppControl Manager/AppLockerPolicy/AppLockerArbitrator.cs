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

namespace AppControlManager.AppLockerPolicy;

/// <summary>
/// The well-known "Everyone" SID; rules scoped to it apply to all identities.
/// </summary>
file static class Sids
{
	internal const string Everyone = "S-1-1-0";
}

/// <summary>
/// Evaluates a single scanned file against an AppLocker policy and returns the verdict.
/// This is the AppLocker analogue of the WDAC <c>SimulationMethods.Arbitrator</c>.
///
/// Semantics implemented:
///  - File type is mapped to a rule collection by extension; ungoverned types are "Not applicable".
///  - Only <see cref="EnforcementModeType.Enabled"/> collections block; AuditOnly runs-but-logs;
///    NotConfigured / a missing collection is "Not applicable".
///  - Deny rules take precedence over Allow rules.
///  - An enforced collection is default-deny: anything not explicitly allowed is blocked.
///  - A rule applies only if the file matches one of its Conditions and none of its Exceptions.
///
/// Caveats: publisher matching is tolerant (exact subject OR Organization) because AppLocker's
/// exact publisher canonicalization is not reproducible from a certificate; per-user SIDs are
/// not evaluated (the what-if is machine-wide).
/// </summary>
internal static class AppLockerArbitrator
{
	/// <param name="applicableSids">
	/// When non-null, only rules whose <c>UserOrGroupSid</c> is "Everyone" (S-1-1-0) or is contained
	/// in this set are considered (the "evaluate as this identity" filter). When null, every rule is
	/// considered regardless of scope (machine-wide what-if). The deciding rule's SID is always
	/// reported so the UI can show admin-only matches.
	/// </param>
	internal static AppLockerSimulationOutput Evaluate(AppLockerFileInfo file, AppLockerPolicyObj policy, IReadOnlyCollection<string>? applicableSids = null)
	{
		AppLockerSimulationOutput output = new()
		{
			FilePath = file.FilePath,
			FileName = file.FileName,
			Collection = file.Collection?.ToString() ?? string.Empty,
			Publisher = file.Publishers.Count > 0 ? file.Publishers[0].SubjectUpper : null,
			ProductName = file.ProductNameUpper,
			FileVersion = file.FileVersion?.ToString(),
			SHA256 = file.SHA256Authenticode
		};

		if (file.ScanError is not null)
		{
			output.Source = AppLockerVerdictSource.NotProcessed;
			output.IsAuthorized = false;
			output.Reason = file.ScanError;
			return output;
		}

		if (file.Collection is null)
		{
			output.Source = AppLockerVerdictSource.NotApplicable;
			output.IsAuthorized = true;
			output.Reason = Atlas.GetStr("AppLockerNotGovernedReason");
			return output;
		}

		// Find the matching collection in the policy.
		RuleCollection? collection = null;
		foreach (RuleCollection rc in CollectionsMarshal.AsSpan(policy.RuleCollections))
		{
			if (rc.Type == file.Collection.Value)
			{
				collection = rc;
				break;
			}
		}

		if (collection is null || collection.EnforcementMode == EnforcementModeType.NotConfigured)
		{
			output.Source = AppLockerVerdictSource.NotApplicable;
			output.IsAuthorized = true;
			output.Reason = Atlas.GetStr("AppLockerCollectionNotEnforcedReason");
			return output;
		}

		// Deny takes precedence: scan denies first.
		foreach (RuleBase rule in CollectionsMarshal.AsSpan(collection.Rules))
		{
			if (rule.Action != RuleActionType.Deny || !AppliesToIdentity(rule, applicableSids))
			{
				continue;
			}

			if (RuleApplies(rule, file, out AppLockerMatchType matchType, out AppLockerMatchConfidence confidence))
			{
				output.Source = AppLockerVerdictSource.DeniedByRule;
				output.IsAuthorized = false;
				output.MatchType = matchType;
				output.MatchConfidence = confidence;
				output.MatchedRuleId = rule.Id;
				output.MatchedRuleName = rule.Name;
				output.UserOrGroupSid = rule.UserOrGroupSid;
				output.Reason = Atlas.GetStr("AppLockerDeniedByRuleReason");
				return output;
			}
		}

		// Then allows.
		foreach (RuleBase rule in CollectionsMarshal.AsSpan(collection.Rules))
		{
			if (rule.Action != RuleActionType.Allow || !AppliesToIdentity(rule, applicableSids))
			{
				continue;
			}

			if (RuleApplies(rule, file, out AppLockerMatchType matchType, out AppLockerMatchConfidence confidence))
			{
				bool auditOnly = collection.EnforcementMode == EnforcementModeType.AuditOnly;
				output.Source = auditOnly ? AppLockerVerdictSource.AuditOnly : AppLockerVerdictSource.Allowed;
				output.IsAuthorized = true;
				output.MatchType = matchType;
				output.MatchConfidence = confidence;
				output.MatchedRuleId = rule.Id;
				output.MatchedRuleName = rule.Name;
				output.UserOrGroupSid = rule.UserOrGroupSid;
				output.Reason = auditOnly
					? Atlas.GetStr("AppLockerAuditOnlyReason")
					: Atlas.GetStr("AppLockerAllowedByRuleReason");
				return output;
			}
		}

		// Nothing matched in an enforced collection -> default deny.
		bool audit = collection.EnforcementMode == EnforcementModeType.AuditOnly;
		output.Source = audit ? AppLockerVerdictSource.AuditOnly : AppLockerVerdictSource.DefaultDeny;
		output.IsAuthorized = audit;
		output.Reason = audit
			? Atlas.GetStr("AppLockerAuditOnlyDefaultReason")
			: Atlas.GetStr("AppLockerDefaultDenyReason");
		return output;
	}

	/// <summary>
	/// Whether a rule's identity scope includes the requested identity set. Everyone-scoped rules
	/// always apply; a null filter means "consider all rules regardless of scope".
	/// </summary>
	private static bool AppliesToIdentity(RuleBase rule, IReadOnlyCollection<string>? applicableSids)
	{
		if (applicableSids is null)
		{
			return true;
		}

		if (string.Equals(rule.UserOrGroupSid, Sids.Everyone, StringComparison.OrdinalIgnoreCase))
		{
			return true;
		}

		foreach (string sid in applicableSids)
		{
			if (string.Equals(rule.UserOrGroupSid, sid, StringComparison.OrdinalIgnoreCase))
			{
				return true;
			}
		}

		return false;
	}

	/// <summary>
	/// A rule applies to the file when the file matches one of the rule's Conditions and none
	/// of its Exceptions.
	/// </summary>
	private static bool RuleApplies(RuleBase rule, AppLockerFileInfo file, out AppLockerMatchType matchType, out AppLockerMatchConfidence confidence)
	{
		if (!TryMatchAny(rule.Conditions, file, out matchType, out confidence))
		{
			return false;
		}

		if (rule.Exceptions.Count > 0 &&
			TryMatchAny(rule.Exceptions, file, out _, out _))
		{
			// Excluded by an exception.
			matchType = AppLockerMatchType.None;
			confidence = AppLockerMatchConfidence.NotApplicable;
			return false;
		}

		return true;
	}

	private static bool TryMatchAny(List<ConditionBase> conditions, AppLockerFileInfo file, out AppLockerMatchType matchType, out AppLockerMatchConfidence confidence)
	{
		foreach (ConditionBase condition in CollectionsMarshal.AsSpan(conditions))
		{
			switch (condition)
			{
				case FilePathCondition path when AppLockerMatching.PathMatches(file.FilePath, path.Path):
					matchType = AppLockerMatchType.Path;
					confidence = AppLockerMatchConfidence.Exact;
					return true;

				case FileHashCondition hash when HashMatches(hash, file):
					matchType = AppLockerMatchType.Hash;
					confidence = AppLockerMatchConfidence.Exact;
					return true;

				case FilePublisherCondition pub when PublisherMatches(pub, file, out confidence):
					matchType = AppLockerMatchType.Publisher;
					return true;
			}
		}

		matchType = AppLockerMatchType.None;
		confidence = AppLockerMatchConfidence.NotApplicable;
		return false;
	}

	private static bool HashMatches(FileHashCondition condition, AppLockerFileInfo file)
	{
		foreach (FileHash hash in CollectionsMarshal.AsSpan(condition.Hashes))
		{
			string data = NormalizeHash(hash.Data);
			if (data.Length == 0)
			{
				continue;
			}

			if (string.Equals(data, file.SHA256Authenticode, StringComparison.OrdinalIgnoreCase) ||
				string.Equals(data, file.SHA256Flat, StringComparison.OrdinalIgnoreCase))
			{
				return true;
			}
		}

		return false;
	}

	private static string NormalizeHash(string data)
	{
		if (string.IsNullOrEmpty(data))
		{
			return string.Empty;
		}

		string trimmed = data.Trim();
		if (trimmed.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
		{
			trimmed = trimmed[2..];
		}

		return trimmed.ToUpperInvariant();
	}

	private static bool PublisherMatches(FilePublisherCondition condition, AppLockerFileInfo file, out AppLockerMatchConfidence confidence)
	{
		confidence = AppLockerMatchConfidence.NotApplicable;

		if (!file.IsSigned)
		{
			return false;
		}

		// Product / binary name gates (independent of the publisher string).
		if (!WildEquals(condition.ProductName, file.ProductNameUpper) ||
			!WildEquals(condition.BinaryName, file.BinaryNameUpper))
		{
			return false;
		}

		if (!AppLockerMatching.VersionInRange(file.FileVersion, condition.LowSection, condition.HighSection))
		{
			return false;
		}

		// Any-publisher wildcard: matches any signed file.
		if (condition.PublisherName == "*")
		{
			confidence = AppLockerMatchConfidence.Exact;
			return true;
		}

		string policyUpper = condition.PublisherName.ToUpperInvariant();
		string policyOrg = AppLockerMatching.ExtractOrganization(condition.PublisherName);

		foreach (PublisherCandidate candidate in CollectionsMarshal.AsSpan(file.Publishers))
		{
			if (string.Equals(candidate.SubjectUpper, policyUpper, StringComparison.OrdinalIgnoreCase))
			{
				confidence = AppLockerMatchConfidence.Exact;
				return true;
			}
		}

		if (policyOrg.Length > 0)
		{
			foreach (PublisherCandidate candidate in CollectionsMarshal.AsSpan(file.Publishers))
			{
				if (string.Equals(candidate.OrganizationUpper, policyOrg, StringComparison.OrdinalIgnoreCase))
				{
					confidence = AppLockerMatchConfidence.Organization;
					return true;
				}
			}
		}

		return false;
	}

	/// <summary>
	/// AppLocker "*" wildcard equality: a "*" pattern matches anything; otherwise a
	/// case-insensitive equality against the (already upper-cased) file value.
	/// </summary>
	private static bool WildEquals(string policyValue, string? fileValueUpper)
	{
		if (string.IsNullOrEmpty(policyValue) || policyValue == "*")
		{
			return true;
		}

		return string.Equals(policyValue.ToUpperInvariant(), fileValueUpper, StringComparison.OrdinalIgnoreCase);
	}
}
