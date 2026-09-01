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
using System.Linq;

namespace AppControlManager.AppLockerPolicy;

/// <summary>
/// The outcome of comparing one rule (or exception) against the reference policy.
/// </summary>
internal enum AppLockerDiffStatus
{
	/// <summary>Present in both policies and identical.</summary>
	Unchanged,
	/// <summary>Present in the comparison policy but not in the reference (+).</summary>
	Added,
	/// <summary>Present in the reference policy but not in the comparison (-).</summary>
	Removed,
	/// <summary>Matched rule, but its exceptions differ (~).</summary>
	Changed
}

/// <summary>
/// A single exception-level difference within a matched rule.
/// </summary>
internal sealed class AppLockerExceptionDiff
{
	/// <summary>True = added in comparison (+); false = present only in reference (-).</summary>
	internal required bool Added { get; init; }
	internal required string Summary { get; init; }

	internal string Glyph => Added ? "+" : "-";
}

/// <summary>
/// A rule-level difference row shown in the compare results.
/// </summary>
internal sealed partial class AppLockerDiffEntry
{
	internal required AppLockerDiffStatus Status { get; init; }
	internal required string Collection { get; init; }
	internal required string Kind { get; init; }
	internal required string Action { get; init; }
	internal required string UserOrGroupSid { get; init; }
	internal required string ConditionSummary { get; init; }
	internal string RuleName { get; init; } = string.Empty;
	internal List<AppLockerExceptionDiff> ExceptionDiffs { get; init; } = [];

	internal string StatusGlyph => Status switch
	{
		AppLockerDiffStatus.Added => "+",
		AppLockerDiffStatus.Removed => "-",
		AppLockerDiffStatus.Changed => "~",
		_ => "="
	};

	internal string StatusText => Status.ToString();
}

/// <summary>
/// Semantic diff of two AppLocker policies. Rules are matched by meaning (collection + kind +
/// action + identity SID + conditions), never by GUID, so equivalent rules authored separately
/// still match. Exceptions are then diffed within matched rules.
/// </summary>
internal static class AppLockerComparison
{
	private const char Sep = '␟'; // unit separator, unlikely to appear in data

	/// <summary>A rule together with the collection it belongs to.</summary>
	private readonly record struct RuleRef(RuleCollectionType Collection, RuleBase Rule);

	internal static List<AppLockerDiffEntry> Compare(AppLockerPolicyObj reference, AppLockerPolicyObj comparison)
	{
		Dictionary<string, RuleRef> refRules = IndexRules(reference);
		Dictionary<string, RuleRef> cmpRules = IndexRules(comparison);

		List<AppLockerDiffEntry> results = [];

		// Reference rules: removed (missing in comparison) or matched (maybe changed exceptions).
		foreach ((string key, RuleRef refRule) in refRules)
		{
			if (!cmpRules.TryGetValue(key, out RuleRef cmpRule))
			{
				results.Add(BuildEntry(AppLockerDiffStatus.Removed, refRule, []));
				continue;
			}

			List<AppLockerExceptionDiff> exceptionDiffs = DiffExceptions(refRule.Rule, cmpRule.Rule);
			AppLockerDiffStatus status = exceptionDiffs.Count > 0 ? AppLockerDiffStatus.Changed : AppLockerDiffStatus.Unchanged;
			results.Add(BuildEntry(status, cmpRule, exceptionDiffs));
		}

		// Comparison rules not present in the reference: added.
		foreach ((string key, RuleRef cmpRule) in cmpRules)
		{
			if (!refRules.ContainsKey(key))
			{
				results.Add(BuildEntry(AppLockerDiffStatus.Added, cmpRule, []));
			}
		}

		// Stable, readable ordering: by collection, then status, then condition text.
		return [.. results
			.OrderBy(e => e.Collection, StringComparer.Ordinal)
			.ThenBy(e => e.Status)
			.ThenBy(e => e.ConditionSummary, StringComparer.OrdinalIgnoreCase)];
	}

	private static Dictionary<string, RuleRef> IndexRules(AppLockerPolicyObj policy)
	{
		Dictionary<string, RuleRef> map = new(StringComparer.Ordinal);
		foreach (RuleCollection collection in policy.RuleCollections)
		{
			foreach (RuleBase rule in collection.Rules)
			{
				// First occurrence wins; duplicates collapse (they are semantically identical).
				_ = map.TryAdd(RuleKey(collection, rule), new RuleRef(collection.Type, rule));
			}
		}
		return map;
	}

	private static string RuleKey(RuleCollection collection, RuleBase rule)
	{
		string kind = KindOf(rule);
		string conditions = string.Join("|", rule.Conditions.Select(ConditionKey).OrderBy(s => s, StringComparer.Ordinal));
		return string.Join(Sep, collection.Type, kind, rule.Action, rule.UserOrGroupSid.ToUpperInvariant(), conditions);
	}

	private static string ConditionKey(ConditionBase condition) => condition switch
	{
		FilePathCondition p => "P:" + p.Path.ToUpperInvariant(),
		FilePublisherCondition u => "U:" + string.Join("~",
			u.PublisherName.ToUpperInvariant(), u.ProductName.ToUpperInvariant(), u.BinaryName.ToUpperInvariant(),
			u.LowSection.ToUpperInvariant(), u.HighSection.ToUpperInvariant()),
		FileHashCondition h => "H:" + string.Join(",", h.Hashes.Select(x => NormalizeHash(x.Data)).OrderBy(s => s, StringComparer.Ordinal)),
		_ => "?"
	};

	private static List<AppLockerExceptionDiff> DiffExceptions(RuleBase refRule, RuleBase cmpRule)
	{
		Dictionary<string, ConditionBase> refExc = ExceptionMap(refRule);
		Dictionary<string, ConditionBase> cmpExc = ExceptionMap(cmpRule);

		List<AppLockerExceptionDiff> diffs = [];

		foreach ((string key, ConditionBase c) in refExc)
		{
			if (!cmpExc.ContainsKey(key))
			{
				diffs.Add(new AppLockerExceptionDiff { Added = false, Summary = Describe(c) });
			}
		}
		foreach ((string key, ConditionBase c) in cmpExc)
		{
			if (!refExc.ContainsKey(key))
			{
				diffs.Add(new AppLockerExceptionDiff { Added = true, Summary = Describe(c) });
			}
		}

		return diffs;
	}

	private static Dictionary<string, ConditionBase> ExceptionMap(RuleBase rule)
	{
		Dictionary<string, ConditionBase> map = new(StringComparer.Ordinal);
		foreach (ConditionBase c in rule.Exceptions)
		{
			_ = map.TryAdd(ConditionKey(c), c);
		}
		return map;
	}

	private static AppLockerDiffEntry BuildEntry(AppLockerDiffStatus status, RuleRef rule, List<AppLockerExceptionDiff> exceptionDiffs)
	{
		return new AppLockerDiffEntry
		{
			Status = status,
			Collection = rule.Collection.ToString(),
			Kind = KindOf(rule.Rule),
			Action = rule.Rule.Action.ToString(),
			UserOrGroupSid = rule.Rule.UserOrGroupSid,
			ConditionSummary = ConditionsSummary(rule.Rule),
			RuleName = rule.Rule.Name,
			ExceptionDiffs = exceptionDiffs
		};
	}

	private static string KindOf(RuleBase rule) => rule switch
	{
		FilePublisherRule => "Publisher",
		FilePathRule => "Path",
		FileHashRule => "Hash",
		_ => "Unknown"
	};

	private static string ConditionsSummary(RuleBase rule)
	{
		return string.Join("; ", rule.Conditions.Select(Describe));
	}

	private static string Describe(ConditionBase condition) => condition switch
	{
		FilePathCondition p => p.Path,
		FilePublisherCondition u => $"{u.PublisherName} | {u.ProductName} | {u.BinaryName} [{u.LowSection}-{u.HighSection}]",
		FileHashCondition h => $"{h.Hashes.Count} file hash(es)",
		_ => "unknown"
	};

	private static string NormalizeHash(string data)
	{
		string t = data.Trim();
		if (t.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
		{
			t = t[2..];
		}
		return t.ToUpperInvariant();
	}
}
