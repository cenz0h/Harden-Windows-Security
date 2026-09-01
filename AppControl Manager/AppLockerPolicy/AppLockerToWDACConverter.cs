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
using AppControlManager.Others;
using AppControlManager.SiPolicy;
using AppControlManager.XMLOps;
using CommonCore.IntelGathering;

namespace AppControlManager.AppLockerPolicy;

/// <summary>
/// The fate of a single AppLocker rule when translated to WDAC/App Control.
/// </summary>
internal enum RuleMigrationOutcome
{
	/// <summary>Translated to an equivalent WDAC rule with full fidelity (path/hash rules).</summary>
	Converted,
	/// <summary>Translated to a weaker WDAC rule (publisher rule -> attribute/FileName rule; loses the signature requirement).</summary>
	Degraded,
	/// <summary>Not emitted here because the optional file re-scan will produce a faithful signer/hash rule instead.</summary>
	DeferredToScan,
	/// <summary>Could not be translated and was skipped (e.g. an all-wildcard publisher rule, or an unsupported path macro).</summary>
	Dropped
}

/// <summary>
/// One entry in the migration report, describing what happened to a source AppLocker rule.
/// </summary>
internal sealed class RuleMigrationNote(string collection, string ruleType, string action, string ruleName, RuleMigrationOutcome outcome, string detail)
{
	internal string Collection => collection;
	internal string RuleType => ruleType;
	internal string Action => action;
	internal string RuleName => ruleName;
	internal RuleMigrationOutcome Outcome => outcome;
	internal string Detail => detail;

	// Display helpers for XAML x:Bind.
	internal string OutcomeText => outcome.ToString();
}

/// <summary>
/// Aggregated result of a conversion: the built WDAC supplemental policy object (rules only; not yet
/// linked to a base or versioned) plus a per-rule report of what was converted, degraded or dropped.
/// </summary>
internal sealed class AppLockerConversionResult
{
	internal required SiPolicy.SiPolicy Supplemental { get; init; }
	internal List<RuleMigrationNote> Notes { get; } = [];

	internal int ConvertedCount { get; set; }
	internal int DegradedCount { get; set; }
	internal int DeferredCount { get; set; }
	internal int DroppedCount { get; set; }
	internal int ExceptionsSkipped { get; set; }
	internal int NonEveryoneScopedRules { get; set; }

	/// <summary>True if at least one FilePath rule was produced (base uses this to relax runtime path protection).</summary>
	internal bool HasFilePathRules { get; set; }
}

/// <summary>
/// Bridges the app's parsed AppLocker model (<see cref="AppLockerPolicyObj"/>) to the WDAC/App Control
/// object model (<see cref="SiPolicy.SiPolicy"/>) by reusing the existing XMLOps rule builders.
///
/// Fidelity notes (this is a pure XML translation; no files are read):
/// - Path rules  -> WDAC FilePath rules (clean, after macro translation).
/// - Hash rules  -> WDAC hash rules carrying the AppLocker SHA256 value only (AppLocker XML has no SHA1);
///   AppLocker vs WDAC Authenticode hash semantics should be validated, or the file re-scan used instead.
/// - Publisher rules cannot become true WDAC signer rules from XML alone (a WDAC signer needs the
///   certificate TBS hash, which AppLocker XML does not contain). They are either degraded to
///   attribute/FileName rules (weaker) or deferred to the optional file re-scan.
/// </summary>
internal static class AppLockerToWDACConverter
{
	// AppLocker "Everyone" well-known SID; rules scoped to it are machine-wide.
	private const string EveryoneSid = "S-1-1-0";

	/// <summary>
	/// Translates an AppLocker policy into a WDAC supplemental policy object (rules only).
	/// </summary>
	/// <param name="source">The parsed AppLocker policy.</param>
	/// <param name="degradePublisherToFileName">
	/// When true, publisher rules are degraded to WDAC FileName/attribute rules; when false they are dropped.
	/// Ignored when <paramref name="deferPublisherAndHashToScan"/> is true.
	/// </param>
	/// <param name="deferPublisherAndHashToScan">
	/// When true (the optional file re-scan is enabled by the caller), publisher and hash rules are NOT
	/// emitted here; the caller will produce faithful signer/hash rules from the scanned files instead.
	/// Path rules are always emitted regardless.
	/// </param>
	internal static AppLockerConversionResult Convert(AppLockerPolicyObj source, bool degradePublisherToFileName, bool deferPublisherAndHashToScan)
	{
		// Buckets fed into the existing XMLOps builders (via Master.Initiate).
		List<FilePathCreator> allowPaths = [];
		List<FilePathCreator> denyPaths = [];
		List<FileNameRuleCreator> allowFileNames = [];
		List<FileNameRuleCreator> denyFileNames = [];

		// Hash rules are emitted directly (see AddSha256HashRules) because HashCreator/NewHashLevelRules
		// require BOTH an Authenticode SHA256 and SHA1, and AppLocker XML only carries one hash.
		List<HashRuleData> allowHashes = [];
		List<HashRuleData> denyHashes = [];

		List<RuleMigrationNote> notes = [];
		int exceptionsSkipped = 0;
		int nonEveryoneScoped = 0;

		foreach (RuleCollection collection in source.RuleCollections)
		{
			string collectionName = collection.Type.ToString();

			// Every AppLocker collection (Exe/Dll/Msi/Script/Appx) governs user-mode files; WDAC kernel-mode
			// (signing scenario 131) is driver-only and has no AppLocker analogue. FilePath/FileName builders
			// place rules under the user-mode scenario for SSType.UserMode.
			const SSType ss = SSType.UserMode;

			foreach (RuleBase rule in collection.Rules)
			{
				bool isDeny = rule.Action == RuleActionType.Deny;
				string action = isDeny ? "Deny" : "Allow";

				if (rule.Exceptions.Count > 0)
				{
					exceptionsSkipped++;
				}

				if (!string.IsNullOrWhiteSpace(rule.UserOrGroupSid) &&
					!string.Equals(rule.UserOrGroupSid, EveryoneSid, StringComparison.OrdinalIgnoreCase))
				{
					nonEveryoneScoped++;
				}

				switch (rule)
				{
					case FilePathRule:
						{
							int emitted = 0;
							foreach (ConditionBase condition in rule.Conditions)
							{
								if (condition is not FilePathCondition pathCondition)
								{
									continue;
								}

								(List<string> paths, string? dropReason) = TranslatePath(pathCondition.Path);

								if (paths.Count == 0)
								{
									notes.Add(new RuleMigrationNote(collectionName, "Path", action, rule.Name,
										RuleMigrationOutcome.Dropped, dropReason ?? "Unsupported path."));
									continue;
								}

								foreach (string wdacPath in paths)
								{
									(isDeny ? denyPaths : allowPaths).Add(new FilePathCreator(wdacPath, "0.0.0.0", ss));
									emitted++;
								}
							}

							if (emitted > 0)
							{
								notes.Add(new RuleMigrationNote(collectionName, "Path", action, rule.Name,
									RuleMigrationOutcome.Converted, emitted == 1 ? "Converted to a WDAC FilePath rule." : $"Converted to {emitted} WDAC FilePath rules."));
							}

							break;
						}

					case FileHashRule:
						{
							if (deferPublisherAndHashToScan)
							{
								notes.Add(new RuleMigrationNote(collectionName, "Hash", action, rule.Name,
									RuleMigrationOutcome.DeferredToScan, "Deferred to the file re-scan for authoritative Authenticode hashes."));
								break;
							}

							int emitted = 0;
							foreach (ConditionBase condition in rule.Conditions)
							{
								if (condition is not FileHashCondition hashCondition)
								{
									continue;
								}

								foreach (FileHash fileHash in hashCondition.Hashes)
								{
									string? normalized = NormalizeHex(fileHash.Data);
									if (normalized is null)
									{
										continue;
									}

									(isDeny ? denyHashes : allowHashes).Add(new HashRuleData(normalized, fileHash.SourceFileName));
									emitted++;
								}
							}

							if (emitted > 0)
							{
								notes.Add(new RuleMigrationNote(collectionName, "Hash", action, rule.Name,
									RuleMigrationOutcome.Converted, "Carried the AppLocker SHA256 hash across. Validate against WDAC Authenticode semantics, or use the file re-scan."));
							}
							else
							{
								notes.Add(new RuleMigrationNote(collectionName, "Hash", action, rule.Name,
									RuleMigrationOutcome.Dropped, "No usable hash value found in the rule."));
							}

							break;
						}

					case FilePublisherRule:
						{
							if (deferPublisherAndHashToScan)
							{
								notes.Add(new RuleMigrationNote(collectionName, "Publisher", action, rule.Name,
									RuleMigrationOutcome.DeferredToScan, "Deferred to the file re-scan to build a faithful WDAC signer rule."));
								break;
							}

							if (!degradePublisherToFileName)
							{
								notes.Add(new RuleMigrationNote(collectionName, "Publisher", action, rule.Name,
									RuleMigrationOutcome.Dropped, "Publisher rules can't become WDAC signer rules from XML alone, and degrade-to-FileName is off."));
								break;
							}

							int emitted = 0;
							foreach (ConditionBase condition in rule.Conditions)
							{
								if (condition is not FilePublisherCondition publisherCondition)
								{
									continue;
								}

								string? originalFileName = NormalizeAttribute(publisherCondition.BinaryName);
								string? productName = NormalizeAttribute(publisherCondition.ProductName);

								// If neither attribute is usable, a FileName rule would be an all-wildcard allow -> unsafe.
								if (originalFileName is null && productName is null)
								{
									continue;
								}

								Version? minVersion = ParseVersion(publisherCondition.LowSection);

								(isDeny ? denyFileNames : allowFileNames).Add(new FileNameRuleCreator(
									fileVersion: minVersion,
									fileDescription: null,
									internalName: null,
									originalFileName: originalFileName,
									productName: productName,
									siSigningScenario: ss));
								emitted++;
							}

							notes.Add(emitted > 0
								? new RuleMigrationNote(collectionName, "Publisher", action, rule.Name,
									RuleMigrationOutcome.Degraded, "Degraded to a WDAC FileName/attribute rule (no signature check). Use the file re-scan for a faithful signer rule.")
								: new RuleMigrationNote(collectionName, "Publisher", action, rule.Name,
									RuleMigrationOutcome.Dropped, "Too broad to degrade safely (all-wildcard publisher/product/binary)."));

							break;
						}

					default:
						break;
				}
			}
		}

		// Build the allow and deny halves through the existing pipeline, then merge them.
		SiPolicy.SiPolicy allowPolicy = Master.Initiate(
			new FileBasedInfoPackage([], [], [], [], allowPaths, [], allowFileNames),
			SiPolicyIntel.Authorization.Allow);

		SiPolicy.SiPolicy denyPolicy = Master.Initiate(
			new FileBasedInfoPackage([], [], [], [], denyPaths, [], denyFileNames),
			SiPolicyIntel.Authorization.Deny,
			noAllowAllWildCards: true);

		SiPolicy.SiPolicy supplemental = Merger.Merge(allowPolicy, [denyPolicy]);

		// Hash rules are added directly (SHA256 only) since the XMLOps hash builder requires both hashes.
		AddSha256HashRules(supplemental, allowHashes, isDeny: false);
		AddSha256HashRules(supplemental, denyHashes, isDeny: true);

		AppLockerConversionResult result = new() { Supplemental = supplemental };
		result.Notes.AddRange(notes);
		result.ExceptionsSkipped = exceptionsSkipped;
		result.NonEveryoneScopedRules = nonEveryoneScoped;
		result.HasFilePathRules = allowPaths.Count > 0 || denyPaths.Count > 0;

		foreach (RuleMigrationNote note in notes)
		{
			switch (note.Outcome)
			{
				case RuleMigrationOutcome.Converted: result.ConvertedCount++; break;
				case RuleMigrationOutcome.Degraded: result.DegradedCount++; break;
				case RuleMigrationOutcome.DeferredToScan: result.DeferredCount++; break;
				case RuleMigrationOutcome.Dropped: result.DroppedCount++; break;
				default: break;
			}
		}

		return result;
	}

	/// <summary>
	/// Adds SHA256-only Authenticode hash rules directly to the policy's user-mode signing scenario.
	/// Mirrors <see cref="NewHashLevelRules"/> but emits a single SHA256 rule (AppLocker XML has no SHA1).
	/// </summary>
	private static void AddSha256HashRules(SiPolicy.SiPolicy policy, List<HashRuleData> hashes, bool isDeny)
	{
		if (hashes.Count == 0)
		{
			return;
		}

		policy.FileRules ??= [];

		SigningScenario umciScenario = NewPublisherLevelRules.EnsureScenario(policy, 12);
		umciScenario.ProductSigners.FileRulesRef ??= new FileRulesRef([]);

		foreach (HashRuleData hash in hashes)
		{
			byte[] hashBytes;
			try
			{
				hashBytes = System.Convert.FromHexString(hash.DataHex);
			}
			catch
			{
				// Skip malformed hash values rather than aborting the whole conversion.
				continue;
			}

			string ruleId = $"ID_{(isDeny ? "DENY" : "ALLOW")}_A_{Guid.CreateVersion7().ToString("N").ToUpperInvariant()}";
			string friendlyName = $"AppLocker migrated hash rule - {hash.SourceFileName}";

			if (isDeny)
			{
				policy.FileRules.Add(new Deny(id: ruleId) { FriendlyName = friendlyName, Hash = hashBytes });
			}
			else
			{
				policy.FileRules.Add(new Allow(id: ruleId) { FriendlyName = friendlyName, Hash = hashBytes });
			}

			umciScenario.ProductSigners.FileRulesRef.FileRuleRef.Add(new FileRuleRef(ruleID: ruleId));
		}
	}

	/// <summary>
	/// Translates an AppLocker file-path (with its macros) into zero or more WDAC file-path strings.
	/// Returns the produced paths plus, when empty, a human-readable reason it was dropped.
	/// </summary>
	private static (List<string> Paths, string? DropReason) TranslatePath(string appLockerPath)
	{
		if (string.IsNullOrWhiteSpace(appLockerPath))
		{
			return ([], "Empty path.");
		}

		string path = appLockerPath.Trim();

		// Macros WDAC does not support at all.
		if (path.StartsWith("%REMOVABLE%", StringComparison.OrdinalIgnoreCase))
		{
			return ([], "%REMOVABLE% has no WDAC equivalent.");
		}
		if (path.StartsWith("%HOT%", StringComparison.OrdinalIgnoreCase))
		{
			return ([], "%HOT% has no WDAC equivalent.");
		}

		// %PROGRAMFILES% covers both Program Files locations in AppLocker; WDAC has no macro for it,
		// so expand to the two concrete locations under the OS drive.
		if (path.StartsWith("%PROGRAMFILES%", StringComparison.OrdinalIgnoreCase))
		{
			string remainder = path["%PROGRAMFILES%".Length..];
			return ([
				$@"%OSDRIVE%\Program Files{remainder}",
				$@"%OSDRIVE%\Program Files (x86){remainder}"
			], null);
		}

		// %WINDIR%, %SYSTEM32% and %OSDRIVE% are all valid WDAC macros and pass through unchanged.
		return ([path], null);
	}

	/// <summary>
	/// Normalizes an AppLocker hash "Data" value (e.g. "0xABCD…") into a bare, even-length hex string,
	/// or null if it isn't usable.
	/// </summary>
	private static string? NormalizeHex(string? data)
	{
		if (string.IsNullOrWhiteSpace(data))
		{
			return null;
		}

		string cleaned = data.Trim();
		if (cleaned.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
		{
			cleaned = cleaned[2..];
		}

		cleaned = cleaned.Replace(" ", string.Empty).ToUpperInvariant();

		if (cleaned.Length == 0 || cleaned.Length % 2 != 0)
		{
			return null;
		}

		return cleaned;
	}

	/// <summary>
	/// Normalizes an AppLocker publisher attribute (BinaryName / ProductName). Returns null when the
	/// value is absent, "*", or contains a wildcard (WDAC attribute rules match exactly, no wildcards).
	/// </summary>
	private static string? NormalizeAttribute(string? value)
	{
		if (string.IsNullOrWhiteSpace(value))
		{
			return null;
		}

		string trimmed = value.Trim();
		if (trimmed == "*" || trimmed.Contains('*'))
		{
			return null;
		}

		return trimmed;
	}

	/// <summary>
	/// Parses an AppLocker version section ("0.0.0.0", "*", empty) into a <see cref="Version"/>, or null.
	/// </summary>
	private static Version? ParseVersion(string? section)
	{
		if (string.IsNullOrWhiteSpace(section) || section.Trim() == "*")
		{
			return null;
		}

		return Version.TryParse(section.Trim(), out Version? version) ? version : null;
	}

	/// <summary>Internal carrier for a single SHA256 hash rule to emit.</summary>
	private readonly struct HashRuleData(string dataHex, string sourceFileName)
	{
		internal string DataHex => dataHex;
		internal string SourceFileName => sourceFileName;
	}
}
