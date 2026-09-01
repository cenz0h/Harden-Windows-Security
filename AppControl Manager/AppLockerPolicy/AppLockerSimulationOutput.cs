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

using System.Text.Json.Serialization;

namespace AppControlManager.AppLockerPolicy;

/// <summary>
/// Why a file received its verdict in an AppLocker simulation.
/// </summary>
internal enum AppLockerVerdictSource
{
	/// <summary>Explicitly allowed by an Allow rule.</summary>
	Allowed,
	/// <summary>Explicitly denied by a Deny rule (Deny wins over Allow).</summary>
	DeniedByRule,
	/// <summary>Blocked because the collection is enforced and no Allow rule matched.</summary>
	DefaultDeny,
	/// <summary>The collection is AuditOnly, so the file runs but would be logged.</summary>
	AuditOnly,
	/// <summary>AppLocker does not govern this file type, or the collection is NotConfigured/absent.</summary>
	NotApplicable,
	/// <summary>The file could not be read/hashed.</summary>
	NotProcessed
}

/// <summary>
/// The kind of condition that decided the verdict.
/// </summary>
internal enum AppLockerMatchType
{
	None,
	Publisher,
	Path,
	Hash
}

/// <summary>
/// Confidence of a publisher match, given AppLocker's exact publisher canonicalization is not
/// fully reproducible from a certificate. Path/Hash matches are always <see cref="Exact"/>.
/// </summary>
internal enum AppLockerMatchConfidence
{
	NotApplicable,
	/// <summary>Full publisher subject matched.</summary>
	Exact,
	/// <summary>Matched on the Organization (O=) component only.</summary>
	Organization
}

/// <summary>
/// One result row of an AppLocker simulation.
/// </summary>
internal sealed class AppLockerSimulationOutput
{
	[JsonInclude] internal string FilePath { get; set; } = string.Empty;
	[JsonInclude] internal string FileName { get; set; } = string.Empty;

	/// <summary>The rule collection the file's type maps to (Exe/Dll/…), or empty if none.</summary>
	[JsonInclude] internal string Collection { get; set; } = string.Empty;

	/// <summary>True if the file would be permitted to run.</summary>
	[JsonInclude] internal bool IsAuthorized { get; set; }

	[JsonInclude]
	[JsonConverter(typeof(JsonStringEnumConverter<AppLockerVerdictSource>))]
	internal AppLockerVerdictSource Source { get; set; }

	[JsonInclude]
	[JsonConverter(typeof(JsonStringEnumConverter<AppLockerMatchType>))]
	internal AppLockerMatchType MatchType { get; set; }

	[JsonInclude]
	[JsonConverter(typeof(JsonStringEnumConverter<AppLockerMatchConfidence>))]
	internal AppLockerMatchConfidence MatchConfidence { get; set; }

	/// <summary>Id of the rule that decided the verdict (Allow or Deny), if any.</summary>
	[JsonInclude] internal string? MatchedRuleId { get; set; }
	[JsonInclude] internal string? MatchedRuleName { get; set; }

	/// <summary>The UserOrGroupSid of the deciding rule (informational; simulation is machine-wide).</summary>
	[JsonInclude] internal string? UserOrGroupSid { get; set; }

	/// <summary>Human-readable explanation of the verdict.</summary>
	[JsonInclude] internal string? Reason { get; set; }

	// A few file details useful for triage in the results grid.
	[JsonInclude] internal string? Publisher { get; set; }
	[JsonInclude] internal string? ProductName { get; set; }
	[JsonInclude] internal string? FileVersion { get; set; }
	[JsonInclude] internal string? SHA256 { get; set; }

	// Display-only helpers for XAML binding (excluded from JSON export).
	[JsonIgnore] internal string VerdictText => IsAuthorized ? "Allowed" : "Blocked";
	[JsonIgnore] internal string SourceText => Source.ToString();
	[JsonIgnore] internal string MatchText => MatchType == AppLockerMatchType.None
		? string.Empty
		: MatchConfidence is AppLockerMatchConfidence.NotApplicable
			? MatchType.ToString()
			: $"{MatchType} ({MatchConfidence})";
}

/// <summary>
/// JSON source-generated context for <see cref="AppLockerSimulationOutput"/> (AOT-safe export).
/// </summary>
[JsonSourceGenerationOptions(WriteIndented = true)]
[JsonSerializable(typeof(AppLockerSimulationOutput))]
[JsonSerializable(typeof(System.Collections.Generic.List<AppLockerSimulationOutput>))]
internal sealed partial class AppLockerSimulationOutputJsonContext : JsonSerializerContext
{
}
