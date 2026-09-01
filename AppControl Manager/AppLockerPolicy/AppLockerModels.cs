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

namespace AppControlManager.AppLockerPolicy;

/// <summary>
/// The AppLocker rule-collection kinds. These correspond 1:1 with the
/// <c>Type</c> attribute of an AppLocker <c>&lt;RuleCollection&gt;</c> element.
/// </summary>
internal enum RuleCollectionType
{
	Appx,
	Dll,
	Exe,
	Msi,
	Script
}

/// <summary>
/// The enforcement mode of a rule collection (the <c>EnforcementMode</c> attribute).
/// </summary>
internal enum EnforcementModeType
{
	NotConfigured,
	Enabled,
	AuditOnly
}

/// <summary>
/// The action of a rule (the <c>Action</c> attribute). Deny always wins over Allow.
/// </summary>
internal enum RuleActionType
{
	Allow,
	Deny
}

/// <summary>
/// Root object of a parsed AppLocker policy XML (<c>&lt;AppLockerPolicy&gt;</c>).
/// Unlike WDAC/SiPolicy, AppLocker XML has no XML namespace.
/// </summary>
internal sealed class AppLockerPolicyObj
{
	/// <summary>
	/// The <c>Version</c> attribute of the root element (e.g. "1").
	/// </summary>
	internal string Version { get; set; } = "1";

	/// <summary>
	/// The rule collections, preserved in document order.
	/// </summary>
	internal List<RuleCollection> RuleCollections { get; set; } = [];
}

/// <summary>
/// An AppLocker <c>&lt;RuleCollection&gt;</c>. Holds an ordered list of rules of any kind
/// so the original document order is preserved on round-trip.
/// </summary>
internal sealed class RuleCollection
{
	internal RuleCollectionType Type { get; set; }
	internal EnforcementModeType EnforcementMode { get; set; } = EnforcementModeType.NotConfigured;

	/// <summary>
	/// The rules in this collection, in document order (mix of publisher/path/hash rules).
	/// </summary>
	internal List<RuleBase> Rules { get; set; } = [];
}

/// <summary>
/// Base type shared by every AppLocker rule. The attributes here are common to
/// <c>FilePublisherRule</c>, <c>FilePathRule</c> and <c>FileHashRule</c>.
/// </summary>
internal abstract class RuleBase
{
	internal string Id { get; set; } = string.Empty;
	internal string Name { get; set; } = string.Empty;
	internal string Description { get; set; } = string.Empty;
	internal string UserOrGroupSid { get; set; } = string.Empty;
	internal RuleActionType Action { get; set; } = RuleActionType.Allow;

	/// <summary>
	/// The rule's primary conditions (inside <c>&lt;Conditions&gt;</c>).
	/// </summary>
	internal List<ConditionBase> Conditions { get; set; } = [];

	/// <summary>
	/// Optional exceptions (inside <c>&lt;Exceptions&gt;</c>). AppLocker permits any
	/// condition kind to appear as an exception, regardless of the rule kind.
	/// </summary>
	internal List<ConditionBase> Exceptions { get; set; } = [];

	/// <summary>
	/// Any attributes present on the rule element that we do not model explicitly,
	/// captured so a load/save round-trip does not silently drop them.
	/// </summary>
	internal Dictionary<string, string> ExtraAttributes { get; set; } = [];
}

internal sealed class FilePublisherRule : RuleBase { }

internal sealed class FilePathRule : RuleBase { }

internal sealed class FileHashRule : RuleBase { }

/// <summary>
/// Base type for anything that can appear inside <c>&lt;Conditions&gt;</c> or <c>&lt;Exceptions&gt;</c>.
/// </summary>
internal abstract class ConditionBase { }

/// <summary>
/// <c>&lt;FilePublisherCondition&gt;</c>. AppLocker matches signed files by the certificate's
/// full subject name string, the product name, the binary (original file) name and a version range.
/// </summary>
internal sealed class FilePublisherCondition : ConditionBase
{
	/// <summary>
	/// The signing certificate's subject in AppLocker canonical form, e.g.
	/// "O=ADOBE INC., L=SAN JOSE, S=CA, C=US". "*" means any publisher.
	/// </summary>
	internal string PublisherName { get; set; } = "*";
	internal string ProductName { get; set; } = "*";
	internal string BinaryName { get; set; } = "*";

	/// <summary>
	/// Inclusive low bound of the version range, e.g. "0.0.0.0" or "*".
	/// </summary>
	internal string LowSection { get; set; } = "*";

	/// <summary>
	/// Inclusive high bound of the version range, e.g. "*".
	/// </summary>
	internal string HighSection { get; set; } = "*";
}

/// <summary>
/// <c>&lt;FilePathCondition&gt;</c>. Matches by path, supporting AppLocker macros
/// (%WINDIR%, %PROGRAMFILES%, %SYSTEM32%, %OSDRIVE%, %REMOVABLE%, %HOT%) and "*" wildcards.
/// </summary>
internal sealed class FilePathCondition : ConditionBase
{
	internal string Path { get; set; } = string.Empty;
}

/// <summary>
/// <c>&lt;FileHashCondition&gt;</c>. Wraps one or more <c>&lt;FileHash&gt;</c> entries.
/// </summary>
internal sealed class FileHashCondition : ConditionBase
{
	internal List<FileHash> Hashes { get; set; } = [];
}

/// <summary>
/// A single <c>&lt;FileHash&gt;</c> entry inside a <see cref="FileHashCondition"/>.
/// </summary>
internal sealed class FileHash
{
	/// <summary>
	/// The hash algorithm, e.g. "SHA256" or "SHA256Authenticode".
	/// </summary>
	internal string Type { get; set; } = "SHA256";
	internal string SourceFileName { get; set; } = string.Empty;

	/// <summary>
	/// The source file length in bytes; kept as a string to preserve the exact original text.
	/// </summary>
	internal string SourceFileLength { get; set; } = string.Empty;

	/// <summary>
	/// The hash value as an upper-case hex string (the <c>Data</c> attribute, e.g. "0x....").
	/// </summary>
	internal string Data { get; set; } = string.Empty;
}
