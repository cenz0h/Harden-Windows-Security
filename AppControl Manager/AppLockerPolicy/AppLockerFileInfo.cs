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
/// One signer candidate extracted from a scanned file, in the shape AppLocker publisher
/// rules compare against.
/// </summary>
internal sealed class PublisherCandidate
{
	/// <summary>Full subject of the leaf certificate, upper-cased (best-effort canonical form).</summary>
	internal string SubjectUpper { get; set; } = string.Empty;

	/// <summary>The Organization (O=) RDN of the leaf certificate, upper-cased. Primary match key.</summary>
	internal string OrganizationUpper { get; set; } = string.Empty;

	/// <summary>Leaf certificate common name, upper-cased.</summary>
	internal string CommonNameUpper { get; set; } = string.Empty;
}

/// <summary>
/// The per-file metadata the <see cref="AppLockerArbitrator"/> matches against. Built once per
/// file by <c>AppControlManager.Main.AppLockerSimulation</c> using the app's existing scanners.
/// </summary>
internal sealed class AppLockerFileInfo
{
	internal string FilePath { get; set; } = string.Empty;

	/// <summary>File name only (e.g. "app.exe").</summary>
	internal string FileName { get; set; } = string.Empty;

	/// <summary>Lower-case extension including the dot (e.g. ".exe").</summary>
	internal string Extension { get; set; } = string.Empty;

	/// <summary>The rule collection this file's extension belongs to, or null if not governed by AppLocker.</summary>
	internal RuleCollectionType? Collection { get; set; }

	/// <summary>SHA256 Authenticode hash (upper-case hex, no "0x"). Used for PE-format hash rules.</summary>
	internal string? SHA256Authenticode { get; set; }

	/// <summary>Flat SHA256 of the whole file (upper-case hex, no "0x"). Used for non-PE (script) hash rules.</summary>
	internal string? SHA256Flat { get; set; }

	/// <summary>Original file name from the version resource (AppLocker "BinaryName"), upper-cased.</summary>
	internal string? BinaryNameUpper { get; set; }

	/// <summary>Product name from the version resource, upper-cased.</summary>
	internal string? ProductNameUpper { get; set; }

	/// <summary>File version from the version resource, or null.</summary>
	internal Version? FileVersion { get; set; }

	/// <summary>Whether the file carries at least one valid signature.</summary>
	internal bool IsSigned => Publishers.Count > 0;

	/// <summary>Signer candidates (usually one).</summary>
	internal List<PublisherCandidate> Publishers { get; set; } = [];

	/// <summary>Set when the file could not be read/hashed; the simulation reports it as not-processed.</summary>
	internal string? ScanError { get; set; }
}
