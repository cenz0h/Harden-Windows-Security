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
using AppControlManager.SiPolicy;
using CommonCore.IntelGathering;

namespace AppControlManager.Others;

/// <summary>
/// Abstraction over "something whose publisher-rule matching can be edited".
///
/// Two things implement this so a single editor dialog serves both journeys:
/// - <see cref="FileIdentityEditTarget"/>: a scan result, edited BEFORE the policy is generated.
/// - <see cref="PolicyElementEditTarget"/>: a rule already inside a policy, edited in the Policy
///   Editor so an existing policy can be adjusted and redeployed without rescanning the app.
/// </summary>
internal interface IPublisherRuleEditTarget
{
	Version? MinVersion { get; set; }
	Version? MaxVersion { get; set; }
	string? OriginalFileName { get; set; }
	string? InternalName { get; set; }
	string? FileDescription { get; set; }
	string? ProductName { get; set; }

	/// <summary>
	/// The signing certificate this rule is tied to, for display only. The publisher comes from the
	/// signer (which is keyed on the certificate's TBS hash) and can't be typed in by hand, so it is
	/// shown as read-only context for the attributes that CAN be edited.
	/// </summary>
	string? PublisherDisplay { get; }
}

/// <summary>
/// Edits a scanned file's details before <see cref="XMLOps.SignerAndHashBuilder"/> turns it into a rule.
/// </summary>
internal sealed class FileIdentityEditTarget(FileIdentity item) : IPublisherRuleEditTarget
{
	internal FileIdentity Item => item;

	public Version? MinVersion { get => item.FileVersion; set => item.FileVersion = value; }
	public Version? MaxVersion { get => item.MaxFileVersion; set => item.MaxFileVersion = value; }
	public string? OriginalFileName { get => item.OriginalFileName; set => item.OriginalFileName = value; }
	public string? InternalName { get => item.InternalName; set => item.InternalName = value; }
	public string? FileDescription { get => item.FileDescription; set => item.FileDescription = value; }
	public string? ProductName { get => item.ProductName; set => item.ProductName = value; }

	/// <summary>The signer CNs gathered during the scan.</summary>
	public string? PublisherDisplay => string.IsNullOrWhiteSpace(item.FilePublishersToDisplay) ? null : item.FilePublishersToDisplay;
}

/// <summary>
/// Edits a rule element that already lives inside a policy: <see cref="Allow"/>, <see cref="Deny"/>,
/// <see cref="FileAttrib"/> or <see cref="FileRule"/>. Those four are independent sealed types with no
/// shared base, hence the per-type switches.
///
/// Mutating these objects is what makes the change stick: the Policy Editor's Save serializes these
/// very element instances back into the policy XML.
///
/// Note the element's <c>FileName</c> attribute is the file's Original File Name, which is why it maps
/// onto <see cref="OriginalFileName"/>.
/// </summary>
internal sealed class PolicyElementEditTarget(object element, string? publisherDisplay = null) : IPublisherRuleEditTarget
{
	internal object Element => element;

	/// <summary>
	/// Resolved by the caller from the policy's Signers (the signer that references this FileAttrib).
	/// Null for hash / file path / file name rules, which have no publisher.
	/// </summary>
	public string? PublisherDisplay => publisherDisplay;

	private static Version? Parse(string? value) => Version.TryParse(value, out Version? parsed) ? parsed : null;

	public Version? MinVersion
	{
		get => Parse(element switch
		{
			Allow a => a.MinimumFileVersion,
			Deny d => d.MinimumFileVersion,
			FileAttrib f => f.MinimumFileVersion,
			FileRule r => r.MinimumFileVersion,
			_ => null
		});
		set
		{
			string? v = value?.ToString();
			switch (element)
			{
				case Allow a: a.MinimumFileVersion = v; break;
				case Deny d: d.MinimumFileVersion = v; break;
				case FileAttrib f: f.MinimumFileVersion = v; break;
				case FileRule r: r.MinimumFileVersion = v; break;
				default: break;
			}
		}
	}

	public Version? MaxVersion
	{
		get => Parse(element switch
		{
			Allow a => a.MaximumFileVersion,
			Deny d => d.MaximumFileVersion,
			FileAttrib f => f.MaximumFileVersion,
			FileRule r => r.MaximumFileVersion,
			_ => null
		});
		set
		{
			string? v = value?.ToString();
			switch (element)
			{
				case Allow a: a.MaximumFileVersion = v; break;
				case Deny d: d.MaximumFileVersion = v; break;
				case FileAttrib f: f.MaximumFileVersion = v; break;
				case FileRule r: r.MaximumFileVersion = v; break;
				default: break;
			}
		}
	}

	public string? OriginalFileName
	{
		get => element switch
		{
			Allow a => a.FileName,
			Deny d => d.FileName,
			FileAttrib f => f.FileName,
			FileRule r => r.FileName,
			_ => null
		};
		set
		{
			switch (element)
			{
				case Allow a: a.FileName = value; break;
				case Deny d: d.FileName = value; break;
				case FileAttrib f: f.FileName = value; break;
				case FileRule r: r.FileName = value; break;
				default: break;
			}
		}
	}

	public string? InternalName
	{
		get => element switch
		{
			Allow a => a.InternalName,
			Deny d => d.InternalName,
			FileAttrib f => f.InternalName,
			FileRule r => r.InternalName,
			_ => null
		};
		set
		{
			switch (element)
			{
				case Allow a: a.InternalName = value; break;
				case Deny d: d.InternalName = value; break;
				case FileAttrib f: f.InternalName = value; break;
				case FileRule r: r.InternalName = value; break;
				default: break;
			}
		}
	}

	public string? FileDescription
	{
		get => element switch
		{
			Allow a => a.FileDescription,
			Deny d => d.FileDescription,
			FileAttrib f => f.FileDescription,
			FileRule r => r.FileDescription,
			_ => null
		};
		set
		{
			switch (element)
			{
				case Allow a: a.FileDescription = value; break;
				case Deny d: d.FileDescription = value; break;
				case FileAttrib f: f.FileDescription = value; break;
				case FileRule r: r.FileDescription = value; break;
				default: break;
			}
		}
	}

	public string? ProductName
	{
		get => element switch
		{
			Allow a => a.ProductName,
			Deny d => d.ProductName,
			FileAttrib f => f.ProductName,
			FileRule r => r.ProductName,
			_ => null
		};
		set
		{
			switch (element)
			{
				case Allow a: a.ProductName = value; break;
				case Deny d: d.ProductName = value; break;
				case FileAttrib f: f.ProductName = value; break;
				case FileRule r: r.ProductName = value; break;
				default: break;
			}
		}
	}
}
