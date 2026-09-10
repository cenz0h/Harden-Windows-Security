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
using System.ComponentModel;
using System.Runtime.CompilerServices;
using AppControlManager.CustomUIElements;
using CommonCore.IntelGathering;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace AppControlManager.Pages;

/// <summary>
/// Lets the user adjust what a publisher rule will match BEFORE the policy is generated - mirroring
/// AppLocker's publisher rule dialog.
///
/// By default a scanned file produces a rule with only a MinimumFileVersion, i.e. "this version and
/// anything newer". This dialog can pin it to an exact version, an upper bound, a closed range, or
/// any version, and (for a single row) can also adjust the file attributes the rule matches on.
///
/// Edits are written straight back onto the <see cref="FileIdentity"/> objects, which is what
/// SignerAndHashBuilder reads when the policy is finally built.
/// </summary>
internal sealed partial class FilePublisherRuleEditorDialog : ContentDialogV2, INotifyPropertyChanged
{
	/// <summary>Version matching modes offered by the dialog.</summary>
	private enum VersionMode
	{
		AndAbove = 0,
		Exactly = 1,
		AndBelow = 2,
		CustomRange = 3,
		AnyVersion = 4
	}

	private readonly List<FileIdentity> _targets;

	internal FilePublisherRuleEditorDialog(List<FileIdentity> targets)
	{
		InitializeComponent();
		_targets = targets;

		// Seed the fields from the first row so the dialog opens showing real values.
		FileIdentity? first = targets.Count > 0 ? targets[0] : null;

		if (first is not null)
		{
			MinVersionText = first.FileVersion?.ToString() ?? string.Empty;
			MaxVersionText = first.MaxFileVersion?.ToString() ?? string.Empty;

			// Reflect the row's existing constraint in the mode picker.
			VersionModeIndex = first.MaxFileVersion is null
				? (int)VersionMode.AndAbove
				: first.FileVersion is null
					? (int)VersionMode.AndBelow
					: first.FileVersion.Equals(first.MaxFileVersion)
						? (int)VersionMode.Exactly
						: (int)VersionMode.CustomRange;

			if (IsSingle)
			{
				OriginalFileNameText = first.OriginalFileName ?? string.Empty;
				InternalNameText = first.InternalName ?? string.Empty;
				FileDescriptionText = first.FileDescription ?? string.Empty;
				ProductNameText = first.ProductName ?? string.Empty;
			}
		}

		PrimaryButtonClick += OnApplyClicked;
	}

	public event PropertyChangedEventHandler? PropertyChanged;
	private void OnPropertyChanged([CallerMemberName] string? propertyName = null) =>
		PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));

	private bool IsSingle => _targets.Count == 1;

	#region Bound properties

	internal string TitleString => IsSingle ? "Edit publisher rule" : $"Edit publisher rules ({_targets.Count} files)";

	internal string ScopeDescription => IsSingle
		? "Adjust what this rule will match before it is written to the policy."
		: $"Version settings will be applied to all {_targets.Count} selected files. File attributes can only be edited when a single file is selected.";

	/// <summary>File attribute editing only makes sense for one row at a time.</summary>
	internal bool AttributesEnabled => IsSingle;

	internal int VersionModeIndex
	{
		get; set
		{
			if (field == value) return;
			field = value;
			OnPropertyChanged(nameof(VersionModeIndex));
			OnPropertyChanged(nameof(MinVersionEnabled));
			OnPropertyChanged(nameof(MaxVersionEnabled));
		}
	}

	private VersionMode SelectedMode => (VersionMode)VersionModeIndex;

	internal bool MinVersionEnabled => SelectedMode is VersionMode.AndAbove or VersionMode.Exactly or VersionMode.CustomRange;

	internal bool MaxVersionEnabled => SelectedMode is VersionMode.AndBelow or VersionMode.CustomRange;

	internal string MinVersionText { get; set => SetField(ref field, value); } = string.Empty;
	internal string MaxVersionText { get; set => SetField(ref field, value); } = string.Empty;

	internal string OriginalFileNameText { get; set => SetField(ref field, value); } = string.Empty;
	internal string InternalNameText { get; set => SetField(ref field, value); } = string.Empty;
	internal string FileDescriptionText { get; set => SetField(ref field, value); } = string.Empty;
	internal string ProductNameText { get; set => SetField(ref field, value); } = string.Empty;

	internal string ValidationMessage { get; set => SetField(ref field, value); } = string.Empty;

	internal Visibility ValidationVisibility => string.IsNullOrEmpty(ValidationMessage) ? Visibility.Collapsed : Visibility.Visible;

	private void SetField(ref string storage, string value, [CallerMemberName] string? propertyName = null)
	{
		if (string.Equals(storage, value, StringComparison.Ordinal)) return;
		storage = value;
		OnPropertyChanged(propertyName);

		if (string.Equals(propertyName, nameof(ValidationMessage), StringComparison.Ordinal))
			OnPropertyChanged(nameof(ValidationVisibility));
	}

	#endregion

	/// <summary>
	/// Validates the input and, if it's good, writes the changes onto every targeted FileIdentity.
	/// Cancels the dialog close when validation fails so the user can correct it.
	/// </summary>
	private void OnApplyClicked(ContentDialog sender, ContentDialogButtonClickEventArgs args)
	{
		Version? min = null;
		Version? max = null;

		if (MinVersionEnabled && !string.IsNullOrWhiteSpace(MinVersionText))
		{
			if (!Version.TryParse(MinVersionText.Trim(), out Version? parsedMin))
			{
				Fail(args, "Minimum version isn't a valid version (expected something like 1.2.3.4).");
				return;
			}
			min = parsedMin;
		}

		if (MaxVersionEnabled && !string.IsNullOrWhiteSpace(MaxVersionText))
		{
			if (!Version.TryParse(MaxVersionText.Trim(), out Version? parsedMax))
			{
				Fail(args, "Maximum version isn't a valid version (expected something like 1.2.3.4).");
				return;
			}
			max = parsedMax;
		}

		// Resolve the final range from the chosen mode.
		switch (SelectedMode)
		{
			case VersionMode.AndAbove:
				if (min is null) { Fail(args, "Enter a minimum version, or choose 'Any version'."); return; }
				max = null;
				break;

			case VersionMode.Exactly:
				if (min is null) { Fail(args, "Enter the exact version to match."); return; }
				max = min;
				break;

			case VersionMode.AndBelow:
				if (max is null) { Fail(args, "Enter a maximum version."); return; }
				min = null;
				break;

			case VersionMode.CustomRange:
				if (min is null || max is null) { Fail(args, "A custom range needs both a minimum and a maximum version."); return; }
				if (min > max) { Fail(args, "Minimum version can't be greater than the maximum version."); return; }
				break;

			case VersionMode.AnyVersion:
				// No version constraint at all - the rule matches on attributes/publisher only.
				min = null;
				max = null;
				break;

			default:
				break;
		}

		foreach (FileIdentity target in _targets)
		{
			target.FileVersion = min;
			target.MaxFileVersion = max;

			if (IsSingle)
			{
				target.OriginalFileName = NullIfBlank(OriginalFileNameText);
				target.InternalName = NullIfBlank(InternalNameText);
				target.FileDescription = NullIfBlank(FileDescriptionText);
				target.ProductName = NullIfBlank(ProductNameText);
			}
		}
	}

	private void Fail(ContentDialogButtonClickEventArgs args, string message)
	{
		args.Cancel = true;
		ValidationMessage = message;
		OnPropertyChanged(nameof(ValidationVisibility));
	}

	private static string? NullIfBlank(string value) => string.IsNullOrWhiteSpace(value) ? null : value.Trim();
}
