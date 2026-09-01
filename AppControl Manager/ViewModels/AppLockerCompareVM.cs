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
using System.Collections.ObjectModel;
using System.Linq;
using System.Threading.Tasks;
using AppControlManager.AppLockerPolicy;
using Microsoft.UI.Xaml;

namespace AppControlManager.ViewModels;

/// <summary>
/// View model for the AppLocker Compare page: diffs a comparison policy against a reference policy
/// and shows +/-/~ per rule (and per exception within matched rules).
/// </summary>
internal sealed partial class AppLockerCompareVM : ViewModelBase
{
	internal readonly InfoBarSettings MainInfoBar = new();

	private AppLockerPolicyObj? _reference;
	private AppLockerPolicyObj? _comparison;
	private readonly List<AppLockerDiffEntry> _all = [];

	internal bool ElementsAreEnabled
	{
		get; set
		{
			if (SP(ref field, value))
			{
				ProgressRingVisibility = field ? Visibility.Collapsed : Visibility.Visible;
				MainInfoBar.IsClosable = field;
			}
		}
	} = true;

	internal Visibility ProgressRingVisibility { get; set => SP(ref field, value); } = Visibility.Collapsed;

	internal string? ReferencePath { get; set => SP(ref field, value); }
	internal string? ComparisonPath { get; set => SP(ref field, value); }

	internal ObservableCollection<AppLockerDiffEntry> Results { get; } = [];

	internal bool HideUnchanged { get; set { if (SP(ref field, value)) ApplyFilter(); } } = true;

	internal string SummaryText { get; set => SP(ref field, value); } = string.Empty;

	internal async void BrowseReference()
	{
		string? path = FileDialogHelper.ShowFilePickerDialog(Atlas.XMLFilePickerFilter);
		if (path is null) return;
		_reference = await LoadAsync(path);
		ReferencePath = _reference is null ? null : path;
	}

	internal async void BrowseComparison()
	{
		string? path = FileDialogHelper.ShowFilePickerDialog(Atlas.XMLFilePickerFilter);
		if (path is null) return;
		_comparison = await LoadAsync(path);
		ComparisonPath = _comparison is null ? null : path;
	}

	private async Task<AppLockerPolicyObj?> LoadAsync(string path)
	{
		try
		{
			ElementsAreEnabled = false;
			return await Task.Run(() =>
			{
				AppLockerValidation.Validate(path);
				return AppLockerDeserialization.Deserialize(path, null);
			});
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex);
			return null;
		}
		finally
		{
			ElementsAreEnabled = true;
		}
	}

	internal async void CompareButton_Click()
	{
		if (_reference is null || _comparison is null)
		{
			MainInfoBar.WriteWarning(Atlas.GetStr("AppLockerSelectBothPoliciesMsg"));
			return;
		}

		try
		{
			ElementsAreEnabled = false;
			MainInfoBar.WriteInfo(Atlas.GetStr("AppLockerComparingMsg"));

			AppLockerPolicyObj reference = _reference;
			AppLockerPolicyObj comparison = _comparison;

			List<AppLockerDiffEntry> diff = await Task.Run(() => AppLockerComparison.Compare(reference, comparison));

			_all.Clear();
			_all.AddRange(diff);
			ApplyFilter();

			int added = diff.Count(e => e.Status == AppLockerDiffStatus.Added);
			int removed = diff.Count(e => e.Status == AppLockerDiffStatus.Removed);
			int changed = diff.Count(e => e.Status == AppLockerDiffStatus.Changed);
			int unchanged = diff.Count(e => e.Status == AppLockerDiffStatus.Unchanged);

			SummaryText = string.Format(Atlas.GetStr("AppLockerCompareSummary"), added, removed, changed, unchanged);
			MainInfoBar.WriteSuccess(SummaryText);
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex);
		}
		finally
		{
			ElementsAreEnabled = true;
		}
	}

	private void ApplyFilter()
	{
		Results.Clear();
		foreach (AppLockerDiffEntry entry in _all)
		{
			if (HideUnchanged && entry.Status == AppLockerDiffStatus.Unchanged)
			{
				continue;
			}
			Results.Add(entry);
		}
	}

	internal void ClearResults()
	{
		_all.Clear();
		Results.Clear();
		SummaryText = string.Empty;
	}
}
