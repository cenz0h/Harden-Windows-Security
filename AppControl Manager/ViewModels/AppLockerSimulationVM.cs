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
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Threading.Tasks;
using AppControlManager.AppLockerPolicy;
using AppControlManager.Main;
using Microsoft.UI.Xaml;

namespace AppControlManager.ViewModels;

/// <summary>
/// View model for the AppLocker Policy Simulation page. Lets the user pick an AppLocker policy
/// and a set of files/folders, then reports whether each file would be allowed or blocked,
/// reusing <see cref="AppLockerSimulation"/>.
/// </summary>
internal sealed partial class AppLockerSimulationVM : ViewModelBase
{
	internal readonly InfoBarSettings MainInfoBar = new();

	/// <summary>The parsed policy, set when the user selects a valid AppLocker XML file.</summary>
	private AppLockerPolicyObj? _policy;

	#region UI-bound properties

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

	internal double ProgressPercent { get; set => SP(ref field, value); }

	internal string? SelectedPolicyPath { get; set => SP(ref field, value); }

	/// <summary>Worker thread count for the scan.</summary>
	internal double ScalabilityValue { get; set => SP(ref field, value); } = 2;

	/// <summary>
	/// Identity scope: 0 = all rules (machine-wide), 1 = standard user (Everyone-scoped only),
	/// 2 = Everyone + local Administrators.
	/// </summary>
	internal int IdentityModeIndex { get; set => SP(ref field, value); }

	internal string SummaryText { get; set => SP(ref field, value); } = string.Empty;

	/// <summary>Files explicitly chosen by the user.</summary>
	internal ObservableCollection<string> FilePaths { get; } = [];

	/// <summary>Folders chosen by the user (scanned recursively).</summary>
	internal ObservableCollection<string> FolderPaths { get; } = [];

	/// <summary>Simulation results shown in the grid.</summary>
	internal ObservableCollection<AppLockerSimulationOutput> Results { get; } = [];

	#endregion

	/// <summary>
	/// Prompts for an AppLocker policy XML, validates and parses it.
	/// </summary>
	internal async void BrowsePolicyButton_Click()
	{
		string? selected = FileDialogHelper.ShowFilePickerDialog(Atlas.XMLFilePickerFilter);
		if (selected is null)
		{
			return;
		}

		try
		{
			ElementsAreEnabled = false;
			MainInfoBar.WriteInfo(Atlas.GetStr("AppLockerLoadingPolicyMsg"));

			AppLockerPolicyObj parsed = await Task.Run(() =>
			{
				AppLockerValidation.Validate(selected);
				return AppLockerDeserialization.Deserialize(selected, null);
			});

			_policy = parsed;
			SelectedPolicyPath = selected;

			int ruleCount = parsed.RuleCollections.Sum(c => c.Rules.Count);
			MainInfoBar.WriteSuccess(string.Format(Atlas.GetStr("AppLockerPolicyLoadedMsg"), ruleCount, parsed.RuleCollections.Count));
		}
		catch (Exception ex)
		{
			_policy = null;
			SelectedPolicyPath = null;
			MainInfoBar.WriteError(ex);
		}
		finally
		{
			ElementsAreEnabled = true;
		}
	}

	internal void SelectFilesButton_Click()
	{
		foreach (string item in FileDialogHelper.ShowMultipleFilePickerDialog(Atlas.AnyFilePickerFilter))
		{
			FilePaths.Add(item);
		}
	}

	internal void SelectFoldersButton_Click()
	{
		foreach (string folder in FileDialogHelper.ShowMultipleDirectoryPickerDialog())
		{
			FolderPaths.Add(folder);
		}
	}

	internal void ClearPolicy_Click()
	{
		_policy = null;
		SelectedPolicyPath = null;
	}

	internal void ClearFiles_Click() => FilePaths.Clear();

	internal void ClearFolders_Click() => FolderPaths.Clear();

	internal void ClearResults_Click()
	{
		Results.Clear();
		SummaryText = string.Empty;
	}

	/// <summary>
	/// Maps <see cref="IdentityModeIndex"/> to the SID filter passed to the engine.
	/// </summary>
	private IReadOnlyCollection<string>? BuildIdentityFilter() => IdentityModeIndex switch
	{
		1 => Array.Empty<string>(),                 // Everyone-scoped rules only
		2 => ["S-1-5-32-544"],                      // Everyone + local Administrators
		_ => null                                    // all rules regardless of scope
	};

	/// <summary>
	/// Runs the simulation over the selected files/folders.
	/// </summary>
	internal async void RunSimulationButton_Click()
	{
		if (_policy is null)
		{
			MainInfoBar.WriteWarning(Atlas.GetStr("AppLockerSelectPolicyFirstMsg"));
			return;
		}

		if (FilePaths.Count == 0 && FolderPaths.Count == 0)
		{
			MainInfoBar.WriteWarning(Atlas.GetStr("AppLockerSelectFilesFirstMsg"));
			return;
		}

		try
		{
			ElementsAreEnabled = false;
			ProgressPercent = 0;
			Results.Clear();
			SummaryText = string.Empty;
			MainInfoBar.WriteInfo(Atlas.GetStr("AppLockerRunningSimulationMsg"));

			List<string> files = [.. FilePaths];
			List<string> folders = [.. FolderPaths];
			AppLockerPolicyObj policy = _policy;
			ushort threads = (ushort)Math.Max(1, (int)ScalabilityValue);
			IReadOnlyCollection<string>? sids = BuildIdentityFilter();

			Progress<double> progress = new(p => ProgressPercent = p);

			ConcurrentDictionary<string, AppLockerSimulationOutput> results = await Task.Run(() =>
				AppLockerSimulation.Invoke(files, folders, policy, threads, progress, null, sids));

			int allowed = 0, blocked = 0, na = 0, notProcessed = 0;
			foreach (AppLockerSimulationOutput output in results.Values.OrderBy(r => r.FilePath))
			{
				Results.Add(output);
				switch (output.Source)
				{
					case AppLockerVerdictSource.Allowed:
					case AppLockerVerdictSource.AuditOnly:
						allowed++;
						break;
					case AppLockerVerdictSource.NotApplicable:
						na++;
						break;
					case AppLockerVerdictSource.NotProcessed:
						notProcessed++;
						break;
					default:
						blocked++;
						break;
				}
			}

			SummaryText = string.Format(Atlas.GetStr("AppLockerSimulationSummary"), Results.Count, allowed, blocked, na, notProcessed);
			MainInfoBar.WriteSuccess(SummaryText);
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex);
		}
		finally
		{
			ProgressPercent = 100;
			ElementsAreEnabled = true;
		}
	}

	/// <summary>
	/// Exports the current results to a JSON file.
	/// </summary>
	internal async void ExportToJsonButton_Click()
	{
		if (Results.Count == 0)
		{
			MainInfoBar.WriteWarning(Atlas.GetStr("AppLockerNoResultsToExportMsg"));
			return;
		}

		try
		{
			string fileName = $"AppLocker_Simulation_Export_{DateTime.Now:yyyy-MM-dd_HH-mm-ss}.json";
			string? savePath = FileDialogHelper.ShowSaveFileDialog(Atlas.JSONPickerFilter, fileName);
			if (savePath is null)
			{
				return;
			}

			if (!savePath.EndsWith(".json", StringComparison.OrdinalIgnoreCase))
			{
				savePath += ".json";
			}

			List<AppLockerSimulationOutput> data = [.. Results];
			await Task.Run(() =>
			{
				string json = JsonSerializer.Serialize(data, AppLockerSimulationOutputJsonContext.Default.ListAppLockerSimulationOutput);
				File.WriteAllText(savePath, json);
			});

			MainInfoBar.WriteSuccess(string.Format(Atlas.GetStr("AppLockerExportedResultsMsg"), data.Count, savePath));
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex);
		}
	}
}
