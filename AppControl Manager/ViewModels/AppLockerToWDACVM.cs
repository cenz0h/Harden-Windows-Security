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
using System.Threading.Tasks;
using AppControlManager.AppLockerPolicy;
using AppControlManager.Main;
using AppControlManager.Others;
using AppControlManager.SiPolicy;
using AppControlManager.XMLOps;
using CommonCore.IntelGathering;
using Microsoft.UI.Xaml;

namespace AppControlManager.ViewModels;

/// <summary>
/// View model for the "AppLocker → App Control" migration page. Takes an existing AppLocker policy XML
/// and produces a clean WDAC base policy plus a supplemental policy holding the migrated rules, reusing
/// <see cref="AppLockerToWDACConverter"/> for the rule mapping and, optionally, a file re-scan
/// (<see cref="AppLockerSimulation"/> + <see cref="LocalFilesScan"/>) to upgrade publisher/hash rules
/// into faithful WDAC signer rules.
/// </summary>
internal sealed partial class AppLockerToWDACVM : ViewModelBase
{
	internal readonly InfoBarSettings MainInfoBar = new();

	/// <summary>The parsed AppLocker policy, set when the user selects a valid AppLocker XML file.</summary>
	private AppLockerPolicyObj? _policy;

	/// <summary>The generated base policy, held in memory until the user saves it.</summary>
	private PolicyFileRepresent? _baseRepresent;

	/// <summary>The generated supplemental policy, held in memory until the user saves it.</summary>
	private PolicyFileRepresent? _supplementalRepresent;

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

	/// <summary>Name for the produced supplemental policy; defaults to "&lt;file&gt; - Migrated" when blank.</summary>
	internal string SupplementalPolicyName { get; set => SP(ref field, value); } = string.Empty;

	/// <summary>0 = generate AllowMicrosoft base, 1 = generate DefaultWindows base, 2 = use an existing base policy file.</summary>
	internal int BasePolicyModeIndex { get; set => SP(ref field, value); }

	internal string? ExistingBasePolicyPath { get; set => SP(ref field, value); }

	/// <summary>When true, the generated base policy is set to Audit mode (nothing is blocked; events are logged).</summary>
	internal bool AuditMode { get; set => SP(ref field, value); } = true;

	/// <summary>When true, AppLocker publisher rules are degraded to WDAC FileName/attribute rules instead of dropped (XML-only mode).</summary>
	internal bool DegradePublisherRules { get; set => SP(ref field, value); } = true;

	/// <summary>When true, the referenced files are re-scanned to build faithful WDAC signer/hash rules.</summary>
	internal bool ScanUpgradeEnabled { get; set => SP(ref field, value); }

	/// <summary>Worker thread count for the optional file re-scan.</summary>
	internal double ScalabilityValue { get; set => SP(ref field, value); } = 2;

	/// <summary>Folders to re-scan when the scan-upgrade is enabled.</summary>
	internal ObservableCollection<string> ScanFolderPaths { get; } = [];

	/// <summary>Per-rule migration report shown in the results grid.</summary>
	internal ObservableCollection<RuleMigrationNote> ReportNotes { get; } = [];

	internal string SummaryText { get; set => SP(ref field, value); } = string.Empty;

	/// <summary>Enables the Save/Open buttons once a conversion has produced policies.</summary>
	internal bool OutputActionsEnabled { get; set => SP(ref field, value); }

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

			if (string.IsNullOrWhiteSpace(SupplementalPolicyName))
			{
				SupplementalPolicyName = $"{Path.GetFileNameWithoutExtension(selected)} - Migrated";
			}

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

	internal void SelectScanFoldersButton_Click()
	{
		foreach (string folder in FileDialogHelper.ShowMultipleDirectoryPickerDialog())
		{
			ScanFolderPaths.Add(folder);
		}
	}

	internal void ClearScanFolders_Click() => ScanFolderPaths.Clear();

	internal void BrowseExistingBaseButton_Click()
	{
		string? selected = FileDialogHelper.ShowFilePickerDialog(Atlas.XMLFilePickerFilter);
		if (selected is not null)
		{
			ExistingBasePolicyPath = selected;
		}
	}

	/// <summary>
	/// Runs the migration: XML translation, optional file re-scan upgrade, then base + supplemental assembly.
	/// </summary>
	internal async void ConvertButton_Click() => await ConvertButton_Internal();

	private async Task ConvertButton_Internal()
	{
		if (_policy is null)
		{
			MainInfoBar.WriteWarning(Atlas.GetStr("AppLockerToWDACSelectPolicyFirstMsg"));
			return;
		}

		if (BasePolicyModeIndex == 2 && string.IsNullOrWhiteSpace(ExistingBasePolicyPath))
		{
			MainInfoBar.WriteWarning(Atlas.GetStr("AppLockerToWDACSelectBaseFirstMsg"));
			return;
		}

		if (ScanUpgradeEnabled && ScanFolderPaths.Count == 0)
		{
			MainInfoBar.WriteWarning(Atlas.GetStr("AppLockerToWDACSelectScanFoldersMsg"));
			return;
		}

		try
		{
			ElementsAreEnabled = false;
			OutputActionsEnabled = false;
			ProgressPercent = 0;
			ReportNotes.Clear();
			SummaryText = string.Empty;
			MainInfoBar.WriteInfo(Atlas.GetStr("AppLockerToWDACConvertingMsg"));

			AppLockerPolicyObj policy = _policy;
			string name = string.IsNullOrWhiteSpace(SupplementalPolicyName)
				? $"{Path.GetFileNameWithoutExtension(SelectedPolicyPath)} - Migrated"
				: SupplementalPolicyName;
			int baseMode = BasePolicyModeIndex;
			string? existingBase = ExistingBasePolicyPath;
			bool audit = AuditMode;
			bool degrade = DegradePublisherRules;
			bool scan = ScanUpgradeEnabled;
			List<string> folders = [.. ScanFolderPaths];
			ushort threads = (ushort)Math.Max(1, (int)ScalabilityValue);
			Progress<double> progress = new(p => ProgressPercent = p);

			(AppLockerConversionResult Conv, SiPolicy.SiPolicy BaseObj, SiPolicy.SiPolicy Supplemental, int ScanMatched, int ScanAllowed) outcome =
				await Task.Run(() =>
				{
					// 1) Pure XML translation. When the scan-upgrade is on, publisher/hash rules are deferred to the scan.
					AppLockerConversionResult conv = AppLockerToWDACConverter.Convert(policy, degrade, deferPublisherAndHashToScan: scan);
					SiPolicy.SiPolicy supplemental = conv.Supplemental;

					int scanMatched = 0;
					int scanAllowed = 0;

					// 2) Optional file re-scan: build faithful signer/hash rules from files the AppLocker policy allows.
					if (scan && folders.Count > 0)
					{
						(IEnumerable<string> Files, int Count) collected = FileUtility.GetFilesFast(folders, null, null, null);

						if (collected.Count > 0)
						{
							List<FileIdentity> scanned = [.. LocalFilesScan.Scan(collected, threads, progress, null)];

							ConcurrentDictionary<string, AppLockerSimulationOutput> verdicts =
								AppLockerSimulation.Invoke(null, folders, policy, threads, progress, null, null);

							HashSet<string> allowed = new(StringComparer.OrdinalIgnoreCase);
							foreach (KeyValuePair<string, AppLockerSimulationOutput> verdict in verdicts)
							{
								if (verdict.Value.IsAuthorized)
								{
									_ = allowed.Add(verdict.Key);
								}
							}
							scanAllowed = allowed.Count;

							List<FileIdentity> matched = [.. scanned.Where(f => !string.IsNullOrEmpty(f.FilePath) && allowed.Contains(f.FilePath))];
							scanMatched = matched.Count;

							if (matched.Count > 0)
							{
								FileBasedInfoPackage pkg = SignerAndHashBuilder.BuildSignerAndHashObjects(data: matched, level: ScanLevels.WHQLFilePublisher);
								SiPolicy.SiPolicy faithful = Master.Initiate(pkg, SiPolicyIntel.Authorization.Allow);
								supplemental = Merger.Merge(supplemental, [faithful]);
							}
						}
					}

					// 3) Build the base policy (offline templates), ensuring it allows supplementals and honors the audit choice.
					SiPolicy.SiPolicy baseObj = baseMode switch
					{
						1 => BasePolicyCreator.BuildDefaultWindows(false, null, false, false, false, false, false, null, false, false).PolicyObj,
						2 => Management.Initialize(existingBase!, null),
						_ => BasePolicyCreator.BuildAllowMSFT(false, null, false, false, false, false, false, null, false, false).PolicyObj
					};

					baseObj = CiRuleOptions.Set(baseObj, rulesToAdd: [OptionType.EnabledAllowSupplementalPolicies], EnableAuditMode: audit);

					// 4) Link the supplemental to the base, apply supplemental rule options, set the version.
					supplemental = SetCiPolicyInfo.Set(supplemental, true, name, baseObj.BasePolicyID);

					List<OptionType>? extraOptions = conv.HasFilePathRules ? [OptionType.DisabledRuntimeFilePathRuleProtection] : null;
					supplemental = CiRuleOptions.Set(supplemental, template: CiRuleOptions.PolicyTemplate.Supplemental, rulesToAdd: extraOptions);

					supplemental = SetCiPolicyInfo.Set(supplemental, new Version("1.0.0.0"));

					return (conv, baseObj, supplemental, scanMatched, scanAllowed);
				});

			// Back on the UI thread: register both policies in the sidebar library.
			_baseRepresent = new(outcome.BaseObj);
			_supplementalRepresent = new(outcome.Supplemental);
			await ViewModelProvider.MainWindowVM.AssignToSidebar(_baseRepresent);
			await ViewModelProvider.MainWindowVM.AssignToSidebar(_supplementalRepresent);

			foreach (RuleMigrationNote note in outcome.Conv.Notes)
			{
				ReportNotes.Add(note);
			}

			string scanText = scan
				? string.Format(Atlas.GetStr("AppLockerToWDACScanSummary"), outcome.ScanMatched, outcome.ScanAllowed)
				: string.Empty;

			SummaryText = string.Format(
				Atlas.GetStr("AppLockerToWDACSummary"),
				outcome.Conv.ConvertedCount,
				outcome.Conv.DegradedCount,
				outcome.Conv.DeferredCount,
				outcome.Conv.DroppedCount,
				outcome.Conv.ExceptionsSkipped,
				outcome.Conv.NonEveryoneScopedRules) + scanText;

			OutputActionsEnabled = true;
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

	internal async void SaveBasePolicy_Click()
	{
		if (_baseRepresent is null)
		{
			return;
		}
		_ = await MainWindow.ExecuteSaveAsXML(_baseRepresent);
	}

	internal async void SaveSupplementalPolicy_Click()
	{
		if (_supplementalRepresent is null)
		{
			return;
		}
		_ = await MainWindow.ExecuteSaveAsXML(_supplementalRepresent);
	}

	internal async void OpenSupplementalPolicy_Click()
	{
		if (_supplementalRepresent is null)
		{
			return;
		}
		await PolicyFileRepresent.OpenInDefaultFileHandler(_supplementalRepresent);
	}
}
