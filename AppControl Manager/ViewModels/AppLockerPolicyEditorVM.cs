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
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using AppControlManager.AppLockerPolicy;
using AppControlManager.Main;
using Microsoft.UI.Xaml;

namespace AppControlManager.ViewModels;

/// <summary>
/// View model for the AppLocker Policy Editor: opens an AppLocker policy XML, shows its rules in a
/// filterable grid, allows add/edit/delete, and saves back to valid AppLocker XML.
/// </summary>
internal sealed partial class AppLockerPolicyEditorVM : ViewModelBase
{
	internal readonly InfoBarSettings MainInfoBar = new();

	private AppLockerPolicyObj? _policy;
	private readonly List<AppLockerRuleRow> _allRows = [];

	// Index → collection type used by the filter and the "add" combo (index 0 of the filter = All).
	private static readonly RuleCollectionType[] CollectionByIndex =
		[RuleCollectionType.Appx, RuleCollectionType.Dll, RuleCollectionType.Exe, RuleCollectionType.Msi, RuleCollectionType.Script];

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

	internal string? SelectedPolicyPath { get; set => SP(ref field, value); }

	internal ObservableCollection<AppLockerRuleRow> Rules { get; } = [];

	internal AppLockerRuleRow? SelectedRow
	{
		get; set
		{
			if (SP(ref field, value))
			{
				OnPropertyChanged(nameof(DetailPaneVisibility));
			}
		}
	}

	/// <summary>Visible only when a rule is selected, so the detail editor is hidden otherwise.</summary>
	internal Visibility DetailPaneVisibility => SelectedRow is null ? Visibility.Collapsed : Visibility.Visible;

	internal int CollectionFilterIndex { get; set { if (SP(ref field, value)) ApplyFilters(); } }

	internal int KindFilterIndex { get; set { if (SP(ref field, value)) ApplyFilters(); } }

	internal string SearchText { get; set { if (SP(ref field, value)) ApplyFilters(); } } = string.Empty;

	internal string StatusText { get; set => SP(ref field, value); } = string.Empty;

	// "Add rule" selectors.
	internal int AddCollectionIndex { get; set => SP(ref field, value); }

	internal int AddKindIndex { get; set => SP(ref field, value); }

	// Quick-rule templates. 'Templates' is the full master set (used when adding); 'VisibleTemplates'
	// is what the flyout shows, filtered by category. Both reference the same choice objects so
	// selections persist across category switches.
	internal List<AppLockerTemplateChoice> Templates { get; } = [];

	internal ObservableCollection<AppLockerTemplateChoice> VisibleTemplates { get; } = [];

	/// <summary>0 = Allow (Everyone), 1 = Allow (Administrators only), 2 = Deny (Everyone).</summary>
	internal int TemplateActionIndex { get; set => SP(ref field, value); }

	/// <summary>0 = All, 1 = Script hosts, 2 = Torrent clients, 3 = Remote-access.</summary>
	internal int TemplateCategoryFilterIndex { get; set { if (SP(ref field, value)) RebuildVisibleTemplates(); } }

	/// <summary>Common built-in SIDs shown in the SID legend flyout.</summary>
	internal IReadOnlyList<SidInfo> CommonSids => WellKnownSids.CommonGroups;

	// "Add rule from an app" options.
	/// <summary>0 = Auto (publisher if signed, else hash, else path), 1 = Publisher, 2 = Path, 3 = Hash.</summary>
	internal int FileRefRuleTypeIndex { get; set => SP(ref field, value); }

	/// <summary>0 = Allow (Everyone), 1 = Allow (Administrators only), 2 = Deny (Everyone).</summary>
	internal int FileRefActionIndex { get; set => SP(ref field, value); }

	#endregion

	/// <summary>Sets the selected rule's UserOrGroupSid (used by the SID legend's Apply buttons).</summary>
	internal void ApplySidToSelected(string sid)
	{
		if (SelectedRow is not null)
		{
			SelectedRow.UserOrGroupSid = sid;
		}
		else
		{
			MainInfoBar.WriteWarning(Atlas.GetStr("AppLockerSelectRuleForSidMsg"));
		}
	}

	internal AppLockerPolicyEditorVM()
	{
		foreach (AppLockerTemplate template in AppLockerTemplates.All)
		{
			Templates.Add(new AppLockerTemplateChoice(template));
		}
		RebuildVisibleTemplates();
	}

	private void RebuildVisibleTemplates()
	{
		string? wanted = TemplateCategoryFilterIndex switch
		{
			1 => AppLockerTemplates.ScriptHostsCategory,
			2 => AppLockerTemplates.TorrentCategory,
			3 => AppLockerTemplates.RemoteAccessCategory,
			_ => null
		};

		VisibleTemplates.Clear();
		foreach (AppLockerTemplateChoice choice in Templates)
		{
			if (wanted is null || string.Equals(choice.Category, wanted, StringComparison.Ordinal))
			{
				VisibleTemplates.Add(choice);
			}
		}
	}

	/// <summary>Opens an AppLocker policy file, validates and loads it.</summary>
	internal async void BrowseAndLoad()
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
			RebuildRows();

			MainInfoBar.WriteSuccess(string.Format(Atlas.GetStr("AppLockerPolicyLoadedMsg"), _allRows.Count, parsed.RuleCollections.Count));
		}
		catch (Exception ex)
		{
			_policy = null;
			SelectedPolicyPath = null;
			_allRows.Clear();
			Rules.Clear();
			MainInfoBar.WriteError(ex);
		}
		finally
		{
			ElementsAreEnabled = true;
		}
	}

	private void RebuildRows()
	{
		_allRows.Clear();
		if (_policy is not null)
		{
			foreach (RuleCollection collection in _policy.RuleCollections)
			{
				foreach (RuleBase rule in collection.Rules)
				{
					_allRows.Add(new AppLockerRuleRow(collection, rule));
				}
			}
		}
		ApplyFilters();
	}

	private void ApplyFilters()
	{
		IEnumerable<AppLockerRuleRow> query = _allRows;

		if (CollectionFilterIndex > 0 && CollectionFilterIndex <= CollectionByIndex.Length)
		{
			RuleCollectionType wanted = CollectionByIndex[CollectionFilterIndex - 1];
			query = query.Where(r => r.Collection.Type == wanted);
		}

		query = KindFilterIndex switch
		{
			1 => query.Where(r => r.IsPublisherRule),
			2 => query.Where(r => r.IsPathRule),
			3 => query.Where(r => r.IsHashRule),
			_ => query
		};

		if (!string.IsNullOrWhiteSpace(SearchText))
		{
			string term = SearchText.Trim();
			query = query.Where(r =>
				r.Name.Contains(term, StringComparison.OrdinalIgnoreCase) ||
				r.ConditionSummary.Contains(term, StringComparison.OrdinalIgnoreCase) ||
				r.Id.Contains(term, StringComparison.OrdinalIgnoreCase));
		}

		Rules.Clear();
		foreach (AppLockerRuleRow row in query)
		{
			Rules.Add(row);
		}

		StatusText = string.Format(Atlas.GetStr("AppLockerEditorStatus"), Rules.Count, _allRows.Count);
	}

	/// <summary>Deletes the selected rule from the policy.</summary>
	internal void DeleteSelectedRule()
	{
		if (SelectedRow is null || _policy is null)
		{
			return;
		}

		AppLockerRuleRow row = SelectedRow;
		_ = row.Collection.Rules.Remove(row.Rule);
		_ = _allRows.Remove(row);
		_ = Rules.Remove(row);
		SelectedRow = null;
		ApplyFilters();
	}

	/// <summary>Adds a new rule of the chosen kind to the chosen collection.</summary>
	internal void AddRule()
	{
		if (_policy is null)
		{
			MainInfoBar.WriteWarning(Atlas.GetStr("AppLockerLoadPolicyBeforeAddMsg"));
			return;
		}

		RuleCollectionType collectionType = CollectionByIndex[Math.Clamp(AddCollectionIndex, 0, CollectionByIndex.Length - 1)];

		RuleCollection? collection = _policy.RuleCollections.FirstOrDefault(c => c.Type == collectionType);
		if (collection is null)
		{
			collection = new RuleCollection { Type = collectionType, EnforcementMode = EnforcementModeType.Enabled };
			_policy.RuleCollections.Add(collection);
		}

		RuleBase rule = AddKindIndex switch
		{
			0 => new FilePublisherRule { Conditions = { new FilePublisherCondition() } },
			1 => new FilePathRule { Conditions = { new FilePathCondition { Path = "*" } } },
			_ => new FileHashRule { Conditions = { new FileHashCondition() } }
		};

		rule.Id = Guid.NewGuid().ToString();
		rule.Name = Atlas.GetStr("AppLockerNewRuleName");
		rule.UserOrGroupSid = "S-1-1-0";
		rule.Action = RuleActionType.Allow;

		collection.Rules.Add(rule);

		AppLockerRuleRow newRow = new(collection, rule);
		_allRows.Add(newRow);
		ApplyFilters();
		SelectedRow = Rules.Contains(newRow) ? newRow : null;
	}

	/// <summary>
	/// Adds rules generated from the selected templates using the chosen action/identity scope.
	/// </summary>
	internal void AddSelectedTemplates()
	{
		if (_policy is null)
		{
			MainInfoBar.WriteWarning(Atlas.GetStr("AppLockerLoadPolicyBeforeAddMsg"));
			return;
		}

		(RuleActionType action, string sid, string scopeLabel) = TemplateActionIndex switch
		{
			1 => (RuleActionType.Allow, "S-1-5-32-544", "Administrators"),
			2 => (RuleActionType.Deny, "S-1-1-0", "Everyone"),
			_ => (RuleActionType.Allow, "S-1-1-0", "Everyone")
		};

		int added = 0;
		AppLockerRuleRow? lastRow = null;

		foreach (AppLockerTemplateChoice choice in Templates)
		{
			if (!choice.IsSelected)
			{
				continue;
			}

			AppLockerTemplate template = choice.Template;

			RuleCollection? collection = _policy.RuleCollections.FirstOrDefault(c => c.Type == template.Collection);
			if (collection is null)
			{
				collection = new RuleCollection { Type = template.Collection, EnforcementMode = EnforcementModeType.Enabled };
				_policy.RuleCollections.Add(collection);
			}

			// One rule per path - AppLocker allows only a single condition per rule.
			foreach (FilePathRule rule in AppLockerTemplates.CreateRules(template, action, sid, scopeLabel))
			{
				collection.Rules.Add(rule);
				lastRow = new AppLockerRuleRow(collection, rule);
				_allRows.Add(lastRow);
				added++;
			}

			choice.IsSelected = false;
		}

		if (added == 0)
		{
			MainInfoBar.WriteWarning(Atlas.GetStr("AppLockerNoTemplatesSelectedMsg"));
			return;
		}

		ApplyFilters();
		if (lastRow is not null && Rules.Contains(lastRow))
		{
			SelectedRow = lastRow;
		}

		MainInfoBar.WriteSuccess(string.Format(Atlas.GetStr("AppLockerTemplatesAddedMsg"), added, $"{action} / {scopeLabel}"));
	}

	/// <summary>
	/// Prompts for one or more applications and creates a rule from each, reading the app's
	/// publisher/product/binary/version/hash the same way the simulation does.
	/// </summary>
	internal async void AddRuleFromFile()
	{
		if (_policy is null)
		{
			MainInfoBar.WriteWarning(Atlas.GetStr("AppLockerLoadPolicyBeforeAddMsg"));
			return;
		}

		List<string> files = FileDialogHelper.ShowMultipleFilePickerDialog(Atlas.AnyFilePickerFilter);
		if (files.Count == 0)
		{
			return;
		}

		(RuleActionType action, string sid, string scopeLabel) = FileRefActionIndex switch
		{
			1 => (RuleActionType.Allow, "S-1-5-32-544", "Administrators"),
			2 => (RuleActionType.Deny, "S-1-1-0", "Everyone"),
			_ => (RuleActionType.Allow, "S-1-1-0", "Everyone")
		};

		try
		{
			ElementsAreEnabled = false;
			MainInfoBar.WriteInfo(Atlas.GetStr("AppLockerReadingAppInfoMsg"));

			int typeIndex = FileRefRuleTypeIndex;

			List<(AppLockerFileInfo Info, long Length)> scanned = await Task.Run(() =>
				files.Select(f => (AppLockerSimulation.ScanFile(f), SafeLength(f))).ToList());

			int added = 0, skipped = 0;
			AppLockerRuleRow? lastRow = null;

			foreach ((AppLockerFileInfo info, long length) in scanned)
			{
				if (info.Collection is null)
				{
					skipped++;
					continue;
				}

				RuleBase? rule = BuildRuleFromFile(info, length, typeIndex, action, sid, scopeLabel);
				if (rule is null)
				{
					skipped++;
					continue;
				}

				RuleCollectionType collType = info.Collection.Value;
				RuleCollection? collection = _policy.RuleCollections.FirstOrDefault(c => c.Type == collType);
				if (collection is null)
				{
					collection = new RuleCollection { Type = collType, EnforcementMode = EnforcementModeType.Enabled };
					_policy.RuleCollections.Add(collection);
				}

				collection.Rules.Add(rule);
				lastRow = new AppLockerRuleRow(collection, rule);
				_allRows.Add(lastRow);
				added++;
			}

			ApplyFilters();
			if (lastRow is not null && Rules.Contains(lastRow))
			{
				SelectedRow = lastRow;
			}

			MainInfoBar.WriteSuccess(string.Format(Atlas.GetStr("AppLockerRulesFromAppsMsg"), added, skipped));
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

	private static long SafeLength(string path)
	{
		try { return new FileInfo(path).Length; } catch { return 0; }
	}

	/// <summary>
	/// Builds a rule from scanned app info. Type index: 0 Auto, 1 Publisher, 2 Path, 3 Hash.
	/// Auto (and unsatisfiable explicit choices) fall back: Publisher→Hash→Path.
	/// </summary>
	private static RuleBase? BuildRuleFromFile(AppLockerFileInfo info, long length, int typeIndex, RuleActionType action, string sid, string scopeLabel)
	{
		bool hasHash = !string.IsNullOrEmpty(info.SHA256Authenticode) || !string.IsNullOrEmpty(info.SHA256Flat);

		// Resolve the effective rule type with sensible fallbacks.
		int effective = typeIndex;
		if (effective == 0)
		{
			effective = info.IsSigned ? 1 : (hasHash ? 3 : 2);
		}
		if (effective == 1 && !info.IsSigned)
		{
			effective = hasHash ? 3 : 2;
		}
		if (effective == 3 && !hasHash)
		{
			effective = 2;
		}

		RuleBase rule;
		string kindLabel;

		switch (effective)
		{
			case 1: // Publisher
				rule = new FilePublisherRule
				{
					Conditions =
					{
						new FilePublisherCondition
						{
							PublisherName = info.Publishers.Count > 0 ? info.Publishers[0].SubjectUpper : "*",
							ProductName = string.IsNullOrEmpty(info.ProductNameUpper) ? "*" : info.ProductNameUpper!,
							BinaryName = string.IsNullOrEmpty(info.BinaryNameUpper) ? "*" : info.BinaryNameUpper!,
							LowSection = info.FileVersion?.ToString() ?? "*",
							HighSection = "*"
						}
					}
				};
				kindLabel = "Publisher";
				break;

			case 3: // Hash
				string? data = info.SHA256Authenticode ?? info.SHA256Flat;
				rule = new FileHashRule
				{
					Conditions =
					{
						new FileHashCondition
						{
							Hashes =
							{
								new FileHash
								{
									Type = "SHA256",
									Data = "0x" + data,
									SourceFileName = info.FileName,
									SourceFileLength = length.ToString()
								}
							}
						}
					}
				};
				kindLabel = "Hash";
				break;

			default: // Path
				rule = new FilePathRule
				{
					Conditions = { new FilePathCondition { Path = info.FilePath } }
				};
				kindLabel = "Path";
				break;
		}

		rule.Id = Guid.NewGuid().ToString();
		rule.Name = $"{info.FileName} - {kindLabel} [{action} - {scopeLabel}]";
		rule.UserOrGroupSid = sid;
		rule.Action = action;
		return rule;
	}

	/// <summary>Adds a new path exception to the selected rule.</summary>
	internal void AddPathException() => SelectedRow?.AddException(new FilePathCondition { Path = "*" });

	/// <summary>Adds a new publisher exception to the selected rule.</summary>
	internal void AddPublisherException() => SelectedRow?.AddException(new FilePublisherCondition());

	/// <summary>Removes the given exception row from the selected rule.</summary>
	internal void RemoveException(AppLockerConditionRow row) => SelectedRow?.RemoveExceptionRow(row);

	internal async void Save() => await SaveInternal(SelectedPolicyPath);

	internal async void SaveAs()
	{
		string? path = FileDialogHelper.ShowSaveFileDialog(Atlas.XMLFilePickerFilter, "AppLockerPolicy.xml");
		if (path is not null)
		{
			await SaveInternal(path);
		}
	}

	private async Task SaveInternal(string? path)
	{
		if (_policy is null || string.IsNullOrEmpty(path))
		{
			MainInfoBar.WriteWarning(Atlas.GetStr("AppLockerNothingToSaveMsg"));
			return;
		}

		try
		{
			ElementsAreEnabled = false;
			AppLockerPolicyObj policy = _policy;
			string target = path;

			string? validationError = null;
			await Task.Run(() =>
			{
				AppLockerSerialization.Serialize(policy, target);
				// Validate what we just wrote so we never hand back a policy AppLocker would reject.
				try { AppLockerValidation.Validate(target); }
				catch (Exception vex) { validationError = vex.Message; }
			});

			SelectedPolicyPath = target;

			if (validationError is null)
			{
				MainInfoBar.WriteSuccess(string.Format(Atlas.GetStr("AppLockerSavedPolicyMsg"), target));
			}
			else
			{
				MainInfoBar.WriteWarning(string.Format(Atlas.GetStr("AppLockerSavedButInvalidMsg"), target, validationError));
			}
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
}
