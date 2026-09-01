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

using System.Collections.ObjectModel;
using System.Linq;
using AppControlManager.AppLockerPolicy;
using Microsoft.UI.Xaml;

namespace AppControlManager.ViewModels;

/// <summary>
/// An editable view over a single AppLocker rule for the editor grid + detail pane. It is a thin
/// façade: setters write straight into the underlying <see cref="RuleBase"/>, so saving just
/// re-serializes the policy object with no separate reconciliation step.
/// </summary>
internal sealed partial class AppLockerRuleRow : ViewModelBase
{
	internal RuleCollection Collection { get; }
	internal RuleBase Rule { get; }

	internal AppLockerRuleRow(RuleCollection collection, RuleBase rule)
	{
		Collection = collection;
		Rule = rule;

		foreach (ConditionBase exception in rule.Exceptions)
		{
			ExceptionRows.Add(new AppLockerConditionRow(exception));
		}
	}

	/// <summary>Editable rows for the rule's exceptions.</summary>
	internal ObservableCollection<AppLockerConditionRow> ExceptionRows { get; } = [];

	/// <summary>Adds a new exception condition to the rule.</summary>
	internal void AddException(ConditionBase condition)
	{
		Rule.Exceptions.Add(condition);
		ExceptionRows.Add(new AppLockerConditionRow(condition));
		RaiseExceptionChanges();
	}

	/// <summary>Removes an exception row from the rule.</summary>
	internal void RemoveExceptionRow(AppLockerConditionRow row)
	{
		_ = Rule.Exceptions.Remove(row.Condition);
		_ = ExceptionRows.Remove(row);
		RaiseExceptionChanges();
	}

	private void RaiseExceptionChanges()
	{
		OnPropertyChanged(nameof(ExceptionCount));
		OnPropertyChanged(nameof(ExceptionsBadge));
		OnPropertyChanged(nameof(ExceptionsSummary));
	}

	internal string CollectionText => Collection.Type.ToString();

	internal string KindText => Rule switch
	{
		FilePublisherRule => "Publisher",
		FilePathRule => "Path",
		FileHashRule => "Hash",
		_ => "Unknown"
	};

	internal bool IsPublisherRule => Rule is FilePublisherRule;
	internal bool IsPathRule => Rule is FilePathRule;
	internal bool IsHashRule => Rule is FileHashRule;

	internal Visibility PublisherPaneVisibility => IsPublisherRule ? Visibility.Visible : Visibility.Collapsed;
	internal Visibility PathPaneVisibility => IsPathRule ? Visibility.Visible : Visibility.Collapsed;
	internal Visibility HashPaneVisibility => IsHashRule ? Visibility.Visible : Visibility.Collapsed;

	internal string Id => Rule.Id;

	internal string Name
	{
		get => Rule.Name;
		set { Rule.Name = value; OnPropertyChanged(nameof(Name)); }
	}

	internal string Description
	{
		get => Rule.Description;
		set { Rule.Description = value; OnPropertyChanged(nameof(Description)); }
	}

	internal string UserOrGroupSid
	{
		get => Rule.UserOrGroupSid;
		set { Rule.UserOrGroupSid = value; OnPropertyChanged(nameof(UserOrGroupSid)); OnPropertyChanged(nameof(ResolvedSidName)); }
	}

	/// <summary>Live friendly-name resolution of <see cref="UserOrGroupSid"/> for the detail pane.</summary>
	internal string ResolvedSidName => WellKnownSids.Resolve(Rule.UserOrGroupSid);

	/// <summary>Action as a combo index (0 = Allow, 1 = Deny).</summary>
	internal int ActionIndex
	{
		get => (int)Rule.Action;
		set
		{
			Rule.Action = (RuleActionType)value;
			OnPropertyChanged(nameof(ActionIndex));
			OnPropertyChanged(nameof(ActionText));
		}
	}

	internal string ActionText => Rule.Action.ToString();

	private FilePublisherCondition? FirstPublisher => Rule.Conditions.OfType<FilePublisherCondition>().FirstOrDefault();
	private FilePathCondition? FirstPath => Rule.Conditions.OfType<FilePathCondition>().FirstOrDefault();

	internal string PublisherName
	{
		get => FirstPublisher?.PublisherName ?? string.Empty;
		set { if (FirstPublisher is { } c) { c.PublisherName = value; OnPropertyChanged(nameof(PublisherName)); OnPropertyChanged(nameof(ConditionSummary)); } }
	}

	internal string ProductName
	{
		get => FirstPublisher?.ProductName ?? string.Empty;
		set { if (FirstPublisher is { } c) { c.ProductName = value; OnPropertyChanged(nameof(ProductName)); } }
	}

	internal string BinaryName
	{
		get => FirstPublisher?.BinaryName ?? string.Empty;
		set { if (FirstPublisher is { } c) { c.BinaryName = value; OnPropertyChanged(nameof(BinaryName)); } }
	}

	internal string LowSection
	{
		get => FirstPublisher?.LowSection ?? string.Empty;
		set { if (FirstPublisher is { } c) { c.LowSection = value; OnPropertyChanged(nameof(LowSection)); } }
	}

	internal string HighSection
	{
		get => FirstPublisher?.HighSection ?? string.Empty;
		set { if (FirstPublisher is { } c) { c.HighSection = value; OnPropertyChanged(nameof(HighSection)); } }
	}

	internal string PathValue
	{
		get => FirstPath?.Path ?? string.Empty;
		set { if (FirstPath is { } c) { c.Path = value; OnPropertyChanged(nameof(PathValue)); OnPropertyChanged(nameof(ConditionSummary)); } }
	}

	/// <summary>Read-only summary of the hash entries, for hash rules.</summary>
	internal string HashSummary
	{
		get
		{
			FileHashCondition? hc = Rule.Conditions.OfType<FileHashCondition>().FirstOrDefault();
			if (hc is null)
			{
				return string.Empty;
			}
			return string.Join(Environment.NewLine, hc.Hashes.Select(h => $"{h.Type}  {h.Data}  ({h.SourceFileName})"));
		}
	}

	/// <summary>Short single-line description of the rule's condition(s) for the grid.</summary>
	internal string ConditionSummary
	{
		get
		{
			if (FirstPath is { } p)
			{
				return p.Path;
			}
			if (FirstPublisher is { } pub)
			{
				return $"{pub.PublisherName} | {pub.ProductName} | {pub.BinaryName} [{pub.LowSection}-{pub.HighSection}]";
			}
			if (IsHashRule)
			{
				int count = Rule.Conditions.OfType<FileHashCondition>().Sum(h => h.Hashes.Count);
				return string.Format(Atlas.GetStr("AppLockerHashCountSummary"), count);
			}
			return string.Empty;
		}
	}

	/// <summary>Number of exceptions on the rule (shown in the grid).</summary>
	internal int ExceptionCount => Rule.Exceptions.Count;

	/// <summary>Short badge for the grid, e.g. "2 exceptions" (empty when none).</summary>
	internal string ExceptionsBadge => ExceptionCount == 0
		? string.Empty
		: string.Format(Atlas.GetStr("AppLockerExceptionsBadge"), ExceptionCount);

	internal Visibility ExceptionsPaneVisibility => ExceptionCount > 0 ? Visibility.Visible : Visibility.Collapsed;

	/// <summary>A readable, multi-line listing of the rule's exceptions for the detail pane.</summary>
	internal string ExceptionsSummary
	{
		get
		{
			if (Rule.Exceptions.Count == 0)
			{
				return string.Empty;
			}

			return string.Join(Environment.NewLine, Rule.Exceptions.Select(DescribeCondition));
		}
	}

	private static string DescribeCondition(ConditionBase condition) => condition switch
	{
		FilePathCondition p => $"Path: {p.Path}",
		FilePublisherCondition pub => $"Publisher: {pub.PublisherName} | {pub.ProductName} | {pub.BinaryName} [{pub.LowSection}-{pub.HighSection}]",
		FileHashCondition h => $"Hash: {h.Hashes.Count} file hash(es)",
		_ => "Unknown condition"
	};
}
