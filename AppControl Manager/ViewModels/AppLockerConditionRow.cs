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

using System.Linq;
using AppControlManager.AppLockerPolicy;
using Microsoft.UI.Xaml;

namespace AppControlManager.ViewModels;

/// <summary>
/// An editable façade over a single <see cref="ConditionBase"/> (used for a rule's exceptions).
/// Setters write straight into the underlying condition object.
/// </summary>
internal sealed partial class AppLockerConditionRow : ViewModelBase
{
	internal ConditionBase Condition { get; }

	internal AppLockerConditionRow(ConditionBase condition) => Condition = condition;

	internal bool IsPath => Condition is FilePathCondition;
	internal bool IsPublisher => Condition is FilePublisherCondition;
	internal bool IsHash => Condition is FileHashCondition;

	internal Visibility PathVisibility => IsPath ? Visibility.Visible : Visibility.Collapsed;
	internal Visibility PublisherVisibility => IsPublisher ? Visibility.Visible : Visibility.Collapsed;
	internal Visibility HashVisibility => IsHash ? Visibility.Visible : Visibility.Collapsed;

	internal string TypeText => Condition switch
	{
		FilePathCondition => "Path",
		FilePublisherCondition => "Publisher",
		FileHashCondition => "Hash",
		_ => "Unknown"
	};

	private FilePathCondition? AsPath => Condition as FilePathCondition;
	private FilePublisherCondition? AsPublisher => Condition as FilePublisherCondition;

	internal string PathValue
	{
		get => AsPath?.Path ?? string.Empty;
		set { if (AsPath is { } c) { c.Path = value; OnPropertyChanged(nameof(PathValue)); } }
	}

	internal string PublisherName
	{
		get => AsPublisher?.PublisherName ?? string.Empty;
		set { if (AsPublisher is { } c) { c.PublisherName = value; OnPropertyChanged(nameof(PublisherName)); } }
	}

	internal string ProductName
	{
		get => AsPublisher?.ProductName ?? string.Empty;
		set { if (AsPublisher is { } c) { c.ProductName = value; OnPropertyChanged(nameof(ProductName)); } }
	}

	internal string BinaryName
	{
		get => AsPublisher?.BinaryName ?? string.Empty;
		set { if (AsPublisher is { } c) { c.BinaryName = value; OnPropertyChanged(nameof(BinaryName)); } }
	}

	internal string LowSection
	{
		get => AsPublisher?.LowSection ?? string.Empty;
		set { if (AsPublisher is { } c) { c.LowSection = value; OnPropertyChanged(nameof(LowSection)); } }
	}

	internal string HighSection
	{
		get => AsPublisher?.HighSection ?? string.Empty;
		set { if (AsPublisher is { } c) { c.HighSection = value; OnPropertyChanged(nameof(HighSection)); } }
	}

	internal string HashSummary
	{
		get
		{
			if (Condition is FileHashCondition h)
			{
				return string.Join(Environment.NewLine, h.Hashes.Select(x => $"{x.Type}  {x.Data}  ({x.SourceFileName})"));
			}
			return string.Empty;
		}
	}
}
