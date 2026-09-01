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

using Microsoft.UI.Xaml;

namespace AppControlManager.AppLockerPolicy;

/// <summary>
/// UI-only visibility helpers for <see cref="AppLockerDiffEntry"/>, kept out of the (pure,
/// console-testable) comparison engine file. Each status maps to one visible, pre-coloured glyph.
/// </summary>
internal sealed partial class AppLockerDiffEntry
{
	internal Visibility AddedVisibility => Status == AppLockerDiffStatus.Added ? Visibility.Visible : Visibility.Collapsed;
	internal Visibility RemovedVisibility => Status == AppLockerDiffStatus.Removed ? Visibility.Visible : Visibility.Collapsed;
	internal Visibility ChangedVisibility => Status == AppLockerDiffStatus.Changed ? Visibility.Visible : Visibility.Collapsed;
	internal Visibility UnchangedVisibility => Status == AppLockerDiffStatus.Unchanged ? Visibility.Visible : Visibility.Collapsed;

	internal Visibility ExceptionsVisibility => ExceptionDiffs.Count > 0 ? Visibility.Visible : Visibility.Collapsed;
}
