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
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Navigation;

namespace AppControlManager.Pages;

internal sealed partial class AppLockerPolicyEditor : Page, CommonCore.UI.IPageHeaderProvider
{
	private ViewModels.AppLockerPolicyEditorVM ViewModel => ViewModels.ViewModelProvider.AppLockerPolicyEditorVM;

	internal AppLockerPolicyEditor()
	{
		InitializeComponent();
		NavigationCacheMode = NavigationCacheMode.Disabled;
		DataContext = ViewModel;
	}

	/// <summary>
	/// Applies the clicked SID legend entry to the currently selected rule.
	/// </summary>
	private void SidApply_Click(object sender, RoutedEventArgs e)
	{
		if ((sender as FrameworkElement)?.DataContext is ViewModels.SidInfo sidInfo)
		{
			ViewModel.ApplySidToSelected(sidInfo.Sid);
		}
	}

	/// <summary>
	/// Removes the exception whose row was clicked from the selected rule.
	/// </summary>
	private void RemoveException_Click(object sender, RoutedEventArgs e)
	{
		if ((sender as FrameworkElement)?.DataContext is ViewModels.AppLockerConditionRow row)
		{
			ViewModel.RemoveException(row);
		}
	}

	string CommonCore.UI.IPageHeaderProvider.HeaderTitle => Atlas.GetStr("AppLockerPolicyEditorPageTitle");
	Uri? CommonCore.UI.IPageHeaderProvider.HeaderGuideUri => new("https://github.com/HotCakeX/Harden-Windows-Security/wiki");
}
