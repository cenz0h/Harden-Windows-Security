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

namespace AppControlManager.Others;

/// <summary>
/// Central kill switch for the app's self-update feature in this fork.
///
/// WHY THIS EXISTS
/// This fork is deliberately pinned to an older upstream base so the AppLocker -> App Control (WDAC)
/// migration tooling keeps working. Installing an upstream release would replace this custom build
/// with the official one and silently remove every feature added here, forcing a re-clone and rebuild.
///
/// WHAT IT BLOCKS
/// Only the SELF-UPDATE paths: the startup update check, the update check/notification, and the
/// "Check for update" button that downloads and installs the upstream package.
///
/// WHAT IT DOES NOT BLOCK
/// The Package Installer sub-page still works, so you can deliberately install a local .msix /
/// .msixbundle - including your OWN build of this fork. Suppression is about preventing an accidental
/// upstream overwrite, not about preventing you from installing anything.
///
/// TO RE-ENABLE
/// Set <see cref="UpdatesSuppressed"/> to false and rebuild. Consider doing that once this fork has
/// been rebased onto current upstream.
///
/// NOTE
/// This only governs the app's own updater. If the officially published package is ever installed
/// from the Microsoft Store or by running its installer, Windows can still replace this build,
/// because it shares the same package identity.
/// </summary>
internal static class UpdateSuppression
{
	/// <summary>
	/// When true, the app will never check for or install an update of itself.
	///
	/// Intentionally static readonly rather than const: a const would let the compiler prove the code
	/// after each guard is unreachable, which this project reports as an error (CS0162).
	/// </summary>
	internal static readonly bool UpdatesSuppressed = true;

	/// <summary>
	/// Shown in the UI and written to the log whenever an update action is blocked.
	/// </summary>
	internal const string Reason =
		"Self-update is disabled in this build. This fork is intentionally held back so the AppLocker to App Control migration tooling keeps working - updating would replace it with the upstream release. You can still install a package manually from the Package Installer page.";
}
