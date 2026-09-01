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

using System.IO;
using System.Xml;
using System.Xml.Schema;

namespace AppControlManager.AppLockerPolicy;

/// <summary>
/// Validates an AppLocker policy XML file. Mirrors <c>Main.CiPolicyTest.TestCiPolicy</c>.
/// If the bundled structural schema is present it validates against it; otherwise it falls
/// back to a well-formedness check (the schema is a pragmatic structural check, not a
/// byte-for-byte copy of Microsoft's internal AppLocker grammar).
/// </summary>
internal static class AppLockerValidation
{
	/// <summary>
	/// Validates the AppLocker XML file, throwing on the first problem.
	/// </summary>
	/// <param name="xmlFilePath">Path to the AppLocker policy XML file.</param>
	/// <exception cref="FileNotFoundException">When the input file does not exist.</exception>
	/// <exception cref="XmlSchemaValidationException">When schema validation fails.</exception>
	internal static void Validate(string xmlFilePath)
	{
		if (!File.Exists(xmlFilePath))
		{
			throw new FileNotFoundException(Atlas.GetStr("FileNotExists"), xmlFilePath);
		}

		string schemaPath = Path.Join(AppContext.BaseDirectory, "XSDSchemas", "AppLockerPolicy.xsd");

		XmlDocument xmlDoc = new();
		xmlDoc.Load(xmlFilePath);

		// If the schema file is missing for any reason, still guarantee well-formedness
		// (the Load above already parsed it) and return without a hard failure.
		if (!File.Exists(schemaPath))
		{
			return;
		}

		XmlReaderSettings settings = new();
		_ = settings.Schemas.Add(null, schemaPath);
		settings.ValidationType = ValidationType.Schema;
		settings.ValidationFlags |= XmlSchemaValidationFlags.ReportValidationWarnings;
		settings.ValidationEventHandler += (sender, args) =>
		{
			throw new XmlSchemaValidationException(
				string.Format(
					Atlas.GetStr("XmlValidationErrorMessage"),
					xmlFilePath,
					args.Message));
		};

		using XmlReader reader = XmlReader.Create(new StringReader(xmlDoc.OuterXml), settings);
		while (reader.Read()) { }
	}
}
