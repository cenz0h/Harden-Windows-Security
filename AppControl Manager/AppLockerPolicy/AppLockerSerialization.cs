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

using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;
using System.Xml;

namespace AppControlManager.AppLockerPolicy;

/// <summary>
/// Builds AppLocker policy XML from an <see cref="AppLockerPolicyObj"/>.
/// Mirrors the manual <see cref="System.Xml.XmlDocument"/> building style used by
/// <c>SiPolicy.CustomSerialization</c>. Output matches the layout produced by
/// <c>Get-AppLockerPolicy -Xml</c> (2-space indentation, no XML declaration).
/// </summary>
internal static class AppLockerSerialization
{
	/// <summary>
	/// Creates an <see cref="XmlDocument"/> representing the policy.
	/// </summary>
	internal static XmlDocument CreateXml(AppLockerPolicyObj policy)
	{
		XmlDocument xmlDoc = new();

		XmlElement root = xmlDoc.CreateElement("AppLockerPolicy");
		root.SetAttribute("Version", policy.Version);
		_ = xmlDoc.AppendChild(root);

		foreach (RuleCollection collection in CollectionsMarshal.AsSpan(policy.RuleCollections))
		{
			XmlElement collectionElem = xmlDoc.CreateElement("RuleCollection");
			collectionElem.SetAttribute("Type", collection.Type.ToString());
			collectionElem.SetAttribute("EnforcementMode", collection.EnforcementMode.ToString());
			_ = root.AppendChild(collectionElem);

			foreach (RuleBase rule in CollectionsMarshal.AsSpan(collection.Rules))
			{
				_ = collectionElem.AppendChild(BuildRule(xmlDoc, rule));
			}
		}

		return xmlDoc;
	}

	/// <summary>
	/// Serializes the policy to a file using AppLocker's canonical formatting.
	/// </summary>
	internal static void Serialize(AppLockerPolicyObj policy, string filePath)
	{
		XmlDocument xmlDoc = CreateXml(policy);

		XmlWriterSettings settings = new()
		{
			Indent = true,
			IndentChars = "  ",
			// AppLocker XML produced by Get-AppLockerPolicy has no XML declaration.
			OmitXmlDeclaration = true,
			Encoding = new UTF8Encoding(encoderShouldEmitUTF8Identifier: false)
		};

		using XmlWriter writer = XmlWriter.Create(filePath, settings);
		xmlDoc.Save(writer);
	}

	private static XmlElement BuildRule(XmlDocument xmlDoc, RuleBase rule)
	{
		string elementName = rule switch
		{
			FilePublisherRule => "FilePublisherRule",
			FilePathRule => "FilePathRule",
			FileHashRule => "FileHashRule",
			_ => "FilePathRule"
		};

		XmlElement ruleElem = xmlDoc.CreateElement(elementName);

		// Preserve AppLocker's attribute order.
		ruleElem.SetAttribute("Id", rule.Id);
		ruleElem.SetAttribute("Name", rule.Name);
		ruleElem.SetAttribute("Description", rule.Description);
		ruleElem.SetAttribute("UserOrGroupSid", rule.UserOrGroupSid);
		ruleElem.SetAttribute("Action", rule.Action.ToString());

		foreach (KeyValuePair<string, string> extra in rule.ExtraAttributes)
		{
			ruleElem.SetAttribute(extra.Key, extra.Value);
		}

		XmlElement conditionsElem = xmlDoc.CreateElement("Conditions");
		_ = ruleElem.AppendChild(conditionsElem);
		AppendConditions(xmlDoc, conditionsElem, rule.Conditions);

		if (rule.Exceptions.Count > 0)
		{
			XmlElement exceptionsElem = xmlDoc.CreateElement("Exceptions");
			_ = ruleElem.AppendChild(exceptionsElem);
			AppendConditions(xmlDoc, exceptionsElem, rule.Exceptions);
		}

		return ruleElem;
	}

	private static void AppendConditions(XmlDocument xmlDoc, XmlElement container, List<ConditionBase> conditions)
	{
		foreach (ConditionBase condition in CollectionsMarshal.AsSpan(conditions))
		{
			switch (condition)
			{
				case FilePublisherCondition pub:
				{
					XmlElement condElem = xmlDoc.CreateElement("FilePublisherCondition");
					condElem.SetAttribute("PublisherName", pub.PublisherName);
					condElem.SetAttribute("ProductName", pub.ProductName);
					condElem.SetAttribute("BinaryName", pub.BinaryName);

					XmlElement versionRange = xmlDoc.CreateElement("BinaryVersionRange");
					versionRange.SetAttribute("LowSection", pub.LowSection);
					versionRange.SetAttribute("HighSection", pub.HighSection);
					_ = condElem.AppendChild(versionRange);

					_ = container.AppendChild(condElem);
					break;
				}
				case FilePathCondition path:
				{
					XmlElement condElem = xmlDoc.CreateElement("FilePathCondition");
					condElem.SetAttribute("Path", path.Path);
					_ = container.AppendChild(condElem);
					break;
				}
				case FileHashCondition hashCond:
				{
					XmlElement condElem = xmlDoc.CreateElement("FileHashCondition");

					foreach (FileHash hash in CollectionsMarshal.AsSpan(hashCond.Hashes))
					{
						XmlElement hashElem = xmlDoc.CreateElement("FileHash");
						hashElem.SetAttribute("Type", hash.Type);
						hashElem.SetAttribute("Data", hash.Data);
						hashElem.SetAttribute("SourceFileName", hash.SourceFileName);
						hashElem.SetAttribute("SourceFileLength", hash.SourceFileLength);
						_ = condElem.AppendChild(hashElem);
					}

					_ = container.AppendChild(condElem);
					break;
				}
				default:
					break;
			}
		}
	}
}
