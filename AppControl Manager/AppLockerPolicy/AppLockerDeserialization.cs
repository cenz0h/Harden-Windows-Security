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
using System.Xml;

namespace AppControlManager.AppLockerPolicy;

/// <summary>
/// Parses an AppLocker policy XML file into an <see cref="AppLockerPolicyObj"/>.
/// Mirrors the manual <see cref="System.Xml.XmlDocument"/> walking style used by
/// <c>SiPolicy.CustomDeserialization</c> (the project is AOT/trimmed and avoids XmlSerializer).
/// AppLocker XML has no XML namespace, so element access is by local name only.
/// </summary>
internal static class AppLockerDeserialization
{
	/// <summary>
	/// The rule-element attributes we model explicitly; everything else is preserved in
	/// <see cref="RuleBase.ExtraAttributes"/> for a faithful round-trip.
	/// </summary>
	private static readonly HashSet<string> KnownRuleAttributes = new(StringComparer.Ordinal)
	{
		"Id", "Name", "Description", "UserOrGroupSid", "Action"
	};

	/// <summary>
	/// Deserializes an AppLocker policy from a file path or an already-loaded document.
	/// </summary>
	/// <param name="filePath">Path to the AppLocker XML file. Used when <paramref name="xml"/> is null.</param>
	/// <param name="xml">A pre-loaded XML document to use instead of a file path.</param>
	/// <exception cref="InvalidOperationException">When neither a file path nor a document is supplied, or the root is wrong.</exception>
	internal static AppLockerPolicyObj Deserialize(string? filePath, XmlDocument? xml)
	{
		XmlElement root;

		if (!string.IsNullOrEmpty(filePath))
		{
			XmlDocument xmlDoc = new();
			xmlDoc.Load(filePath);
			root = xmlDoc.DocumentElement
				?? throw new InvalidOperationException(Atlas.GetStr("AppLockerMissingRootValidationError"));
		}
		else if (xml is not null)
		{
			root = xml.DocumentElement
				?? throw new InvalidOperationException(Atlas.GetStr("AppLockerMissingRootValidationError"));
		}
		else
		{
			throw new InvalidOperationException(Atlas.GetStr("FilePathOrXmlRequiredMessage"));
		}

		if (!string.Equals(root.LocalName, "AppLockerPolicy", StringComparison.Ordinal))
		{
			throw new InvalidOperationException(Atlas.GetStr("NotAnAppLockerPolicyValidationError"));
		}

		AppLockerPolicyObj policy = new()
		{
			Version = root.HasAttribute("Version") ? root.GetAttribute("Version") : "1"
		};

		foreach (XmlNode node in root.ChildNodes)
		{
			if (node is not XmlElement collectionElem ||
				!string.Equals(collectionElem.LocalName, "RuleCollection", StringComparison.Ordinal))
			{
				continue;
			}

			policy.RuleCollections.Add(ParseCollection(collectionElem));
		}

		return policy;
	}

	private static RuleCollection ParseCollection(XmlElement collectionElem)
	{
		RuleCollection collection = new()
		{
			Type = ParseEnum(collectionElem.GetAttribute("Type"), RuleCollectionType.Exe),
			EnforcementMode = ParseEnum(collectionElem.GetAttribute("EnforcementMode"), EnforcementModeType.NotConfigured)
		};

		foreach (XmlNode node in collectionElem.ChildNodes)
		{
			if (node is not XmlElement ruleElem)
			{
				continue;
			}

			RuleBase? rule = ParseRule(ruleElem);
			if (rule is not null)
			{
				collection.Rules.Add(rule);
			}
		}

		return collection;
	}

	private static RuleBase? ParseRule(XmlElement ruleElem)
	{
		RuleBase rule = ruleElem.LocalName switch
		{
			"FilePublisherRule" => new FilePublisherRule(),
			"FilePathRule" => new FilePathRule(),
			"FileHashRule" => new FileHashRule(),
			_ => null!
		};

		if (rule is null)
		{
			// Unknown rule element kind - skip rather than fail the whole load.
			return null;
		}

		rule.Id = ruleElem.GetAttribute("Id");
		rule.Name = ruleElem.GetAttribute("Name");
		rule.Description = ruleElem.GetAttribute("Description");
		rule.UserOrGroupSid = ruleElem.GetAttribute("UserOrGroupSid");
		rule.Action = ParseEnum(ruleElem.GetAttribute("Action"), RuleActionType.Allow);

		// Preserve any attributes we do not model explicitly.
		foreach (XmlAttribute attr in ruleElem.Attributes)
		{
			if (!KnownRuleAttributes.Contains(attr.LocalName))
			{
				rule.ExtraAttributes[attr.Name] = attr.Value;
			}
		}

		XmlElement? conditionsElem = FirstChild(ruleElem, "Conditions");
		if (conditionsElem is not null)
		{
			ParseConditions(conditionsElem, rule.Conditions);
		}

		XmlElement? exceptionsElem = FirstChild(ruleElem, "Exceptions");
		if (exceptionsElem is not null)
		{
			ParseConditions(exceptionsElem, rule.Exceptions);
		}

		return rule;
	}

	private static void ParseConditions(XmlElement container, List<ConditionBase> target)
	{
		foreach (XmlNode node in container.ChildNodes)
		{
			if (node is not XmlElement condElem)
			{
				continue;
			}

			switch (condElem.LocalName)
			{
				case "FilePublisherCondition":
					target.Add(ParsePublisherCondition(condElem));
					break;
				case "FilePathCondition":
					target.Add(new FilePathCondition { Path = condElem.GetAttribute("Path") });
					break;
				case "FileHashCondition":
					target.Add(ParseHashCondition(condElem));
					break;
				default:
					break;
			}
		}
	}

	private static FilePublisherCondition ParsePublisherCondition(XmlElement condElem)
	{
		FilePublisherCondition condition = new()
		{
			PublisherName = condElem.GetAttribute("PublisherName"),
			ProductName = condElem.GetAttribute("ProductName"),
			BinaryName = condElem.GetAttribute("BinaryName")
		};

		XmlElement? versionRange = FirstChild(condElem, "BinaryVersionRange");
		if (versionRange is not null)
		{
			condition.LowSection = versionRange.GetAttribute("LowSection");
			condition.HighSection = versionRange.GetAttribute("HighSection");
		}

		return condition;
	}

	private static FileHashCondition ParseHashCondition(XmlElement condElem)
	{
		FileHashCondition condition = new();

		foreach (XmlNode node in condElem.ChildNodes)
		{
			if (node is XmlElement hashElem && string.Equals(hashElem.LocalName, "FileHash", StringComparison.Ordinal))
			{
				condition.Hashes.Add(new FileHash
				{
					Type = hashElem.GetAttribute("Type"),
					Data = hashElem.GetAttribute("Data"),
					SourceFileName = hashElem.GetAttribute("SourceFileName"),
					SourceFileLength = hashElem.GetAttribute("SourceFileLength")
				});
			}
		}

		return condition;
	}

	private static XmlElement? FirstChild(XmlElement parent, string localName)
	{
		foreach (XmlNode node in parent.ChildNodes)
		{
			if (node is XmlElement elem && string.Equals(elem.LocalName, localName, StringComparison.Ordinal))
			{
				return elem;
			}
		}
		return null;
	}

	private static TEnum ParseEnum<TEnum>(string value, TEnum fallback) where TEnum : struct
	{
		return Enum.TryParse(value, ignoreCase: true, out TEnum parsed) ? parsed : fallback;
	}
}
