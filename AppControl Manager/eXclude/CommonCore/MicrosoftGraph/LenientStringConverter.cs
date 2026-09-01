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
using System.Buffers;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace CommonCore.MicrosoftGraph;

/// <summary>
/// Reads a JSON value of ANY scalar token type (string, number, boolean, null) as a string, and
/// skips objects/arrays (returning null).
///
/// Why this exists: Intune's <c>omaSettings</c> are polymorphic. When we retrieve every
/// <c>windows10CustomConfiguration</c> profile in a tenant (not just the App Control ones this app
/// creates), a profile authored elsewhere can contain a non-base64 setting - e.g.
/// <c>#microsoft.graph.omaSettingInteger</c> or <c>omaSettingBoolean</c> - whose <c>value</c> is a
/// JSON number or boolean. Binding that to the string <see cref="OmaSettingBase64.Value"/> would
/// throw and fail the ENTIRE retrieval. This converter tolerates those foreign values so the list
/// (including our App Control policies) still loads.
/// </summary>
internal sealed class LenientStringConverter : JsonConverter<string?>
{
	public override string? Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
	{
		switch (reader.TokenType)
		{
			case JsonTokenType.Null:
				return null;

			case JsonTokenType.String:
				return reader.GetString();

			case JsonTokenType.Number:
				// Preserve the raw numeric literal without assuming int vs. double.
				return reader.HasValueSequence
					? Encoding.UTF8.GetString(reader.ValueSequence.ToArray())
					: Encoding.UTF8.GetString(reader.ValueSpan);

			case JsonTokenType.True:
				return "true";

			case JsonTokenType.False:
				return "false";

			case JsonTokenType.StartObject:
			case JsonTokenType.StartArray:
				// Nested value (e.g. omaSettingGroup) - not something we consume; skip it.
				reader.Skip();
				return null;

			default:
				reader.Skip();
				return null;
		}
	}

	public override void Write(Utf8JsonWriter writer, string? value, JsonSerializerOptions options)
	{
		if (value is null)
		{
			writer.WriteNullValue();
		}
		else
		{
			writer.WriteStringValue(value);
		}
	}
}
