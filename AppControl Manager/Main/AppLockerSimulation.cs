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

using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using AppControlManager.AppLockerPolicy;
using CommonCore.IntelGathering;

namespace AppControlManager.Main;

/// <summary>
/// Runs an AppLocker policy "what-if" over a set of files/folders. It reuses the app's existing
/// file-enumeration, hashing and certificate scanners, and delegates per-file verdicts to
/// <see cref="AppLockerArbitrator"/>. This is the AppLocker analogue of <see cref="AppControlSimulation"/>.
/// </summary>
internal static class AppLockerSimulation
{
	// Organization RDN OID.
	private const string OrganizationOid = "2.5.4.10";
	private const string CommonNameOid = "2.5.4.3";

	/// <summary>
	/// Simulates the policy against the selected files/folders.
	/// </summary>
	/// <param name="filePaths">Explicit files to test (optional).</param>
	/// <param name="folderPaths">Folders whose files will be tested (optional).</param>
	/// <param name="policy">The parsed AppLocker policy.</param>
	/// <param name="threadsCount">Concurrent worker count (min 1).</param>
	/// <param name="progressReporter">Optional 0-100 progress.</param>
	/// <param name="cToken">Optional cancellation.</param>
	/// <param name="applicableSids">
	/// Optional "evaluate as this identity" filter. When non-null, only rules scoped to Everyone
	/// or to a SID in this set are considered; when null, all rules are considered (machine-wide).
	/// </param>
	internal static ConcurrentDictionary<string, AppLockerSimulationOutput> Invoke(
		IReadOnlyCollection<string>? filePaths,
		IReadOnlyCollection<string>? folderPaths,
		AppLockerPolicyObj policy,
		ushort threadsCount = 2,
		IProgress<double>? progressReporter = null,
		CancellationToken? cToken = null,
		IReadOnlyCollection<string>? applicableSids = null)
	{
		threadsCount = Math.Max((ushort)1, threadsCount);

		// Enumerate every file (no extension filter - AppLocker governs specific types and the
		// arbitrator reports ungoverned types as "Not applicable").
		(IEnumerable<string> Files, int Count) collected = FileUtility.GetFilesFast(folderPaths, filePaths, null);

		ConcurrentDictionary<string, AppLockerSimulationOutput> results = new(threadsCount, Math.Max(1, collected.Count));

		if (collected.Count == 0)
		{
			return results;
		}

		int processed = 0;
		double total = collected.Count;

		using Timer? progressTimer = progressReporter is not null
			? new Timer(_ =>
			{
				int current = Volatile.Read(ref processed);
				int pct = Math.Min((int)(current / total * 100), 100);
				progressReporter.Report(pct);
			}, null, 0, 2000)
			: null;

		IEnumerable<string[]> chunks = collected.Files.Chunk((int)Math.Ceiling(total / threadsCount));

		List<Task> tasks = [];

		foreach (string[] chunk in chunks)
		{
			tasks.Add(Task.Run(() =>
			{
				foreach (string filePath in chunk)
				{
					cToken?.ThrowIfCancellationRequested();
					_ = Interlocked.Increment(ref processed);

					AppLockerFileInfo info = ScanFile(filePath);
					AppLockerSimulationOutput output = AppLockerArbitrator.Evaluate(info, policy, applicableSids);
					_ = results.TryAdd(filePath, output);
				}
			}, cToken ?? CancellationToken.None));
		}

		Task.WaitAll([.. tasks], cToken ?? CancellationToken.None);

		progressReporter?.Report(100);

		return results;
	}

	/// <summary>
	/// Gathers the AppLocker-relevant metadata for a single file using existing scanners.
	/// Also used by the editor's "add rule from an app" feature.
	/// </summary>
	internal static AppLockerFileInfo ScanFile(string filePath)
	{
		FileInfo fi = new(filePath);
		AppLockerFileInfo info = new()
		{
			FilePath = fi.FullName,
			FileName = fi.Name,
			Extension = fi.Extension.ToLowerInvariant()
		};

		info.Collection = AppLockerMatching.CollectionForExtension(info.Extension);

		// Version-resource attributes (product name, original/binary name, version).
		try
		{
			ExFileInfo ex = GetExtendedFileAttrib.Get(fi.FullName);
			info.ProductNameUpper = ex.ProductName?.ToUpperInvariant();
			info.BinaryNameUpper = ex.OriginalFileName?.ToUpperInvariant();
			info.FileVersion = ex.Version;
		}
		catch { /* version info is optional */ }

		// Hashes: Authenticode (for PE files) and a flat SHA256 (for scripts / non-PE).
		try
		{
			CodeIntegrityHashes ciHashes = CiFileHash.GetCiFileHashes(fi.FullName);
			info.SHA256Authenticode = ciHashes.SHA256Authenticode?.ToUpperInvariant();
		}
		catch { /* not fatal - hash rules just won't match */ }

		try
		{
			using FileStream fs = File.OpenRead(fi.FullName);
			info.SHA256Flat = Convert.ToHexString(SHA256.HashData(fs));
		}
		catch (Exception ex)
		{
			// If we can't even read the file, record it so the arbitrator reports "not processed".
			if (info.SHA256Authenticode is null)
			{
				info.ScanError = string.Format(Atlas.GetStr("AppLockerFileInaccessibleReason"), ex.Message);
				return info;
			}
		}

		// Signer candidates.
		try
		{
			List<AllFileSigners> signers = AllCertificatesGrabber.GetAllFileSigners(fi.FullName);
			if (signers.Count > 0)
			{
				List<ChainPackage> chains = GetCertificateDetails.Get(signers);
				foreach (ChainPackage chain in chains)
				{
					X509Certificate2? leaf = chain.LeafCertificate?.Certificate;
					if (leaf is not null)
					{
						info.Publishers.Add(BuildPublisherCandidate(leaf, chain.LeafCertificate!.SubjectCN));
					}
				}
			}
		}
		catch { /* unsigned or unreadable signature - treated as not signed */ }

		return info;
	}

	private static PublisherCandidate BuildPublisherCandidate(X509Certificate2 leaf, string subjectCN)
	{
		PublisherCandidate candidate = new()
		{
			SubjectUpper = leaf.Subject.ToUpperInvariant(),
			CommonNameUpper = subjectCN.ToUpperInvariant()
		};

		try
		{
			foreach (X500RelativeDistinguishedName rdn in leaf.SubjectName.EnumerateRelativeDistinguishedNames())
			{
				string oid = rdn.GetSingleElementType().Value ?? string.Empty;
				if (string.Equals(oid, OrganizationOid, StringComparison.Ordinal))
				{
					candidate.OrganizationUpper = (rdn.GetSingleElementValue() ?? string.Empty).ToUpperInvariant();
				}
				else if (string.Equals(oid, CommonNameOid, StringComparison.Ordinal) && candidate.CommonNameUpper.Length == 0)
				{
					candidate.CommonNameUpper = (rdn.GetSingleElementValue() ?? string.Empty).ToUpperInvariant();
				}
			}
		}
		catch { /* fall back to whatever we already have */ }

		return candidate;
	}
}
