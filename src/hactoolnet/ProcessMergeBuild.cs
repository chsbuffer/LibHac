using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using LibHac.Common;
using LibHac.Common.Keys;
using LibHac.Fs;
using LibHac.Fs.Fsa;
using LibHac.FsSystem;
using LibHac.Tools.Fs;
using LibHac.Tools.FsSystem;
using LibHac.Tools.FsSystem.NcaUtils;
using LibHac.Tools.Ncm;
using ContentType = LibHac.Ncm.ContentType;

namespace hactoolnet;

internal static class ProcessMergeBuild
{
    public static void Process(Context ctx)
    {
        if (ctx.Options.OutFile == null)
        {
            ctx.Logger.LogMessage("Output file must be specified.");
            return;
        }

        using var baseNsp = new LocalStorage(ctx.Options.BaseFile, FileAccess.Read);
        using var updateNsp = new LocalStorage(ctx.Options.InFile, FileAccess.Read);

        using var baseFs = new PartitionFileSystem();
        using var updateFs = new PartitionFileSystem();

        baseFs.Initialize(baseNsp).ThrowIfFailure();
        updateFs.Initialize(updateNsp).ThrowIfFailure();

        if (!baseFs.EnumerateEntries("*.nca", SearchOptions.Default).Any())
        {
            return;
        }

        ProcessAppFs.ImportTickets(ctx, baseFs);
        ProcessAppFs.ImportTickets(ctx, updateFs);
        using var baseNxFs = SwitchFs.OpenNcaDirectory(ctx.KeySet, baseFs);
        using var updateNxFs = SwitchFs.OpenNcaDirectory(ctx.KeySet, updateFs);
        // Control Nca from update nsp, copy it as-is
        var controlNca = updateNxFs.Ncas.Single(x => x.Value.Nca.Header.ContentType == NcaContentType.Control);

        // patch program nca
        var baseNca = baseNxFs.Ncas.Values.Single(x => x.Nca.Header.ContentType == NcaContentType.Program);
        var updateNca = updateNxFs.Ncas.Values.Single(x => x.Nca.Header.ContentType == NcaContentType.Program);
        var ncaBuilder = new NcaBuilder(ctx.KeySet);
        var newProgram = ncaBuilder.Build(baseNca.Nca, updateNca.Nca);

        ctx.Logger.LogMessage("Calculating new Program NCA hash.");
        List<NcaHolder> ncas =
        [
            new(newProgram, ContentType.Program, ctx.Logger),
            new(controlNca.Value.Nca.BaseStorage, ContentType.Control)
        ];

        // re-generate meta nca
        var metaNca = baseNxFs.Ncas.Values.Single(x => x.Nca.Header.ContentType == NcaContentType.Meta);
        var newMeta = CreatePatchedMetaNca(ctx.KeySet, metaNca, ncas);
        ncas.Add(new NcaHolder(newMeta, ContentType.Meta));

        // build nsp
        ctx.Logger.LogMessage("Saving new NSP. ");
        var pfsBuilder = new PartitionFileSystemBuilder();
        foreach (var file in ncas)
        {
            pfsBuilder.AddFile(file.FileName, file.File.AsFile(OpenMode.Read));
        }

        var nsp = pfsBuilder.Build(PartitionFileSystemType.Standard);
        // TestNsp(ctx, nsp);
        nsp.WriteAllBytes(ctx.Options.OutFile, ctx.Logger);
    }

    private static void TestNsp(Context ctx, IStorage nsp)
    {
        using var fs = new PartitionFileSystem();
        fs.Initialize(nsp);
        using var switchFs = SwitchFs.OpenNcaDirectory(ctx.KeySet, fs);
        ProcessSwitchFs.ListNcas(switchFs);
        ProcessSwitchFs.ListTitles(switchFs);
        ProcessSwitchFs.ListApplications(switchFs);
    }

    private class NcaHolder
    {
        public IStorage File { get; }
        public ContentType ContentType { get; }
        public byte[] HashData { get; }
        public Span<byte> ContentId => HashData.AsSpan(0, 0x10);
        public readonly long Size;

        public NcaHolder(IStorage file, ContentType contentType, IProgressReport progress = null)
        {
            File = file;
            file.GetSize(out Size);
            ContentType = contentType;
            HashData = DoHash(file, progress);
        }

        public string FileName
        {
            get
            {
                var hashStr = Convert.ToHexString(ContentId).ToLowerInvariant();
                var extension = ContentType == ContentType.Meta ? ".cnmt.nca" : ".nca";
                return hashStr + extension;
            }
        }

        public CnmtContentEntry ToCnmtContentEntry()
        {
            return new CnmtContentEntry
            {
                Hash = HashData,
                NcaId = ContentId.ToArray(),
                Size = Size,
                Type = ContentType
            };
        }
    }

    private static byte[] DoHash(IStorage input, IProgressReport progress = null)
    {
        input.GetSize(out long inputSize).ThrowIfFailure();
        using var sha256 = SHA256.Create();
        using (var crypto = new CryptoStream(Stream.Null, sha256, CryptoStreamMode.Write))
        {
            input.CopyToStream(crypto, inputSize, progress);
        }

        return sha256.Hash;
    }

    private static IStorage CreatePatchedMetaNca(KeySet keySet, SwitchFsNca nca, IEnumerable<NcaHolder> ncas)
    {
        // read cnmt
        using var fs = nca.OpenFileSystem(NcaSectionType.Data, IntegrityCheckLevel.ErrorOnInvalid);
        var cnmtPath = fs.EnumerateEntries("/", "*.cnmt").Single().FullPath;
        using var file = new UniqueRef<IFile>();
        fs.OpenFile(ref file.Ref, cnmtPath.ToU8Span(), OpenMode.Read).ThrowIfFailure();
        var metadata = new Cnmt(file.Release().AsStream());

        // update cnmt
        metadata.ContentEntries = ncas.Select(x => x.ToCnmtContentEntry()).ToArray();
        var newCnmt = metadata.Build();

        // build section0
        var pfs0Builder = new PartitionFileSystemBuilder();
        pfs0Builder.AddFile(cnmtPath[1..], new MemoryStorage(newCnmt).AsFile(OpenMode.Read));
        var section0 = pfs0Builder.Build(PartitionFileSystemType.Standard);

        // build nca
        var ncaBuilder = new NcaBuilder(keySet);
        ncaBuilder.CopyHeader(nca.Nca);
        var fsHeader = ncaBuilder.CopyFsHeader(nca.Nca, 0);
        fsHeader.EncryptionType = NcaEncryptionType.None;
        ncaBuilder.AddPfsSection(0, section0, NcaBuilder.HashBlockSize1);
        return ncaBuilder.Build();
    }
}