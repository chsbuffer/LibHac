using System;
using LibHac.Common.Keys;
using LibHac.Crypto;
using LibHac.Fs;
using LibHac.Util;

namespace LibHac.Tools.FsSystem.NcaUtils;

public class NcaBuilder
{
    private KeySet KeySet { get; }
    private ConcatenationStorageBuilder Builder { get; } = new();

    public readonly NcaHeader Header;
    public readonly IStorage HeaderStorage;

    public int Blocks => (int)BitUtil.DivideUp(Size, BlockSize);
    public long Size { get; private set; } = NcaHeader.HeaderSize;
    public long AlignedSize => (long)Blocks * BlockSize;

    public NcaBuilder(KeySet keySet, NcaContentType contentType = NcaContentType.Program)
    {
        KeySet = keySet;
        var buffer = new byte[NcaHeader.HeaderSize];
        Header = new NcaHeader(buffer)
        {
            Magic = LibHac.FsSystem.NcaHeader.Magic3,
            ContentIndex = 0,
            NcaSize = 0,
            ContentType = contentType,
            DistributionType = DistributionType.Download,
            SdkVersion = new TitleVersion(0, isSystemTitle: true), // TODO
            KeyGeneration = 0, // TODO
            TitleId = 0, // TODO
            KeyAreaKeyIndex = 0, // TODO
        };
        HeaderStorage = new MemoryStorage(buffer);
    }

    private const int BlockSize = 0x200;

    public IStorage Build(Nca baseNca, Nca patchNca)
    {
        CopyHeader(baseNca);
        // copy Logo
        CopyRawStorage(baseNca, 2);
        // copy ExeFs
        CopyRawStorage(patchNca, 0);
        // copy merged RomFs
        CopyRomFs(baseNca, patchNca);

        return Build();
    }

    public void CopyHeader(Nca sourceNca)
    {
        sourceNca.OpenHeaderStorage(openEncrypted: false)
            .Slice(0, NcaHeader.NcaHeaderStruct.SectionEntriesOffset)
            .CopyTo(HeaderStorage);
    }

    /// <summary>
    /// Copy other FsHeader[index] to self, as-is
    /// </summary>
    /// <param name="sourceNca">source nca</param>
    /// <param name="index">index</param>
    /// <returns>reference to self FsHeader[index]</returns>
    public NcaFsHeader CopyFsHeader(Nca sourceNca, int index)
    {
        var fsHeaderData = Header.GetFsHeaderUncheck(index);
        sourceNca.Header.GetFsHeaderUncheck(index).CopyTo(fsHeaderData);
        return new NcaFsHeader(fsHeaderData);
    }

    public IStorage Build()
    {
        for (var i = 0; i < NcaHeader.SectionCount; i++)
            if (Header.IsSectionEnabled(i))
                FsHeaderDoHash(i);

        Builder.Add(new CachedStorage(
            new Aes128XtsStorage(
                HeaderStorage
                , KeySet.HeaderKey, NcaHeader.HeaderSectorSize, true, false), 1, true), 0);

        var padSize = AlignedSize - Size;
        if (padSize != 0)
            Builder.Add(new NullStorage(padSize), Size);

        Header.NcaSize = AlignedSize;
        return Builder.Build();
    }

    private void CopyRawStorage(Nca nca, int index, bool decrypt = true)
    {
        var section = nca.OpenRawStorage(index, openEncrypted: !decrypt);
        AddSectionUpdateFsEntry(index, section);

        var fsHeader = CopyFsHeader(nca, index);
        if (!decrypt) return;
        fsHeader.EncryptionType = NcaEncryptionType.None;
    }

    public const int HashBlockSize1 = 0x1000;
    public const int HashBlockSize2 = 0x8000;

    /// <summary>
    /// Calc Pfs HashData, write FsHeader HashData, Update FsEntry
    /// </summary>
    /// <param name="index"></param>
    /// <param name="dataStorage"></param>
    /// <param name="hashBlockSize"></param>
    public void AddPfsSection(int index, IStorage dataStorage, int hashBlockSize)
    {
        var fsHeader = new NcaFsHeader(Header.GetFsHeaderUncheck(index));
        var hashData = CalcHashTable(hashBlockSize, dataStorage);
        var dataOffset = BitUtil.DivideUp(hashData.Length, hashBlockSize) * hashBlockSize;
        dataStorage.GetSize(out long dataSize).ThrowIfFailure();

        var rawStorage = new ConcatenationStorageBuilder(
        [
            new ConcatenationStorageSegment(new MemoryStorage(hashData), 0),
            new ConcatenationStorageSegment(dataStorage, dataOffset),
        ]).Build();

        var info = fsHeader.GetIntegrityInfoSha256();
        info.BlockSize = hashBlockSize;
        info.GetLevelOffset(0) = 0;
        info.GetLevelSize(0) = hashData.Length;
        info.GetLevelOffset(1) = dataOffset;
        info.GetLevelSize(1) = dataSize;
        Sha256.GenerateSha256Hash(hashData, info.MasterHash);
        AddSectionUpdateFsEntry(index, rawStorage);
    }

    private byte[] CalcHashTable(int hashBlockSize, IStorage dataStorage)
    {
        dataStorage.GetSize(out long dataSize).ThrowIfFailure();
        var blocks = BitUtil.DivideUp(dataSize, hashBlockSize);
        var hashData = new byte[Sha256.DigestSize * blocks];

        var ofs = 0;
        var blk = 0;
        var buffer = new byte[hashBlockSize];
        while (ofs < dataSize)
        {
            var toRead = (int)Math.Min(hashBlockSize, dataSize - ofs);
            var data = buffer.AsSpan(0, toRead);
            var hash = hashData.AsSpan(blk * Sha256.DigestSize, Sha256.DigestSize);
            dataStorage.Read(ofs, data).ThrowIfFailure();
            Sha256.GenerateSha256Hash(data, hash);
            ofs += toRead;
            blk++;
        }

        return hashData;
    }

    private void CopyRomFs(Nca baseNca, Nca patchNca)
    {
        const int index = 1;
        // copy patched(base+update) RomFS section (layered something) and 
        var section = baseNca.OpenRawStorageWithPatch(patchNca, NcaSectionType.Data);
        AddSectionUpdateFsEntry(index, section);

        // copy update RomFS FsHeader
        var fsHeader = CopyFsHeader(patchNca, index);
        fsHeader.EncryptionType = NcaEncryptionType.None;
        // wipe patch flag
        var patchInfoData = Header.GetFsHeaderUncheck(index).Slice(
            NcaFsHeader.FsHeaderStruct.PatchInfoOffset,
            NcaFsHeader.FsHeaderStruct.PatchInfoSize);
        patchInfoData.Span.Clear();
    }

    /// <summary>
    /// Write Section, Update FsEntry
    /// </summary>
    /// <param name="index"></param>
    /// <param name="section"></param>
    private void AddSectionUpdateFsEntry(int index, IStorage section)
    {
        ref var entry = ref Header.GetSectionEntry(index);
        if (entry.IsEnabled)
            throw new InvalidOperationException($"Section {index} already added!");

        section.GetSize(out long size).ThrowIfFailure();
        Builder.Add(section, AlignedSize);
        entry.StartBlock = Blocks;
        Size += size;
        entry.EndBlock = Blocks;
        entry.IsEnabled = true;
    }

    /// <summary>
    /// Update Hash for FsHeader 
    /// </summary>
    /// <param name="i"></param>
    private void FsHeaderDoHash(int i)
    {
        Span<byte> hash = stackalloc byte[Sha256.DigestSize];
        Sha256.GenerateSha256Hash(Header.GetFsHeaderUncheck(i).Span, hash);
        hash.CopyTo(Header.GetFsHeaderHash(i));
    }
}