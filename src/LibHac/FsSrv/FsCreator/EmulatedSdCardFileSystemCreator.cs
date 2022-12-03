﻿using System;
using LibHac.Common;
using LibHac.Fs;
using LibHac.Fs.Fsa;
using LibHac.Util;
using Utility = LibHac.FsSrv.Impl.Utility;

namespace LibHac.FsSrv.FsCreator;

public class EmulatedSdCardFileSystemCreator : ISdCardProxyFileSystemCreator, IDisposable
{
    private const string DefaultPath = "/sdcard";

    private EmulatedSdCard _sdCard;
    private SharedRef<IFileSystem> _rootFileSystem;
    private SharedRef<IFileSystem> _sdCardFileSystem;
    private string _path;

    public EmulatedSdCardFileSystemCreator(EmulatedSdCard sdCard, ref SharedRef<IFileSystem> rootFileSystem)
    {
        _sdCard = sdCard;
        _rootFileSystem = SharedRef<IFileSystem>.CreateMove(ref rootFileSystem);
    }

    public EmulatedSdCardFileSystemCreator(EmulatedSdCard sdCard, ref SharedRef<IFileSystem> rootFileSystem, string path)
    {
        _sdCard = sdCard;
        _rootFileSystem = SharedRef<IFileSystem>.CreateMove(ref rootFileSystem);
        _path = path;
    }

    public void Dispose()
    {
        _rootFileSystem.Destroy();
        _sdCardFileSystem.Destroy();
    }

    public Result Create(ref SharedRef<IFileSystem> outFileSystem, bool openCaseSensitive)
    {
        if (!_sdCard.IsSdCardInserted())
        {
            return ResultFs.PortSdCardNoDevice.Log();
        }

        if (_sdCardFileSystem.HasValue)
        {
            outFileSystem.SetByCopy(in _sdCardFileSystem);

            return Result.Success;
        }

        if (!_rootFileSystem.HasValue)
        {
            return ResultFs.PreconditionViolation.Log();
        }

        string path = _path ?? DefaultPath;

        using var sdCardPath = new Path();
        Result res = sdCardPath.Initialize(StringUtils.StringToUtf8(path));
        if (res.IsFailure()) return res.Miss();

        var pathFlags = new PathFlags();
        pathFlags.AllowEmptyPath();
        res = sdCardPath.Normalize(pathFlags);
        if (res.IsFailure()) return res.Miss();

        // Todo: Add ProxyFileSystem?

        using SharedRef<IFileSystem> fileSystem = SharedRef<IFileSystem>.CreateCopy(in _rootFileSystem);
        res = Utility.WrapSubDirectory(ref _sdCardFileSystem, ref fileSystem.Ref, in sdCardPath, true);
        if (res.IsFailure()) return res.Miss();

        outFileSystem.SetByCopy(in _sdCardFileSystem);

        return Result.Success;
    }

    public Result Format(bool removeFromFatFsCache)
    {
        throw new NotImplementedException();
    }

    public Result Format()
    {
        throw new NotImplementedException();
    }
}