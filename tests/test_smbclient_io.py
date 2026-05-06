# Copyright: (c) 2026, Acconeer AB <henrik.nilsson@acconeer.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import warnings

import pytest

import smbclient._io as io
from smbclient._io import SMBDirectoryIO, SMBRawIO
from smbprotocol.exceptions import (
    AccessDenied,
    BadNetworkName,
    NoSuchFile,
    ObjectNameNotFound,
    SMBOSError,
)
from smbprotocol.header import NtStatus


@pytest.fixture
def raw(mocker):
    """Construct an SMBRawIO without opening any socket.

    SMBRawIO.__init__ normally calls get_smb_tree which establishes a connection.
    Patching that and Open lets the finalizer be exercised deterministically.
    """
    mock_tree = mocker.MagicMock()
    mocker.patch.object(io, "get_smb_tree", return_value=(mock_tree, "file"))
    mocker.patch.object(io, "Open")

    return SMBRawIO(r"\\server\share\file.txt", mode="r", share_access="r")


@pytest.fixture
def directory_io(mocker):
    """Construct an SMBDirectoryIO without opening any socket.

    The constructor normally calls get_smb_tree which establishes a connection.
    Patching that and Open lets the underlying fd be replaced with a mock for
    deterministic enumeration scenarios.
    """
    mock_tree = mocker.MagicMock()
    mocker.patch.object(io, "get_smb_tree", return_value=(mock_tree, "dir"))
    mocker.patch.object(io, "Open")

    return SMBDirectoryIO(r"\\server\share\dir", mode="r", share_access="r")


def test_del_does_not_close_a_connected_handle(raw):
    # The override must skip self.close() to avoid deadlocking the worker.
    raw.fd.connected = True

    with warnings.catch_warnings():
        warnings.simplefilter("ignore", ResourceWarning)
        raw.__del__()

    raw.fd.close.assert_not_called()


def test_del_emits_resource_warning_for_leaked_handle(raw):
    raw.fd.connected = True

    with pytest.warns(ResourceWarning, match=r"unclosed SMB handle"):
        raw.__del__()


@pytest.mark.parametrize(
    ("exc_factory", "expected_status"),
    [
        (BadNetworkName, NtStatus.STATUS_BAD_NETWORK_NAME),
        (ObjectNameNotFound, NtStatus.STATUS_OBJECT_NAME_NOT_FOUND),
        (AccessDenied, NtStatus.STATUS_ACCESS_DENIED),
    ],
)
def test_raw_io_translates_smb_response_to_os_error(mocker, exc_factory, expected_status):
    # Anything escaping get_smb_tree here must surface as OSError so the
    # rmtree, remove, rmdir, and scandir error paths route it correctly.
    mocker.patch.object(io, "get_smb_tree", side_effect=exc_factory())

    path = r"\\server\share\missing"
    with pytest.raises(SMBOSError) as exc_info:
        io.SMBRawIO(path)

    assert exc_info.value.ntstatus == expected_status
    assert exc_info.value.filename == path


def test_query_directory_treats_no_such_file_as_end_of_enumeration(directory_io, mocker):
    # MS-SMB2 3.3.5.18 lists both STATUS_NO_MORE_FILES and STATUS_NO_SUCH_FILE as common
    # return codes for QUERY_DIRECTORY. Both must drain the generator without raising.
    directory_io.fd.query_directory = mocker.MagicMock(side_effect=NoSuchFile(mocker.MagicMock()))

    entries = list(directory_io.query_directory("*", info_class=mocker.MagicMock()))

    assert entries == []
    directory_io.fd.query_directory.assert_called_once()
