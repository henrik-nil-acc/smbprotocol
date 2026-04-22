# Copyright: (c) 2026, Acconeer AB <henrik.nilsson@acconeer.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import warnings

import pytest

import smbclient._io as io
from smbclient._io import SMBRawIO
from smbprotocol.exceptions import (
    AccessDenied,
    BadNetworkName,
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
