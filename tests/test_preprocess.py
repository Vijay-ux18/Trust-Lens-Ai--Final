"""
Unit tests for Module 1: Preprocessing & Feature Extraction.
"""

from unittest.mock import MagicMock, patch

import pandas as pd
import pefile
import pytest

from btech.preprocess import (
    calculate_entropy,
    extract_pe_features,
    preprocess_dataset,
)


def test_calculate_entropy_empty() -> None:
    """Ensure empty bytes stream returns 0.0 entropy."""
    assert calculate_entropy(b"") == 0.0


def test_calculate_entropy_uniform() -> None:
    """Ensure zero entropy for uniform bytes."""
    # Log2(1) = 0
    assert calculate_entropy(b"aaaaaaa") == 0.0


def test_calculate_entropy_standard() -> None:
    """Check entropy calculations for known distributions."""
    # 4 distinct characters, frequency 0.25 each
    # Entropy = -4 * (0.25 * log2(0.25)) = 2.0
    data = b"abcd"
    assert calculate_entropy(data) == 2.0


def test_preprocess_dataset_cleaning() -> None:
    """Test dropping of identifiers, duplicates, and resolving contradictions."""
    # Create raw dataframe representing input CSV
    raw_data = {
        "Name": ["file1.exe", "file2.exe", "file3.exe", "file3.exe", "file4.exe"],
        "md5": ["hash1", "hash2", "hash3", "hash3", "hash4"],
        "Machine": [332, 332, 332, 332, 332],
        "legitimate": [1, 0, 1, 0, 1],  # hash3 has contradictory labels (1 and 0)
    }
    df = pd.DataFrame(raw_data)

    X, y = preprocess_dataset(df)

    # 1. Assert metadata and label columns dropped from features X
    assert "Name" not in X.columns
    assert "md5" not in X.columns
    assert "legitimate" not in X.columns

    # 2. Assert contradictory hash3 records are entirely removed
    # Remaining hashes should be hash1, hash2, and hash4
    assert len(X) == 3
    assert len(y) == 3

    # 3. Check clean alignment of features and labels
    assert list(y) == [1, 0, 1]


def test_extract_pe_features_invalid_file() -> None:
    """Verify pefile raises an error on non-PE formats (e.g. text/ELF)."""
    with pytest.raises(pefile.PEFormatError):
        extract_pe_features(b"this is plain text, not a PE executable")


@patch("pefile.PE")
def test_extract_pe_features_mock(mock_pe_class: MagicMock) -> None:
    """Verify feature extractor correctly maps fields from pefile object using a Mock PE."""
    # Set up mock PE instance hierarchy
    mock_pe = MagicMock()
    mock_pe_class.return_value = mock_pe

    mock_pe.FILE_HEADER.Machine = 332
    mock_pe.FILE_HEADER.SizeOfOptionalHeader = 224
    mock_pe.FILE_HEADER.Characteristics = 258

    mock_pe.OPTIONAL_HEADER.MajorLinkerVersion = 14
    mock_pe.OPTIONAL_HEADER.MinorLinkerVersion = 0
    mock_pe.OPTIONAL_HEADER.SizeOfCode = 1000
    mock_pe.OPTIONAL_HEADER.SizeOfInitializedData = 5000
    mock_pe.OPTIONAL_HEADER.SizeOfUninitializedData = 0
    mock_pe.OPTIONAL_HEADER.AddressOfEntryPoint = 4096
    mock_pe.OPTIONAL_HEADER.BaseOfCode = 4096
    mock_pe.OPTIONAL_HEADER.BaseOfData = 8192
    mock_pe.OPTIONAL_HEADER.ImageBase = 4194304
    mock_pe.OPTIONAL_HEADER.SectionAlignment = 4096
    mock_pe.OPTIONAL_HEADER.FileAlignment = 512
    mock_pe.OPTIONAL_HEADER.MajorOperatingSystemVersion = 6
    mock_pe.OPTIONAL_HEADER.MinorOperatingSystemVersion = 0
    mock_pe.OPTIONAL_HEADER.MajorImageVersion = 0
    mock_pe.OPTIONAL_HEADER.MinorImageVersion = 0
    mock_pe.OPTIONAL_HEADER.MajorSubsystemVersion = 6
    mock_pe.OPTIONAL_HEADER.MinorSubsystemVersion = 0
    mock_pe.OPTIONAL_HEADER.SizeOfImage = 16384
    mock_pe.OPTIONAL_HEADER.SizeOfHeaders = 1024
    mock_pe.OPTIONAL_HEADER.CheckSum = 12345
    mock_pe.OPTIONAL_HEADER.Subsystem = 2
    mock_pe.OPTIONAL_HEADER.DllCharacteristics = 32768
    mock_pe.OPTIONAL_HEADER.SizeOfStackReserve = 1048576
    mock_pe.OPTIONAL_HEADER.SizeOfStackCommit = 4096
    mock_pe.OPTIONAL_HEADER.SizeOfHeapReserve = 1048576
    mock_pe.OPTIONAL_HEADER.SizeOfHeapCommit = 4096
    mock_pe.OPTIONAL_HEADER.LoaderFlags = 0
    mock_pe.OPTIONAL_HEADER.NumberOfRvaAndSizes = 16

    # Mock sections
    sec1 = MagicMock()
    sec1.SizeOfRawData = 1000
    sec1.Misc_VirtualSize = 1024
    sec1.get_data.return_value = b"\x00" * 100
    mock_pe.sections = [sec1]

    # Mock imports
    imp_entry = MagicMock()
    imp = MagicMock()
    imp.name = b"CreateFileA"
    imp_entry.imports = [imp]
    mock_pe.DIRECTORY_ENTRY_IMPORT = [imp_entry]

    # Mock empty exports and resources
    del mock_pe.DIRECTORY_ENTRY_EXPORT
    del mock_pe.DIRECTORY_ENTRY_RESOURCE
    mock_pe.DIRECTORY_ENTRY_ACTIVE_CONFIG = []

    features = extract_pe_features(b"dummy_bytes")

    # Assert values mapped correctly
    assert features["Machine"] == 332
    assert features["SectionsNb"] == 1
    assert features["ImportsNb"] == 1
    assert features["ImportsNbDLL"] == 1
    assert features["ExportNb"] == 0
    assert features["ResourcesNb"] == 0
