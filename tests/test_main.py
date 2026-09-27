"""
Unit tests for Module 4: Main Application & CLI Entrypoint.
"""

from unittest.mock import MagicMock, patch

import pytest

from btech.main import main


def test_main_no_args() -> None:
    """Verify that calling CLI without arguments raises SystemExit."""
    with pytest.raises(SystemExit) as excinfo:
        main([])
    assert excinfo.value.code == 1


@patch("btech.main.run_pipeline")
def test_main_train(mock_run_pipeline: MagicMock) -> None:
    """Verify that 'train' subcommand invokes the training pipeline."""
    main(["train"])
    mock_run_pipeline.assert_called_once()


@patch("btech.main.handle_scan")
def test_main_scan(mock_handle_scan: MagicMock) -> None:
    """Verify that 'scan' subcommand routes to the file scanning handler."""
    main(["scan", "test.exe"])
    mock_handle_scan.assert_called_once_with("test.exe")


@patch("btech.main.handle_ui")
def test_main_ui(mock_handle_ui: MagicMock) -> None:
    """Verify that 'ui' subcommand routes to the Streamlit launcher."""
    main(["ui"])
    mock_handle_ui.assert_called_once()
