"""
Unit tests for Module 2c: ML Asset Serialization.
"""

import os
from unittest.mock import MagicMock, patch

from btech.save_model import load_assets, save_assets


@patch("joblib.dump")
def test_save_assets(mock_joblib_dump: MagicMock) -> None:
    """Verify save_assets calls joblib.dump for both model and preprocessor."""
    model = MagicMock()
    preprocessor = MagicMock()

    save_assets(model, preprocessor, "test_model.joblib", "test_preprocessor.joblib")

    assert mock_joblib_dump.call_count == 2
    mock_joblib_dump.assert_any_call(model, "test_model.joblib")
    mock_joblib_dump.assert_any_call(preprocessor, "test_preprocessor.joblib")


@patch("joblib.load")
@patch("os.path.exists")
def test_load_assets(mock_exists: MagicMock, mock_joblib_load: MagicMock) -> None:
    """Verify load_assets calls joblib.load if paths exist, else returns None."""
    # 1. Test when files exist
    mock_exists.return_value = True
    mock_model = MagicMock()
    mock_preprocessor = MagicMock()
    mock_joblib_load.side_effect = [mock_model, mock_preprocessor]

    m, p = load_assets("test_model.joblib", "test_preprocessor.joblib")
    assert m == mock_model
    assert p == mock_preprocessor
    assert mock_joblib_load.call_count == 2

    # 2. Test when files do not exist
    mock_exists.return_value = False
    mock_joblib_load.reset_mock()
    m2, p2 = load_assets("test_model.joblib", "test_preprocessor.joblib")
    assert m2 is None
    assert p2 is None
    mock_joblib_load.assert_not_called()
