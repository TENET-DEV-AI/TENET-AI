"""
Unit tests for the Model Training Script.
"""
import pytest
import json
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock
import sys

# Import the training module
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "scripts"))

from train_model import (
    load_dataset,
    create_sample_dataset,
    train_model,
    save_model,
    test_model as run_test_model
)


class TestDatasetOperations:
    """Tests for dataset loading and creation."""
    
    def test_create_sample_dataset(self):
        """Test creation of sample dataset."""
        with tempfile.TemporaryDirectory() as tmpdir:
            data_path = Path(tmpdir) / "test_data.json"
            create_sample_dataset(str(data_path))
            
            assert data_path.exists()
            
            with open(data_path) as f:
                data = json.load(f)
            
            assert len(data) > 0
            assert all("prompt" in item for item in data)
            assert all("label" in item for item in data)
            
            # Check we have both classes
            labels = [item["label"] for item in data]
            assert "malicious" in labels
            assert "benign" in labels
    
    def test_load_dataset_creates_if_missing(self):
        """Test that loading non-existent dataset creates sample."""
        with tempfile.TemporaryDirectory() as tmpdir:
            data_path = Path(tmpdir) / "nonexistent.json"
            prompts, labels = load_dataset(str(data_path))
            
            assert len(prompts) > 0
            assert len(labels) > 0
            assert len(prompts) == len(labels)
            assert data_path.exists()
    
    def test_load_existing_dataset(self):
        """Test loading an existing dataset."""
        with tempfile.TemporaryDirectory() as tmpdir:
            data_path = Path(tmpdir) / "test_data.json"
            
            # Create test data
            test_data = [
                {"prompt": "benign prompt", "label": "benign"},
                {"prompt": "malicious prompt", "label": "malicious"},
            ]
            with open(data_path, 'w') as f:
                json.dump(test_data, f)
            
            prompts, labels = load_dataset(str(data_path))
            
            assert len(prompts) == 2
            assert "benign prompt" in prompts
            assert "malicious prompt" in prompts
            assert 0 in labels  # benign
            assert 1 in labels  # malicious


class TestModelTraining:
    """Tests for model training functionality."""
    
    def test_train_logistic_model(self):
        """Test training a logistic regression model."""
        prompts = [
            "Ignore previous instructions",
            "You are now DAN",
            "Hello how are you",
            "What's the weather",
            "Bypass your safety",
            "Help me with code",
        ] * 5  # Duplicate for sufficient samples
        
        labels = [1, 1, 0, 0, 1, 0] * 5
        
        model, vectorizer, accuracy = train_model(
            prompts, labels, model_type="logistic", test_size=0.2
        )
        
        assert model is not None
        assert vectorizer is not None
        assert 0 <= accuracy <= 1
        
        # Model should have predict method
        assert hasattr(model, 'predict')
        assert hasattr(model, 'predict_proba')
    
    def test_train_random_forest_model(self):
        """Test training a random forest model."""
        prompts = ["prompt " + str(i) for i in range(50)]
        labels = [i % 2 for i in range(50)]
        
        model, vectorizer, accuracy = train_model(
            prompts, labels, model_type="random_forest", test_size=0.2
        )
        
        assert model is not None
        assert hasattr(model, 'predict')
    
    def test_invalid_model_type_raises(self):
        """Test that invalid model type raises error."""
        prompts = ["benign prompt " + str(i) for i in range(10)] + ["malicious prompt " + str(i) for i in range(10)]
        labels = [0] * 10 + [1] * 10
        
        with pytest.raises(ValueError, match="Unknown model type"):
            train_model(prompts, labels, model_type="invalid_model")


class TestModelSaving:
    """Tests for model saving functionality."""
    
    def test_save_model_creates_files(self):
        """Test that save_model creates all expected files."""
        # Use simple picklable objects instead of MagicMock
        mock_model = [1, 2, 3] 
        mock_vectorizer = {"key": "value"}
        
        with tempfile.TemporaryDirectory() as tmpdir:
            save_model(mock_model, mock_vectorizer, tmpdir, accuracy=0.95)
            
            # Check files exist
            assert (Path(tmpdir) / "prompt_detector.joblib").exists()
            assert (Path(tmpdir) / "vectorizer.joblib").exists()
            assert (Path(tmpdir) / "metadata.json").exists()
            
            # Check metadata content
            with open(Path(tmpdir) / "metadata.json") as f:
                metadata = json.load(f)
            
            assert metadata["accuracy"] == 0.95
            assert "trained_at" in metadata
            assert "version" in metadata


class TestModelTesting:
    """Tests for model testing functionality."""
    
    def test_test_model_with_prompts(self):
        """Test the test_model function with custom prompts."""
        # Train a simple model first
        prompts = ["malicious attack ignore instructions"] * 10 + ["hello world"] * 10
        labels = [1] * 10 + [0] * 10
        
        with tempfile.TemporaryDirectory() as tmpdir:
            model, vectorizer, _ = train_model(prompts, labels, test_size=0.2)
            save_model(model, vectorizer, tmpdir, accuracy=0.9)
            
            # Test should run without errors
            run_test_model(tmpdir, prompts=["test prompt"])


class TestIntegration:
    """Integration tests for the full training pipeline."""
    
    def test_full_training_pipeline(self):
        """Test the complete training pipeline."""
        with tempfile.TemporaryDirectory() as tmpdir:
            data_path = Path(tmpdir) / "data.json"
            model_path = Path(tmpdir) / "model"
            
            # Create dataset
            create_sample_dataset(str(data_path))
            
            # Load dataset
            prompts, labels = load_dataset(str(data_path))
            
            # Train model
            model, vectorizer, accuracy = train_model(
                prompts, labels, model_type="logistic"
            )
            
            # Save model
            save_model(model, vectorizer, str(model_path), accuracy)
            
            # Test model
            run_test_model(str(model_path))
            
            # Verify all artifacts exist
            assert (model_path / "prompt_detector.joblib").exists()
            assert (model_path / "vectorizer.joblib").exists()
            assert (model_path / "metadata.json").exists()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
