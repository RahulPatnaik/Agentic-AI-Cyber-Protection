"""
ML Inference Engine
Async inference with Random Forest + Isolation Forest ensemble
"""

import asyncio
import pickle
from pathlib import Path
from typing import Optional, List, Dict, Any
from datetime import datetime
import numpy as np
import structlog

from src.models.network import PacketFeatures
from src.models.alerts import MLPrediction, ThreatType
from src.config.settings import Settings

logger = structlog.get_logger()


class MLEnsemble:
    """
    ML ensemble for threat detection.
    Combines Random Forest (classification) and Isolation Forest (anomaly detection).
    """

    def __init__(self, config: Settings):
        """
        Initialize ML ensemble.

        Args:
            config: Application settings
        """
        self.config = config
        self.random_forest = None
        self.isolation_forest = None
        self.scaler = None
        self.label_encoders = None
        self.metadata = None
        self.is_loaded = False

        # Model metadata (default threat classes)
        self.threat_classes = [
            ThreatType.MITM_ATTACK.value,
            ThreatType.DEAUTH_ATTACK.value,
            ThreatType.EVIL_TWIN.value,
            ThreatType.DNS_SPOOFING.value,
            ThreatType.ROGUE_AP.value,
            "benign"
        ]

    @classmethod
    async def load_from_disk(cls, config: Settings) -> "MLEnsemble":
        """
        Load trained models from disk.

        Args:
            config: Application settings

        Returns:
            MLEnsemble instance with loaded models
        """
        ensemble = cls(config)

        models_path = Path(config.ml_models_path)
        rf_path = models_path / "random_forest.pkl"
        if_path = models_path / "isolation_forest.pkl"
        scaler_path = models_path / "scaler.pkl"
        encoders_path = models_path / "label_encoders.pkl"
        metadata_path = models_path / "model_metadata.pkl"

        try:
            # Load models in thread pool to avoid blocking
            if rf_path.exists():
                ensemble.random_forest = await asyncio.to_thread(
                    cls._load_model, rf_path
                )
                logger.info("Loaded Random Forest model", path=str(rf_path))

            if if_path.exists():
                ensemble.isolation_forest = await asyncio.to_thread(
                    cls._load_model, if_path
                )
                logger.info("Loaded Isolation Forest model", path=str(if_path))

            # Load scaler
            if scaler_path.exists():
                ensemble.scaler = await asyncio.to_thread(
                    cls._load_model, scaler_path
                )
                logger.info("Loaded feature scaler", path=str(scaler_path))

            # Load label encoders
            if encoders_path.exists():
                ensemble.label_encoders = await asyncio.to_thread(
                    cls._load_model, encoders_path
                )
                logger.info("Loaded label encoders", path=str(encoders_path))

            # Load metadata
            if metadata_path.exists():
                ensemble.metadata = await asyncio.to_thread(
                    cls._load_model, metadata_path
                )
                ensemble.threat_classes = ensemble.metadata.get('threat_types', ensemble.threat_classes)
                logger.info("Loaded model metadata",
                           accuracy=f"{ensemble.metadata.get('ensemble_accuracy', 0)*100:.2f}%")

            ensemble.is_loaded = True

        except Exception as e:
            logger.warning(
                "Failed to load ML models, using mock predictions",
                error=str(e)
            )
            # Models will remain None, predict() will use mock logic

        return ensemble

    @staticmethod
    def _load_model(path: Path) -> Any:
        """Load pickled model from disk"""
        with open(path, 'rb') as f:
            return pickle.load(f)

    def _map_to_nslkdd_features(self, features: PacketFeatures) -> np.ndarray:
        """
        Map WiFi PacketFeatures to NSL-KDD feature format.

        NSL-KDD features (15 total):
        1. duration, 2. src_bytes, 3. dst_bytes, 4. count, 5. srv_count,
        6. serror_rate, 7. rerror_rate, 8. same_srv_rate, 9. diff_srv_rate,
        10. srv_diff_host_rate, 11. dst_host_count, 12. dst_host_srv_count,
        13. protocol_type_encoded, 14. service_encoded, 15. flag_encoded

        Args:
            features: WiFi PacketFeatures

        Returns:
            Numpy array with 15 features matching NSL-KDD format
        """
        # Map WiFi features to NSL-KDD equivalents (best effort)
        feature_vector = [
            features.flow_duration or 0.0,  # duration
            float(features.packet_size),     # src_bytes
            float(features.packet_size),     # dst_bytes (approx)
            features.packet_rate or 10.0,    # count (packets per window)
            features.packet_rate or 10.0,    # srv_count (approx)
            0.0,                              # serror_rate (not available in WiFi)
            0.0,                              # rerror_rate (not available)
            0.8,                              # same_srv_rate (default)
            0.2,                              # diff_srv_rate (default)
            0.1,                              # srv_diff_host_rate (default)
            float(features.unique_dst_ips or 1),  # dst_host_count
            float(features.unique_dst_ips or 1),  # dst_host_srv_count
            self._encode_protocol(features.protocol),  # protocol_type_encoded
            0.0,                              # service_encoded (HTTP equiv)
            0.0                               # flag_encoded (SF equiv)
        ]

        return np.array(feature_vector).reshape(1, -1)

    def _encode_protocol(self, protocol: str) -> float:
        """
        Encode protocol string to numeric value.
        Maps WiFi protocols to NSL-KDD protocol types (tcp=0, udp=1, icmp=2)
        """
        protocol_map = {
            'TCP': 0.0,
            'UDP': 1.0,
            'ICMP': 2.0,
            'ARP': 1.0,  # Map ARP to UDP
            'DNS': 1.0,  # Map DNS to UDP
        }
        return protocol_map.get(protocol, 0.0)

    async def predict(self, features: PacketFeatures) -> MLPrediction:
        """
        Run ensemble prediction on packet features.

        Args:
            features: Extracted packet features

        Returns:
            MLPrediction with ensemble results
        """
        try:
            if self.random_forest is not None and self.scaler is not None:
                # Use real models with NSL-KDD feature mapping
                feature_vector = self._map_to_nslkdd_features(features)

                # Apply scaling
                feature_vector_scaled = self.scaler.transform(feature_vector)

                # Predict with Random Forest
                rf_prediction = await self._predict_random_forest(feature_vector_scaled)

                # Predict anomaly score if Isolation Forest available
                if self.isolation_forest is not None:
                    anomaly_score = await self._predict_isolation_forest(feature_vector_scaled)
                    rf_prediction.anomaly_score = anomaly_score

                return rf_prediction
            else:
                # Use mock prediction for development
                return await self._mock_predict(features)

        except Exception as e:
            logger.error("Prediction failed", error=str(e))
            # Return benign prediction on error
            return MLPrediction(
                model_name="ensemble",
                prediction="benign",
                confidence=0.5,
                anomaly_score=0.0
            )

    async def _predict_random_forest(self, feature_vector: np.ndarray) -> MLPrediction:
        """
        Predict using Random Forest model.

        Args:
            feature_vector: Numpy array of features

        Returns:
            MLPrediction instance
        """
        # Run prediction in thread pool (sklearn is blocking)
        prediction = await asyncio.to_thread(
            self.random_forest.predict, feature_vector
        )
        probabilities = await asyncio.to_thread(
            self.random_forest.predict_proba, feature_vector
        )

        predicted_class = prediction[0]
        probs_list = probabilities[0].tolist()
        confidence = max(probs_list)

        return MLPrediction(
            model_name="random_forest",
            prediction=self.threat_classes[predicted_class] if isinstance(predicted_class, int) else str(predicted_class),
            confidence=float(confidence),
            probabilities=probs_list
        )

    async def _predict_isolation_forest(self, feature_vector: np.ndarray) -> float:
        """
        Predict anomaly score using Isolation Forest.

        Args:
            feature_vector: Numpy array of features

        Returns:
            Anomaly score (-1 for outlier, 1 for inlier)
        """
        score = await asyncio.to_thread(
            self.isolation_forest.score_samples, feature_vector
        )
        return float(score[0])

    async def _mock_predict(self, features: PacketFeatures) -> MLPrediction:
        """
        Mock prediction for development/testing when models not available.
        Uses heuristic rules to simulate threat detection.

        Args:
            features: PacketFeatures instance

        Returns:
            MLPrediction with mock results
        """
        # Simple heuristics for mock detection
        is_suspicious = False
        threat_type = "benign"
        confidence = 0.9

        # Heuristic 1: High packet rate (possible DoS)
        if features.packet_rate and features.packet_rate > 1000:
            is_suspicious = True
            threat_type = ThreatType.DOS_ATTACK.value
            confidence = 0.92

        # Heuristic 2: Unusual destination diversity (possible scanning)
        if features.unique_dst_ips and features.unique_dst_ips > 50:
            is_suspicious = True
            threat_type = ThreatType.ROGUE_AP.value
            confidence = 0.88

        # Heuristic 3: Large inter-arrival time variance (possible injection)
        if features.std_packet_size and features.std_packet_size > 500:
            is_suspicious = True
            threat_type = ThreatType.PACKET_INJECTION.value
            confidence = 0.85

        # Heuristic 4: Low RSSI with high traffic (possible evil twin)
        if features.rssi and features.rssi < -70 and features.packet_rate and features.packet_rate > 100:
            is_suspicious = True
            threat_type = ThreatType.EVIL_TWIN.value
            confidence = 0.87

        # Random variation for realism
        import random
        confidence += random.uniform(-0.05, 0.05)
        confidence = max(0.0, min(1.0, confidence))

        return MLPrediction(
            model_name="mock_rf",
            prediction=threat_type,
            confidence=confidence if is_suspicious else 0.95,
            probabilities=[1 - confidence, confidence] if is_suspicious else [0.95, 0.05],
            anomaly_score=-0.8 if is_suspicious else 0.2
        )

    def ensemble_vote(
        self,
        rf_prediction: MLPrediction,
        anomaly_score: Optional[float] = None
    ) -> tuple[str, float]:
        """
        Combine Random Forest and Isolation Forest predictions.

        Args:
            rf_prediction: Random Forest prediction
            anomaly_score: Isolation Forest anomaly score

        Returns:
            Tuple of (final_prediction, combined_confidence)
        """
        # If anomaly score indicates outlier and RF predicts threat
        if anomaly_score and anomaly_score < -0.5:
            # High anomaly, boost confidence if RF predicts malicious
            if rf_prediction.prediction != "benign":
                boosted_confidence = min(1.0, rf_prediction.confidence * 1.1)
                return rf_prediction.prediction, boosted_confidence

        # Default to RF prediction
        return rf_prediction.prediction, rf_prediction.confidence

    async def predict_batch(self, features_list: List[PacketFeatures]) -> List[MLPrediction]:
        """
        Predict on a batch of features (more efficient).

        Args:
            features_list: List of PacketFeatures

        Returns:
            List of MLPrediction instances
        """
        # For MVP, process sequentially
        # TODO: Optimize with true batch processing for production
        predictions = []
        for features in features_list:
            prediction = await self.predict(features)
            predictions.append(prediction)

        return predictions

    def get_model_info(self) -> Dict[str, Any]:
        """Get information about loaded models"""
        return {
            "random_forest_loaded": self.random_forest is not None,
            "isolation_forest_loaded": self.isolation_forest is not None,
            "is_loaded": self.is_loaded,
            "threat_classes": self.threat_classes,
            "using_mock": self.random_forest is None
        }
