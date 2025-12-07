import os
import numpy as np
from typing import Dict, List, Tuple, Optional
import logging

try:
    from catboost import CatBoostClassifier, Pool
except ImportError:
    raise ImportError("catboost is required. Install with: pip install catboost")

from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    accuracy_score
)

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


def train_model(
    X_train: np.ndarray,
    y_train: np.ndarray,
    X_val: Optional[np.ndarray] = None,
    y_val: Optional[np.ndarray] = None,
    model_path: str = "models/phishing_model.cbm",
    iterations: int = 200,
    depth: int = 6,
    learning_rate: float = 0.1,
    verbose: bool = False
) -> CatBoostClassifier:
    
    logger.info("="*60)
    logger.info("Training CatBoost Classifier")
    logger.info("="*60)
    
    model = CatBoostClassifier(
        iterations=iterations,
        depth=depth,
        learning_rate=learning_rate,
        loss_function='Logloss',
        eval_metric='AUC',
        random_seed=42,
        verbose=verbose,
        thread_count=-1,  
        auto_class_weights='Balanced',  
        od_type='Iter',  
        od_wait=20  
    )
    
    logger.info(f"Model parameters:")
    logger.info(f"  Iterations: {iterations}")
    logger.info(f"  Depth: {depth}")
    logger.info(f"  Learning rate: {learning_rate}")
    logger.info(f"  Auto class weights: Balanced")
    
    eval_set = None
    if X_val is not None and y_val is not None:
        eval_set = (X_val, y_val)
        logger.info(f"Using validation set: {X_val.shape[0]} samples")
    
    logger.info(f"Training on {X_train.shape[0]} samples with {X_train.shape[1]} features...")
    
    model.fit(
        X_train,
        y_train,
        eval_set=eval_set,
        verbose=verbose
    )
    
    logger.info("Training complete!")
    
    # Save model
    os.makedirs(os.path.dirname(model_path), exist_ok=True)
    model.save_model(model_path)
    logger.info(f"Model saved to: {model_path}")
    
    return model


def load_model(model_path: str) -> CatBoostClassifier:

    if not os.path.exists(model_path):
        raise FileNotFoundError(f"Model file not found: {model_path}")
    
    logger.info(f"Loading model from: {model_path}")
    model = CatBoostClassifier()
    model.load_model(model_path)
    logger.info("Model loaded successfully")
    
    return model


def predict_proba(
    model: CatBoostClassifier,
    features: Dict[str, float],
    feature_names: List[str]
) -> float:
    
    feature_vector = np.array([features.get(f, 0.0) for f in feature_names])
    feature_vector = feature_vector.reshape(1, -1)
    
    proba = model.predict_proba(feature_vector)[0]
    
    phishing_probability = proba[0]
    
    return phishing_probability


def predict(model: CatBoostClassifier, X: np.ndarray) -> np.ndarray:
    predictions = model.predict(X)
    return predictions.astype(int)


def evaluate_model(
    model: CatBoostClassifier,
    X_test: np.ndarray,
    y_test: np.ndarray,
    verbose: bool = True
) -> Dict[str, float]:
   

    logger.info("Model Evaluation")

    
    y_pred = predict(model, X_test)
    y_pred_proba = model.predict_proba(X_test)[:, 1]  
    
    accuracy = accuracy_score(y_test, y_pred)
    precision = precision_score(y_test, y_pred, average='binary', pos_label=0)  # Phishing as positive
    recall = recall_score(y_test, y_pred, average='binary', pos_label=0)
    f1 = f1_score(y_test, y_pred, average='binary', pos_label=0)
    auc = roc_auc_score(y_test, y_pred_proba)
    
    cm = confusion_matrix(y_test, y_pred)
    
    metrics = {
        'accuracy': accuracy,
        'precision': precision,
        'recall': recall,
        'f1_score': f1,
        'auc_roc': auc
    }
    
    
    return metrics


def get_feature_importance(
    model: CatBoostClassifier,
    feature_names: List[str],
    top_n: int = 10
) -> List[Tuple[str, float]]:
 
    importances = model.get_feature_importance()
    
    feature_importance = list(zip(feature_names, importances))

    feature_importance.sort(key=lambda x: x[1], reverse=True)

    top_features = feature_importance[:top_n]
    

    for rank, (name, importance) in enumerate(top_features, 1):
        logger.info(f"{rank:2d}. {name:30s} {importance:8.2f}")
    
    return top_features


def cross_validate_model(
    X: np.ndarray,
    y: np.ndarray,
    n_folds: int = 5,
    iterations: int = 200,
    depth: int = 6,
    learning_rate: float = 0.1
) -> Dict[str, List[float]]:
    
    from sklearn.model_selection import StratifiedKFold
    
    
    skf = StratifiedKFold(n_splits=n_folds, shuffle=True, random_state=42)
    
    cv_scores = {
        'accuracy': [],
        'precision': [],
        'recall': [],
        'f1_score': [],
        'auc_roc': []
    }
    
    for fold, (train_idx, val_idx) in enumerate(skf.split(X, y), 1):
        logger.info(f"\nFold {fold}/{n_folds}")
        
        X_train_fold, X_val_fold = X[train_idx], X[val_idx]
        y_train_fold, y_val_fold = y[train_idx], y[val_idx]
        
        model = CatBoostClassifier(
            iterations=iterations,
            depth=depth,
            learning_rate=learning_rate,
            loss_function='Logloss',
            random_seed=42,
            verbose=False,
            thread_count=-1,
            auto_class_weights='Balanced'
        )
        
        model.fit(X_train_fold, y_train_fold, verbose=False)
        
        # Evaluate
        metrics = evaluate_model(model, X_val_fold, y_val_fold, verbose=False)
        
        for metric_name, metric_value in metrics.items():
            cv_scores[metric_name].append(metric_value)
        
        logger.info(f"  Accuracy: {metrics['accuracy']:.4f}, AUC: {metrics['auc_roc']:.4f}")
    
    logger.info("Cross-Validation Summary")

    for metric_name, scores in cv_scores.items():
        mean_score = np.mean(scores)
        std_score = np.std(scores)
        logger.info(f"{metric_name:12s}: {mean_score:.4f} ± {std_score:.4f}")
    
    return cv_scores


