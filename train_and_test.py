import os
import sys
from typing import List

from data_prep import prepare_ml_data
from ml_classifier import (
    train_model,
    load_model,
    evaluate_model,
    get_feature_importance,
    predict_proba,
    cross_validate_model
)
from feature_extractor import extract_features


def train_phishing_detector(
    dataset_path: str,
    model_save_path: str = "models/phishing_model.cbm",
    samples_per_class: int = 5000,
    perform_cv: bool = False
):
    print(" PHISHING DETECTION MODEL TRAINING")
    print("="*70)
    
    X_train, X_test, y_train, y_test, feature_names = prepare_ml_data(
        dataset_path=dataset_path,
        samples_per_class=samples_per_class,
        test_size=0.2
    )
    
    if perform_cv:
        cv_scores = cross_validate_model(
            X_train, y_train,
            n_folds=5,
            iterations=200,
            depth=6,
            learning_rate=0.1
        )
    
    model = train_model(
        X_train=X_train,
        y_train=y_train,
        X_val=X_test,
        y_val=y_test,
        model_path=model_save_path,
        iterations=200,
        depth=6,
        learning_rate=0.1,
        verbose=False
    )
    
    metrics = evaluate_model(model, X_test, y_test, verbose=True)
    
    importance = get_feature_importance(model, feature_names, top_n=16)
    
    print(" TRAINING COMPLETE!")
    print("="*70)
    print(f"Model saved to: {model_save_path}")
    print(f"Test Accuracy: {metrics['accuracy']:.4f}")
    print(f"Test AUC-ROC: {metrics['auc_roc']:.4f}")
    
    return model, feature_names


def test_on_new_urls(
    model_path: str,
    feature_names: List[str],
    test_urls: List[str]
):
    print(" TESTING ON NEW URLs")
    print("="*70)
    
    model = load_model(model_path)
    
    for i, url in enumerate(test_urls, 1):
        features = extract_features(url)
        
        phishing_prob = predict_proba(model, features, feature_names)
        legitimate_prob = 1.0 - phishing_prob
        
        if phishing_prob > 0.5:
            prediction = "PHISHING"
            confidence = phishing_prob
        else:
            prediction = "LEGITIMATE"
            confidence = legitimate_prob
        
        print(f"URL: {url}")
        print(f"Prediction: {prediction}")
        print(f"Confidence: {confidence:.2%}")
        print(f"Phishing probability: {phishing_prob:.4f}")
        print(f"Legitimate probability: {legitimate_prob:.4f}")
        
        print("Key Features:")
        print(f"URL Length: {features['url_length']}")
        print(f"HTTPS: {'Yes' if features['https_flag'] else 'No'}")
        print(f"Has IP: {'Yes' if features['has_ip_address'] else 'No'}")
        print(f"Subdomain Count: {features['subdomain_count']}")
        print(f"URL Entropy: {features['url_entropy']:.2f}")
        print(f"Suspicious Extension: {'Yes' if features['suspicious_file_extension'] else 'No'}")


def main():
    DATASET_PATH = "data/phishing_dataset.csv"
    MODEL_PATH = "models/phishing_model.cbm"
    
    if not os.path.exists(DATASET_PATH):
        print(f"Dataset not found at: {DATASET_PATH}")
        return
    
    model, feature_names = train_phishing_detector(
        dataset_path=DATASET_PATH,
        model_save_path=MODEL_PATH,
        samples_per_class=30000,
        perform_cv=False
    )
    
    test_urls = [
        "https://www.google.com/search?q=phishing+detection",
        "https://github.com/anthropics/claude",
        "https://www.wikipedia.org/wiki/Phishing",
        "http://192.168.1.1/secure-login.php?user=admin",
        "https://paypal-security-verify.tk/update.php?id=12345",
        "http://bit.ly.secure-account.xyz/login.exe",
        "https://www.g00gle.com/signin",
        "http://amazon-verify-account-now.free.nf/update/"
    ]
    
    test_on_new_urls(MODEL_PATH, feature_names, test_urls)
    
    print(" ALL DONE!")
    print("You can now use the trained model for inference:")
    print(f"Model: {MODEL_PATH}")
    print(f"Features: {len(feature_names)} features")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("Interrupt.")
        sys.exit(0)
    except Exception as e:
        print(f"ERROR: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)