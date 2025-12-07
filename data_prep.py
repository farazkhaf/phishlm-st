import os
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from typing import Tuple, List
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


def load_dataset(dataset_path: str) -> pd.DataFrame:
    """
    Load the phishing dataset from CSV file.
    
    Args:
        dataset_path: Path to the CSV file
        
    Returns:
        DataFrame with all columns
        
    Raises:
        FileNotFoundError: If dataset file doesn't exist
        ValueError: If required columns are missing
    """
    if not os.path.exists(dataset_path):
        raise FileNotFoundError(f"Dataset not found at: {dataset_path}")
    
    logger.info(f"Loading dataset from: {dataset_path}")
    df = pd.read_csv(dataset_path)
    
    required_columns = [
        'URL', 'url_length', 'has_ip_address', 'dot_count', 'https_flag',
        'url_entropy', 'token_count', 'subdomain_count', 'query_param_count',
        'tld_length', 'path_length', 'has_hyphen_in_domain', 'number_of_digits',
        'tld_popularity', 'suspicious_file_extension', 'domain_name_length',
        'percentage_numeric_chars', 'ClassLabel'
    ]
    
    missing_cols = [col for col in required_columns if col not in df.columns]
    if missing_cols:
        raise ValueError(f"Missing required columns: {missing_cols}")
    
    logger.info(f"Dataset loaded: {len(df)} rows, {len(df.columns)} columns")
    
    return df


def clean_data(df: pd.DataFrame) -> pd.DataFrame:
    """
    Clean the dataset by removing missing values and invalid entries.
    
    Args:
        df: Raw DataFrame
        
    Returns:
        Cleaned DataFrame
    """
    initial_rows = len(df)
    
    df = df.dropna(subset=['ClassLabel'])
    
    df = df.dropna(subset=['URL'])
    
    df = df.drop_duplicates(subset=['URL'], keep='first')
    
    # Ensure ClassLabel is binary (0 or 1)
    df = df[df['ClassLabel'].isin([0.0, 1.0])]
    
    df['ClassLabel'] = df['ClassLabel'].astype(int)
    
    rows_removed = initial_rows - len(df)
    logger.info(f"Data cleaning: removed {rows_removed} rows, {len(df)} rows remaining")
    
    return df


def balance_and_sample(df: pd.DataFrame, samples_per_class: int = 5000) -> pd.DataFrame:
    """
    Create a balanced sample with equal number of phishing and legitimate URLs.
    
    Args:
        df: Cleaned DataFrame
        samples_per_class: Number of samples to take from each class
        
    Returns:
        Balanced DataFrame
    """
    class_counts = df['ClassLabel'].value_counts()
    logger.info(f"Class distribution before sampling:\n{class_counts}")
    
    min_class_count = class_counts.min()
    if samples_per_class > min_class_count:
        logger.warning(
            f"Requested {samples_per_class} samples per class, but only {min_class_count} "
            f"available in minority class. Using {min_class_count} samples per class."
        )
        samples_per_class = min_class_count
    
    phishing = df[df['ClassLabel'] == 0].sample(n=samples_per_class, random_state=42)
    legitimate = df[df['ClassLabel'] == 1].sample(n=samples_per_class, random_state=42)
    
    # Combine and shuffle order
    balanced_df = pd.concat([phishing, legitimate], ignore_index=True)
    balanced_df = balanced_df.sample(frac=1, random_state=42).reset_index(drop=True)
    
    
    return balanced_df


def prepare_features_and_labels(df: pd.DataFrame) -> Tuple[pd.DataFrame, np.ndarray, List[str]]:
    """
    Separate features and labels from DataFrame.
    
    Args:
        df: DataFrame with features and ClassLabel
        
    Returns:
        Tuple of (features_df, labels_array, feature_names_list)
    """

    feature_columns = [
        'url_length', 'has_ip_address', 'dot_count', 'https_flag',
        'url_entropy', 'token_count', 'subdomain_count', 'query_param_count',
        'tld_length', 'path_length', 'has_hyphen_in_domain', 'number_of_digits',
        'tld_popularity', 'suspicious_file_extension', 'domain_name_length',
        'percentage_numeric_chars'
    ]
    
    X = df[feature_columns].copy()
    
    y = df['ClassLabel'].values
    
    logger.info(f"Features prepared: {X.shape[0]} samples, {X.shape[1]} features")
    logger.info(f"Feature names: {feature_columns}")
    
    return X, y, feature_columns


def split_data(
    X: pd.DataFrame,
    y: np.ndarray,
    test_size: float = 0.2,
    random_state: int = 42
) -> Tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray]:

    X_train, X_test, y_train, y_test = train_test_split(
        X.values,
        y,
        test_size=test_size,
        random_state=random_state,
        stratify=y  
    )
    
    logger.info(f"Data split: {len(X_train)} training, {len(X_test)} testing samples")
    logger.info(f"Training class distribution: "
                f"Phishing={sum(y_train==0)}, Legitimate={sum(y_train==1)}")
    logger.info(f"Testing class distribution: "
                f"Phishing={sum(y_test==0)}, Legitimate={sum(y_test==1)}")
    
    return X_train, X_test, y_train, y_test


def get_feature_statistics(X: pd.DataFrame) -> pd.DataFrame:
    stats = X.describe().T
    stats['missing'] = X.isnull().sum()
    
    logger.info("\nFeature Statistics:")
    logger.info(f"\n{stats.to_string()}")
    
    return stats


def prepare_ml_data(
    dataset_path: str,
    samples_per_class: int = 5000,
    test_size: float = 0.2,
    random_state: int = 42
) -> Tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray, List[str]]:
    """
    Complete data preparation pipeline.
    
    Args:
        dataset_path: Path to CSV dataset file
        samples_per_class: Number of samples per class for balanced dataset
        test_size: Proportion of data for testing
        random_state: Random seed for reproducibility
        
    Returns:
        Tuple of (X_train, X_test, y_train, y_test, feature_names)
    """
    
    df = load_dataset(dataset_path)
    
    df = clean_data(df)
    
    df = balance_and_sample(df, samples_per_class=samples_per_class)
    
    X, y, feature_names = prepare_features_and_labels(df)
    
    get_feature_statistics(X)
    
    X_train, X_test, y_train, y_test = split_data(
        X, y, test_size=test_size, random_state=random_state
    )
    
    logger.info("="*60)
    logger.info("Data Preparation Complete")
    logger.info("="*60)
    
    return X_train, X_test, y_train, y_test, feature_names



if __name__ == "__main__":
    dataset_path = "data/phishing_dataset.csv"
    
    if os.path.exists(dataset_path):
        try:
            X_train, X_test, y_train, y_test, feature_names = prepare_ml_data(
                dataset_path=dataset_path,
                samples_per_class=5000,
                test_size=0.2
            )
            
            print("\n" + "="*60)
            print("SUMMARY")
            print("="*60)
            print(f"Training set: {X_train.shape}")
            print(f"Testing set: {X_test.shape}")
            print(f"Number of features: {len(feature_names)}")
            print(f"Features: {feature_names}")
            
        except Exception as e:
            logger.error(f"Error in data prep: {e}")
    else:
        logger.warning(f"Dataset not found at {dataset_path}")
        logger.info(" provide the correct path.")