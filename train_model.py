import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score
from sklearn.preprocessing import LabelEncoder
import joblib
import time
import os
from joblib import Parallel, delayed

def print_with_timestamp(message):
    print(f"{time.strftime('%Y-%m-%d %H:%M:%S')} - {message}")

print_with_timestamp("Loading dataset...")

# Load the dataset in larger chunks
chunksize = 200000  # Adjust the chunk size as needed
chunks = []
for chunk in pd.read_csv('C:\\Users\\SHIVA SATHVIKA\\CascadeProjects\\mini-project-20250127T165325Z-001\\malicious-url-detection\\Dataset.csv', chunksize=chunksize):
    chunks.append(chunk)
print_with_timestamp("Dataset loaded successfully.")

# Initialize the vectorizer, label encoder, and model
vectorizer = TfidfVectorizer()
label_encoder = LabelEncoder()
model = RandomForestClassifier(n_estimators=20, n_jobs=-1)  # Reduced number of estimators for faster training

# Fit the vectorizer on the entire dataset
print_with_timestamp("Fitting vectorizer on the entire dataset...")
all_urls = pd.concat([chunk['url'] for chunk in chunks])
vectorizer.fit(all_urls)
print_with_timestamp("Vectorizer fitted successfully.")

# Ensure the directory exists
os.makedirs('malicious-url-detection', exist_ok=True)

def process_chunk(i, chunk):
    print_with_timestamp(f"Processing chunk {i+1}/{len(chunks)}...")
    
    # Preprocess the dataset
    X = chunk['url']
    y = label_encoder.fit_transform(chunk['type'])
    
    # Vectorize the URLs
    X_vectorized = vectorizer.transform(X)
    
    # Split the dataset into training and testing sets
    X_train, X_test, y_train, y_test = train_test_split(X_vectorized, y, test_size=0.2, random_state=42)
    
    # Train the model incrementally
    model.fit(X_train, y_train)
    
    # Evaluate the model
    y_pred = model.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)
    print_with_timestamp(f'Chunk {i+1} model accuracy: {accuracy * 100:.2f}%')
    
    # Save the intermediate model, vectorizer, and label encoder
    joblib.dump(model, f'malicious-url-detection/model_chunk_{i+1}.pkl')
    joblib.dump(vectorizer, f'malicious-url-detection/vectorizer_chunk_{i+1}.pkl')
    joblib.dump(label_encoder, f'malicious-url-detection/label_encoder_chunk_{i+1}.pkl')
    print_with_timestamp(f"Chunk {i+1} model, vectorizer, and label encoder saved.")

# Process each chunk in parallel
Parallel(n_jobs=-1)(delayed(process_chunk)(i, chunk) for i, chunk in enumerate(chunks))

# Save the final label encoder
joblib.dump(label_encoder, 'malicious-url-detection/label_encoder.pkl')
print_with_timestamp("Final label encoder saved.")
print_with_timestamp("All chunks processed.")
