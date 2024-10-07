# -*- coding: utf-8 -*-
"""IR_CA2.ipynb

Automatically generated by Colab.

Original file is located at
    https://colab.research.google.com/drive/1REXhptBBOJCEddYr8oP0TzfqzbFOxBa1
"""

import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from scipy.sparse import csr_matrix

# Example documents and query
documents = [
    "the cat in the hat",
    "the quick brown fox",
    "the cat and the hat",
    "the quick red fox",
    "the fox and the cat"
]

query = "cat fox"

# Relevance feedback
relevant_docs_indices = [0, 2]  # indices of relevant documents
non_relevant_docs_indices = [1, 3]  # indices of non-relevant documents

# Parameters for Rocchio algorithm
alpha = 1.0
beta = 0.75
gamma = 0.15

# Preprocessing: TF-IDF vectorization
vectorizer = TfidfVectorizer()
tfidf_matrix = vectorizer.fit_transform(documents)
query_vector = vectorizer.transform([query])

# Rocchio Algorithm
def rocchio(query_vector, tfidf_matrix, relevant_indices, non_relevant_indices, alpha, beta, gamma):
    # Compute the centroids of relevant and non-relevant documents
    relevant_docs = tfidf_matrix[relevant_indices]
    non_relevant_docs = tfidf_matrix[non_relevant_indices]

    # Average relevant and non-relevant document vectors
    if len(relevant_indices) > 0:
        relevant_centroid = relevant_docs.mean(axis=0)
    else:
        relevant_centroid = np.zeros(query_vector.shape)

    if len(non_relevant_indices) > 0:
        non_relevant_centroid = non_relevant_docs.mean(axis=0)
    else:
        non_relevant_centroid = np.zeros(query_vector.shape)

    # Rocchio update formula
    new_query_vector = alpha * query_vector + beta * relevant_centroid - gamma * non_relevant_centroid

    return new_query_vector

# Compute the new query vector using Rocchio algorithm
new_query_vector = rocchio(query_vector, tfidf_matrix, relevant_docs_indices, non_relevant_docs_indices, alpha, beta, gamma)

# Print the updated query vector
print("Updated Query Vector (TF-IDF values):")
print(new_query_vector)
# newly added line
new_query_vector = csr_matrix(new_query_vector)

# Ranking documents based on new query vector
def rank_documents(new_query_vector, tfidf_matrix):
    # Compute cosine similarity between new query vector and document vectors
    scores = (tfidf_matrix * new_query_vector.T).toarray().flatten()

    # Rank documents based on scores
    ranked_docs = np.argsort(scores)[::-1]

    for i, doc_index in enumerate(ranked_docs):
        print(f"Rank {i+1}: Document {doc_index+1} (Score: {scores[doc_index]:.4f}) - '{documents[doc_index]}'")

# Rank documents using the updated query vector
rank_documents(new_query_vector, tfidf_matrix)

"""## BIN"""

import numpy as np
import pandas as pd

# Example documents and query
documents = [
    "the cat in the hat",
    "the quick brown fox",
    "the cat and the hat",
    "the quick red fox",
    "the fox and the cat"
]

query = "cat hat"

# Preprocessing: Tokenize documents and query
def tokenize(doc):
    return doc.lower().split()

doc_tokens = [set(tokenize(doc)) for doc in documents]
query_tokens = set(tokenize(query))

# Inverse document frequency calculation
def compute_idf(doc_tokens, num_docs):
    term_doc_count = {}
    for tokens in doc_tokens:
        for token in tokens:
            if token in term_doc_count:
                term_doc_count[token] += 1
            else:
                term_doc_count[token] = 1

    idf = {}
    for term, count in term_doc_count.items():
        idf[term] = np.log((num_docs - count + 0.5) / (count + 0.5))

    return idf

# Binary Independence Model
def compute_bim_score(doc_tokens, query_tokens, idf, num_docs):
    scores = []

    for tokens in doc_tokens:
        score = 0
        for term in query_tokens:
            if term in idf:
                if term in tokens:  # Term is present in document
                    score += idf[term]
                else:  # Term is not present in document
                    score += np.log((0.5) / (num_docs + 0.5))
        scores.append(score)

    return scores

# Main function to compute and rank documents
def rank_documents(documents, query):
    num_docs = len(documents)
    idf = compute_idf(doc_tokens, num_docs)
    scores = compute_bim_score(doc_tokens, query_tokens, idf, num_docs)

    print(scores)

    ranked_docs = np.argsort(scores)[::-1]
    print(ranked_docs)

    for i, doc_index in enumerate(ranked_docs):
        print(f"Rank {i+1}: Document {doc_index+1} (Score: {scores[doc_index]:.4f}) - '{documents[doc_index]}'")

# Rank documents based on query
rank_documents(documents, query)

"""## Preprocessing"""

import pandas as pd

# Load the CSV file using pandas
df = pd.read_csv('your_file.csv')

# Assuming the document text is in a column named 'document'
documents = df['document'].tolist()  # Replace 'document' with the actual column name

def preprocess(text):
  text = re.sub('[^A-Za-z0-9]+   ', '', text)
  text = text.lower()
  text = text.replace("\n"," ")
  text = text.replace("\ufeff","")
  return text

preprocessed_docs = [preprocess(doc) for doc in documents]

def tokenize(text):
    return text.lower().split()

# Tokenize all documents
tokenized_docs = [tokenize(doc) for doc in documents]

word_count = {}

# Iterate over each document
for doc in tokenized_docs:
    for word in doc:
        if word in word_count:
            word_count[word] += 1
        else:
            word_count[word] = 1

threshold = 10  # Adjust this based on your dataset

# Create a set of stopwords based on the threshold
stopwords = {word for word, count in word_count.items() if count > threshold}

# Filter the documents by removing stopwords
filtered_docs = [[word for word in doc if word not in stopwords] for doc in tokenized_docs]

"""## Metrics"""

import numpy as np
from sklearn.metrics import precision_score, recall_score, f1_score, average_precision_score

# Sample relevance judgments (ground truth)
# 1 = relevant, 0 = non-relevant
true_relevance = [1, 0, 1, 1, 0]  # This is the ground truth (relevant or not)
# binary_list = [1] * count_of_ones + [0] * (total_length - count_of_ones)

# # Shuffle the list to randomize the position of 1's and 0's
# random.shuffle(binary_list)

# Assume these are the BM25 scores we computed previously
bm25_scores = [2.2273, 2.0479, 1.9872, 1.7328, 1.4151]

# Binary prediction based on a threshold (e.g., 1.5 for BM25)
threshold = 1.5
predicted_relevance = [1 if score > threshold else 0 for score in bm25_scores]  # Binary classification

# Precision
precision_val = precision_score(true_relevance, predicted_relevance)

# Recall
recall_val = recall_score(true_relevance, predicted_relevance)

# F1-Score
f1_val = f1_score(true_relevance, predicted_relevance)

# Mean Average Precision (MAP) using raw BM25 scores and true relevance labels
map_val = average_precision_score(true_relevance, bm25_scores)

# Output the metrics
print(f"Precision: {precision_val:.4f}")
print(f"Recall: {recall_val:.4f}")
print(f"F1-Score: {f1_val:.4f}")
print(f"Mean Average Precision (MAP): {map_val:.4f}")

"""##BM25 - Same as BIN"""

import numpy as np
import pandas as pd

# Example documents and query
documents = [
    "the cat in the hat",
    "the quick brown fox",
    "the cat and the hat",
    "the quick red fox",
    "the fox and the cat"
]

query = "cat fox"

# Preprocessing: Tokenize documents and query
def tokenize(doc):
    return doc.lower().split()

doc_tokens = [tokenize(doc) for doc in documents]  # Modified from set(tokenize(doc)) to just tokenize(doc) to allow term frequency count
query_tokens = tokenize(query)

# BM25 Parameters (NEW PARAMETERS)
k1 = 1.5  # term frequency saturation, typically between 1.2 and 2
b = 0.75  # length normalization, typically 0.75

# Inverse document frequency calculation for BM25 (MODIFIED)
def compute_idf(doc_tokens, num_docs):
    term_doc_count = {}
    for tokens in doc_tokens:
        for token in set(tokens):  # Only count a term once per document
            if token in term_doc_count:
                term_doc_count[token] += 1
            else:
                term_doc_count[token] = 1

    idf = {}
    for term, count in term_doc_count.items():
        # BM25 IDF formula (MODIFIED)
        idf[term] = np.log((num_docs - count + 0.5) / (count + 0.5) + 1)

    return idf

# Compute BM25 score (MODIFIED)
def compute_bm25_score(doc_tokens, query_tokens, idf, num_docs):
    scores = []
    avg_doc_length = np.mean([len(tokens) for tokens in doc_tokens])  # Compute average document length (NEW)

    for tokens in doc_tokens:
        score = 0
        doc_len = len(tokens)  # Get document length (NEW)
        token_counts = {token: tokens.count(token) for token in tokens}  # Term frequency calculation (NEW)

        for term in query_tokens:
            if term in idf:
                # Calculate term frequency (TF) (NEW)
                tf = token_counts.get(term, 0)
                # BM25 formula (MODIFIED)
                term_score = idf[term] * ((tf * (k1 + 1)) / (tf + k1 * (1 - b + b * (doc_len / avg_doc_length))))
                score += term_score

        scores.append(score)

    return scores

# Main function to compute and rank documents
def rank_documents(documents, query):
    num_docs = len(documents)
    idf = compute_idf(doc_tokens, num_docs)  # Uses BM25 IDF (MODIFIED)
    scores = compute_bm25_score(doc_tokens, query_tokens, idf, num_docs)  # Uses BM25 score calculation (MODIFIED)

    ranked_docs = np.argsort(scores)[::-1]  # Same sorting mechanism as before

    for i, doc_index in enumerate(ranked_docs):
        print(f"Rank {i+1}: Document {doc_index+1} (Score: {scores[doc_index]:.4f}) - '{documents[doc_index]}'")

# Rank documents based on query using BM25 (MODIFIED)
rank_documents(documents, query)

