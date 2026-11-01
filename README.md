# PHISH BUSTER
### AI-Powered Phishing URL Detection System

## About the Project

PHISH BUSTER is a machine-learning-based web application designed to analyse URLs and classify them according to their potential security threats.

The system uses URL feature engineering and trained machine learning models to help identify potentially malicious URLs.

## Objectives

- Analyse submitted URLs.
- Extract relevant URL characteristics.
- Apply trained machine learning models.
- Identify potentially suspicious URLs.
- Present prediction results through a user-friendly interface.

## Technologies Used

- Python
- Streamlit
- Pandas and NumPy
- Scikit-learn
- XGBoost
- Joblib

## Machine Learning Models

The project uses trained machine learning models for URL classification. The final application loads the required saved models and preprocessing objects.

## How to Run Locally

1. Clone or download this repository.
2. Install the required dependencies using `requirements.txt`.
3. Ensure the required model and encoder files are available.
4. Run the application:

   `streamlit run app.py`

## Disclaimer

PHISH BUSTER is an academic project intended to assist with URL threat analysis. Its predictions should not be treated as a guarantee that a URL is safe or malicious.