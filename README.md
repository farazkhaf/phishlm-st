# PhishLM Security Analyzer

PhishLM is hybrid phishing URL detection system. It integrates classical machine learning (ML) methods with semantic reasoning enabled by Large Language Models (LLMs) to enhance detection accuracy and provide interpretable results. 

## Setup Instructions (Windows)

1.  **Python Environment:** Ensure Python is installed on your system.
2.  **Virtual Environment:** Open Command Prompt or PowerShell. Navigate to the project directory. Run `python -m venv venv` to create a virtual environment named `venv`.
3.  **Activate Environment:** Activate the environment using `venv\Scripts\activate`.
4.  **Install Dependencies:** Run `pip install -r requirements.txt` to install the required Python packages. 

## Running the Application

1.  **Train the ML Model:** Execute the command `python train_and_test.py`. This script trains the CatBoost ML model and saves it. It also logs the results.
1.5. **Note**: Submitted project directory already contains saved model file. There is no need to run this command.
2.  **Configure LLM API:** Obtain an API key for the LLM service (Groq).  Place API key inside this file = groq_api.txt
3.  **Launch the Web Interface:** Run the command `streamlit run frontend.py`  The application will start. Access the interface via the URL shown in the terminal.

## Core Components

*   `train_and_test.py`: Script for training the CatBoost ML model.
*   `groq_api.txt`: File containing the LLM API key.
*   `frontend.py` : The main Streamlit application script.
*   `analysis.py` : Module with core analysis logic.